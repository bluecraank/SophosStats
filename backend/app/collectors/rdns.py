"""Lernt Hostnamen zu den IPs aus den Logs per Reverse-DNS – gedrosselt, im Hintergrund, mit Cache.

Jede IP wird höchstens einmal je RDNS_TTL_HOURS nachgeschlagen; IPs ohne PTR-Eintrag werden ebenfalls
vermerkt, damit sie nicht bei jeder Logzeile erneut abgefragt werden.
"""

import asyncio
import ipaddress
import logging
import socket
import time
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import get_settings
from app.db import SessionLocal
from app.models import HostName

log = logging.getLogger(__name__)

MAX_PENDING = 50_000
BATCH = 200


class HostResolver:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.pending: set[str] = set()
        self.next_due: dict[str, float] = {}  # IP -> monotonic Zeitpunkt der nächsten erlaubten Abfrage

    def observe(self, *ips: str | None) -> None:
        """Vom Syslog-Empfang aufgerufen: IPs merken, die (wieder) nachgeschlagen werden sollen."""
        if not self.settings.rdns_enabled:
            return
        now = time.monotonic()
        for ip in ips:
            if not ip or ip in self.pending or self.next_due.get(ip, 0) > now or len(self.pending) >= MAX_PENDING:
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
                continue
            if self.settings.rdns_private_only and not addr.is_private:
                continue
            self.pending.add(ip)

    async def _load(self) -> None:
        ttl = self.settings.rdns_ttl_hours * 3600
        now_wall, now_mono = datetime.now(UTC), time.monotonic()
        async with SessionLocal() as db:
            for ip, resolved_at in (await db.execute(select(HostName.ip, HostName.resolved_at))).all():
                self.next_due[ip] = now_mono + max(0.0, ttl - (now_wall - resolved_at).total_seconds())

    async def _lookup(self, sem: asyncio.Semaphore, ip: str) -> tuple[str, str | None]:
        loop = asyncio.get_running_loop()
        async with sem:
            try:
                name = (await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 3))[0]
                return ip, name.rstrip(".") or None
            except (OSError, TimeoutError, UnicodeError):
                return ip, None

    async def resolve_batch(self, batch: list[str]) -> list[tuple[str, str | None]]:
        sem = asyncio.Semaphore(self.settings.rdns_concurrency)
        results = await asyncio.gather(*(self._lookup(sem, ip) for ip in batch))
        now = datetime.now(UTC)
        async with SessionLocal() as db, db.begin():
            stmt = pg_insert(HostName).values(
                [{"ip": ip, "hostname": name, "resolved_at": now} for ip, name in results]
            )
            await db.execute(
                stmt.on_conflict_do_update(
                    index_elements=["ip"],
                    # Ein vorübergehend fehlender PTR-Eintrag überschreibt keinen bekannten Namen
                    set_={
                        "hostname": func.coalesce(stmt.excluded.hostname, HostName.hostname),
                        "resolved_at": stmt.excluded.resolved_at,
                    },
                )
            )
        due = time.monotonic() + self.settings.rdns_ttl_hours * 3600
        for ip, _ in results:
            self.next_due[ip] = due
        return results

    async def run(self, stop: asyncio.Event) -> None:
        if not self.settings.rdns_enabled:
            return
        await self._load()
        while not stop.is_set():
            batch = [self.pending.pop() for _ in range(min(BATCH, len(self.pending)))]
            if batch:
                try:
                    await self.resolve_batch(batch)
                except Exception:
                    log.exception("Reverse-DNS fehlgeschlagen")
            try:
                await asyncio.wait_for(stop.wait(), 2 if self.pending else 10)
            except TimeoutError:
                pass

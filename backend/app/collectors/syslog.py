"""Syslog-Empfänger (UDP + TCP) mit gebündeltem Schreiben in die Datenbank.

Auf der Firewall: System services > Log settings > Syslog server hinzufügen
(Format "Device standard format", Port wie SYSLOG_*_PORT) und die gewünschten Log-Kategorien
– mindestens "Firewall" – aktivieren. In den Firewall-Regeln "Log firewall traffic" einschalten.
"""

import asyncio
import ipaddress
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.collectors import sfos_log
from app.config import get_settings
from app.db import SessionLocal
from app.models import AdminEvent, Firewall, LogEntry, RuleLastSeen, RuleUsageHourly

log = logging.getLogger(__name__)

MAX_MESSAGE = 16 * 1024


@dataclass(slots=True)
class RawMessage:
    source_ip: str
    received: datetime
    text: str


class SyslogServer:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.queue: asyncio.Queue[RawMessage] = asyncio.Queue(maxsize=100_000)
        self.dropped_full = 0
        self.dropped_unknown = 0
        self._source_map: dict[str, int] = {}
        self._serial_map: dict[str, int] = {}
        self._map_loaded = 0.0
        self._servers: list = []

    # --- Empfang ---------------------------------------------------------

    def _enqueue(self, source_ip: str, text: str) -> None:
        try:
            self.queue.put_nowait(RawMessage(source_ip, datetime.now(UTC), text[:MAX_MESSAGE]))
        except asyncio.QueueFull:
            self.dropped_full += 1

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        server = self

        class Udp(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr) -> None:
                server._enqueue(addr[0], data.decode("utf-8", errors="replace"))

        transport, _ = await loop.create_datagram_endpoint(
            Udp, local_addr=(self.settings.syslog_bind, self.settings.syslog_udp_port)
        )
        self._servers.append(transport)
        tcp = await asyncio.start_server(
            self._handle_tcp, self.settings.syslog_bind, self.settings.syslog_tcp_port, limit=MAX_MESSAGE * 2
        )
        self._servers.append(tcp)
        log.info("Syslog lauscht auf UDP %s / TCP %s", self.settings.syslog_udp_port, self.settings.syslog_tcp_port)

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")[0]
        try:
            while True:
                first = await reader.read(1)
                if not first:
                    break
                if first.isdigit():
                    # RFC 6587 Octet-Counting: "<länge> <nachricht>"
                    length_bytes = first + await reader.readuntil(b" ")
                    length = int(length_bytes.strip())
                    if length > MAX_MESSAGE * 4:
                        break
                    data = await reader.readexactly(length)
                else:
                    data = first + await reader.readuntil(b"\n")
                text = data.decode("utf-8", errors="replace").strip()
                if text:
                    self._enqueue(peer, text)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, ValueError):
            pass
        finally:
            writer.close()

    # --- Zuordnung Absender -> Firewall ----------------------------------

    async def _refresh_source_map(self) -> None:
        if time.monotonic() - self._map_loaded < 30:
            return
        async with SessionLocal() as db:
            rows = (
                await db.execute(select(Firewall.id, Firewall.host, Firewall.syslog_source_ip, Firewall.serial))
            ).all()
        source_map, serial_map = {}, {}
        for fw_id, host, syslog_ip, serial in rows:
            for candidate in (syslog_ip, host):
                if not candidate:
                    continue
                try:
                    source_map[str(ipaddress.ip_address(candidate))] = fw_id
                except ValueError:
                    continue
            if serial:
                serial_map[serial] = fw_id
        self._source_map, self._serial_map = source_map, serial_map
        self._map_loaded = time.monotonic()

    def _firewall_for(self, msg: RawMessage, parsed: sfos_log.ParsedLog) -> int | None:
        fw_id = self._source_map.get(msg.source_ip)
        if fw_id is None:
            serial = parsed.get("device_serial_id", "device_id")
            fw_id = self._serial_map.get(serial) if serial else None
        return fw_id

    # --- Schreiben ---------------------------------------------------------

    async def run_writer(self) -> None:
        while True:
            batch: list[RawMessage] = [await self.queue.get()]
            deadline = time.monotonic() + self.settings.log_flush_seconds
            while len(batch) < self.settings.log_flush_batch:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self.queue.get(), timeout))
                except TimeoutError:
                    break
            try:
                await self._write(batch)
            except Exception:
                log.exception("Schreiben von %d Logeinträgen fehlgeschlagen", len(batch))

    async def _write(self, batch: list[RawMessage]) -> None:
        await self._refresh_source_map()
        rows: list[dict] = []
        admin_rows: list[dict] = []
        usage: dict[tuple[int, int, datetime], dict] = defaultdict(
            lambda: {"hits": 0, "denied": 0, "sent_bytes": 0, "recv_bytes": 0, "sent_pkts": 0, "recv_pkts": 0}
        )
        last_seen: dict[int, datetime] = {}

        for msg in batch:
            parsed = sfos_log.parse(msg.text, msg.received)
            if parsed is None:
                continue
            fw_id = self._firewall_for(msg, parsed)
            if fw_id is None:
                self.dropped_unknown += 1
                if self.dropped_unknown % 1000 == 1:
                    log.warning("Syslog von unbekannter Quelle %s verworfen", msg.source_ip)
                continue
            last_seen[fw_id] = max(last_seen.get(fw_id, parsed.time), parsed.time)
            rows.append(
                {
                    "time": parsed.time,
                    "firewall_id": fw_id,
                    "source_ip": msg.source_ip,
                    "log_type": parsed.log_type,
                    "log_component": parsed.get("log_component"),
                    "log_subtype": parsed.get("log_subtype"),
                    "status": parsed.get("status"),
                    "severity": parsed.get("priority", "severity"),
                    "rule_id": parsed.rule_id,
                    "rule_name": parsed.rule_name,
                    "src_ip": parsed.get("src_ip"),
                    "src_port": parsed.get_int("src_port"),
                    "dst_ip": parsed.get("dst_ip"),
                    "dst_port": parsed.get_int("dst_port"),
                    "protocol": parsed.get("protocol"),
                    "user_name": parsed.get("user_name", "user"),
                    "sent_bytes": parsed.sent_bytes,
                    "recv_bytes": parsed.recv_bytes,
                    "message": parsed.get("message"),
                    "fields": parsed.fields,
                }
            )

            if parsed.is_admin:
                admin_rows.append(
                    {
                        "time": parsed.time,
                        "firewall_id": fw_id,
                        "user_name": parsed.get("user_name", "user"),
                        "src_ip": parsed.get("src_ip"),
                        "component": parsed.get("log_component"),
                        "message": parsed.get("message"),
                    }
                )

            if parsed.log_type == "Firewall" and parsed.rule_id is not None:
                bucket = parsed.time.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
                agg = usage[(fw_id, parsed.rule_id, bucket)]
                agg["rule_name"] = parsed.rule_name or agg.get("rule_name")
                agg["last_seen"] = max(agg.get("last_seen", parsed.time), parsed.time)
                if parsed.counts_as_hit:
                    agg["hits"] += 1
                    if parsed.is_denied:
                        agg["denied"] += 1
                if parsed.counts_bytes:
                    agg["sent_bytes"] += parsed.sent_bytes or 0
                    agg["recv_bytes"] += parsed.recv_bytes or 0
                    agg["sent_pkts"] += parsed.sent_pkts or 0
                    agg["recv_pkts"] += parsed.recv_pkts or 0

        if not rows:
            return
        async with SessionLocal() as db, db.begin():
            await db.execute(insert(LogEntry), rows)
            if admin_rows:
                await db.execute(insert(AdminEvent), admin_rows)
            if usage:
                values = [
                    {"firewall_id": fw, "rule_id": rid, "time": bucket, **agg}
                    for (fw, rid, bucket), agg in usage.items()
                ]
                stmt = pg_insert(RuleUsageHourly).values(values)
                t = RuleUsageHourly.__table__.c
                ex = stmt.excluded
                stmt = stmt.on_conflict_do_update(
                    index_elements=["firewall_id", "rule_id", "time"],
                    set_={
                        "hits": t.hits + ex.hits,
                        "denied": t.denied + ex.denied,
                        "sent_bytes": t.sent_bytes + ex.sent_bytes,
                        "recv_bytes": t.recv_bytes + ex.recv_bytes,
                        "sent_pkts": t.sent_pkts + ex.sent_pkts,
                        "recv_pkts": t.recv_pkts + ex.recv_pkts,
                        "rule_name": func.coalesce(ex.rule_name, t.rule_name),
                        "last_seen": func.greatest(t.last_seen, ex.last_seen),
                    },
                )
                await db.execute(stmt)

                seen: dict[tuple[int, int], dict] = {}
                for (fw, rid, bucket), agg in usage.items():
                    cur = seen.setdefault(
                        (fw, rid), {"first_seen": bucket, "last_seen": agg["last_seen"], "rule_name": None}
                    )
                    cur["first_seen"] = min(cur["first_seen"], bucket)
                    cur["last_seen"] = max(cur["last_seen"], agg["last_seen"])
                    cur["rule_name"] = agg.get("rule_name") or cur["rule_name"]
                ls = pg_insert(RuleLastSeen).values(
                    [{"firewall_id": fw, "rule_id": rid, **v} for (fw, rid), v in seen.items()]
                )
                c = RuleLastSeen.__table__.c
                await db.execute(
                    ls.on_conflict_do_update(
                        index_elements=["firewall_id", "rule_id"],
                        set_={
                            "last_seen": func.greatest(c.last_seen, ls.excluded.last_seen),
                            "rule_name": func.coalesce(ls.excluded.rule_name, c.rule_name),
                        },
                    )
                )
            for fw_id, ts in last_seen.items():
                await db.execute(
                    update(Firewall)
                    .where(Firewall.id == fw_id)
                    .values(last_log_at=func.greatest(func.coalesce(Firewall.last_log_at, ts), ts))
                )

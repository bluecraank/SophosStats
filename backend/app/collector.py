"""Hintergrund-Collector: plant SNMP-/XML-API-Abfragen pro Firewall und empfängt Syslog.

Start: python -m app.collector
"""

import asyncio
import logging
import signal
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.collectors import poller
from app.collectors.syslog import SyslogServer
from app.config import get_settings
from app.db import SessionLocal, init_schema
from app.models import Firewall

log = logging.getLogger("collector")


class Scheduler:
    def __init__(self) -> None:
        self.running: dict[tuple[int, str], asyncio.Task] = {}
        # Letzter Versuch (auch fehlgeschlagene), damit Fehler nicht bei jedem Tick neu versucht werden
        self.last_attempt: dict[tuple[int, str], datetime] = {}

    def _due(self, key: tuple[int, str], last_ok: datetime | None, interval_s: int, now: datetime) -> bool:
        last = max((t for t in (last_ok, self.last_attempt.get(key)) if t), default=None)
        return last is None or now - last >= timedelta(seconds=interval_s)

    def _spawn(self, key: tuple[int, str], job: Callable[[int], Awaitable[None]], now: datetime) -> None:
        if key in self.running and not self.running[key].done():
            return
        self.last_attempt[key] = now
        task = asyncio.create_task(job(key[0]), name=f"{key[1]}-{key[0]}")
        task.add_done_callback(self._done)
        self.running[key] = task

    @staticmethod
    def _done(task: asyncio.Task) -> None:
        if not task.cancelled() and task.exception():
            log.error("Job %s abgebrochen", task.get_name(), exc_info=task.exception())

    async def tick(self) -> None:
        now = datetime.now(UTC)
        async with SessionLocal() as db:
            firewalls = (await db.execute(select(Firewall).where(Firewall.enabled))).scalars().all()
        for fw in firewalls:
            forced = fw.poll_requested
            key = (fw.id, "metrics")
            if fw.snmp_enabled and (forced or self._due(key, fw.last_metrics_at, fw.metrics_interval_s, now)):
                self._spawn(key, poller.poll_metrics, now)
            key = (fw.id, "config")
            if forced or self._due(key, fw.last_config_at, fw.config_interval_s, now):
                self._spawn(key, poller.poll_config, now)
            if forced:
                await poller.clear_poll_request(fw.id)

    async def run(self, stop: asyncio.Event) -> None:
        tick = get_settings().scheduler_tick_seconds
        while not stop.is_set():
            try:
                await self.tick()
            except Exception:
                log.exception("Scheduler-Tick fehlgeschlagen")
            try:
                await asyncio.wait_for(stop.wait(), tick)
            except TimeoutError:
                pass


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    await init_schema()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows
            pass

    syslog = SyslogServer()
    await syslog.start()
    writer = asyncio.create_task(syslog.run_writer(), name="syslog-writer")
    log.info("Collector gestartet")
    await Scheduler().run(stop)
    writer.cancel()


if __name__ == "__main__":
    asyncio.run(main())

"""Scheduler: erzwungene Abrufe gehen nicht verloren, laufende Jobs werden nicht doppelt gestartet."""

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace

from app import collector


class FakeSession:
    def __init__(self, fws):
        self.fws = fws

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, _stmt):
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.fws))


async def test_forced_poll_waits_for_running_job(monkeypatch):
    now = datetime.now(UTC)
    fw = SimpleNamespace(
        id=1,
        snmp_enabled=True,
        poll_requested=True,
        last_config_at=now,
        config_interval_s=900,
        last_metrics_at=now,
        metrics_interval_s=60,
    )
    started: list[str] = []
    release = asyncio.Event()

    async def poll_config(_id):
        started.append("config")
        await release.wait()

    async def poll_metrics(_id):
        started.append("metrics")

    async def clear(_id):
        fw.poll_requested = False

    monkeypatch.setattr(collector, "SessionLocal", lambda: FakeSession([fw]))
    monkeypatch.setattr(collector.poller, "poll_config", poll_config)
    monkeypatch.setattr(collector.poller, "poll_metrics", poll_metrics)
    monkeypatch.setattr(collector.poller, "clear_poll_request", clear)

    s = collector.Scheduler()
    s.running[(1, "config")] = asyncio.create_task(release.wait())  # Konfig-Abruf läuft bereits
    await s.tick()
    await asyncio.sleep(0)
    assert started == ["metrics"] and (1, "config") in s.forced

    await s.tick()  # Konfig läuft noch: nichts Neues, Metriken nicht erneut
    await asyncio.sleep(0)
    assert started == ["metrics"]

    release.set()
    await asyncio.sleep(0)
    await s.tick()  # jetzt startet der angeforderte Konfig-Abruf
    await asyncio.sleep(0)
    assert started == ["metrics", "config"] and not s.forced
    release.set()

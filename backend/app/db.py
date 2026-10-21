import logging
from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

log = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


engine = create_async_engine(get_settings().database_url, pool_pre_ping=True, pool_size=10)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session


# (Tabelle, Spalte für Retention-Einstellung, segmentby für Kompression)
_HYPERTABLES = [
    ("metrics", "retention_metrics_days", "firewall_id, name"),
    ("interface_metrics", "retention_metrics_days", "firewall_id, interface"),
    ("log_entries", "retention_logs_days", "firewall_id"),
    ("rule_usage_hourly", "retention_rule_usage_days", "firewall_id"),
]

_SCHEMA_LOCK_ID = 727274001

_ADDED_COLUMNS = [
    "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS last_config_warning TEXT",
    "ALTER TABLE config_changes ADD COLUMN IF NOT EXISTS window_start TIMESTAMPTZ",
]


async def init_schema() -> None:
    """Legt Tabellen an und richtet TimescaleDB ein. API und Collector rufen das beim Start auf,
    ein Advisory-Lock verhindert, dass beide gleichzeitig migrieren."""
    from app import models  # noqa: F401 - registriert die Tabellen an Base.metadata

    settings = get_settings()
    async with engine.begin() as conn:
        await conn.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _SCHEMA_LOCK_ID})
        try:
            async with conn.begin_nested():
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
            timescale = True
        except Exception:  # noqa: BLE001
            log.warning("TimescaleDB nicht verfügbar – Retention/Kompression deaktiviert")
            timescale = False
        await conn.run_sync(Base.metadata.create_all)
        # create_all ergänzt keine Spalten in bestehenden Tabellen – nachträglich hinzugekommene hier nachziehen
        for stmt in _ADDED_COLUMNS:
            await conn.execute(text(stmt))

        if not timescale:
            return
        for table, retention_attr, segment_by in _HYPERTABLES:
            days = getattr(settings, retention_attr)
            await conn.execute(text(f"SELECT create_hypertable('{table}', by_range('time'), if_not_exists => TRUE)"))
            await conn.execute(text(f"SELECT remove_retention_policy('{table}', if_exists => TRUE)"))
            await conn.execute(
                text(f"SELECT add_retention_policy('{table}', INTERVAL '{int(days)} days', if_not_exists => TRUE)")
            )
            # Kompression lässt sich nicht neu setzen, wenn schon komprimierte Chunks existieren –
            # Savepoint, damit ein Fehler hier nicht die ganze Transaktion abbricht
            try:
                async with conn.begin_nested():
                    await conn.execute(
                        text(
                            f"ALTER TABLE {table} SET (timescaledb.compress, "
                            f"timescaledb.compress_segmentby = '{segment_by}')"
                        )
                    )
                    await conn.execute(
                        text(f"SELECT add_compression_policy('{table}', INTERVAL '7 days', if_not_exists => TRUE)")
                    )
            except Exception as exc:  # noqa: BLE001
                log.info("Kompression für %s unverändert: %s", table, exc)

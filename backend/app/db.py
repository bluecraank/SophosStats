import json
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
    ("admin_events", "retention_logs_days", "firewall_id"),
    ("rule_usage_hourly", "retention_rule_usage_days", "firewall_id"),
    ("blocked_flows_hourly", "retention_blocked_days", "firewall_id"),
]

_SCHEMA_LOCK_ID = 727274001


# Schema-Ergänzungen, die create_all nicht abdeckt. Jede läuft genau einmal (vermerkt in schema_migrations) –
# wichtig für die Erstbefüllungen, die sonst bei jedem Start die Log-Tabelle scannen würden.
async def _redact_secrets(conn) -> None:
    """Bereits gespeicherte Geheimnisse aus Konfiguration und Änderungshistorie entfernen."""
    from app.collectors.poller import _hash, redact

    rows = (await conn.execute(text("SELECT firewall_id, entity_type, name, data FROM config_objects"))).all()
    for fw_id, entity, name, data in rows:
        clean = redact(data)
        if clean != data:
            await conn.execute(
                text(
                    "UPDATE config_objects SET data = CAST(:d AS JSONB), hash = :h "
                    "WHERE firewall_id = :f AND entity_type = :e AND name = :n"
                ),
                {"d": json.dumps(clean), "h": _hash(clean), "f": fw_id, "e": entity, "n": name},
            )
    for cid, old, new in (await conn.execute(text("SELECT id, old, new FROM config_changes"))).all():
        if redact(old) != old or redact(new) != new:
            await conn.execute(
                text("UPDATE config_changes SET old = CAST(:o AS JSONB), new = CAST(:n AS JSONB) WHERE id = :i"),
                {
                    "o": json.dumps(redact(old)) if old is not None else None,
                    "n": json.dumps(redact(new)) if new is not None else None,
                    "i": cid,
                },
            )


async def _backfill_changed_keys(conn) -> None:
    from app.collectors.poller import changed_keys

    rows = (await conn.execute(text("SELECT id, old, new FROM config_changes WHERE action = 'modified'"))).all()
    for cid, old, new in rows:
        await conn.execute(
            text("UPDATE config_changes SET changed_keys = CAST(:k AS JSONB) WHERE id = :i"),
            {"k": json.dumps(changed_keys(old, new)), "i": cid},
        )


_PYTHON_MIGRATIONS = {"redact_secrets": _redact_secrets, "backfill_changed_keys": _backfill_changed_keys}

_MIGRATIONS: list[tuple[str, str]] = [
    ("001_firewall_config_warning", "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS last_config_warning TEXT"),
    ("002_change_window_start", "ALTER TABLE config_changes ADD COLUMN IF NOT EXISTS window_start TIMESTAMPTZ"),
    ("003_firewall_site_networks", "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS site_networks TEXT"),
    ("004_firewall_site_link_zone", "ALTER TABLE firewalls ADD COLUMN IF NOT EXISTS site_link_zone VARCHAR(100)"),
    # Korrelation von Verbindungen über mehrere Firewalls (Quelle/Ziel im Zeitfenster)
    ("005_index_log_flow", "CREATE INDEX IF NOT EXISTS ix_log_flow ON log_entries (src_ip, dst_ip, time)"),
    ("006_index_log_dst", "CREATE INDEX IF NOT EXISTS ix_log_dst ON log_entries (dst_ip, time)"),
    (
        "007_backfill_rule_last_seen",
        "INSERT INTO rule_last_seen (firewall_id, rule_id, rule_name, first_seen, last_seen) "
        "SELECT firewall_id, rule_id, max(rule_name), min(time), max(last_seen) FROM rule_usage_hourly "
        "GROUP BY firewall_id, rule_id ON CONFLICT DO NOTHING",
    ),
    (
        # gleiche Regel wie sfos_log.ParsedLog.is_admin
        "008_backfill_admin_events",
        "INSERT INTO admin_events (time, firewall_id, user_name, src_ip, component, message) "
        "SELECT time, firewall_id, user_name, src_ip, log_component, message FROM log_entries "
        "WHERE NOT EXISTS (SELECT 1 FROM admin_events) AND firewall_id IS NOT NULL AND ("
        "log_subtype ILIKE '%admin%' OR log_type ILIKE '%admin%' "
        "OR log_component IN ('GUI', 'CLI', 'API', 'Console', 'SSH', 'Admin', 'Central'))",
    ),
    # Bereits gespeicherte Geheimnisse (z.B. VPN-PSK) aus Konfiguration und Änderungshistorie entfernen
    ("010_redact_secrets", "python:redact_secrets"),
    ("011_change_changed_keys", "ALTER TABLE config_changes ADD COLUMN IF NOT EXISTS changed_keys JSONB"),
    ("012_backfill_changed_keys", "python:backfill_changed_keys"),
    (
        # einmalig aus den vorhandenen Logs verdichten (nutzt den Teilindex ix_log_denied)
        "013_backfill_blocked_flows",
        "INSERT INTO blocked_flows_hourly (firewall_id, src_ip, dst_ip, dst_port, protocol, time, hits, rule_name, "
        "last_seen) SELECT firewall_id, src_ip, coalesce(dst_ip, ''), coalesce(dst_port, 0), coalesce(protocol, ''), "
        "date_trunc('hour', time), count(*), max(rule_name), max(time) FROM log_entries "
        "WHERE log_type = 'Firewall' AND (log_subtype IN ('Denied', 'Drop') OR status IN ('Deny', 'Drop')) "
        "AND firewall_id IS NOT NULL AND src_ip IS NOT NULL "
        "GROUP BY 1, 2, 3, 4, 5, 6 ON CONFLICT DO NOTHING",
    ),
    # Abgelehnte Verbindungen (Standortübergreifend, Bericht) ohne Scan über alle Logs finden
    (
        "009_index_log_denied",
        "CREATE INDEX IF NOT EXISTS ix_log_denied ON log_entries (time) WHERE log_type = 'Firewall' "
        "AND (log_subtype IN ('Denied', 'Drop') OR status IN ('Deny', 'Drop'))",
    ),
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
        await conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(id VARCHAR(100) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
        )
        applied = set((await conn.execute(text("SELECT id FROM schema_migrations"))).scalars())
        for mig_id, stmt in _MIGRATIONS:
            if mig_id in applied:
                continue
            try:
                async with conn.begin_nested():
                    if stmt.startswith("python:"):
                        await _PYTHON_MIGRATIONS[stmt.removeprefix("python:")](conn)
                    else:
                        await conn.execute(text(stmt))
                    await conn.execute(text("INSERT INTO schema_migrations (id) VALUES (:id)"), {"id": mig_id})
                log.info("Migration %s ausgeführt", mig_id)
            except Exception as exc:  # noqa: BLE001 - z.B. Index auf komprimierter Hypertable; nächster Start erneut
                log.warning("Migration %s übersprungen: %s", mig_id, exc)

        if not timescale:
            return
        for table, retention_attr, segment_by in _HYPERTABLES:
            days = getattr(settings, retention_attr)
            # migrate_data: neu hinzugekommene Tabellen können beim ersten Start schon befüllt sein (Erstbefüllung)
            await conn.execute(
                text(
                    f"SELECT create_hypertable('{table}', by_range('time'), "
                    "if_not_exists => TRUE, migrate_data => TRUE)"
                )
            )
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

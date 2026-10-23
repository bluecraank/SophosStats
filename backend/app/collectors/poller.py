import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import insert, select, update

from app.collectors.snmp import SnmpClient, SnmpResult
from app.collectors.xmlapi import SophosXmlApi
from app.db import SessionLocal
from app.models import ConfigChange, ConfigObject, Firewall, InterfaceMetric, Metric
from app.security import decrypt

log = logging.getLogger(__name__)


def xml_client(fw: Firewall) -> SophosXmlApi:
    return SophosXmlApi(fw.host, fw.api_port, fw.api_username, decrypt(fw.api_password_enc), fw.verify_tls)


def snmp_client(fw: Firewall) -> SnmpClient:
    if not fw.snmp_username:
        raise ValueError("Kein SNMP-Benutzer konfiguriert")
    return SnmpClient(
        fw.host,
        fw.snmp_port,
        fw.snmp_username,
        fw.snmp_auth_protocol,
        decrypt(fw.snmp_auth_key_enc) if fw.snmp_auth_key_enc else None,
        fw.snmp_priv_protocol,
        decrypt(fw.snmp_priv_key_enc) if fw.snmp_priv_key_enc else None,
    )


def _err(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:1000]


# --- Metriken ----------------------------------------------------------------

# Letzte Interface-Zählerstände je (firewall_id, interface) -> (zeit, in, out), für Ratenberechnung
_last_counters: dict[tuple[int, str], tuple[datetime, int, int]] = {}


def _rate(prev: int, cur: int, seconds: float) -> float | None:
    # Zähler-Reset (Reboot) oder Überlauf: keine sinnvolle Rate
    if seconds <= 0 or cur < prev:
        return None
    return (cur - prev) * 8 / seconds


def interface_rows(fw_id: int, now: datetime, result: SnmpResult) -> list[dict]:
    rows = []
    for itf in result.interfaces:
        key = (fw_id, itf.name)
        prev = _last_counters.get(key)
        in_bps = out_bps = None
        if prev:
            seconds = (now - prev[0]).total_seconds()
            in_bps = _rate(prev[1], itf.in_octets, seconds)
            out_bps = _rate(prev[2], itf.out_octets, seconds)
        _last_counters[key] = (now, itf.in_octets, itf.out_octets)
        rows.append(
            {
                "firewall_id": fw_id,
                "interface": itf.name,
                "time": now,
                "in_bps": in_bps,
                "out_bps": out_bps,
                "in_octets": itf.in_octets,
                "out_octets": itf.out_octets,
                "oper_up": itf.oper_up,
            }
        )
    return rows


async def poll_metrics(fw_id: int) -> None:
    async with SessionLocal() as db:
        fw = await db.get(Firewall, fw_id)
        if fw is None:
            return
        now = datetime.now(UTC)
        try:
            result = await snmp_client(fw).poll()
        except Exception as exc:
            log.warning("SNMP-Abfrage %s fehlgeschlagen: %s", fw.name, exc)
            fw.last_metrics_error = _err(exc)
            await db.commit()
            return

        if result.metrics:
            await db.execute(
                insert(Metric),
                [{"firewall_id": fw.id, "name": k, "time": now, "value": v} for k, v in result.metrics.items()],
            )
        if_rows = interface_rows(fw.id, now, result)
        if if_rows:
            await db.execute(insert(InterfaceMetric), if_rows)
        fw.model = result.device.get("model") or fw.model
        fw.firmware = result.device.get("firmware") or fw.firmware
        fw.serial = result.device.get("serial") or fw.serial
        fw.last_metrics_at = now
        fw.last_metrics_error = None if result.metrics else "SNMP lieferte keine SFOS-Werte (MIB/Rechte prüfen)"
        await db.commit()


# --- Konfiguration -----------------------------------------------------------


# Geheimnisse (VPN-PSK, Passwörter, private Schlüssel) nie speichern – auch Betrachter sehen die Konfiguration
_SECRET_KEY = re.compile(r"(password|passphrase|secret|presharedkey|psk|privatekey|private_key)$", re.IGNORECASE)
REDACTED = "***"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (REDACTED if _SECRET_KEY.search(k) and v not in ("", None) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def _hash(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _item_name(item: dict, index: int) -> str:
    name = item.get("Name")
    if isinstance(name, str) and name:
        return name[:255]
    return f"#{index}-{_hash(item)[:12]}"


async def poll_config(fw_id: int) -> None:
    async with SessionLocal() as db:
        fw = await db.get(Firewall, fw_id)
        if fw is None:
            return
        now = datetime.now(UTC)
        api = xml_client(fw)
        try:
            results = await api.get_config()
        except Exception as exc:
            log.warning("XML-API %s fehlgeschlagen: %s", fw.name, exc)
            fw.last_config_error = _err(exc)
            await db.commit()
            return

        existing_rows = (await db.execute(select(ConfigObject).where(ConfigObject.firewall_id == fw.id))).scalars()
        existing: dict[tuple[str, str], ConfigObject] = {(o.entity_type, o.name): o for o in existing_rows}
        first_snapshot = not existing
        prev_poll = fw.last_config_at
        errors, no_permission = [], []

        for res in results:
            if res.unsupported:
                # Entität gibt es in dieser Firmware nicht (z.B. alter/neuer Name) – still überspringen
                continue
            if res.no_permission:
                no_permission.append(res.entity)
                continue
            if res.error:
                errors.append(f"{res.entity}: {res.error}")
                continue
            seen: set[str] = set()
            for pos, raw in enumerate(res.items):
                item = redact(raw)
                name = _item_name(item, pos)
                if name in seen:
                    continue
                seen.add(name)
                digest = _hash(item)
                obj = existing.get((res.entity, name))
                if obj is None:
                    db.add(
                        ConfigObject(
                            firewall_id=fw.id,
                            entity_type=res.entity,
                            name=name,
                            position=pos,
                            data=item,
                            hash=digest,
                            updated_at=now,
                        )
                    )
                    if not first_snapshot:
                        db.add(
                            ConfigChange(
                                firewall_id=fw.id,
                                entity_type=res.entity,
                                name=name,
                                action="added",
                                new=item,
                                time=now,
                                window_start=prev_poll,
                            )
                        )
                    continue
                if obj.hash != digest and redact(obj.data) == item:
                    # Unterschied nur durch nachträgliches Ausblenden von Geheimnissen – keine echte Änderung
                    obj.data, obj.hash, obj.updated_at = item, digest, now
                elif obj.hash != digest:
                    db.add(
                        ConfigChange(
                            firewall_id=fw.id,
                            entity_type=res.entity,
                            name=name,
                            action="modified",
                            old=obj.data,
                            new=item,
                            time=now,
                            window_start=prev_poll,
                        )
                    )
                    obj.data, obj.hash, obj.updated_at = item, digest, now
                obj.position = pos

            removed = [o for (etype, name), o in existing.items() if etype == res.entity and name not in seen]
            for o in removed:
                db.add(
                    ConfigChange(
                        firewall_id=fw.id,
                        entity_type=res.entity,
                        name=o.name,
                        action="removed",
                        old=o.data,
                        time=now,
                        window_start=prev_poll,
                    )
                )
                await db.delete(o)

        fw.api_version = api.api_version or fw.api_version
        fw.last_config_at = now
        fw.last_config_error = "; ".join(errors)[:1000] or None
        fw.last_config_warning = (
            f"Keine Leserechte für: {', '.join(no_permission)} (Admin-Profil des API-Benutzers prüfen)"
            if no_permission
            else None
        )
        await db.commit()


async def clear_poll_request(fw_id: int) -> None:
    async with SessionLocal() as db:
        await db.execute(update(Firewall).where(Firewall.id == fw_id).values(poll_requested=False))
        await db.commit()

"""Regel-Audit, Änderungsnachverfolgung, Konfigurationsvergleiche und Berichte."""

import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select

from app.api.firewalls import get_firewall
from app.api.stats import Hours, _since, rules_overview
from app.models import AdminEvent, ConfigChange, ConfigObject, FindingAck, Firewall, LogEntry, Metric
from app.schemas import FirewallOut
from app.security import DB, AdminUser, CurrentUser
from app.services.audit import audit_rules
from app.services.config_history import Change, compare_objects, diff_since, state_at

router = APIRouter(prefix="/api", tags=["compliance"])

UnusedDays = Annotated[int, Query(ge=1, le=365)]


# --- Regel-Audit ---------------------------------------------------------------


def _ack_dict(a: FindingAck) -> dict:
    return {
        "id": a.id,
        "reason": a.reason,
        "by": a.created_by,
        "at": a.created_at,
        "expires_at": a.expires_at,
    }


async def _apply_acks(db: DB, fw_id: int, findings: list[dict], now: datetime) -> None:
    """Hängt Akzeptanzen an Befunde. Gültig nur unverändert (Regel-Hash) und nicht abgelaufen."""
    acks = {
        (a.kind, a.rule_name): a
        for a in (await db.execute(select(FindingAck).where(FindingAck.firewall_id == fw_id))).scalars()
    }
    if not acks:
        return
    hashes = dict(
        (
            await db.execute(
                select(ConfigObject.name, ConfigObject.hash).where(
                    ConfigObject.firewall_id == fw_id, ConfigObject.entity_type == "FirewallRule"
                )
            )
        ).all()
    )
    for f in findings:
        a = acks.get((f["kind"], f["rule"]))
        if a is None:
            continue
        if a.rule_hash and hashes.get(f["rule"]) != a.rule_hash:
            f["ack_stale"] = {**_ack_dict(a), "why": "Regel wurde seit der Akzeptanz geändert"}
        elif a.expires_at and a.expires_at <= now:
            f["ack_stale"] = {**_ack_dict(a), "why": "Akzeptanz ist abgelaufen"}
        else:
            f["ack"] = _ack_dict(a)


async def _audit(db: DB, fw_id: int, unused_days: int) -> dict:
    now = datetime.now(UTC)
    since = now - timedelta(days=unused_days)
    overview = await rules_overview(db, fw_id, since)
    rules = overview["rules"]
    findings = audit_rules(rules, now, overview["data_since"], unused_days)

    # Nutzungsprofile (Quellen/Ziele/Ports) bewusst nicht hier: das wäre ein Scan über 30 Tage Roh-Logs für
    # jede breite Regel. Pro Regel abrufbar über /rules/{id}/profile.
    await _apply_acks(db, fw_id, findings, now)
    open_findings = [f for f in findings if "ack" not in f]
    return {
        "unused_days": unused_days,
        "data_since": overview["data_since"],
        "rule_count": len(rules),
        "enabled_count": sum(1 for r in rules if r["enabled"]),
        "summary": dict(Counter(f["kind"] for f in open_findings)),
        "acknowledged": len(findings) - len(open_findings),
        "findings": findings,
    }


@router.get("/firewalls/{fw_id}/audit")
async def audit(fw_id: int, db: DB, _user: CurrentUser, unused_days: UnusedDays = 30) -> dict:
    await get_firewall(db, fw_id)
    return await _audit(db, fw_id, unused_days)


class AckIn(BaseModel):
    kind: str = Field(max_length=32)
    rule: str = Field(max_length=255)
    reason: str = Field(min_length=5, max_length=2000)
    expires_days: int | None = Field(default=None, ge=1, le=1095)


@router.post("/firewalls/{fw_id}/audit/acks", status_code=status.HTTP_201_CREATED)
async def acknowledge(fw_id: int, body: AckIn, db: DB, admin: AdminUser) -> dict:
    """Befund als bewusst akzeptiert markieren (ersetzt eine frühere Akzeptanz desselben Befunds)."""
    await get_firewall(db, fw_id)
    rule_hash = await db.scalar(
        select(ConfigObject.hash).where(
            ConfigObject.firewall_id == fw_id,
            ConfigObject.entity_type == "FirewallRule",
            ConfigObject.name == body.rule,
        )
    )
    if rule_hash is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Regel nicht gefunden")
    await db.execute(
        delete(FindingAck).where(
            FindingAck.firewall_id == fw_id, FindingAck.kind == body.kind, FindingAck.rule_name == body.rule
        )
    )
    ack = FindingAck(
        firewall_id=fw_id,
        kind=body.kind,
        rule_name=body.rule,
        rule_hash=rule_hash,
        reason=body.reason.strip(),
        created_by=admin.username,
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=body.expires_days) if body.expires_days else None,
    )
    db.add(ack)
    await db.commit()
    return _ack_dict(ack)


@router.delete("/firewalls/{fw_id}/audit/acks/{ack_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_ack(fw_id: int, ack_id: int, db: DB, _admin: AdminUser) -> None:
    await db.execute(delete(FindingAck).where(FindingAck.firewall_id == fw_id, FindingAck.id == ack_id))
    await db.commit()


@router.get("/firewalls/{fw_id}/rules/{rule_id}/profile")
async def rule_profile(fw_id: int, rule_id: int, db: DB, _user: CurrentUser, hours: Hours = 24 * 30) -> dict:
    """Tatsächlich genutzte Verbindungen einer Regel – Grundlage, um zu breite Regeln einzuschränken."""
    await get_firewall(db, fw_id)
    base = [
        LogEntry.firewall_id == fw_id,
        LogEntry.rule_id == rule_id,
        LogEntry.log_type == "Firewall",
        LogEntry.time > _since(hours),
    ]
    counts = (
        await db.execute(
            select(
                func.count(func.distinct(LogEntry.src_ip)),
                func.count(func.distinct(LogEntry.dst_ip)),
                func.count(func.distinct(LogEntry.dst_port)),
                func.count(func.distinct(LogEntry.src_ip.concat(">").concat(LogEntry.dst_ip))),
            ).where(*base)
        )
    ).one()
    total_bytes = func.sum(func.coalesce(LogEntry.sent_bytes, 0) + func.coalesce(LogEntry.recv_bytes, 0))
    flows = (
        await db.execute(
            select(
                LogEntry.src_ip,
                LogEntry.dst_ip,
                LogEntry.dst_port,
                LogEntry.protocol,
                func.count().label("hits"),
                total_bytes.label("bytes"),
                func.max(LogEntry.time).label("last_seen"),
            )
            .where(*base)
            .group_by(LogEntry.src_ip, LogEntry.dst_ip, LogEntry.dst_port, LogEntry.protocol)
            .order_by(func.count().desc())
            .limit(25)
        )
    ).all()
    ports = (
        await db.execute(
            select(LogEntry.protocol, LogEntry.dst_port, func.count().label("hits"))
            .where(*base, LogEntry.dst_port.is_not(None))
            .group_by(LogEntry.protocol, LogEntry.dst_port)
            .order_by(func.count().desc())
            .limit(25)
        )
    ).all()
    return {
        "hours": hours,
        "distinct": {"sources": counts[0], "destinations": counts[1], "ports": counts[2], "pairs": counts[3]},
        "ports": [{"protocol": p.protocol, "port": p.dst_port, "hits": p.hits} for p in ports],
        "flows": [
            {
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "dst_port": f.dst_port,
                "protocol": f.protocol,
                "hits": f.hits,
                "bytes": int(f.bytes or 0),
                "last_seen": f.last_seen,
            }
            for f in flows
        ],
    }


# --- Änderungen: wer, wann, Stand am Datum ------------------------------------


_CHANGE_WORDS = ("add", "modif", "delet", "chang", "updat", "creat", "remov", "edit", "appl")
_BY = re.compile(r"\bby\s+'?([^'\s]+)'?", re.IGNORECASE)
_FROM = re.compile(r"\bfrom\s+'?([0-9a-fA-F:.]+)'?", re.IGNORECASE)
_USING = re.compile(r"\busing\s+'?([^'\s]+)'?", re.IGNORECASE)


def _actor(log, exact: bool) -> dict:
    """Benutzer/IP/Zugang aus den Logfeldern, ersatzweise aus dem Meldungstext
    ("... was modified by 'admin' from '10.0.0.5' using 'GUI'")."""
    msg = log.message or ""

    def find(rx):
        m = rx.search(msg)
        return m.group(1) if m else None

    return {
        "time": log.time,
        "user": log.user_name or find(_BY),
        "src_ip": log.src_ip or find(_FROM),
        "via": find(_USING) or log.log_component,
        "message": msg,
        "exact": exact,
    }


async def change_actors(db: DB, fw: Firewall, changes: list[ConfigChange]) -> dict[int, list[dict]]:
    """Ordnet erkannten Änderungen Admin-Events aus dem Syslog im selben Zeitfenster zu (seit dem vorherigen
    Abruf). Exakt, wenn der Objektname in der Meldung steht – sonst die Änderungsaktionen im Fenster als
    Vermutung (exact=False)."""
    if not changes:
        return {}
    starts = {
        c.id: (c.window_start or c.time - timedelta(seconds=fw.config_interval_s)) - timedelta(minutes=1)
        for c in changes
    }
    logs = (
        await db.execute(
            select(
                AdminEvent.time,
                AdminEvent.user_name,
                AdminEvent.src_ip,
                AdminEvent.component.label("log_component"),
                AdminEvent.message,
            )
            .where(
                AdminEvent.firewall_id == fw.id,
                AdminEvent.time >= min(starts.values()),
                AdminEvent.time <= max(c.time for c in changes),
                AdminEvent.message.is_not(None),
            )
            .order_by(AdminEvent.time)
            .limit(20_000)
        )
    ).all()
    result: dict[int, list[dict]] = {}
    for c in changes:
        window = [log for log in logs if starts[c.id] <= log.time <= c.time]
        name = c.name.lower()
        exact = [_actor(log, True) for log in window if name in log.message.lower()]
        if exact:
            result[c.id] = exact[-3:]
            continue
        guesses = [_actor(log, False) for log in window if any(w in log.message.lower() for w in _CHANGE_WORDS)]
        if guesses:
            result[c.id] = guesses[-3:]
    return result


@router.get("/firewalls/{fw_id}/admin-events/status")
async def admin_events_status(fw_id: int, db: DB, _user: CurrentUser) -> dict:
    """Kommen Admin-Events per Syslog an? Ohne sie ist "wer hat geändert" nicht ermittelbar."""
    await get_firewall(db, fw_id)
    row = (
        await db.execute(
            select(func.count(), func.max(AdminEvent.time)).where(
                AdminEvent.firewall_id == fw_id, AdminEvent.time > datetime.now(UTC) - timedelta(days=7)
            )
        )
    ).one()
    return {"count_7d": row[0], "last_at": row[1]}


def _change_dict(c: ConfigChange, actors: dict[int, list[dict]]) -> dict:
    return {
        "id": c.id,
        "time": c.time,
        "window_start": c.window_start,
        "entity_type": c.entity_type,
        "name": c.name,
        "action": c.action,
        "old": c.old,
        "new": c.new,
        "actors": actors.get(c.id, []),
    }


@router.get("/firewalls/{fw_id}/changes")
async def changes(
    fw_id: int,
    db: DB,
    _user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    fw = await get_firewall(db, fw_id)
    rows = list(
        (
            await db.execute(
                select(ConfigChange)
                .where(ConfigChange.firewall_id == fw_id)
                .order_by(ConfigChange.time.desc(), ConfigChange.id.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars()
    )
    actors = await change_actors(db, fw, rows)
    return [_change_dict(c, actors) for c in rows]


async def _current_and_changes_after(db: DB, fw_id: int, time: datetime):
    current = {
        (o.entity_type, o.name): o.data
        for o in (await db.execute(select(ConfigObject).where(ConfigObject.firewall_id == fw_id))).scalars()
    }
    after = [
        Change(c.id, c.time, c.entity_type, c.name, c.action, c.old, c.new)
        for c in (
            await db.execute(select(ConfigChange).where(ConfigChange.firewall_id == fw_id, ConfigChange.time > time))
        ).scalars()
    ]
    return current, after


def _clamp_to_history(fw: Firewall, time: datetime) -> tuple[datetime, bool]:
    """Vor dem ersten Abruf ist kein Stand bekannt – frühestens ab Anlage der Firewall rekonstruieren."""
    return (fw.created_at, True) if time < fw.created_at else (time, False)


@router.get("/firewalls/{fw_id}/config/at")
async def config_at(fw_id: int, time: datetime, db: DB, _user: CurrentUser, entity_type: str | None = None) -> dict:
    """Konfiguration, wie sie zum Zeitpunkt `time` war (rekonstruiert aus der Änderungshistorie)."""
    fw = await get_firewall(db, fw_id)
    time, clamped = _clamp_to_history(fw, time)
    current, after = await _current_and_changes_after(db, fw_id, time)
    state = state_at(current, after)
    types = Counter(t for t, _ in state)
    objects = sorted(
        ({"name": n, "data": d} for (t, n), d in state.items() if t == entity_type), key=lambda o: o["name"]
    )
    return {"time": time, "clamped": clamped, "types": dict(sorted(types.items())), "objects": objects}


@router.get("/firewalls/{fw_id}/changes/since")
async def changes_since(fw_id: int, time: datetime, db: DB, _user: CurrentUser) -> dict:
    """Netto-Unterschiede zwischen dem Stand zum Zeitpunkt `time` und heute."""
    fw = await get_firewall(db, fw_id)
    time, clamped = _clamp_to_history(fw, time)
    current, after = await _current_and_changes_after(db, fw_id, time)
    diff = diff_since(current, after)
    return {
        "time": time,
        "clamped": clamped,
        "summary": dict(Counter(d["action"] for d in diff)),
        "items": diff,
    }


# --- Firewall-Vergleich -----------------------------------------------------------


async def _objects(db: DB, fw_id: int, entity_type: str | None = None) -> dict[str, dict[str, dict]]:
    stmt = select(ConfigObject).where(ConfigObject.firewall_id == fw_id)
    if entity_type:
        stmt = stmt.where(ConfigObject.entity_type == entity_type)
    result: dict[str, dict[str, dict]] = {}
    for o in (await db.execute(stmt)).scalars():
        result.setdefault(o.entity_type, {})[o.name] = o.data
    return result


@router.get("/compare")
async def compare(a: int, b: int, db: DB, _user: CurrentUser, entity_type: str | None = None) -> dict:
    """Vergleicht die Konfiguration zweier Firewalls. Ohne entity_type: Zusammenfassung je Objekttyp."""
    await get_firewall(db, a)
    await get_firewall(db, b)
    objs_a, objs_b = await _objects(db, a, entity_type), await _objects(db, b, entity_type)
    if entity_type:
        return {"entity_type": entity_type, **compare_objects(objs_a.get(entity_type, {}), objs_b.get(entity_type, {}))}
    summary = []
    for t in sorted(set(objs_a) | set(objs_b)):
        r = compare_objects(objs_a.get(t, {}), objs_b.get(t, {}))
        summary.append(
            {
                "entity_type": t,
                "only_a": len(r["only_a"]),
                "only_b": len(r["only_b"]),
                "different": len(r["different"]),
                "same": r["same"],
            }
        )
    return {"types": summary}


# --- Bericht ------------------------------------------------------------------------


@router.get("/firewalls/{fw_id}/report")
async def report(
    fw_id: int,
    start: datetime,
    end: datetime,
    db: DB,
    _user: CurrentUser,
    unused_days: UnusedDays = 30,
) -> dict:
    """Bündelt alle Kennzahlen eines Zeitraums für einen druckbaren Bericht."""
    fw = await get_firewall(db, fw_id)
    if end <= start or end - start > timedelta(days=400):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Zeitraum ungültig (max. 400 Tage)")

    change_rows = list(
        (
            await db.execute(
                select(ConfigChange)
                .where(ConfigChange.firewall_id == fw_id, ConfigChange.time >= start, ConfigChange.time < end)
                .order_by(ConfigChange.time)
                .limit(1000)
            )
        ).scalars()
    )
    actors = await change_actors(db, fw, change_rows)

    overview = await rules_overview(db, fw_id, start, end)
    used = [r for r in overview["rules"] if r["usage"]]
    totals = {
        "hits": sum(r["usage"]["hits"] for r in used) + sum(u["hits"] for u in overview["unmapped_usage"]),
        "denied": sum(r["usage"]["denied"] for r in used) + sum(u["denied"] for u in overview["unmapped_usage"]),
        "sent_bytes": sum(r["usage"]["sent_bytes"] for r in used),
        "recv_bytes": sum(r["usage"]["recv_bytes"] for r in used),
    }
    top_rules = sorted(used, key=lambda r: r["usage"]["sent_bytes"] + r["usage"]["recv_bytes"], reverse=True)[:10]

    blocked = (
        await db.execute(
            select(LogEntry.src_ip, func.count().label("hits"))
            .where(
                LogEntry.firewall_id == fw_id,
                LogEntry.time >= start,
                LogEntry.time < end,
                LogEntry.log_type == "Firewall",
                or_(LogEntry.log_subtype.ilike("denied"), LogEntry.status.ilike("deny")),
                LogEntry.src_ip.is_not(None),
            )
            .group_by(LogEntry.src_ip)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()

    metric_rows = (
        await db.execute(
            select(Metric.name, func.avg(Metric.value), func.max(Metric.value))
            .where(
                Metric.firewall_id == fw_id,
                Metric.time >= start,
                Metric.time < end,
                Metric.name.in_(["cpu_percent", "memory_percent", "disk_percent"]),
            )
            .group_by(Metric.name)
        )
    ).all()

    admin_events = await db.scalar(
        select(func.count()).where(AdminEvent.firewall_id == fw_id, AdminEvent.time >= start, AdminEvent.time < end)
    )

    return {
        "generated_at": datetime.now(UTC),
        "firewall": FirewallOut.model_validate(fw).model_dump(mode="json"),
        "start": start,
        "end": end,
        "metrics": {name: {"avg": avg, "max": mx} for name, avg, mx in metric_rows},
        "traffic": totals,
        "top_rules": [
            {"name": r["name"], "position": r["position"], "action": r["action"], **r["usage"]} for r in top_rules
        ],
        "top_blocked_sources": [{"src_ip": r.src_ip, "hits": r.hits} for r in blocked],
        "changes": [_change_dict(c, actors) for c in change_rows],
        "change_summary": dict(Counter(c.action for c in change_rows)),
        "admin_events": admin_events or 0,
        "audit": await _audit(db, fw_id, unused_days),
    }

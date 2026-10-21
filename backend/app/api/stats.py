from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import and_, func, literal_column, or_, select, tuple_
from sqlalchemy.dialects.postgresql import distinct_on

from app.api.firewalls import get_firewall
from app.models import ConfigObject, Firewall, InterfaceMetric, LogEntry, Metric, RuleUsageHourly
from app.schemas import FirewallOut
from app.security import DB, CurrentUser
from app.services.log_filters import LogFilter, to_condition
from app.services.rules import rule_groups, summarize_rule

_FILTER_LIST = TypeAdapter(list[LogFilter])

router = APIRouter(prefix="/api", tags=["stats"])

Hours = Annotated[int, Query(ge=1, le=24 * 400)]


def _since(hours: int) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours)


def _bucket_seconds(hours: int) -> int:
    if hours <= 6:
        return 60
    if hours <= 48:
        return 300
    if hours <= 24 * 8:
        return 1800
    if hours <= 24 * 31:
        return 3 * 3600
    return 24 * 3600


def _bucket(column, seconds: int):
    return func.date_bin(
        literal_column(f"INTERVAL '{int(seconds)} seconds'"), column, literal_column("TIMESTAMPTZ '2000-01-01Z'")
    )


@router.get("/dashboard")
async def dashboard(db: DB, _user: CurrentUser) -> list[dict]:
    firewalls = (await db.execute(select(Firewall).order_by(Firewall.name))).scalars().all()
    latest = (
        await db.execute(
            select(Metric.firewall_id, Metric.name, Metric.value, Metric.time)
            .ext(distinct_on(Metric.firewall_id, Metric.name))
            .where(Metric.time > _since(1))
            .order_by(Metric.firewall_id, Metric.name, Metric.time.desc())
        )
    ).all()
    usage = {
        row.firewall_id: row
        for row in (
            await db.execute(
                select(
                    RuleUsageHourly.firewall_id,
                    func.sum(RuleUsageHourly.hits).label("hits"),
                    func.sum(RuleUsageHourly.denied).label("denied"),
                    func.sum(RuleUsageHourly.sent_bytes + RuleUsageHourly.recv_bytes).label("bytes"),
                )
                .where(RuleUsageHourly.time > _since(24))
                .group_by(RuleUsageHourly.firewall_id)
            )
        ).all()
    }
    result = []
    for fw in firewalls:
        metrics = {r.name: r.value for r in latest if r.firewall_id == fw.id}
        u = usage.get(fw.id)
        result.append(
            {
                "firewall": FirewallOut.model_validate(fw).model_dump(mode="json"),
                "metrics": metrics,
                "hits_24h": int(u.hits or 0) if u else 0,
                "denied_24h": int(u.denied or 0) if u else 0,
                "bytes_24h": int(u.bytes or 0) if u else 0,
            }
        )
    return result


@router.get("/firewalls/{fw_id}/metrics")
async def metrics(
    fw_id: int,
    db: DB,
    _user: CurrentUser,
    hours: Hours = 24,
    names: Annotated[list[str] | None, Query()] = None,
) -> dict:
    await get_firewall(db, fw_id)
    secs = _bucket_seconds(hours)
    bucket = _bucket(Metric.time, secs).label("bucket")
    stmt = (
        select(bucket, Metric.name, func.avg(Metric.value).label("v"), func.max(Metric.value).label("max"))
        .where(Metric.firewall_id == fw_id, Metric.time > _since(hours))
        .group_by(bucket, Metric.name)
        .order_by(bucket)
    )
    if names:
        stmt = stmt.where(Metric.name.in_(names))
    series: dict[str, list[dict]] = {}
    for row in (await db.execute(stmt)).all():
        series.setdefault(row.name, []).append({"t": row.bucket, "v": row.v, "max": row.max})
    return {"bucket_seconds": secs, "series": series}


@router.get("/firewalls/{fw_id}/interfaces")
async def interfaces(fw_id: int, db: DB, _user: CurrentUser, hours: Hours = 24) -> dict:
    await get_firewall(db, fw_id)
    latest = (
        await db.execute(
            select(InterfaceMetric)
            .ext(distinct_on(InterfaceMetric.interface))
            .where(InterfaceMetric.firewall_id == fw_id, InterfaceMetric.time > _since(1))
            .order_by(InterfaceMetric.interface, InterfaceMetric.time.desc())
        )
    ).scalars()
    secs = _bucket_seconds(hours)
    bucket = _bucket(InterfaceMetric.time, secs).label("bucket")
    rows = (
        await db.execute(
            select(
                bucket,
                InterfaceMetric.interface,
                func.avg(InterfaceMetric.in_bps).label("in_bps"),
                func.avg(InterfaceMetric.out_bps).label("out_bps"),
            )
            .where(InterfaceMetric.firewall_id == fw_id, InterfaceMetric.time > _since(hours))
            .group_by(bucket, InterfaceMetric.interface)
            .order_by(bucket)
        )
    ).all()
    return {
        "bucket_seconds": secs,
        "latest": [
            {"interface": i.interface, "time": i.time, "in_bps": i.in_bps, "out_bps": i.out_bps, "oper_up": i.oper_up}
            for i in latest
        ],
        "series": [{"t": r.bucket, "interface": r.interface, "in_bps": r.in_bps, "out_bps": r.out_bps} for r in rows],
    }


def _usage_columns():
    u = RuleUsageHourly
    return (
        u.rule_id,
        func.max(u.rule_name).label("rule_name"),
        func.sum(u.hits).label("hits"),
        func.sum(u.denied).label("denied"),
        func.sum(u.sent_bytes).label("sent_bytes"),
        func.sum(u.recv_bytes).label("recv_bytes"),
        func.sum(u.sent_pkts).label("sent_pkts"),
        func.sum(u.recv_pkts).label("recv_pkts"),
        func.max(u.last_seen).label("last_seen"),
    )


def _usage_dict(row) -> dict:
    return {
        "rule_id": row.rule_id,
        "hits": int(row.hits or 0),
        "denied": int(row.denied or 0),
        "sent_bytes": int(row.sent_bytes or 0),
        "recv_bytes": int(row.recv_bytes or 0),
        "sent_pkts": int(row.sent_pkts or 0),
        "recv_pkts": int(row.recv_pkts or 0),
        "last_seen": row.last_seen,
    }


@router.get("/firewalls/{fw_id}/rules")
async def rules(fw_id: int, db: DB, _user: CurrentUser, hours: Hours = 24 * 7) -> dict:
    """Konfigurierte Firewall-Regeln mit Nutzung im Zeitraum (aus den Logs aggregiert)."""
    await get_firewall(db, fw_id)
    return {"hours": hours, **await rules_overview(db, fw_id, _since(hours))}


async def rules_overview(db: DB, fw_id: int, start: datetime, end: datetime | None = None) -> dict:
    """Regeln (Konfiguration) + Nutzung im Zeitraum [start, end]. Auch von Audit und Bericht genutzt."""
    objects = (
        (
            await db.execute(
                select(ConfigObject)
                .where(
                    ConfigObject.firewall_id == fw_id,
                    ConfigObject.entity_type.in_(["FirewallRule", "FirewallRuleGroup"]),
                )
                .order_by(ConfigObject.position)
            )
        )
        .scalars()
        .all()
    )
    groups = rule_groups([o.data for o in objects if o.entity_type == "FirewallRuleGroup"])

    range_filter = [RuleUsageHourly.firewall_id == fw_id, RuleUsageHourly.time >= start]
    if end is not None:
        range_filter.append(RuleUsageHourly.time < end)
    in_range = (
        await db.execute(select(*_usage_columns()).where(*range_filter).group_by(RuleUsageHourly.rule_id))
    ).all()
    ever = (
        await db.execute(
            select(RuleUsageHourly.rule_id, func.max(RuleUsageHourly.rule_name), func.max(RuleUsageHourly.last_seen))
            .where(RuleUsageHourly.firewall_id == fw_id)
            .group_by(RuleUsageHourly.rule_id)
        )
    ).all()
    data_since = await db.scalar(select(func.min(RuleUsageHourly.time)).where(RuleUsageHourly.firewall_id == fw_id))

    id_by_name = {name: rid for rid, name, _ in ever if name}
    last_seen_ever = {rid: ts for rid, _, ts in ever}
    usage_by_id = {row.rule_id: _usage_dict(row) for row in in_range}

    result, matched_ids = [], set()
    for obj in objects:
        if obj.entity_type != "FirewallRule":
            continue
        summary = summarize_rule(obj.data)
        rid = id_by_name.get(obj.name)
        if rid is not None:
            matched_ids.add(rid)
        summary.update(
            position=obj.position,
            group=groups.get(obj.name),
            rule_id=rid,
            usage=usage_by_id.get(rid) if rid is not None else None,
            last_seen_ever=last_seen_ever.get(rid) if rid is not None else None,
        )
        result.append(summary)

    # Nutzung zu Regel-IDs ohne Namenszuordnung (z.B. Firmware ohne fw_rule_name im Log, Default-Drop-Regel 0)
    unmapped = [
        {**u, "rule_name": next((n for rid, n, _ in ever if rid == u["rule_id"]), None)}
        for u in usage_by_id.values()
        if u["rule_id"] not in matched_ids
    ]
    return {"data_since": data_since, "rules": result, "unmapped_usage": unmapped}


@router.get("/firewalls/{fw_id}/rules/{rule_id}/series")
async def rule_series(fw_id: int, rule_id: int, db: DB, _user: CurrentUser, hours: Hours = 24 * 7) -> dict:
    await get_firewall(db, fw_id)
    secs = max(3600, _bucket_seconds(hours))
    u = RuleUsageHourly
    bucket = _bucket(u.time, secs).label("bucket")
    rows = (
        await db.execute(
            select(
                bucket,
                func.sum(u.hits).label("hits"),
                func.sum(u.sent_bytes).label("sent_bytes"),
                func.sum(u.recv_bytes).label("recv_bytes"),
            )
            .where(u.firewall_id == fw_id, u.rule_id == rule_id, u.time > _since(hours))
            .group_by(bucket)
            .order_by(bucket)
        )
    ).all()
    return {
        "bucket_seconds": secs,
        "series": [
            {"t": r.bucket, "hits": int(r.hits), "sent_bytes": int(r.sent_bytes), "recv_bytes": int(r.recv_bytes)}
            for r in rows
        ],
    }


TopBy = Literal["src_ip", "dst_ip", "dst_port", "user_name", "protocol", "rule_name"]


@router.get("/firewalls/{fw_id}/top")
async def top(
    fw_id: int,
    db: DB,
    _user: CurrentUser,
    by: TopBy = "src_ip",
    hours: Hours = 24,
    rule_id: int | None = None,
    order: Literal["bytes", "hits"] = "bytes",
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
) -> list[dict]:
    await get_firewall(db, fw_id)
    col = getattr(LogEntry, by)
    total_bytes = func.sum(func.coalesce(LogEntry.sent_bytes, 0) + func.coalesce(LogEntry.recv_bytes, 0))
    stmt = (
        select(
            col.label("key"),
            func.count().label("hits"),
            func.sum(func.coalesce(LogEntry.sent_bytes, 0)).label("sent_bytes"),
            func.sum(func.coalesce(LogEntry.recv_bytes, 0)).label("recv_bytes"),
            total_bytes.label("bytes"),
        )
        .where(
            LogEntry.firewall_id == fw_id,
            LogEntry.time > _since(hours),
            LogEntry.log_type == "Firewall",
            col.is_not(None),
        )
        .group_by(col)
        .order_by((total_bytes if order == "bytes" else func.count()).desc())
        .limit(limit)
    )
    if rule_id is not None:
        stmt = stmt.where(LogEntry.rule_id == rule_id)
    return [
        {"key": str(r.key), "hits": r.hits, "sent_bytes": int(r.sent_bytes), "recv_bytes": int(r.recv_bytes)}
        for r in (await db.execute(stmt)).all()
    ]


@router.get("/firewalls/{fw_id}/config/types")
async def config_types(fw_id: int, db: DB, _user: CurrentUser) -> list[dict]:
    await get_firewall(db, fw_id)
    rows = (
        await db.execute(
            select(ConfigObject.entity_type, func.count(), func.max(ConfigObject.updated_at))
            .where(ConfigObject.firewall_id == fw_id)
            .group_by(ConfigObject.entity_type)
            .order_by(ConfigObject.entity_type)
        )
    ).all()
    return [{"entity_type": t, "count": c, "updated_at": u} for t, c, u in rows]


@router.get("/firewalls/{fw_id}/config")
async def config_objects(fw_id: int, entity_type: str, db: DB, _user: CurrentUser) -> list[dict]:
    await get_firewall(db, fw_id)
    rows = (
        await db.execute(
            select(ConfigObject)
            .where(ConfigObject.firewall_id == fw_id, ConfigObject.entity_type == entity_type)
            .order_by(ConfigObject.position, ConfigObject.name)
        )
    ).scalars()
    return [{"name": o.name, "position": o.position, "data": o.data, "updated_at": o.updated_at} for o in rows]


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/logs")
async def logs(
    db: DB,
    _user: CurrentUser,
    firewall_id: int | None = None,
    log_type: str | None = None,
    log_subtype: str | None = None,
    rule_id: int | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    filters: Annotated[str | None, Query(max_length=4000, description="JSON-Liste [{field, op, value}]")] = None,
    start: datetime | None = None,
    end: datetime | None = None,
    before_time: datetime | None = None,
    before_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict:
    conditions = []
    if firewall_id is not None:
        conditions.append(LogEntry.firewall_id == firewall_id)
    if log_type:
        conditions.append(LogEntry.log_type == log_type)
    if log_subtype:
        conditions.append(LogEntry.log_subtype == log_subtype)
    if rule_id is not None:
        conditions.append(LogEntry.rule_id == rule_id)
    if src_ip:
        conditions.append(LogEntry.src_ip == src_ip)
    if dst_ip:
        conditions.append(LogEntry.dst_ip == dst_ip)
    if q:
        pattern = f"%{_escape_like(q)}%"
        conditions.append(
            or_(
                LogEntry.message.ilike(pattern, escape="\\"),
                LogEntry.user_name.ilike(pattern, escape="\\"),
                LogEntry.rule_name.ilike(pattern, escape="\\"),
                LogEntry.src_ip.ilike(pattern, escape="\\"),
                LogEntry.dst_ip.ilike(pattern, escape="\\"),
            )
        )
    if filters:
        try:
            parsed = _FILTER_LIST.validate_json(filters)
            conditions.extend(to_condition(f) for f in parsed[:20])
        except (ValidationError, ValueError) as exc:
            detail = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else str(exc)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Filter ungültig: {detail}") from exc
    # Ohne Zeitfilter auf die letzten 24h begrenzen, damit die Abfrage nicht alle Chunks scannt
    conditions.append(LogEntry.time >= (start or _since(24)))
    if end:
        conditions.append(LogEntry.time <= end)
    if before_time and before_id is not None:
        conditions.append(tuple_(LogEntry.time, LogEntry.id) < tuple_(before_time, before_id))

    rows = (
        (
            await db.execute(
                select(LogEntry)
                .where(and_(*conditions))
                .order_by(LogEntry.time.desc(), LogEntry.id.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    items = [
        {
            "id": r.id,
            "time": r.time,
            "firewall_id": r.firewall_id,
            "log_type": r.log_type,
            "log_component": r.log_component,
            "log_subtype": r.log_subtype,
            "status": r.status,
            "severity": r.severity,
            "rule_id": r.rule_id,
            "rule_name": r.rule_name,
            "src_ip": r.src_ip,
            "src_port": r.src_port,
            "dst_ip": r.dst_ip,
            "dst_port": r.dst_port,
            "protocol": r.protocol,
            "user_name": r.user_name,
            "sent_bytes": r.sent_bytes,
            "recv_bytes": r.recv_bytes,
            "message": r.message,
            "fields": r.fields,
        }
        for r in rows
    ]
    cursor = {"before_time": rows[-1].time, "before_id": rows[-1].id} if len(rows) == limit else None
    return {"items": items, "next": cursor}


@router.get("/logs/facets")
async def log_facets(db: DB, _user: CurrentUser, firewall_id: int | None = None) -> dict:
    stmt = (
        select(LogEntry.log_type, LogEntry.log_subtype, func.count().label("n"))
        .where(LogEntry.time > _since(24 * 7))
        .group_by(LogEntry.log_type, LogEntry.log_subtype)
        .order_by(LogEntry.log_type, LogEntry.log_subtype)
    )
    if firewall_id is not None:
        stmt = stmt.where(LogEntry.firewall_id == firewall_id)
    facets: dict[str, list[str]] = {}
    for log_type, subtype, _n in (await db.execute(stmt)).all():
        if log_type:
            facets.setdefault(log_type, [])
            if subtype:
                facets[log_type].append(subtype)
    return {"log_types": facets}

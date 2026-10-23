"""Standortübergreifende Auswertung: Standort-Netze, Pfadverfolgung einer Verbindung über mehrere
Firewalls und Übersicht blockierter Verbindungen zwischen Standorten."""

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select, tuple_

from app.api.stats import Hours, _since
from app.models import ConfigObject, Firewall, LogEntry, denied_firewall_logs
from app.security import DB, CurrentUser
from app.services.crosssite import INTERFACE_ENTITIES, Hop, SiteMap, networks_from_config, parse_manual, verdict

router = APIRouter(prefix="/api", tags=["cross-site"])


def _denied():
    return denied_firewall_logs()


async def load_sites(db: DB) -> tuple[list[Firewall], dict[int, list[dict]], SiteMap]:
    """Netze je Firewall: automatisch aus den Interfaces + manuell gepflegt. Automatisch erkannte Netze,
    die auf mehreren Firewalls vorkommen, sind nicht eindeutig und werden verworfen."""
    firewalls = list((await db.execute(select(Firewall).order_by(Firewall.name))).scalars())
    rows = (
        await db.execute(
            select(ConfigObject.firewall_id, ConfigObject.entity_type, ConfigObject.name, ConfigObject.data).where(
                ConfigObject.entity_type.in_([*INTERFACE_ENTITIES, "Zone"])
            )
        )
    ).all()
    per_fw: dict[int, list[tuple[str, str, dict]]] = {}
    for fw_id, entity, name, data in rows:
        per_fw.setdefault(fw_id, []).append((entity, name, data))

    sites: dict[int, list[dict]] = {}
    for fw in firewalls:
        nets = networks_from_config(per_fw.get(fw.id, []))
        nets += [
            {"cidr": c, "interface": None, "zone": None, "source": "manual"} for c in parse_manual(fw.site_networks)
        ]
        sites[fw.id] = nets
    auto_count = Counter(n["cidr"] for nets in sites.values() for n in nets if n["source"] == "auto")
    for nets in sites.values():
        for n in nets:
            n["conflict"] = n["source"] == "auto" and auto_count[n["cidr"]] > 1
    site_map = SiteMap({fw_id: [n["cidr"] for n in nets if not n["conflict"]] for fw_id, nets in sites.items()})
    return firewalls, sites, site_map


@router.get("/sites")
async def sites(db: DB, _user: CurrentUser) -> list[dict]:
    firewalls, nets, _ = await load_sites(db)
    return [{"firewall_id": fw.id, "name": fw.name, "networks": nets[fw.id]} for fw in firewalls]


def _hops(fw_names: dict[int, str], origin: int | None, dest: int | None, rows) -> list[Hop]:
    """Erwartete Firewalls (Quell- und Ziel-Standort) plus alle, die die Verbindung tatsächlich gesehen haben."""
    hops: dict[int, Hop] = {}
    if origin is not None:
        hops[origin] = Hop(origin, fw_names[origin], "single" if origin == dest else "origin")
    if dest is not None and dest != origin:
        hops[dest] = Hop(dest, fw_names[dest], "destination")
    for r in rows:
        if r.firewall_id is None:
            continue
        h = hops.setdefault(r.firewall_id, Hop(r.firewall_id, fw_names.get(r.firewall_id, "?"), "transit"))
        rule = r.rule_name or (f"#{r.rule_id}" if r.rule_id is not None else "unbekannt")
        denied = (r.log_subtype or "").lower() == "denied" or (r.status or "").lower() in ("deny", "drop")
        if denied:
            h.denied += r.n
            h.deny_rules.add(rule)
        else:
            h.allowed += r.n
            h.allow_rules.add(rule)
    order = {"origin": 0, "single": 0, "transit": 1, "destination": 2}
    return sorted(hops.values(), key=lambda h: order[h.role])


def _hop_dict(h: Hop) -> dict:
    return {
        "firewall_id": h.firewall_id,
        "name": h.name,
        "role": h.role,
        "decision": h.decision,
        "allowed": h.allowed,
        "denied": h.denied,
        "allow_rules": sorted(h.allow_rules),
        "deny_rules": sorted(h.deny_rules),
    }


@router.get("/trace")
async def trace(
    db: DB,
    _user: CurrentUser,
    src_ip: Annotated[str, Query(max_length=64)],
    dst_ip: Annotated[str, Query(max_length=64)],
    dst_port: int | None = None,
    protocol: Annotated[str | None, Query(max_length=16)] = None,
    time: datetime | None = None,
    window_s: Annotated[int, Query(ge=5, le=3600)] = 60,
    hours: Hours = 24,
) -> dict:
    """Verfolgt eine Verbindung über alle Firewalls. Mit `time` wird ein Zeitfenster um diesen Zeitpunkt
    betrachtet (z.B. aus einem Logeintrag), sonst der gesamte Zeitraum `hours`."""
    firewalls, _, site_map = await load_sites(db)
    names = {fw.id: fw.name for fw in firewalls}
    origin, dest = site_map.site_of(src_ip), site_map.site_of(dst_ip)

    if time is not None:
        start, end = time - timedelta(seconds=window_s), time + timedelta(seconds=window_s)
    else:
        start, end = _since(hours), datetime.now(UTC)
    cond = [
        LogEntry.src_ip == src_ip,
        LogEntry.dst_ip == dst_ip,
        LogEntry.time >= start,
        LogEntry.time <= end,
        LogEntry.log_type == "Firewall",
    ]
    if dst_port is not None:
        cond.append(LogEntry.dst_port == dst_port)
    if protocol:
        cond.append(LogEntry.protocol.ilike(protocol))

    rows = (
        await db.execute(
            select(
                LogEntry.firewall_id,
                LogEntry.rule_id,
                LogEntry.rule_name,
                LogEntry.log_subtype,
                LogEntry.status,
                func.count().label("n"),
                func.min(LogEntry.time).label("first"),
                func.max(LogEntry.time).label("last"),
            )
            .where(*cond)
            .group_by(LogEntry.firewall_id, LogEntry.rule_id, LogEntry.rule_name, LogEntry.log_subtype, LogEntry.status)
        )
    ).all()
    hops = _hops(names, origin, dest, rows)
    state, text = verdict(hops)
    timeline = [
        {
            "firewall_id": r.firewall_id,
            "firewall": names.get(r.firewall_id, "?"),
            "rule": r.rule_name or (f"#{r.rule_id}" if r.rule_id is not None else None),
            "subtype": r.log_subtype,
            "status": r.status,
            "count": r.n,
            "first": r.first,
            "last": r.last,
        }
        for r in sorted(rows, key=lambda r: r.first)
    ]
    return {
        "query": {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "start": start,
            "end": end,
        },
        "src_site": {"firewall_id": origin, "name": names.get(origin)} if origin else None,
        "dst_site": {"firewall_id": dest, "name": names.get(dest)} if dest else None,
        "hops": [_hop_dict(h) for h in hops],
        "verdict": {"status": state, "text": text},
        "timeline": timeline,
    }


@router.get("/cross-site/blocked")
async def cross_site_blocked(
    db: DB,
    _user: CurrentUser,
    hours: Hours = 24,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> dict:
    """Blockierte Verbindungen zwischen verschiedenen Standorten, zusammengefasst über Wiederholungsversuche
    (ohne Quellport). Zu jeder Zeile: wo blockiert, ob die andere Seite erlaubt, und wo die Regel fehlt."""
    firewalls, _, site_map = await load_sites(db)
    if len(firewalls) < 2:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Dafür werden mindestens zwei Firewalls benötigt")
    names = {fw.id: fw.name for fw in firewalls}
    since = _since(hours)
    key_cols = (LogEntry.src_ip, LogEntry.dst_ip, LogEntry.dst_port, LogEntry.protocol)

    denied_rows = (
        await db.execute(
            select(
                LogEntry.firewall_id,
                *key_cols,
                func.max(LogEntry.rule_name).label("rule"),
                func.count().label("n"),
                func.max(LogEntry.time).label("last"),
            )
            .where(LogEntry.time > since, _denied(), LogEntry.src_ip.is_not(None))
            .group_by(LogEntry.firewall_id, *key_cols)
            .order_by(func.count().desc())
            .limit(20_000)
        )
    ).all()

    # Nur Verbindungen zwischen zwei verschiedenen (bekannten) Standorten
    flows = {}
    for r in denied_rows:
        s, d = site_map.site_of(r.src_ip), site_map.site_of(r.dst_ip)
        if s is None or d is None or s == d:
            continue
        key = (r.src_ip, r.dst_ip, r.dst_port, r.protocol)
        f = flows.setdefault(key, {"src_site": s, "dst_site": d, "blocked": {}, "attempts": 0, "last": r.last})
        f["blocked"][r.firewall_id] = r.rule or "unbekannt"
        f["attempts"] += r.n
        f["last"] = max(f["last"], r.last)
    if not flows:
        return {"hours": hours, "items": [], "total": 0}

    top = sorted(flows.items(), key=lambda kv: kv[1]["attempts"], reverse=True)[:limit]
    allowed_rows = (
        await db.execute(
            select(LogEntry.firewall_id, *key_cols, func.max(LogEntry.rule_name).label("rule"))
            .where(
                LogEntry.time > since,
                LogEntry.log_type == "Firewall",
                ~_denied(),
                tuple_(*key_cols).in_([k for k, _ in top]),
            )
            .group_by(LogEntry.firewall_id, *key_cols)
        )
    ).all()
    allowed: dict[tuple, dict[int, str]] = {}
    for r in allowed_rows:
        allowed.setdefault((r.src_ip, r.dst_ip, r.dst_port, r.protocol), {})[r.firewall_id] = r.rule or "unbekannt"

    items = []
    for (src, dst, port, proto), f in top:
        ok = allowed.get((src, dst, port, proto), {})
        blocked_on = sorted(f["blocked"])
        origin, dest = f["src_site"], f["dst_site"]
        if origin in f["blocked"]:
            where, fix = "Ausgang", origin
        else:
            where, fix = "Eingang", dest if dest in f["blocked"] else blocked_on[0]
        items.append(
            {
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "protocol": proto,
                "src_site": names.get(origin),
                "dst_site": names.get(dest),
                "attempts": f["attempts"],
                "last": f["last"],
                "blocked": [{"firewall_id": fw, "name": names.get(fw), "rule": f["blocked"][fw]} for fw in blocked_on],
                "allowed": [
                    {"firewall_id": fw, "name": names.get(fw), "rule": rule} for fw, rule in sorted(ok.items())
                ],
                "blocked_at": where,
                "fix_on": {"firewall_id": fix, "name": names.get(fix)},
            }
        )
    return {"hours": hours, "items": items, "total": len(flows)}

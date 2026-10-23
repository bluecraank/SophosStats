"""Hostnamen: Vorschläge beim Tippen ("EDV-" -> alle bekannten Hosts) und IP -> Hostname für die Anzeige.

Quellen: per Reverse-DNS gelernte Namen (host_names), Host-Objekte der Firewalls (IPHost vom Typ IP) und –
falls nichts Bekanntes passt – eine DNS-Auflösung des eingegebenen Namens.
"""

import asyncio
import ipaddress
import socket
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import func, or_, select

from app.models import ConfigObject, HostName
from app.security import DB, CurrentUser

router = APIRouter(prefix="/api/hosts", tags=["hosts"])

_HOST_IP = ConfigObject.data["IPAddress"].astext


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _object_conditions():
    """Host-Objekte der Firewalls mit genau einer IP (HostType IP)."""
    return (
        ConfigObject.entity_type == "IPHost",
        ConfigObject.data["HostType"].astext == "IP",
        _HOST_IP.is_not(None),
    )


def _object_hosts():
    return select(ConfigObject.name, _HOST_IP.label("ip")).where(*_object_conditions())


async def forward_dns(name: str, max_wait: float = 3) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(name, None, type=socket.SOCK_STREAM), max_wait)
    except (OSError, TimeoutError, UnicodeError):
        return []
    return sorted({i[4][0] for i in infos}, key=lambda a: (":" in a, a))


async def resolve_name(db: DB, name: str) -> list[str]:
    """Hostname -> IPs: zuerst bekannte Namen (auch Kurzname zu FQDN), dann Host-Objekte, dann DNS."""
    low = name.strip().lower()
    if not low or " " in low:
        return []
    known = (
        (
            await db.execute(
                select(HostName.ip).where(
                    or_(
                        func.lower(HostName.hostname) == low,
                        func.lower(HostName.hostname).like(f"{_escape_like(low)}.%"),
                    )
                )
            )
        )
        .scalars()
        .all()
    )
    objects = (
        (await db.execute(select(_HOST_IP).where(*_object_conditions(), func.lower(ConfigObject.name) == low)))
        .scalars()
        .all()
    )
    ips = sorted({*known, *(o for o in objects if o)})
    return ips or await forward_dns(low)


@router.get("/suggest")
async def suggest(
    db: DB,
    _user: CurrentUser,
    q: Annotated[str, Query(min_length=1, max_length=100)],
    limit: Annotated[int, Query(ge=1, le=50)] = 15,
) -> list[dict]:
    text = q.strip()
    low = text.lower()
    prefix = f"{_escape_like(low)}%"
    results: dict[tuple[str, str], dict] = {}

    # IP-Anfang ("10.50.") -> bekannte Hosts in diesem Bereich
    by_ip = all(c.isdigit() or c in ".:" for c in text)
    rdns = (
        await db.execute(
            select(HostName.hostname, HostName.ip)
            .where(
                HostName.hostname.is_not(None),
                HostName.ip.like(prefix, escape="\\")
                if by_ip
                else func.lower(HostName.hostname).like(prefix, escape="\\"),
            )
            .order_by(HostName.hostname)
            .limit(limit)
        )
    ).all()
    for name, ip in rdns:
        results[(name.lower(), ip)] = {"hostname": name, "ip": ip, "source": "rdns"}

    obj_q = _object_hosts().where(
        _HOST_IP.like(prefix, escape="\\") if by_ip else func.lower(ConfigObject.name).like(prefix, escape="\\")
    )
    for name, ip in (await db.execute(obj_q.order_by(ConfigObject.name).limit(limit))).all():
        results.setdefault((name.lower(), ip), {"hostname": name, "ip": ip, "source": "object"})

    if not results and not by_ip and "." in text:
        for ip in await forward_dns(text):
            results[(low, ip)] = {"hostname": text, "ip": ip, "source": "dns"}

    return sorted(results.values(), key=lambda r: (r["hostname"].lower(), r["ip"]))[:limit]


@router.get("/lookup")
async def lookup(
    db: DB,
    _user: CurrentUser,
    ip: Annotated[list[str], Query(max_length=300)],
) -> dict[str, str]:
    """IP -> Hostname für die Anzeige (Reverse-DNS, sonst Name des Host-Objekts)."""
    ips = []
    for value in ip[:300]:
        try:
            ips.append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    if not ips:
        return {}
    names = {
        ip_: name
        for ip_, name in (
            await db.execute(
                select(HostName.ip, HostName.hostname).where(HostName.ip.in_(ips), HostName.hostname.is_not(None))
            )
        ).all()
    }
    missing = [i for i in ips if i not in names]
    if missing:
        for name, ip_ in (await db.execute(_object_hosts().where(_HOST_IP.in_(missing)))).all():
            names.setdefault(ip_, name)
    return names

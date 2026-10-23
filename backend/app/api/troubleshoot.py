"""Fehlersuche: Würde eine Verbindung (Quelle, Ziel/Website, Dienst) über alle beteiligten Firewalls
erlaubt? Simuliert das Regelwerk jeder Firewall auf dem Weg und gleicht mit den Logs ab."""

import ipaddress
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.api.crosssite import load_sites, trace
from app.api.hosts import resolve_name
from app.models import ConfigObject
from app.security import DB, CurrentUser
from app.services.crosssite import detect_link_zone
from app.services.policy_sim import Objects, Service, evaluate, parse_service
from app.services.rules import summarize_rule

router = APIRouter(prefix="/api", tags=["troubleshoot"])

_ENTITIES = [
    "FirewallRule",
    "Zone",
    "IPHost",
    "IPHostGroup",
    "FQDNHost",
    "FQDNHostGroup",
    "MACHost",
    "Services",
    "ServiceGroup",
]


async def _resolve(db: DB, target: str, what: str) -> tuple[str, str | None, list[str]]:
    """IP oder Hostname -> (IP für die Prüfung, Hostname oder None, alle IPs). Hostnamen zuerst aus den
    gelernten Namen und Firewall-Objekten (interne Kurznamen wie "EDV-PC01"), sonst per DNS."""
    try:
        return str(ipaddress.ip_address(target)), None, [target]
    except ValueError:
        pass
    host = target.removeprefix("https://").removeprefix("http://").split("/")[0].split(":")[0].strip().lower()
    if not host or " " in host:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{what} muss eine IP-Adresse oder ein Hostname sein")
    ips = await resolve_name(db, host)
    if not ips:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"„{host}“ konnte nicht aufgelöst werden")
    return ips[0], host, ips


def _locate(sites: dict[int, list[dict]], ip: str) -> tuple[int, dict] | None:
    """Firewall und Netz (inkl. Zone) per Longest-Prefix-Match."""
    addr = ipaddress.ip_address(ip)
    best: tuple[int, dict, int] | None = None
    for fw_id, nets in sites.items():
        for n in nets:
            if n.get("conflict"):
                continue
            net = ipaddress.ip_network(n["cidr"])
            if addr.version == net.version and addr in net and (best is None or net.prefixlen > best[2]):
                best = (fw_id, n, net.prefixlen)
    return (best[0], best[1]) if best else None


def _zone_of(loc: tuple[int, dict] | None) -> str | None:
    return loc[1].get("zone") if loc else None


@router.get("/troubleshoot")
async def troubleshoot(
    db: DB,
    user: CurrentUser,
    source: Annotated[str, Query(max_length=64)],
    destination: Annotated[str, Query(max_length=255)],
    service: Annotated[str, Query(max_length=64)],
) -> dict:
    src_ip, src_name, _ = await _resolve(db, source.strip(), "Quelle")
    dst_ip, fqdn, resolved = await _resolve(db, destination.strip(), "Ziel")

    firewalls, sites, _ = await load_sites(db)
    names = {fw.id: fw.name for fw in firewalls}
    rows = (
        await db.execute(
            select(
                ConfigObject.firewall_id,
                ConfigObject.entity_type,
                ConfigObject.name,
                ConfigObject.data,
                ConfigObject.position,
            )
            .where(ConfigObject.entity_type.in_(_ENTITIES))
            .order_by(ConfigObject.firewall_id, ConfigObject.position)
        )
    ).all()
    per_fw: dict[int, list[tuple[str, str, dict]]] = {}
    rules: dict[int, list[dict[str, Any]]] = {}
    for fw_id, entity, name, data, position in rows:
        per_fw.setdefault(fw_id, []).append((entity, name, data))
        if entity == "FirewallRule":
            rules.setdefault(fw_id, []).append({**summarize_rule(data), "position": position})
    objs = {fw.id: Objects(per_fw.get(fw.id, [])) for fw in firewalls}
    try:
        svc: Service = parse_service(service, list(objs.values()))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    src_loc, dst_loc = _locate(sites, src_ip), _locate(sites, dst_ip)
    notes: list[str] = []
    link = {fw.id: detect_link_zone(per_fw.get(fw.id, []), fw.site_link_zone) for fw in firewalls}

    # Weg: welche Firewall sieht die Verbindung mit welchen Zonen
    hops: list[tuple[int, str | None, str | None, str]] = []  # (fw, Quell-Zone, Ziel-Zone, Rolle)
    if src_loc is None and dst_loc is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Weder Quelle noch Ziel liegen in einem bekannten Standort-Netz "
            "(siehe Standortübergreifend → Standorte & Netze)",
        )
    if dst_loc is None:
        hops.append((src_loc[0], _zone_of(src_loc), "WAN", "Ausgang ins Internet"))
    elif src_loc is None:
        hops.append((dst_loc[0], "WAN", _zone_of(dst_loc), "Eingang aus dem Internet"))
        notes.append(
            "Eingehend aus dem Internet: ohne DNAT-Regel ist das Ziel von außen meist nicht erreichbar – "
            "NAT wird nicht geprüft."
        )
    elif src_loc[0] == dst_loc[0]:
        hops.append((src_loc[0], _zone_of(src_loc), _zone_of(dst_loc), "Standort-intern"))
        if src_loc[1]["cidr"] == dst_loc[1]["cidr"]:
            notes.append("Quelle und Ziel liegen im selben Netz – diese Verbindung läuft gar nicht über die Firewall.")
    else:
        s_fw, d_fw = src_loc[0], dst_loc[0]
        hops.append((s_fw, _zone_of(src_loc), link[s_fw][0], f"Ausgang Richtung {names[d_fw]}"))
        hops.append((d_fw, link[d_fw][0], _zone_of(dst_loc), f"Eingang von {names[s_fw]}"))
    if src_name:
        notes.append(f"Quelle {src_name} aufgelöst zu {src_ip}.")
    if fqdn:
        notes.append(f"{fqdn} aufgelöst zu {', '.join(resolved)} (DNS des SophosStats-Servers) – geprüft mit {dst_ip}.")
        notes.append("Web-Filter, Anwendungskontrolle und IPS werden nicht simuliert, nur die Firewall-Regeln.")

    results = []
    for fw_id, src_zone, dst_zone, role in hops:
        ev = evaluate(
            rules.get(fw_id, []),
            objs[fw_id],
            ipaddress.ip_address(src_ip),
            ipaddress.ip_address(dst_ip),
            svc,
            src_zone,
            dst_zone,
            fqdn,
        )
        link_zone, link_source = link[fw_id]
        results.append(
            {
                "firewall_id": fw_id,
                "name": names[fw_id],
                "role": role,
                "src_zone": src_zone,
                "dst_zone": dst_zone,
                "link_zone": {"zone": link_zone, "source": link_source},
                "decision": ev.decision,
                "rule": ev.rule,
                "checks": [c.__dict__ for c in ev.checks],
                "possible_before": ev.possible_before,
                "near_misses": ev.near_misses,
                "rule_count": len(rules.get(fw_id, [])),
            }
        )

    blocked = next((r for r in results if r["decision"] == "deny"), None)
    unsure = next((r for r in results if r["decision"] == "unknown"), None)
    if blocked:
        why = (
            f"Regel #{blocked['rule']['position'] + 1} „{blocked['rule']['name']}“"
            if blocked["rule"]
            else "keine passende Regel (Default Drop)"
        )
        verdict = {"status": "deny", "text": f"Blockiert auf {blocked['name']}: {why}."}
    elif unsure:
        verdict = {"status": "unknown", "text": f"Auf {unsure['name']} nicht eindeutig – siehe unsichere Regeln."}
    else:
        verdict = {
            "status": "allow",
            "text": "Auf allen Firewalls erlaubt: "
            + "; ".join(f"{r['name']}: #{r['rule']['position'] + 1} „{r['rule']['name']}“" for r in results),
        }

    observed = None
    if svc.protocol in ("TCP", "UDP", "ICMP"):
        observed = await trace(
            db,
            user,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=svc.port,
            protocol=svc.protocol if svc.protocol != "ICMP" else None,
            time=None,
            window_s=60,
            hours=24,
        )

    def loc_dict(loc: tuple[int, dict] | None) -> dict | None:
        if not loc:
            return None
        return {"firewall_id": loc[0], "name": names[loc[0]], "cidr": loc[1]["cidr"], "zone": loc[1].get("zone")}

    return {
        "query": {
            "source": src_ip,
            "destination": destination,
            "dst_ip": dst_ip,
            "fqdn": fqdn,
            "resolved": resolved,
            "service": {"protocol": svc.protocol, "port": svc.port, "label": svc.label},
        },
        "src": loc_dict(src_loc),
        "dst": loc_dict(dst_loc),
        "hops": results,
        "verdict": verdict,
        "notes": notes,
        "observed": {"verdict": observed["verdict"], "hops": observed["hops"]} if observed else None,
    }

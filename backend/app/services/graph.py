"""Beziehungsgraph der Firewall-Konfiguration: Zonen, Interfaces, Netzobjekte, Dienste, Regeln.

Firewall-Regeln werden über ihre Zusammenfassung (services.rules) exakt verknüpft. Alle anderen
Objekte (NAT-Regeln, Gruppen, VLANs, Interfaces …) werden generisch durchsucht: jeder String-Wert,
der dem Namen eines bekannten Objekts entspricht, wird zur Kante. Der Feldpfad bestimmt dabei die
Art der Beziehung (Quelle/Ziel/Dienst/Zone/Mitglied) und löst Namensgleichheiten zwischen Typen auf.
"""

from typing import Any

from app.services.rules import summarize_rule

# Entität -> Knotentyp
NODE_TYPES = {
    "Zone": "zone",
    "Interface": "interface",
    "VLAN": "interface",
    "IPHost": "network",
    "IPHostGroup": "network",
    "FQDNHost": "network",
    "FQDNHostGroup": "network",
    "MACHost": "network",
    "Services": "service",
    "ServiceGroup": "service",
    "FirewallRule": "rule",
    "NATRule": "nat",
}
GROUP_ENTITIES = {"IPHostGroup", "FQDNHostGroup", "ServiceGroup"}
_SKIP_KEYS = {"Name", "Description", "Status", "Position", "Action", "IPFamily", "PolicyType", "LogTraffic"}


def node_id(ntype: str, name: str) -> str:
    return f"{ntype}:{name}"


def _type_hint(path: str) -> str | None:
    p = path.lower()
    if "zone" in p:
        return "zone"
    if "service" in p:
        return "service"
    if "interface" in p or "parent" in p:
        return "interface"
    if any(k in p for k in ("network", "host", "source", "destination", "member", "address")):
        return "network"
    return None


def _edge_kind(path: str) -> str:
    p = path.lower()
    if "translated" in p:
        return "translated"
    if "list" in p or "member" in p:
        return "member"
    if "source" in p or p.startswith("src"):
        return "source"
    if "destination" in p or p.startswith("dst"):
        return "destination"
    if "service" in p:
        return "service"
    if "zone" in p:
        return "zone"
    if "interface" in p:
        return "interface"
    return "ref"


def _walk(value: Any, path: str = ""):
    """Liefert (feldpfad, stringwert) für alle String-Blätter."""
    if isinstance(value, dict):
        for k, v in value.items():
            if k in _SKIP_KEYS and not path:
                continue
            yield from _walk(v, f"{path}.{k}" if path else k)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v, path)
    elif isinstance(value, str) and value:
        yield path, value


def _summary(entity: str, data: dict[str, Any]) -> dict[str, Any]:
    """Kurzinfo für die Anzeige im Knoten."""
    if entity == "IPHost":
        ip = data.get("IPAddress") or data.get("StartIPAddress") or ""
        mask = data.get("Subnet") or data.get("EndIPAddress") or ""
        return {"kind": data.get("HostType", "IP"), "detail": f"{ip}{'/' + mask if mask else ''}".strip("/")}
    if entity == "FQDNHost":
        return {"kind": "FQDN", "detail": data.get("FQDN", "")}
    if entity == "Services":
        details = (
            data.get("ServiceDetails", {}).get("ServiceDetail", [])
            if isinstance(data.get("ServiceDetails"), dict)
            else []
        )
        if isinstance(details, dict):
            details = [details]
        ports = [
            f"{d.get('Protocol', '')}/{d.get('DestinationPort', '')}".strip("/") for d in details if isinstance(d, dict)
        ]
        return {"kind": data.get("Type", "Dienst"), "detail": ", ".join(p for p in ports if p)[:80]}
    if entity in GROUP_ENTITIES:
        return {"kind": "Gruppe"}
    if entity in ("Interface", "VLAN"):
        return {"kind": entity, "detail": data.get("IPAddress") or data.get("Hardware") or ""}
    if entity == "Zone":
        return {"kind": data.get("Type", "Zone")}
    return {}


def build_graph(objects: list[tuple[str, str, dict[str, Any]]], rule_usage: dict[str, dict] | None = None) -> dict:
    """objects: (entity_type, name, data). rule_usage: Regelname -> Nutzung (hits, bytes, last_seen …)."""
    rule_usage = rule_usage or {}
    nodes: dict[str, dict[str, Any]] = {}
    by_name: dict[str, set[str]] = {}  # Objektname -> mögliche Knotentypen

    for entity, name, data in objects:
        ntype = NODE_TYPES.get(entity)
        if not ntype:
            continue
        nid = node_id(ntype, name)
        nodes[nid] = {
            "id": nid,
            "type": ntype,
            "entity": entity,
            "name": name,
            "group": entity in GROUP_ENTITIES,
            "builtin": False,
            **_summary(entity, data),
            "data": data,
        }
        if ntype not in ("rule", "nat"):
            by_name.setdefault(name, set()).add(ntype)

    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def ensure(ntype: str, name: str) -> str:
        """Referenzierte, aber nicht abgerufene Objekte (z.B. eingebaute) als Platzhalter anlegen."""
        nid = node_id(ntype, name)
        if nid not in nodes:
            nodes[nid] = {
                "id": nid,
                "type": ntype,
                "entity": None,
                "name": name,
                "group": False,
                "builtin": True,
                "kind": "eingebaut",
                "data": None,
            }
            by_name.setdefault(name, set()).add(ntype)
        return nid

    def add_edge(source: str, target: str, kind: str) -> None:
        if source != target:
            edges.setdefault((source, target, kind), {"source": source, "target": target, "kind": kind})

    for entity, name, data in objects:
        ntype = NODE_TYPES.get(entity)
        if not ntype:
            continue
        src = node_id(ntype, name)

        if entity == "FirewallRule":
            s = summarize_rule(data)
            nodes[src].update(
                action=s["action"],
                enabled=s["enabled"],
                policy_type=s["policy_type"],
                log_traffic=s["log_traffic"],
                usage=rule_usage.get(name),
            )
            for z in s["source_zones"]:
                add_edge(src, ensure("zone", z), "source_zone")
            for z in s["destination_zones"]:
                add_edge(src, ensure("zone", z), "destination_zone")
            for n in s["source_networks"]:
                add_edge(src, ensure("network", n), "source")
            for n in s["destination_networks"]:
                add_edge(src, ensure("network", n), "destination")
            for sv in s["services"]:
                add_edge(src, ensure("service", sv), "service")
            continue

        if entity == "NATRule":
            nodes[src]["enabled"] = str(data.get("Status", "")).lower() == "enable"

        for path, value in _walk(data):
            types = by_name.get(value)
            if not types or value == name and ntype not in ("rule", "nat"):
                continue
            hint = _type_hint(path)
            target_type = hint if hint in types else (next(iter(types)) if len(types) == 1 else None)
            if target_type is None:
                continue
            add_edge(src, node_id(target_type, value), _edge_kind(path))

    # Anzahl Regeln, die direkt auf ein Objekt zeigen – für Größe/Badge im Graphen
    refs: dict[str, int] = {}
    for e in edges.values():
        if nodes[e["source"]]["type"] in ("rule", "nat"):
            refs[e["target"]] = refs.get(e["target"], 0) + 1
    for nid, n in nodes.items():
        n["rule_refs"] = refs.get(nid, 0)

    return {"nodes": list(nodes.values()), "edges": list(edges.values())}

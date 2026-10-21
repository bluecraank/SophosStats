"""Standortübergreifende Verbindungen: welche Netze gehören zu welcher Firewall, und wie hat jede
Firewall auf dem Weg einer Verbindung entschieden.

Annahme: zwischen den Standorten wird nicht genattet (z.B. WireGuard/IPsec mit IP-Forwarding), d.h.
Quell-/Ziel-IP und Ports sind auf allen Firewalls gleich und Logeinträge lassen sich über das Tupel
(Quelle, Ziel, Zielport, Protokoll) in einem kurzen Zeitfenster zuordnen.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Any

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Entitäten mit eigener IP-Konfiguration und Zonen ohne interne Netze
INTERFACE_ENTITIES = {"Interface", "VLAN", "Alias", "LAG", "BridgePair"}
_EXTERNAL_ZONE_TYPES = {"WAN", "VPN"}


def networks_from_config(objects: list[tuple[str, str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """Interne Netze aus Interface-/VLAN-/Alias-Konfiguration (nur private Netze, keine WAN/VPN-Zonen)."""
    zone_types = {name: str(data.get("Type", "")).upper() for entity, name, data in objects if entity == "Zone"}
    result: dict[str, dict[str, Any]] = {}
    for entity, name, data in objects:
        if entity not in INTERFACE_ENTITIES:
            continue
        ip, mask = data.get("IPAddress"), data.get("Netmask")
        if not isinstance(ip, str) or not isinstance(mask, str) or not ip or not mask:
            continue
        zone = data.get("NetworkZone") or data.get("Zone")
        zone = zone if isinstance(zone, str) else None
        if zone and (zone.upper() == "WAN" or zone_types.get(zone) in _EXTERNAL_ZONE_TYPES):
            continue
        try:
            net = ipaddress.ip_interface(f"{ip}/{mask}").network
        except ValueError:
            continue
        # Punkt-zu-Punkt/Transfernetze (z.B. WireGuard-Tunnel in einer LAN-Typ-Zone) gehören zu keinem Standort
        if not net.is_private or net.prefixlen >= (30 if net.version == 4 else 126):
            continue
        result.setdefault(str(net), {"cidr": str(net), "interface": name, "zone": zone, "source": "auto"})
    return sorted(result.values(), key=lambda n: ipaddress.ip_network(n["cidr"]))


def parse_manual(text: str | None) -> list[str]:
    """Manuell gepflegte Netze (Komma/Zeilen getrennt). Ungültige Einträge werden ignoriert."""
    nets = []
    for part in (text or "").replace(",", "\n").replace(";", "\n").splitlines():
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError:
            continue
    return nets


class SiteMap:
    """IP -> Firewall (Standort) per Longest-Prefix-Match."""

    def __init__(self, sites: dict[int, list[str]]):
        self._nets: list[tuple[IPNetwork, int]] = sorted(
            ((ipaddress.ip_network(c), fw) for fw, cidrs in sites.items() for c in cidrs),
            key=lambda x: x[0].prefixlen,
            reverse=True,
        )

    def site_of(self, ip: str | None) -> int | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, fw in self._nets:
            if addr.version == net.version and addr in net:
                return fw
        return None


@dataclass
class Hop:
    firewall_id: int
    name: str
    role: str  # origin | destination | transit | single
    allowed: int = 0
    denied: int = 0
    allow_rules: set[str] = field(default_factory=set)
    deny_rules: set[str] = field(default_factory=set)

    @property
    def seen(self) -> bool:
        return self.allowed + self.denied > 0

    @property
    def decision(self) -> str:
        if not self.seen:
            return "not_seen"
        if self.denied and self.allowed:
            return "mixed"
        return "denied" if self.denied else "allowed"


def _rules(names: set[str]) -> str:
    return ", ".join(sorted(names)) or "unbekannte Regel"


def verdict(hops: list[Hop]) -> tuple[str, str]:
    """(status, Text) für eine Verbindung entlang der erwarteten Firewalls.
    status: ok | blocked | missing_rule | incomplete | unknown"""
    if not hops:
        return "unknown", "Keine Firewall hat diese Verbindung im Zeitfenster geloggt."
    origin = next((h for h in hops if h.role in ("origin", "single")), None)
    dest = next((h for h in hops if h.role == "destination"), None)

    if origin and origin.decision == "denied":
        tail = f" – {dest.name} wurde nie erreicht" if dest and not dest.seen else ""
        return "blocked", f"Blockiert am Ausgang auf {origin.name} (Regel: {_rules(origin.deny_rules)}){tail}."
    if dest and dest.decision in ("denied", "mixed") and (not origin or origin.allowed):
        src = f"Auf {origin.name} erlaubt ({_rules(origin.allow_rules)}), " if origin and origin.allowed else ""
        return (
            "missing_rule",
            f"{src}auf {dest.name} blockiert ({_rules(dest.deny_rules)}) "
            f"→ auf {dest.name} fehlt eine erlaubende Regel.",
        )
    if origin and origin.allowed and dest and not dest.seen:
        return (
            "incomplete",
            f"Auf {origin.name} erlaubt, aber {dest.name} hat nichts geloggt – Routing/Tunnel oder Logging auf "
            f"{dest.name} prüfen.",
        )
    if all(h.decision == "allowed" for h in hops if h.seen) and any(h.seen for h in hops):
        missing = [h.name for h in hops if not h.seen]
        if missing:
            return "incomplete", f"Erlaubt, aber keine Logs von {', '.join(missing)}."
        return "ok", "Auf allen Firewalls erlaubt: " + "; ".join(f"{h.name}: {_rules(h.allow_rules)}" for h in hops)
    denied = [h for h in hops if h.decision in ("denied", "mixed")]
    if denied:
        h = denied[0]
        return "blocked", f"Blockiert auf {h.name} (Regel: {_rules(h.deny_rules)})."
    return "unknown", "Keine eindeutige Aussage möglich."

"""Simulation des Firewall-Regelwerks: Würde eine Verbindung (Quelle, Ziel, Dienst, Zonen) erlaubt?

Ausgewertet wird wie auf der Firewall: aktive Regeln in Reihenfolge, die erste passende entscheidet,
ohne Treffer gilt das implizite Default-Drop. Netz- und Dienstobjekte werden aus der per XML-API
gesicherten Konfiguration aufgelöst. Was sich nicht sicher bestimmen lässt (Benutzerregeln, Zeitpläne,
unbekannte/eingebaute Objekte, FQDNs ohne Namensangabe), wird als "unknown" gemeldet statt geraten.
"""

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Literal

Result = Literal["yes", "no", "unknown"]
Address = ipaddress.IPv4Address | ipaddress.IPv6Address
_ANY_SCHEDULES = {None, "", "All The Time", "All the time"}
# Standarddienste – auch für eingebaute Dienstobjekte, die nicht in der Konfiguration auftauchen
WELL_KNOWN = {
    "http": ("TCP", 80),
    "https": ("TCP", 443),
    "ssh": ("TCP", 22),
    "rdp": ("TCP", 3389),
    "dns": ("UDP", 53),
    "smtp": ("TCP", 25),
    "smb": ("TCP", 445),
    "ldap": ("TCP", 389),
    "ldaps": ("TCP", 636),
    "ntp": ("UDP", 123),
    "snmp": ("UDP", 161),
}


def _as_list(value: Any, key: str | None = None) -> list:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [x for v in value for x in _as_list(v, key)]
    if isinstance(value, dict):
        if key and key in value:
            return _as_list(value[key])
        return [value]
    return [value]


@dataclass
class Check:
    criterion: str
    result: Result
    detail: str = ""


@dataclass
class Service:
    protocol: str  # TCP | UDP | ICMP | IP | ANY
    port: int | None = None
    label: str = ""


class Objects:
    """Netz- und Dienstobjekte einer Firewall, mit Auflösung von Gruppen in beide Richtungen
    (SFOS kennt Mitgliedschaft am Host über HostGroupList und an der Gruppe über HostList)."""

    def __init__(self, objects: list[tuple[str, str, dict[str, Any]]]):
        self.hosts: dict[str, dict] = {}
        self.fqdns: dict[str, dict] = {}
        self.services: dict[str, dict] = {}
        self.net_groups: dict[str, set[str]] = {}
        self.svc_groups: dict[str, set[str]] = {}
        for entity, name, data in objects:
            if entity in ("IPHost", "MACHost"):
                self.hosts[name] = data
                for g in _as_list(data.get("HostGroupList"), "HostGroup"):
                    if isinstance(g, str):
                        self.net_groups.setdefault(g, set()).add(name)
            elif entity == "FQDNHost":
                self.fqdns[name] = data
                for g in _as_list(data.get("FQDNHostGroupList"), "FQDNHostGroup"):
                    if isinstance(g, str):
                        self.net_groups.setdefault(g, set()).add(name)
            elif entity in ("IPHostGroup", "FQDNHostGroup"):
                members = _as_list(data.get("HostList"), "Host") + _as_list(data.get("FQDNHostList"), "FQDNHost")
                self.net_groups.setdefault(name, set()).update(m for m in members if isinstance(m, str))
            elif entity == "Services":
                self.services[name] = data
            elif entity == "ServiceGroup":
                members = _as_list(data.get("ServiceList"), "Service")
                self.svc_groups.setdefault(name, set()).update(m for m in members if isinstance(m, str))

    def service_names(self) -> list[str]:
        return sorted(set(self.services) | set(self.svc_groups))

    # --- Netze ---------------------------------------------------------------

    def _host_contains(self, data: dict, ip: Address) -> Result:
        host_type = str(data.get("HostType", "IP")).lower()
        try:
            if host_type in ("ip", "system host"):
                return "yes" if ip == ipaddress.ip_address(str(data.get("IPAddress", ""))) else "no"
            if host_type == "network":
                net = ipaddress.ip_network(f"{data.get('IPAddress')}/{data.get('Subnet')}", strict=False)
                return "yes" if ip.version == net.version and ip in net else "no"
            if host_type == "iprange":
                lo = ipaddress.ip_address(str(data.get("StartIPAddress")))
                hi = ipaddress.ip_address(str(data.get("EndIPAddress")))
                return "yes" if ip.version == lo.version and lo <= ip <= hi else "no"
            if host_type == "iplist":
                ips = {x.strip() for x in str(data.get("ListOfIPAddresses", "")).split(",") if x.strip()}
                return "yes" if str(ip) in ips else "no"
        except ValueError:
            return "unknown"
        return "unknown"

    def _fqdn_matches(self, data: dict, fqdn: str | None) -> Result:
        pattern = str(data.get("FQDN", "")).lower()
        if not fqdn:
            return "unknown"  # Ziel als IP angegeben – FQDN-Objekt nur per DNS der Firewall bestimmbar
        return "yes" if fnmatch.fnmatch(fqdn.lower(), pattern) or fqdn.lower() == pattern.lstrip("*.") else "no"

    def network_matches(self, name: str, ip: Address, fqdn: str | None = None, _seen: set | None = None) -> Check:
        seen = _seen or set()
        if name in seen:
            return Check("", "no")
        seen.add(name)
        if name in self.hosts:
            r = self._host_contains(self.hosts[name], ip)
            return Check("", r, name if r == "yes" else "")
        if name in self.fqdns:
            r = self._fqdn_matches(self.fqdns[name], fqdn)
            return Check("", r, f"{name} (FQDN)" if r != "no" else "")
        if name in self.net_groups:
            unknown = None
            for member in sorted(self.net_groups[name]):
                c = self.network_matches(member, ip, fqdn, seen)
                if c.result == "yes":
                    return Check("", "yes", f"{name} → {c.detail}")
                if c.result == "unknown":
                    unknown = c
            return (
                Check("", "unknown", f"{name}: {unknown.detail or 'nicht auflösbar'}") if unknown else Check("", "no")
            )
        if "internet" in name.lower():
            # Eingebaute Internet-Gruppen: alles außer privaten Netzen
            return Check("", "yes" if ip.is_global else "no", name)
        return Check("", "unknown", f"{name} (eingebaut/nicht abgerufen)")

    # --- Dienste ---------------------------------------------------------------

    @staticmethod
    def _port_in(spec: Any, port: int) -> bool:
        for part in str(spec or "1:65535").replace(" ", "").split(","):
            if not part:
                continue
            lo, _, hi = part.partition(":")
            try:
                if int(lo) <= port <= int(hi or lo):
                    return True
            except ValueError:
                continue
        return False

    def service_matches(self, name: str, svc: Service, _seen: set | None = None) -> Check:
        seen = _seen or set()
        if name in seen:
            return Check("", "no")
        seen.add(name)
        if name in self.svc_groups:
            for member in sorted(self.svc_groups[name]):
                c = self.service_matches(member, svc, seen)
                if c.result != "no":
                    return Check("", c.result, f"{name} → {c.detail}")
            return Check("", "no")
        data = self.services.get(name)
        if data is None:
            known = WELL_KNOWN.get(name.lower())
            if known:
                hit = svc.protocol in (known[0], "ANY") and (svc.port is None or svc.port == known[1])
                return Check("", "yes" if hit else "no", f"{name} (Standard {known[0]}/{known[1]})")
            return Check("", "unknown", f"{name} (eingebaut/nicht abgerufen)")
        stype = str(data.get("Type", "")).lower()
        details = _as_list(data.get("ServiceDetails"), "ServiceDetail")
        if stype == "icmp" or stype == "icmpv6":
            return Check("", "yes" if svc.protocol == "ICMP" else "no", name)
        if stype in ("ip", "ipprotocol"):
            return Check("", "unknown", f"{name} (IP-Protokoll)")
        for d in details:
            if not isinstance(d, dict):
                continue
            proto = str(d.get("Protocol", "")).upper()
            if svc.protocol not in (proto, "ANY") and not (proto == "TCPORUDP" and svc.protocol in ("TCP", "UDP")):
                continue
            if svc.port is None or self._port_in(d.get("DestinationPort"), svc.port):
                return Check("", "yes", name)
        return Check("", "no")


@dataclass
class Evaluation:
    decision: Literal["allow", "deny", "unknown"]
    rule: dict[str, Any] | None
    checks: list[Check] = field(default_factory=list)
    possible_before: list[dict[str, Any]] = field(default_factory=list)  # unsichere Regeln vor der Entscheidung
    near_misses: list[dict[str, Any]] = field(default_factory=list)  # erlaubende Regeln mit genau einem Fehlkriterium


def _zone_check(label: str, rule_zones: list[str], zone: str | None) -> Check:
    if not rule_zones:
        return Check(label, "yes", "Alle")
    if zone is None:
        return Check(label, "unknown", f"Zone unbekannt (Regel: {', '.join(rule_zones)})")
    hit = zone.lower() in (z.lower() for z in rule_zones)
    return Check(label, "yes" if hit else "no", zone if hit else f"Regel erwartet {', '.join(rule_zones)}")


def _net_check(label: str, objs: Objects, names: list[str], ip: Address, fqdn: str | None = None) -> Check:
    if not names:
        return Check(label, "yes", "Alle")
    unknown = None
    for n in names:
        c = objs.network_matches(n, ip, fqdn)
        if c.result == "yes":
            return Check(label, "yes", c.detail)
        if c.result == "unknown":
            unknown = c
    if unknown:
        return Check(label, "unknown", unknown.detail)
    return Check(label, "no", f"{ip} nicht in {', '.join(names)}")


def _svc_check(objs: Objects, names: list[str], svc: Service) -> Check:
    if not names:
        return Check("Dienst", "yes", "Alle")
    unknown = None
    for n in names:
        c = objs.service_matches(n, svc)
        if c.result == "yes":
            return Check("Dienst", "yes", c.detail)
        if c.result == "unknown":
            unknown = c
    if unknown:
        return Check("Dienst", "unknown", unknown.detail)
    return Check("Dienst", "no", f"{svc.label} nicht in {', '.join(names)}")


def check_rule(
    rule: dict[str, Any],
    objs: Objects,
    src: Address,
    dst: Address,
    svc: Service,
    src_zone: str | None,
    dst_zone: str | None,
    fqdn: str | None = None,
) -> list[Check]:
    checks = [
        _zone_check("Quell-Zone", rule.get("source_zones") or [], src_zone),
        _net_check("Quelle", objs, rule.get("source_networks") or [], src),
        _zone_check("Ziel-Zone", rule.get("destination_zones") or [], dst_zone),
        _net_check("Ziel", objs, rule.get("destination_networks") or [], dst, fqdn),
        _svc_check(objs, rule.get("services") or [], svc),
    ]
    if rule.get("identities"):
        checks.append(Check("Benutzer", "unknown", "nur für " + ", ".join(rule["identities"])))
    if rule.get("schedule") not in _ANY_SCHEDULES:
        checks.append(Check("Zeitplan", "unknown", str(rule.get("schedule"))))
    return checks


def _rule_ref(rule: dict[str, Any]) -> dict[str, Any]:
    return {"name": rule.get("name"), "position": rule.get("position"), "action": rule.get("action")}


def evaluate(
    rules: list[dict[str, Any]],
    objs: Objects,
    src: Address,
    dst: Address,
    svc: Service,
    src_zone: str | None,
    dst_zone: str | None,
    fqdn: str | None = None,
) -> Evaluation:
    """Erste passende aktive Regel entscheidet. Netzwerk-, Benutzer-Regeln werden geprüft, andere Typen
    (z.B. WAF) übersprungen."""
    possible: list[dict[str, Any]] = []
    near: list[dict[str, Any]] = []
    ordered = sorted((r for r in rules if r.get("enabled")), key=lambda r: r.get("position") or 0)
    for rule in ordered:
        if rule.get("policy_type") not in (None, "Network", "User"):
            continue
        checks = check_rule(rule, objs, src, dst, svc, src_zone, dst_zone, fqdn)
        results = [c.result for c in checks]
        if "no" not in results:
            if "unknown" not in results:
                decision = "allow" if rule.get("action") == "Accept" else "deny"
                return Evaluation(decision, _rule_ref(rule), checks, possible, near[:5])
            possible.append({**_rule_ref(rule), "checks": [c.__dict__ for c in checks]})
        elif results.count("no") == 1 and rule.get("action") == "Accept":
            near.append({**_rule_ref(rule), "checks": [c.__dict__ for c in checks]})
    decision = "unknown" if possible else "deny"
    return Evaluation(decision, None, [], possible, near[:5])


def parse_service(text: str, objs_by_fw: list[Objects]) -> Service:
    """'https', '443', 'tcp/443', 'udp/53', 'ping'/'icmp' oder Name eines Dienstobjekts."""
    t = text.strip()
    low = t.lower()
    if low in ("ping", "icmp"):
        return Service("ICMP", None, "ICMP")
    if "/" in low:
        proto, _, port = low.partition("/")
        if proto.upper() in ("TCP", "UDP") and port.isdigit():
            return Service(proto.upper(), int(port), f"{proto.upper()}/{port}")
    if low.isdigit():
        return Service("TCP", int(low), f"TCP/{low}")
    # Dienstobjekt einer Firewall gleichen Namens -> erstes TCP/UDP-Detail übernehmen
    for objs in objs_by_fw:
        for name, data in objs.services.items():
            if name.lower() != low:
                continue
            for d in _as_list(data.get("ServiceDetails"), "ServiceDetail"):
                if isinstance(d, dict) and str(d.get("Protocol", "")).upper() in ("TCP", "UDP"):
                    port = str(d.get("DestinationPort", "")).split(":")[0].split(",")[0]
                    if port.isdigit():
                        return Service(str(d["Protocol"]).upper(), int(port), f"{name} ({d['Protocol']}/{port})")
    if low in WELL_KNOWN:
        proto, port = WELL_KNOWN[low]
        return Service(proto, port, f"{t.upper()} ({proto}/{port})")
    raise ValueError(f"Dienst „{text}“ unbekannt – z.B. https, 443, tcp/3389, udp/53, ping oder ein Dienstname")

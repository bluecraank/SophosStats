"""Was wird für eine Quelle blockiert? Ordnet blockierende Logzeilen aller SFOS-Module einer Kategorie zu
(Firewall-Regel, Web-Filter, Anwendungskontrolle, IPS, ATP, Virenschutz …) und verdichtet sie zu
"Ziel/Grund – wie oft – zuletzt". Die Felder je Modul unterscheiden sich je nach Firmware, deshalb werden
mehrere Schreibweisen akzeptiert und Unbekanntes landet in einer allgemeinen Gruppe."""

from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

# Untertypen/Status, die eine Blockierung bedeuten – modulübergreifend
BLOCK_SUBTYPES = {"denied", "deny", "drop", "dropped", "blocked", "block", "reject", "rejected", "invalid traffic"}
BLOCK_STATUS = {"deny", "denied", "drop", "dropped", "blocked", "block", "reject", "rejected"}

CATEGORY_ORDER = [
    "firewall",
    "webfilter",
    "appfilter",
    "ips",
    "atp",
    "antivirus",
    "antispam",
    "ssl",
    "waf",
    "heartbeat",
]
LABELS = {
    "firewall": "Firewall-Regeln",
    "webfilter": "Web-Filter",
    "appfilter": "Anwendungskontrolle",
    "ips": "IPS (Angriffserkennung)",
    "atp": "Advanced Threat Protection",
    "antivirus": "Virenschutz",
    "antispam": "Spam-Schutz",
    "ssl": "SSL/TLS-Prüfung",
    "waf": "Web Application Firewall",
    "heartbeat": "Security Heartbeat",
}


def category_of(log_type: str | None, log_component: str | None) -> tuple[str, str]:
    """(Schlüssel, Bezeichnung) für Log-Typ und Komponente."""
    lt = (log_type or "").strip().lower()
    lc = (log_component or "").strip().lower()
    if lt == "firewall":
        key = "firewall"
    elif lt == "content filtering":
        key = "appfilter" if "app" in lc else "webfilter"
    elif lt in ("idp", "ips"):
        key = "ips"
    elif lt == "atp":
        key = "atp"
    elif lt.replace("-", "").replace(" ", "") == "antivirus":
        key = "antivirus"
    elif lt.replace("-", "").replace(" ", "") == "antispam":
        key = "antispam"
    elif lt in ("ssl", "ssl/tls", "tls"):
        key = "ssl"
    elif lt == "waf":
        key = "waf"
    elif lt == "heartbeat":
        key = "heartbeat"
    else:
        return (lt or "other"), (log_type or "Sonstige")
    return key, LABELS[key]


def _first(fields: dict[str, Any], *names: str) -> str:
    for n in names:
        v = fields.get(n)
        if v not in (None, "", "-"):
            return str(v)
    return ""


def _domain(fields: dict[str, Any]) -> str:
    d = _first(fields, "domain", "dst_domainname", "fqdn", "host", "server_name", "sni")
    if d:
        return d.lower()
    url = _first(fields, "url", "referer")
    if url:
        host = urlsplit(url if "://" in url else f"//{url}").hostname
        return (host or url).lower()
    return ""


def service_label(dst_port: int | None, protocol: str | None) -> str:
    proto = (protocol or "").upper()
    if proto == "ICMP":
        return "ping"
    if dst_port and proto in ("TCP", "UDP"):
        return f"{proto.lower()}/{dst_port}"
    if dst_port:
        return str(dst_port)
    return proto.lower() if proto else ""


def _target_and_detail(key: str, row: dict[str, Any]) -> tuple[tuple, str, str]:
    """Gruppierschlüssel, Ziel-Beschriftung und Detail (Grund/Regel) je Kategorie."""
    f: dict[str, Any] = row.get("fields") or {}
    dst = row.get("dst_ip") or ""
    port = row.get("dst_port")
    proto = row.get("protocol")
    endpoint = f"{dst}:{port}" if dst and port else dst
    if proto and endpoint:
        endpoint += f" {proto}"
    if key == "firewall":
        rule = row.get("rule_name") or ""
        detail = f"Regel {rule}" if rule and rule != "0" else "keine Regel (Default Drop)"
        if (row.get("log_subtype") or "").lower() == "invalid traffic":
            detail = "ungültiger Verkehr (kein Verbindungsstatus)"
        return (dst, port, proto, rule), endpoint or "–", detail
    if key == "webfilter":
        domain = _domain(f) or endpoint
        cat = _first(f, "category", "categorytype", "url_category")
        reason = _first(f, "reason", "message")
        detail = " · ".join(x for x in (f"Kategorie {cat}" if cat else "", reason) if x)
        return (domain, cat), domain or "–", detail or "vom Web-Filter blockiert"
    if key == "appfilter":
        app = _first(f, "application", "app_name", "application_name")
        cat = _first(f, "app_category", "application_category", "category")
        detail = " · ".join(x for x in (f"Kategorie {cat}" if cat else "", endpoint) if x)
        return (app, cat), app or endpoint or "–", detail or "von der Anwendungskontrolle blockiert"
    if key == "ips":
        sig = _first(f, "signature_msg", "message", "signature") or (row.get("message") or "")
        return (sig, dst, port), endpoint or "–", sig or "IPS-Signatur"
    if key == "atp":
        threat = _first(f, "threatname", "threat_name", "threat")
        target = _domain(f) or endpoint
        return (threat, target), target or "–", threat or "ATP-Treffer"
    if key == "antivirus":
        virus = _first(f, "virus", "virus_name", "threatname")
        target = _domain(f) or endpoint
        return (virus, target), target or "–", virus or "Schadsoftware"
    msg = (row.get("message") or _first(f, "reason", "message"))[:120]
    return (dst, port, proto, msg), endpoint or "–", msg or (row.get("log_subtype") or "blockiert")


def group_blocked(
    rows: list[dict[str, Any]],
    counts: list[tuple[int, str | None, str | None, str | None, int, datetime | None]],
    firewall_names: dict[int, str],
    max_items: int = 25,
) -> list[dict[str, Any]]:
    """Kategorien mit exakten Zählern (aus `counts`: fw, log_type, log_component, log_subtype, n, zuletzt)
    und verdichteten Einträgen aus den jüngsten Logzeilen `rows`."""
    cats: dict[str, dict[str, Any]] = {}

    def cat(key: str, label: str) -> dict[str, Any]:
        return cats.setdefault(
            key,
            {
                "key": key,
                "label": label,
                "total": 0,
                "last_seen": None,
                "log_types": set(),
                "firewalls": {},
                "items": {},
            },
        )

    for fw_id, log_type, log_component, _subtype, n, last in counts:
        key, label = category_of(log_type, log_component)
        c = cat(key, label)
        c["total"] += n
        c["log_types"].add(log_type or "")
        c["firewalls"][fw_id] = c["firewalls"].get(fw_id, 0) + n
        if last and (c["last_seen"] is None or last > c["last_seen"]):
            c["last_seen"] = last

    for row in rows:
        key, label = category_of(row.get("log_type"), row.get("log_component"))
        c = cat(key, label)
        gkey, target, detail = _target_and_detail(key, row)
        fw_id = row.get("firewall_id")
        item = c["items"].setdefault(
            (fw_id, *gkey),
            {
                "firewall_id": fw_id,
                "firewall": firewall_names.get(fw_id, str(fw_id)),
                "target": target,
                "detail": detail,
                "dst_ip": row.get("dst_ip"),
                "dst_port": row.get("dst_port"),
                "protocol": row.get("protocol"),
                "service": service_label(row.get("dst_port"), row.get("protocol")),
                "rule_name": row.get("rule_name"),
                "user_name": row.get("user_name"),
                "log_type": row.get("log_type"),
                "hits": 0,
                "last_seen": None,
            },
        )
        item["hits"] += 1
        t = row.get("time")
        if t and (item["last_seen"] is None or t > item["last_seen"]):
            item["last_seen"] = t
        if not item["user_name"] and row.get("user_name"):
            item["user_name"] = row["user_name"]

    out = []
    for key, c in cats.items():
        items = sorted(c["items"].values(), key=lambda i: (-i["hits"], str(i["last_seen"])))
        out.append(
            {
                "key": key,
                "label": c["label"],
                "total": c["total"] or sum(i["hits"] for i in items),
                "last_seen": c["last_seen"],
                "log_types": sorted(t for t in c["log_types"] if t),
                "firewalls": [
                    {"firewall_id": fw, "name": firewall_names.get(fw, str(fw)), "hits": n}
                    for fw, n in sorted(c["firewalls"].items(), key=lambda x: -x[1])
                ],
                "items": items[:max_items],
                "more": max(0, len(items) - max_items),
            }
        )
    order = {k: i for i, k in enumerate(CATEGORY_ORDER)}
    out.sort(key=lambda c: (order.get(c["key"], len(order)), -c["total"]))
    return out

"""Blockierungen je Quelle: Kategorisierung und Verdichtung der Logzeilen."""

from datetime import UTC, datetime

from app.services import blocked

T = datetime(2026, 10, 29, 10, 0, tzinfo=UTC)


def row(log_type, component, subtype, **kw):
    base = {
        "time": T,
        "firewall_id": 1,
        "log_type": log_type,
        "log_component": component,
        "log_subtype": subtype,
        "status": None,
        "rule_name": None,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "user_name": None,
        "message": None,
        "fields": {},
    }
    return {**base, **kw}


def test_category_mapping():
    assert blocked.category_of("Firewall", "Firewall Rule")[0] == "firewall"
    assert blocked.category_of("Content Filtering", "HTTP")[0] == "webfilter"
    assert blocked.category_of("Content Filtering", "Application")[0] == "appfilter"
    assert blocked.category_of("IDP", "Signatures")[0] == "ips"
    assert blocked.category_of("Anti-Virus", "HTTP")[0] == "antivirus"
    assert blocked.category_of("Irgendwas", None) == ("irgendwas", "Irgendwas")


def test_grouping_per_category():
    rows = [
        row("Firewall", "Firewall Rule", "Denied", dst_ip="10.60.10.1", dst_port=445, protocol="TCP", rule_name="0"),
        row("Firewall", "Firewall Rule", "Denied", dst_ip="10.60.10.1", dst_port=445, protocol="TCP", rule_name="0"),
        row(
            "Firewall", "Firewall Rule", "Denied", dst_ip="8.8.8.8", dst_port=53, protocol="UDP", rule_name="Block DNS"
        ),
        row(
            "Content Filtering",
            "HTTP",
            "Denied",
            dst_ip="1.2.3.4",
            dst_port=443,
            fields={"url": "https://www.example.com/x", "category": "Gambling"},
        ),
        row(
            "Content Filtering",
            "HTTP",
            "Denied",
            dst_ip="1.2.3.5",
            dst_port=443,
            fields={"url": "https://www.example.com/y", "category": "Gambling"},
        ),
    ]
    counts = [
        (1, "Firewall", "Firewall Rule", "Denied", 30, T),
        (1, "Content Filtering", "HTTP", "Denied", 2, T),
    ]
    cats = blocked.group_blocked(rows, counts, {1: "FW-HQ"})
    assert [c["key"] for c in cats] == ["firewall", "webfilter"]
    fw = cats[0]
    assert fw["total"] == 30  # exakter Zähler, nicht Stichprobe
    assert fw["items"][0]["target"] == "10.60.10.1:445 TCP" and fw["items"][0]["hits"] == 2
    assert fw["items"][0]["detail"] == "keine Regel (Default Drop)" and fw["items"][0]["service"] == "tcp/445"
    assert fw["items"][1]["detail"] == "Regel Block DNS"
    web = cats[1]
    assert len(web["items"]) == 1  # beide URLs gleiche Domain und Kategorie
    assert web["items"][0]["target"] == "www.example.com" and "Gambling" in web["items"][0]["detail"]
    assert web["log_types"] == ["Content Filtering"]

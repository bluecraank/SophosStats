"""Fehlersuche-Endpunkt mit Fake-DB: zwei Standorte, WireGuard-Zonen mit unterschiedlichen Namen."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import troubleshoot as ts


def rule(name, sz, dz, sn=(), dn=(), sv=(), action="Accept"):
    pol = {"Action": action, "LogTraffic": "Enable", "Schedule": "All The Time"}
    for k, key, v in (
        ("SourceZones", "Zone", sz),
        ("DestinationZones", "Zone", dz),
        ("SourceNetworks", "Network", sn),
        ("DestinationNetworks", "Network", dn),
        ("Services", "Service", sv),
    ):
        if v:
            pol[k] = {key: list(v)}
    return ("FirewallRule", name, {"Name": name, "Status": "Enable", "PolicyType": "Network", "NetworkPolicy": pol})


SMB = (
    "Services",
    "SMB",
    {
        "Name": "SMB",
        "Type": "TCPorUDP",
        "ServiceDetails": {"ServiceDetail": {"Protocol": "TCP", "DestinationPort": "445"}},
    },
)
CONFIG = {
    1: [
        ("Zone", "LAN", {"Type": "LAN"}),
        ("Zone", "WG_S2S", {"Type": "LAN"}),
        SMB,
        rule("HQ nach Filiale", ["LAN"], ["WG_S2S"], sv=["SMB"]),
    ],
    2: [
        ("Zone", "LAN", {"Type": "LAN"}),
        ("Zone", "WG_Site2Site", {"Type": "LAN"}),
        SMB,
        rule("Filiale: nur HTTPS", ["WG_Site2Site"], ["LAN"], sv=["HTTPS"]),
    ],
}
SITES = {
    1: [{"cidr": "10.50.0.0/16", "zone": "LAN", "interface": "Port1", "source": "auto", "conflict": False}],
    2: [{"cidr": "10.60.0.0/16", "zone": "LAN", "interface": "Port1", "source": "auto", "conflict": False}],
}


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class FakeDB:
    async def execute(self, _stmt):
        rows = []
        for fw_id, objects in CONFIG.items():
            for pos, (entity, name, data) in enumerate(objects):
                rows.append((fw_id, entity, name, data, pos))
        return FakeResult(rows)


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    fws = [
        SimpleNamespace(id=1, name="FW-HQ", site_link_zone=None),
        SimpleNamespace(id=2, name="FW-Branch", site_link_zone=None),
    ]

    async def load_sites(_db):
        return fws, SITES, None

    async def trace(*_a, **_k):
        return {"verdict": {"status": "unknown", "text": ""}, "hops": []}

    async def resolve_name(_db, name):
        return {"edv-pc01": ["10.50.10.21"]}.get(name.lower(), [])

    monkeypatch.setattr(ts, "resolve_name", resolve_name)
    monkeypatch.setattr(ts, "load_sites", load_sites)
    monkeypatch.setattr(ts, "trace", trace)


async def call(src, dst, svc):
    return await ts.troubleshoot(FakeDB(), None, source=src, destination=dst, service=svc)


async def test_cross_site_blocked_on_destination():
    r = await call("10.50.10.5", "10.60.10.1", "smb")
    hq, branch = r["hops"]
    assert (hq["src_zone"], hq["dst_zone"], hq["decision"]) == ("LAN", "WG_S2S", "allow")
    assert (branch["src_zone"], branch["dst_zone"], branch["decision"]) == ("WG_Site2Site", "LAN", "deny")
    assert branch["near_misses"][0]["name"] == "Filiale: nur HTTPS"  # scheitert nur am Dienst
    assert r["verdict"]["status"] == "deny" and "FW-Branch" in r["verdict"]["text"]


async def test_internet_destination_uses_wan_zone():
    r = await call("10.50.10.5", "8.8.8.8", "dns")
    assert [h["name"] for h in r["hops"]] == ["FW-HQ"] and r["hops"][0]["dst_zone"] == "WAN"


async def test_invalid_input():
    with pytest.raises(HTTPException):
        await call("kein-ip", "10.60.10.1", "smb")
    with pytest.raises(HTTPException):
        await call("192.168.99.1", "172.31.1.1", "smb")  # beide Seiten unbekannt
    with pytest.raises(HTTPException):
        await call("10.50.10.5", "10.60.10.1", "quatsch")


async def test_hostname_as_source():
    r = await call("EDV-PC01", "10.60.10.1", "smb")
    assert r["query"]["source"] == "10.50.10.21"
    assert any("EDV-PC01" in n or "edv-pc01" in n for n in r["notes"])


async def test_reach_destination_lists_rules_on_all_firewalls():
    r = await ts.troubleshoot(FakeDB(), None, destination="10.60.10.1")
    assert r["mode"] == "reach" and r["anchor"]["name"] == "FW-Branch"
    branch, hq = r["firewalls"]  # Standort-Firewall zuerst
    assert (branch["name"], branch["zone"], branch["role"]) == ("FW-Branch", "LAN", "Standort des Ziels")
    assert [x["name"] for x in branch["rules"]] == ["Filiale: nur HTTPS"]
    assert branch["rules"][0]["source_zones"] == ["WG_Site2Site"] and branch["rules"][0]["certain"]
    assert hq["zone"] == "WG_S2S" and hq["role"] == "Ausgang Richtung FW-Branch"
    assert [x["name"] for x in hq["rules"]] == ["HQ nach Filiale"]
    assert r["verdict"]["status"] == "allow"


async def test_reach_destination_with_service_filters():
    r = await ts.troubleshoot(FakeDB(), None, destination="10.60.10.1", service="smb")
    branch, hq = r["firewalls"]
    assert branch["rules"] == []  # HTTPS-Regel passt nicht zu SMB
    assert [x["name"] for x in hq["rules"]] == ["HQ nach Filiale"]


async def test_reach_internet_destination_uses_wan():
    r = await ts.troubleshoot(FakeDB(), None, destination="8.8.8.8")
    assert r["anchor"] is None and {f["zone"] for f in r["firewalls"]} == {"WAN"}
    assert r["verdict"]["status"] == "deny"  # keine Regel Richtung WAN


async def test_path_requires_service():
    with pytest.raises(HTTPException):
        await ts.troubleshoot(FakeDB(), None, source="10.50.10.5", destination="10.60.10.1")
    with pytest.raises(HTTPException):
        await ts.troubleshoot(FakeDB(), None, destination="  ")

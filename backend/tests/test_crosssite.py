from app.services.crosssite import Hop, SiteMap, networks_from_config, parse_manual, verdict

CONFIG = [
    ("Zone", "LAN", {"Name": "LAN", "Type": "LAN"}),
    ("Zone", "WG_S2S", {"Name": "WG_S2S", "Type": "VPN"}),
    (
        "Interface",
        "Port1",
        {"Name": "Port1", "NetworkZone": "LAN", "IPAddress": "10.50.10.254", "Netmask": "255.255.255.0"},
    ),
    (
        "Interface",
        "Port2",
        {"Name": "Port2", "NetworkZone": "WAN", "IPAddress": "10.99.0.2", "Netmask": "255.255.255.0"},
    ),
    ("VLAN", "Port1.20", {"Name": "Port1.20", "Zone": "LAN", "IPAddress": "10.50.20.1", "Netmask": "255.255.255.0"}),
    (
        "Interface",
        "wg0",
        {"Name": "wg0", "NetworkZone": "WG_S2S", "IPAddress": "172.31.0.1", "Netmask": "255.255.255.252"},
    ),
    (
        "Interface",
        "Port3",
        {"Name": "Port3", "NetworkZone": "DMZ", "IPAddress": "81.2.3.1", "Netmask": "255.255.255.0"},
    ),
]


def test_networks_from_config_only_internal_private():
    nets = [n["cidr"] for n in networks_from_config(CONFIG)]
    assert nets == ["10.50.10.0/24", "10.50.20.0/24"]


def test_parse_manual():
    assert parse_manual("10.50.0.0/16, quatsch\n10.60.1.5/24") == ["10.50.0.0/16", "10.60.1.0/24"]


def test_site_map_longest_prefix():
    m = SiteMap({1: ["10.50.0.0/16"], 2: ["10.60.0.0/16", "10.50.99.0/24"]})
    assert m.site_of("10.50.10.1") == 1
    assert m.site_of("10.50.99.7") == 2
    assert m.site_of("10.60.10.1") == 2
    assert m.site_of("8.8.8.8") is None


def hop(fw, role, allowed=0, denied=0, allow=(), deny=()):
    return Hop(fw, f"FW{fw}", role, allowed, denied, set(allow), set(deny))


def test_verdicts():
    assert verdict([hop(1, "origin", denied=3, deny={"Default"}), hop(2, "destination")])[0] == "blocked"
    status, text = verdict(
        [hop(1, "origin", allowed=2, allow={"To-B"}), hop(2, "destination", denied=2, deny={"Drop"})]
    )
    assert status == "missing_rule" and "FW2 fehlt" in text
    assert verdict([hop(1, "origin", allowed=1, allow={"A"}), hop(2, "destination")])[0] == "incomplete"
    assert verdict([hop(1, "origin", allowed=1, allow={"A"}), hop(2, "destination", allowed=1, allow={"B"})])[0] == "ok"
    assert verdict([])[0] == "unknown"

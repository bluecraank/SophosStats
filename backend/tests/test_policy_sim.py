import ipaddress

import pytest

from app.services.policy_sim import Objects, Service, evaluate, parse_service

ip = ipaddress.ip_address

OBJECTS = Objects(
    [
        ("IPHost", "Fileserver", {"Name": "Fileserver", "HostType": "IP", "IPAddress": "10.60.10.1"}),
        (
            "IPHost",
            "HQ-LAN",
            {"Name": "HQ-LAN", "HostType": "Network", "IPAddress": "10.50.0.0", "Subnet": "255.255.0.0"},
        ),
        (
            "IPHost",
            "Clients",
            {"Name": "Clients", "HostType": "IPRange", "StartIPAddress": "10.50.10.1", "EndIPAddress": "10.50.10.99"},
        ),
        # Mitgliedschaft am Host statt an der Gruppe
        (
            "IPHost",
            "Printer",
            {
                "Name": "Printer",
                "HostType": "IP",
                "IPAddress": "10.60.20.5",
                "HostGroupList": {"HostGroup": "Branch-Devices"},
            },
        ),
        ("IPHostGroup", "Branch-Devices", {"Name": "Branch-Devices", "HostList": {"Host": ["Fileserver"]}}),
        ("FQDNHost", "Updates", {"Name": "Updates", "FQDN": "*.update.example.com"}),
        (
            "Services",
            "HTTPS",
            {
                "Name": "HTTPS",
                "Type": "TCPorUDP",
                "ServiceDetails": {"ServiceDetail": {"Protocol": "TCP", "DestinationPort": "443"}},
            },
        ),
        (
            "Services",
            "SMB",
            {
                "Name": "SMB",
                "Type": "TCPorUDP",
                "ServiceDetails": {
                    "ServiceDetail": [
                        {"Protocol": "TCP", "DestinationPort": "445"},
                        {"Protocol": "TCP", "DestinationPort": "137:139"},
                    ]
                },
            },
        ),
        ("Services", "Ping", {"Name": "Ping", "Type": "ICMP"}),
        ("ServiceGroup", "Fileshare", {"Name": "Fileshare", "ServiceList": {"Service": ["SMB", "HTTPS"]}}),
    ]
)


def rule(name, pos, action="Accept", sz=("LAN",), dz=("WG",), sn=(), dn=(), sv=(), **kw):
    return {
        "name": name,
        "position": pos,
        "enabled": True,
        "action": action,
        "policy_type": "Network",
        "source_zones": list(sz),
        "destination_zones": list(dz),
        "source_networks": list(sn),
        "destination_networks": list(dn),
        "services": list(sv),
        "identities": [],
        "schedule": "All The Time",
        **kw,
    }


SMB = Service("TCP", 445, "TCP/445")


def run(rules, src="10.50.10.5", dst="10.60.10.1", svc=SMB, sz="LAN", dz="WG", fqdn=None):
    return evaluate(rules, OBJECTS, ip(src), ip(dst), svc, sz, dz, fqdn)


def test_first_matching_rule_wins_and_groups_resolve():
    rules = [
        rule("Nur HTTPS", 0, sn=["HQ-LAN"], dn=["Fileserver"], sv=["HTTPS"]),
        rule("Fileshare zur Filiale", 1, sn=["Clients"], dn=["Branch-Devices"], sv=["Fileshare"]),
        rule("Alles blocken", 2, action="Drop"),
    ]
    e = run(rules)
    assert e.decision == "allow" and e.rule["name"] == "Fileshare zur Filiale"
    by = {c.criterion: c for c in e.checks}
    assert "Branch-Devices → Fileserver" == by["Ziel"].detail
    assert "Fileshare → SMB" == by["Dienst"].detail
    # Regel 0 scheitert nur am Dienst -> Beinahe-Treffer
    assert [n["name"] for n in e.near_misses] == ["Nur HTTPS"]


def test_membership_declared_on_host():
    e = run([rule("Geräte", 0, dn=["Branch-Devices"])], dst="10.60.20.5")
    assert e.decision == "allow"


def test_default_drop_and_zone_mismatch():
    e = run([rule("Falsche Zone", 0, dz=["WAN"])])
    assert e.decision == "deny" and e.rule is None
    assert e.near_misses[0]["name"] == "Falsche Zone"


def test_port_ranges_and_icmp():
    assert run([rule("NetBIOS", 0, sv=["SMB"])], svc=Service("TCP", 138, "TCP/138")).decision == "allow"
    assert run([rule("Ping", 0, sv=["Ping"])], svc=Service("ICMP", None, "ICMP")).decision == "allow"
    assert run([rule("Ping", 0, sv=["Ping"])]).decision == "deny"


def test_unknown_objects_and_users_are_not_guessed():
    e = run([rule("Eingebaut", 0, dn=["Some Builtin Host"]), rule("Drop", 1, action="Drop")])
    assert e.decision == "deny" and e.rule["name"] == "Drop"
    assert e.possible_before and e.possible_before[0]["name"] == "Eingebaut"
    assert run([rule("Nur Vertrieb", 0, identities=["Vertrieb"])]).decision == "unknown"


def test_fqdn_objects():
    rules = [rule("Updates", 0, dz=["WAN"], dn=["Updates"], sv=["HTTPS"])]
    https = Service("TCP", 443, "TCP/443")
    assert run(rules, dst="93.184.216.34", dz="WAN", svc=https, fqdn="dl.update.example.com").decision == "allow"
    assert run(rules, dst="93.184.216.34", dz="WAN", svc=https).decision == "unknown"  # nur IP angegeben


def test_internet_builtin_group():
    rules = [rule("Internet", 0, dz=["WAN"], dn=["Internet IPv4 group"])]
    assert run(rules, dst="8.8.8.8", dz="WAN").decision == "allow"
    assert run(rules, dst="10.1.1.1", dz="WAN").decision == "deny"


def test_parse_service():
    assert parse_service("tcp/3389", []).port == 3389
    assert parse_service("udp/53", []).protocol == "UDP"
    assert parse_service("443", []).label == "TCP/443"
    assert parse_service("ping", []).protocol == "ICMP"
    assert parse_service("smb", [OBJECTS]).port == 445  # Dienstobjekt der Firewall
    assert parse_service("rdp", []).port == 3389  # bekannter Name
    with pytest.raises(ValueError):
        parse_service("quatsch", [])

from app.services.graph import build_graph

OBJECTS = [
    ("Zone", "LAN", {"Name": "LAN", "Type": "LAN"}),
    ("Zone", "WAN", {"Name": "WAN", "Type": "WAN"}),
    ("Interface", "Port1", {"Name": "Port1", "NetworkZone": "LAN", "IPAddress": "10.0.0.1"}),
    ("IPHost", "Server1", {"Name": "Server1", "HostType": "IP", "IPAddress": "10.0.0.10"}),
    ("IPHost", "Server2", {"Name": "Server2", "HostType": "IP", "IPAddress": "10.0.0.11"}),
    ("IPHostGroup", "Servers", {"Name": "Servers", "HostList": {"Host": ["Server1", "Server2"]}}),
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
        "FirewallRule",
        "Web",
        {
            "Name": "Web",
            "Status": "Enable",
            "NetworkPolicy": {
                "Action": "Accept",
                "SourceZones": {"Zone": "WAN"},
                "DestinationZones": {"Zone": "LAN"},
                "DestinationNetworks": {"Network": "Servers"},
                "SourceNetworks": {"Network": "Internet IPv4 group"},
                "Services": {"Service": "HTTPS"},
            },
        },
    ),
    (
        "NATRule",
        "DNAT-Web",
        {
            "Name": "DNAT-Web",
            "Status": "Enable",
            "OriginalDestinationNetworks": {"Network": "Port1"},
            "TranslatedDestination": "Server1",
            "OriginalServices": {"Service": "HTTPS"},
        },
    ),
]


def edges(g):
    return {(e["source"], e["target"], e["kind"]) for e in g["edges"]}


def test_graph_edges():
    g = build_graph(OBJECTS, {"Web": {"hits": 5}})
    e = edges(g)
    assert ("rule:Web", "zone:WAN", "source_zone") in e
    assert ("rule:Web", "network:Servers", "destination") in e
    assert ("rule:Web", "service:HTTPS", "service") in e
    assert ("network:Servers", "network:Server1", "member") in e
    assert ("interface:Port1", "zone:LAN", "zone") in e
    assert ("nat:DNAT-Web", "network:Server1", "translated") in e
    assert ("nat:DNAT-Web", "service:HTTPS", "service") in e
    # Feldname "Network" mit Interface-Namen: einziger Kandidat ist das Interface
    assert ("nat:DNAT-Web", "interface:Port1", "destination") in e


def test_builtin_and_metadata():
    g = build_graph(OBJECTS, {"Web": {"hits": 5}})
    nodes = {n["id"]: n for n in g["nodes"]}
    assert nodes["network:Internet IPv4 group"]["builtin"]
    assert nodes["rule:Web"]["action"] == "Accept" and nodes["rule:Web"]["usage"] == {"hits": 5}
    assert nodes["service:HTTPS"]["detail"] == "TCP/443"
    assert nodes["network:Server1"]["detail"] == "10.0.0.10"
    assert nodes["service:HTTPS"]["rule_refs"] == 2  # Firewall-Regel + NAT-Regel

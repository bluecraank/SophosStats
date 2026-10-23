from datetime import UTC, datetime, timedelta

from defusedxml import ElementTree

from app.collectors.poller import _rate, interface_rows
from app.collectors.snmp import InterfaceSample, SnmpResult
from app.collectors.xmlapi import element_to_value
from app.services.rules import rule_groups, summarize_rule

RULE_XML = """
<FirewallRule transactionid="">
  <Name>LAN to WAN</Name>
  <Description>Internet</Description>
  <IPFamily>IPv4</IPFamily>
  <Status>Enable</Status>
  <Position>Top</Position>
  <PolicyType>Network</PolicyType>
  <NetworkPolicy>
    <Action>Accept</Action>
    <LogTraffic>Enable</LogTraffic>
    <SourceZones><Zone>LAN</Zone><Zone>WiFi</Zone></SourceZones>
    <DestinationZones><Zone>WAN</Zone></DestinationZones>
    <Schedule>All The Time</Schedule>
    <Services><Service>HTTPS</Service></Services>
  </NetworkPolicy>
</FirewallRule>
"""


def test_element_to_value_and_summary():
    item = element_to_value(ElementTree.fromstring(RULE_XML))
    s = summarize_rule(item)
    assert s["name"] == "LAN to WAN"
    assert s["enabled"] and s["log_traffic"]
    assert s["action"] == "Accept"
    assert s["source_zones"] == ["LAN", "WiFi"]
    assert s["destination_zones"] == ["WAN"]
    assert s["services"] == ["HTTPS"]
    assert s["source_networks"] == []


def test_rule_groups():
    groups = [{"Name": "Internet", "SecurityPolicyList": {"SecurityPolicy": ["A", "B"]}}]
    assert rule_groups(groups) == {"A": "Internet", "B": "Internet"}


def test_rate_handles_counter_reset():
    assert _rate(1000, 2000, 10) == 800.0
    assert _rate(5000, 100, 10) is None


def test_interface_rows_compute_bps():
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    first = interface_rows(99, t0, SnmpResult(interfaces=[InterfaceSample("Port1", 0, 0, True)]))
    assert first[0]["in_bps"] is None
    second = interface_rows(
        99, t0 + timedelta(seconds=60), SnmpResult(interfaces=[InterfaceSample("Port1", 60_000, 120_000, True)])
    )
    assert second[0]["in_bps"] == 8000.0
    assert second[0]["out_bps"] == 16000.0


def test_redact_secrets():
    from app.collectors.poller import REDACTED, redact

    data = {
        "Name": "Tunnel",
        "Authentication": {"PresharedKey": "geheim", "AuthenticationType": "PresharedKey"},
        "Peers": [{"PrivateKey": "abc", "PublicKey": "pub"}],
        "Password": "",
    }
    r = redact(data)
    assert r["Authentication"]["PresharedKey"] == REDACTED
    assert r["Authentication"]["AuthenticationType"] == "PresharedKey"  # Wert, kein Schlüssel – bleibt
    assert r["Peers"][0] == {"PrivateKey": REDACTED, "PublicKey": "pub"}
    assert r["Password"] == ""  # leere Felder nicht verändern

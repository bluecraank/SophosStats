from datetime import UTC, datetime

from app.collectors import sfos_log

ALLOWED_STOP = (
    '<30>device="SFW" date=2026-10-21 time=10:15:02 timezone="CET" device_name="XGS2100" '
    'device_id=X1234 log_id=010101600001 log_type="Firewall" log_component="Firewall Rule" '
    'log_subtype="Allowed" status="Allow" priority=Information fw_rule_id=5 fw_rule_name="LAN to WAN" '
    'src_ip=10.0.0.5 src_port=51234 dst_ip=1.1.1.1 dst_port=443 protocol="TCP" '
    'sent_pkts=12 recv_pkts=10 sent_bytes=1820 recv_bytes=9240 con_event="Stop" message=""'
)


def test_parse_fields_and_counters():
    p = sfos_log.parse(ALLOWED_STOP)
    assert p is not None
    assert p.log_type == "Firewall"
    assert p.rule_id == 5
    assert p.rule_name == "LAN to WAN"
    assert p.sent_bytes == 1820
    assert p.recv_bytes == 9240
    assert p.get_int("dst_port") == 443
    assert p.counts_bytes and not p.counts_as_hit
    assert not p.is_denied


def test_time_with_timezone():
    p = sfos_log.parse(ALLOWED_STOP)
    # 21.10. ist noch Sommerzeit (CEST, UTC+2)
    assert p.time == datetime(2026, 10, 21, 8, 15, 2, tzinfo=UTC)


def test_iso_timestamp_preferred():
    p = sfos_log.parse('timestamp="2026-10-21T10:15:02+0200" log_type="Firewall"')
    assert p.time == datetime(2026, 10, 21, 8, 15, 2, tzinfo=UTC)


def test_unknown_timezone_falls_back_to_received():
    received = datetime(2026, 1, 1, tzinfo=UTC)
    p = sfos_log.parse('date=2026-10-21 time=10:00:00 timezone="XYZ" log_type="Firewall"', received)
    assert p.time == received


def test_denied_without_con_event_counts_as_hit():
    p = sfos_log.parse('log_type="Firewall" log_subtype="Denied" status="Deny" fw_rule_id=0')
    assert p.is_denied and p.counts_as_hit and p.rule_id == 0


def test_escaped_quotes_and_bsd_header():
    p = sfos_log.parse('<14>Oct 21 10:00:00 fw01 message="say \\"hi\\"" user_name="max mustermann"')
    assert p.get("message") == 'say "hi"'
    assert p.get("user_name") == "max mustermann"


def test_garbage_returns_none():
    assert sfos_log.parse("hello world") is None

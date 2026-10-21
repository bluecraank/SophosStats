from datetime import UTC, datetime, timedelta

from app.services.audit import audit_rules, covers
from app.services.config_history import Change, compare_objects, diff_since, state_at

NOW = datetime(2026, 10, 21, tzinfo=UTC)


def rule(name, pos, **kw):
    base = {
        "name": name,
        "position": pos,
        "enabled": True,
        "log_traffic": True,
        "action": "Accept",
        "policy_type": "Network",
        "ip_family": "IPv4",
        "schedule": "All The Time",
        "source_zones": ["LAN"],
        "destination_zones": ["WAN"],
        "source_networks": [],
        "destination_networks": [],
        "services": ["HTTPS"],
        "identities": [],
        "rule_id": pos + 1,
        "last_seen_ever": NOW - timedelta(hours=1),
    }
    return base | kw


def kinds(findings, name):
    return {f["kind"] for f in findings if f["rule"] == name}


def test_covers_any_and_subsets():
    broad = rule("broad", 0, services=[])
    narrow = rule("narrow", 1, services=["HTTPS"], source_networks=["Server"])
    assert covers(broad, narrow)
    assert not covers(narrow, broad)
    assert not covers(rule("a", 0, destination_zones=["DMZ"]), rule("b", 1))
    # Zeitplan schränkt die obere Regel ein -> deckt nicht mehr alles ab
    assert not covers(rule("a", 0, schedule="Work hours"), rule("b", 1))
    # Benutzerregel deckt keine Regel ohne Identitäten ab
    assert not covers(rule("a", 0, identities=["Sales"]), rule("b", 1))


def test_shadowed_and_redundant():
    rules = [
        rule("allow-web", 0, services=["HTTP", "HTTPS"]),
        rule("block-https", 1, action="Drop", services=["HTTPS"]),
        rule("allow-https-again", 2, services=["HTTPS"]),
    ]
    f = audit_rules(rules, NOW, NOW - timedelta(days=60))
    assert "shadowed" in kinds(f, "block-https")
    assert "redundant" in kinds(f, "allow-https-again")
    assert not kinds(f, "allow-web")


def test_disabled_rules_do_not_shadow():
    rules = [rule("off", 0, enabled=False, services=[]), rule("below", 1)]
    f = audit_rules(rules, NOW, NOW - timedelta(days=60))
    assert kinds(f, "off") == {"disabled"}
    assert not kinds(f, "below")


def test_unused_needs_enough_data():
    stale = rule("stale", 0, last_seen_ever=NOW - timedelta(days=45))
    never = rule("never", 1, services=["SSH"], last_seen_ever=None)
    nolog = rule("nolog", 2, services=["RDP"], log_traffic=False, last_seen_ever=None)
    f = audit_rules([stale, never, nolog], NOW, NOW - timedelta(days=60), unused_days=30)
    assert "unused" in kinds(f, "stale") and "unused" in kinds(f, "never")
    assert kinds(f, "nolog") == {"no_logging"}
    # Erfassung erst seit 5 Tagen: noch kein Urteil über ungenutzte Regeln
    f = audit_rules([stale, never], NOW, NOW - timedelta(days=5), unused_days=30)
    assert not any(x["kind"] == "unused" for x in f)


def test_too_broad():
    f = audit_rules([rule("any", 0, services=[], source_zones=[])], NOW, None)
    broad = [x for x in f if x["kind"] == "too_broad"]
    assert broad and broad[0]["severity"] == "high"


def _c(i, hour, action, name, old=None, new=None):
    return Change(i, NOW + timedelta(hours=hour), "FirewallRule", name, action, old, new)


def test_state_at_and_diff_since():
    current = {("FirewallRule", "A"): {"v": 3}, ("FirewallRule", "C"): {"v": 1}}
    changes = [
        _c(1, 1, "modified", "A", {"v": 1}, {"v": 2}),
        _c(2, 2, "modified", "A", {"v": 2}, {"v": 3}),
        _c(3, 2, "removed", "B", {"v": 9}),
        _c(4, 3, "added", "C", None, {"v": 1}),
        _c(5, 4, "added", "D", None, {"v": 5}),
        _c(6, 5, "removed", "D", {"v": 5}),
    ]
    before = state_at(current, changes)
    assert before == {("FirewallRule", "A"): {"v": 1}, ("FirewallRule", "B"): {"v": 9}}

    diff = {d["name"]: d for d in diff_since(current, changes)}
    assert diff["A"]["action"] == "modified" and diff["A"]["changes"] == 2
    assert diff["A"]["old"] == {"v": 1} and diff["A"]["new"] == {"v": 3}
    assert diff["B"]["action"] == "removed"
    assert diff["C"]["action"] == "added"
    assert "D" not in diff  # hinzugefügt und wieder entfernt


def test_compare_objects():
    r = compare_objects({"x": 1, "y": 2, "z": 3}, {"y": 2, "z": 4, "w": 5})
    assert [o["name"] for o in r["only_a"]] == ["x"]
    assert [o["name"] for o in r["only_b"]] == ["w"]
    assert [o["name"] for o in r["different"]] == ["z"]
    assert r["same"] == 1

"""Flacht die verschachtelte FirewallRule-Struktur der XML-API in eine Übersicht ab."""

from typing import Any


def flatten(value: Any, key: str | None = None) -> list[str]:
    """{"Zone": ["LAN", "DMZ"]} / {"Zone": "LAN"} / "LAN" / None -> Liste von Strings."""
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [s for v in value for s in flatten(v, key)]
    if isinstance(value, dict):
        if key and key in value:
            return flatten(value[key])
        if len(value) == 1:
            return flatten(next(iter(value.values())))
        name = value.get("Name")
        return [name] if isinstance(name, str) else []
    return [str(value)]


def summarize_rule(item: dict[str, Any]) -> dict[str, Any]:
    policy = item.get("NetworkPolicy") or item.get("UserPolicy") or item.get("HTTPBasedPolicy") or {}
    if not isinstance(policy, dict):
        policy = {}
    return {
        "name": item.get("Name"),
        "description": item.get("Description") or None,
        "enabled": str(item.get("Status", "")).lower() == "enable",
        "policy_type": item.get("PolicyType"),
        "ip_family": item.get("IPFamily"),
        "action": policy.get("Action"),
        "log_traffic": str(policy.get("LogTraffic", "")).lower() == "enable",
        "schedule": policy.get("Schedule"),
        "source_zones": flatten(policy.get("SourceZones"), "Zone"),
        "destination_zones": flatten(policy.get("DestinationZones"), "Zone"),
        "source_networks": flatten(policy.get("SourceNetworks"), "Network"),
        "destination_networks": flatten(policy.get("DestinationNetworks"), "Network"),
        "services": flatten(policy.get("Services"), "Service"),
        "identities": flatten(policy.get("Identity"), "Member"),
    }


def rule_groups(groups: list[dict[str, Any]]) -> dict[str, str]:
    """FirewallRuleGroup-Objekte -> {regelname: gruppenname}."""
    mapping: dict[str, str] = {}
    for g in groups:
        for rule in flatten(g.get("SecurityPolicyList"), "SecurityPolicy"):
            mapping[rule] = g.get("Name", "")
    return mapping

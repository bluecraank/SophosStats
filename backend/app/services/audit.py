"""Regel-Audit: findet ungenutzte, ungeloggte, zu breite und verdeckte Regeln.

Arbeitet auf den Regel-Zusammenfassungen aus services.rules.summarize_rule (plus position,
last_seen_ever). Der Abdeckungsvergleich erfolgt über Objektnamen – Gruppenmitgliedschaften und
IP-Bereiche werden nicht aufgelöst. Er findet daher nur sichere Fälle, keine Teilüberlappungen.
"""

from datetime import datetime, timedelta
from typing import Any

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Dimensionen, in denen eine leere Liste "Any" bedeutet
_DIMENSIONS = ["source_zones", "destination_zones", "source_networks", "destination_networks", "services"]
_ANY_SCHEDULES = {None, "", "All The Time", "All the time"}
_AUDITED_POLICY_TYPES = {None, "Network", "User"}


def _dim_covers(upper: list[str], lower: list[str]) -> bool:
    if not upper:
        return True  # Any deckt alles ab
    if not lower:
        return False  # konkrete Liste deckt kein Any ab
    return set(lower) <= set(upper)


def covers(upper: dict[str, Any], lower: dict[str, Any]) -> bool:
    """True, wenn jede Verbindung, die `lower` trifft, auch von `upper` getroffen wird."""
    if upper.get("ip_family") and lower.get("ip_family") and upper["ip_family"] != lower["ip_family"]:
        return False
    if not all(_dim_covers(upper.get(d) or [], lower.get(d) or []) for d in _DIMENSIONS):
        return False
    # Benutzerregel greift nur für ihre Identitäten
    if upper.get("identities") and not _dim_covers(upper["identities"], lower.get("identities") or []):
        return False
    if upper.get("schedule") not in _ANY_SCHEDULES and upper.get("schedule") != lower.get("schedule"):
        return False
    return True


def _is_any_any(rule: dict[str, Any]) -> bool:
    return not rule.get("source_networks") and not rule.get("destination_networks") and not rule.get("services")


def _finding(kind: str, severity: str, rule: dict[str, Any], message: str, **extra: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "severity": severity,
        "rule": rule["name"],
        "rule_id": rule.get("rule_id"),
        "position": rule.get("position"),
        "message": message,
        **extra,
    }


def audit_rules(
    rules: list[dict[str, Any]],
    now: datetime,
    data_since: datetime | None,
    unused_days: int = 30,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    threshold = now - timedelta(days=unused_days)
    enough_data = data_since is not None and data_since <= threshold
    ordered = sorted(rules, key=lambda r: r.get("position") or 0)
    active = [r for r in ordered if r.get("enabled")]

    for rule in ordered:
        if not rule.get("enabled"):
            findings.append(
                _finding("disabled", "info", rule, "Regel ist deaktiviert – löschen, falls nicht mehr benötigt")
            )
            continue

        if not rule.get("log_traffic"):
            findings.append(
                _finding(
                    "no_logging", "low", rule, "„Log firewall traffic“ ist aus – Nutzung kann nicht erfasst werden"
                )
            )
        elif enough_data:
            last = rule.get("last_seen_ever")
            if last is None:
                findings.append(
                    _finding("unused", "medium", rule, f"Seit Beginn der Erfassung nie genutzt (> {unused_days} Tage)")
                )
            elif last < threshold:
                days = (now - last).days
                findings.append(_finding("unused", "medium", rule, f"Seit {days} Tagen nicht genutzt", last_seen=last))

        if rule.get("action") == "Accept" and _is_any_any(rule):
            zones_any = not rule.get("source_zones") or not rule.get("destination_zones")
            findings.append(
                _finding(
                    "too_broad",
                    "high" if zones_any else "medium",
                    rule,
                    "Erlaubt beliebige Quell- und Zielnetze mit allen Diensten"
                    + (" und ohne Zonen-Einschränkung" if zones_any else ""),
                )
            )

    # Verdeckte/redundante Regeln: eine aktive Regel weiter oben deckt die Regel vollständig ab
    for i, lower in enumerate(active):
        if lower.get("policy_type") not in _AUDITED_POLICY_TYPES:
            continue
        for upper in active[:i]:
            if upper.get("policy_type") not in _AUDITED_POLICY_TYPES or not covers(upper, lower):
                continue
            if upper.get("action") == lower.get("action"):
                findings.append(
                    _finding(
                        "redundant",
                        "medium",
                        lower,
                        f"Wird vollständig von „{upper['name']}“ (#{(upper.get('position') or 0) + 1}) abgedeckt "
                        "– gleiche Aktion, Regel ist überflüssig",
                        covered_by=upper["name"],
                    )
                )
            else:
                findings.append(
                    _finding(
                        "shadowed",
                        "high",
                        lower,
                        f"Wird nie erreicht: „{upper['name']}“ (#{(upper.get('position') or 0) + 1}) weiter oben "
                        f"greift zuerst mit Aktion {upper.get('action')}",
                        covered_by=upper["name"],
                    )
                )
            break

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["position"] or 0))
    return findings

"""Rekonstruktion früherer Konfigurationsstände aus der Änderungshistorie und Vergleiche.

Die Historie beginnt mit dem ersten Konfigurationsabruf – davor liegende Stände sind nicht bekannt.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

Key = tuple[str, str]  # (entity_type, name)


@dataclass
class Change:
    id: int
    time: datetime
    entity_type: str
    name: str
    action: str  # added | removed | modified
    old: Any
    new: Any

    @property
    def key(self) -> Key:
        return (self.entity_type, self.name)


def state_at(current: dict[Key, Any], changes_after: list[Change]) -> dict[Key, Any]:
    """Stand zum Zeitpunkt T: aktuellen Stand nehmen und alle Änderungen nach T rückwärts zurückdrehen."""
    state = dict(current)
    for c in sorted(changes_after, key=lambda c: (c.time, c.id), reverse=True):
        if c.action == "added":
            state.pop(c.key, None)
        else:  # removed / modified: vorherigen Stand wiederherstellen
            state[c.key] = c.old
    return state


def diff_since(current: dict[Key, Any], changes_after: list[Change]) -> list[dict[str, Any]]:
    """Netto-Unterschied zwischen Stand T und heute – mehrfache Änderungen am selben Objekt zusammengefasst."""
    first: dict[Key, Change] = {}
    count: dict[Key, int] = {}
    for c in sorted(changes_after, key=lambda c: (c.time, c.id)):
        first.setdefault(c.key, c)
        count[c.key] = count.get(c.key, 0) + 1

    result = []
    for key, c in first.items():
        old = None if c.action == "added" else c.old
        new = current.get(key)
        if old == new:
            continue  # hinzugefügt und wieder entfernt, oder zurückgeändert
        action = "added" if old is None else "removed" if new is None else "modified"
        result.append(
            {"entity_type": key[0], "name": key[1], "action": action, "old": old, "new": new, "changes": count[key]}
        )
    return sorted(result, key=lambda r: (r["entity_type"], r["name"]))


def compare_objects(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Vergleicht zwei {name: data}-Mengen (z.B. dieselbe Entität auf zwei Firewalls)."""
    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    different = sorted(n for n in set(a) & set(b) if a[n] != b[n])
    return {
        "only_a": [{"name": n, "data": a[n]} for n in only_a],
        "only_b": [{"name": n, "data": b[n]} for n in only_b],
        "different": [{"name": n, "a": a[n], "b": b[n]} for n in different],
        "same": len(set(a) & set(b)) - len(different),
    }

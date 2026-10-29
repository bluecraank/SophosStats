"""Parser für SFOS-Syslog-Nachrichten (key=value-Format, "Device standard format").

Beispiel:
<30>device="SFW" date=2026-10-21 time=10:15:02 timezone="CET" device_name="XGS2100"
device_id=X1234 log_id=010101600001 log_type="Firewall" log_component="Firewall Rule"
log_subtype="Allowed" status="Allow" priority=Information fw_rule_id=5 fw_rule_name="LAN to WAN"
src_ip=10.0.0.5 src_port=51234 dst_ip=1.1.1.1 dst_port=443 protocol="TCP"
sent_pkts=12 recv_pkts=10 sent_bytes=1820 recv_bytes=9240 con_event="Stop"
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_KV = re.compile(r'([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|\S*)')
_PRI = re.compile(r"^<(\d{1,3})>")
ADMIN_COMPONENTS = ("GUI", "CLI", "API", "Console", "SSH", "Admin", "Central")


@dataclass
class ParsedLog:
    time: datetime
    fields: dict[str, str] = field(default_factory=dict)

    def get(self, *keys: str) -> str | None:
        for k in keys:
            v = self.fields.get(k)
            if v not in (None, ""):
                return v
        return None

    def get_int(self, *keys: str) -> int | None:
        v = self.get(*keys)
        if v is None:
            return None
        try:
            return int(v)
        except ValueError:
            return None

    @property
    def log_type(self) -> str | None:
        return self.get("log_type")

    @property
    def rule_id(self) -> int | None:
        return self.get_int("fw_rule_id")

    @property
    def rule_name(self) -> str | None:
        return self.get("fw_rule_name")

    @property
    def sent_bytes(self) -> int | None:
        return self.get_int("sent_bytes", "bytes_sent")

    @property
    def recv_bytes(self) -> int | None:
        return self.get_int("recv_bytes", "bytes_received", "rcvd_bytes")

    @property
    def sent_pkts(self) -> int | None:
        return self.get_int("sent_pkts", "packets_sent")

    @property
    def recv_pkts(self) -> int | None:
        return self.get_int("recv_pkts", "packets_received", "rcvd_pkts")

    @property
    def con_event(self) -> str | None:
        v = self.get("con_event", "connevent")  # Schreibweise je nach Firmware
        return v.lower() if v else None

    @property
    def is_admin(self) -> bool:
        """Admin-Aktion (Anmeldung, Konfigurationsänderung …): je nach Firmware als Typ/Untertyp "Admin"
        oder als Event der Komponente GUI/CLI/API."""
        subtype = (self.get("log_subtype") or "").lower()
        log_type = (self.get("log_type") or "").lower()
        return "admin" in subtype or "admin" in log_type or (self.get("log_component") or "") in ADMIN_COMPONENTS

    @property
    def is_denied(self) -> bool:
        subtype = (self.get("log_subtype") or "").lower()
        status = (self.get("status") or "").lower()
        return subtype in ("denied", "drop") or status in ("deny", "drop")

    @property
    def counts_as_hit(self) -> bool:
        # Bei Logs mit Verbindungs-Events nur den Start zählen, sonst jeden Eintrag
        return self.con_event in (None, "start") or self.is_denied

    @property
    def counts_bytes(self) -> bool:
        # Byte-Zähler stehen im Abschluss-Event einer Verbindung. Interim-Events lassen wir aus,
        # um Doppelzählung zu vermeiden, falls die Firewall kumulierte Werte sendet.
        return self.con_event in (None, "stop", "end", "close")


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v


def _parse_time(fields: dict[str, str], received: datetime) -> datetime:
    ts = fields.get("timestamp")
    if ts:
        try:
            dt = datetime.fromisoformat(ts)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    date, time_ = fields.get("date"), fields.get("time")
    tz_name = fields.get("timezone")
    if date and time_ and tz_name:
        try:
            return datetime.fromisoformat(f"{date}T{time_}").replace(tzinfo=ZoneInfo(tz_name))
        except (ValueError, ZoneInfoNotFoundError):
            pass
    # Uhrzeit ohne auflösbare Zeitzone ist mehrdeutig – dann Empfangszeit verwenden
    return received


# Felder, die bereits als eigene Spalte gespeichert werden oder in jeder Zeile gleich sind – nicht nochmals
# im JSON ablegen (bei ~20 Mio. Logzeilen/Tag macht das einen Großteil des Speichers aus)
_STORED_AS_COLUMN = {
    "log_type",
    "log_component",
    "log_subtype",
    "status",
    "priority",
    "severity",
    "fw_rule_id",
    "fw_rule_name",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "user_name",
    "sent_bytes",
    "recv_bytes",
    "bytes_sent",
    "bytes_received",
    "message",
}
_CONSTANT = {
    "device",
    "device_name",
    "device_model",
    "device_id",
    "device_serial_id",
    "date",
    "time",
    "timezone",
    "timestamp",
    "log_version",
}


def extra_fields(fields: dict[str, str]) -> dict[str, str]:
    """Rohfelder für die JSON-Spalte: ohne Spalten-Duplikate, Gerätekonstanten und leere Werte."""
    return {
        k: v
        for k, v in fields.items()
        if v not in ("", "0") or k.endswith("_pkts")
        if k not in _STORED_AS_COLUMN and k not in _CONSTANT
    }


def parse(message: str, received: datetime | None = None) -> ParsedLog | None:
    received = received or datetime.now(UTC)
    body = _PRI.sub("", message.strip(), count=1)
    fields = {k: _unquote(v) for k, v in _KV.findall(body)}
    if not fields:
        return None
    return ParsedLog(time=_parse_time(fields, received), fields=fields)

"""Strukturierte Log-Filter (Feld, Operator, Wert) → SQLAlchemy-Ausdrücke.

Felder sind entweder bekannte Spalten oder beliebige Rohfelder des SFOS-Logs (JSONB `fields`).
Feldnamen und Operatoren sind über Whitelists bzw. ein Namensmuster abgesichert, Werte werden immer
als Bind-Parameter übergeben.
"""

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import BigInteger, and_, case, cast, literal, not_, or_
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.sql.elements import ColumnElement

from app.models import LogEntry

Op = Literal["eq", "ne", "contains", "not_contains", "starts", "gt", "lt", "cidr", "not_cidr", "exists", "missing"]

TEXT_COLUMNS = {
    "src_ip": LogEntry.src_ip,
    "dst_ip": LogEntry.dst_ip,
    "protocol": LogEntry.protocol,
    "user_name": LogEntry.user_name,
    "rule_name": LogEntry.rule_name,
    "log_type": LogEntry.log_type,
    "log_component": LogEntry.log_component,
    "log_subtype": LogEntry.log_subtype,
    "status": LogEntry.status,
    "severity": LogEntry.severity,
    "message": LogEntry.message,
}
NUMERIC_COLUMNS = {
    "src_port": LogEntry.src_port,
    "dst_port": LogEntry.dst_port,
    "rule_id": LogEntry.rule_id,
    "sent_bytes": LogEntry.sent_bytes,
    "recv_bytes": LogEntry.recv_bytes,
}
_RAW_FIELD = re.compile(r"^[A-Za-z_][\w.-]{0,63}$")
_INT = re.compile(r"^-?\d{1,18}$")
_IP_TEXT = "^[0-9A-Fa-f:.]+$"


class LogFilter(BaseModel):
    field: str = Field(max_length=64)
    op: Op
    value: str = Field(default="", max_length=200)

    @field_validator("field")
    @classmethod
    def _known_or_raw(cls, v: str) -> str:
        if v in TEXT_COLUMNS or v in NUMERIC_COLUMNS or v == "host_ip" or _RAW_FIELD.match(v):
            return v
        raise ValueError("ungültiger Feldname")


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _as_int(expr):
    """Text sicher in Zahl wandeln (nicht-numerische Werte -> NULL statt Fehler)."""
    return case((expr.op("~")(literal(r"^-?\d{1,18}$")), cast(expr, BigInteger)), else_=None)


def _as_inet(expr):
    return case((expr.op("~")(literal(_IP_TEXT)), cast(expr, INET)), else_=None)


_NEGATIVE = {"ne", "not_contains", "not_cidr", "missing"}


def to_condition(f: LogFilter) -> ColumnElement[bool]:
    if f.field == "host_ip":
        # IP als Quelle oder Ziel: positive Bedingung trifft, wenn eine Seite passt; negative, wenn keine passt
        src = to_condition(LogFilter(field="src_ip", op=f.op, value=f.value))
        dst = to_condition(LogFilter(field="dst_ip", op=f.op, value=f.value))
        return and_(src, dst) if f.op in _NEGATIVE else or_(src, dst)
    numeric = f.field in NUMERIC_COLUMNS
    if numeric:
        col = NUMERIC_COLUMNS[f.field]
        text_col = cast(col, LogEntry.message.type)
    else:
        col = TEXT_COLUMNS.get(f.field)
        if col is None:
            col = LogEntry.fields[f.field].astext
        text_col = col

    value = f.value.strip()
    if f.op == "exists":
        return col.is_not(None) & (text_col != "")
    if f.op == "missing":
        return or_(col.is_(None), text_col == "")

    if f.op in ("gt", "lt", "eq", "ne") and _INT.match(value) and (numeric or f.field not in TEXT_COLUMNS):
        num = col if numeric else _as_int(col)
        n = int(value)
        return {"gt": num > n, "lt": num < n, "eq": num == n, "ne": or_(num != n, num.is_(None))}[f.op]
    if f.op in ("gt", "lt"):
        raise ValueError(f"„{f.field}“ größer/kleiner braucht eine Zahl")

    if f.op in ("cidr", "not_cidr"):
        try:
            net = str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"Ungültiges Netz: {value}") from exc
        inside = _as_inet(text_col).op("<<=")(cast(literal(net), INET))
        return inside if f.op == "cidr" else or_(not_(inside), _as_inet(text_col).is_(None))

    pattern = _escape_like(value)
    if f.op == "eq":
        return text_col.ilike(pattern, escape="\\")
    if f.op == "ne":
        return or_(not_(text_col.ilike(pattern, escape="\\")), text_col.is_(None))
    if f.op == "contains":
        return text_col.ilike(f"%{pattern}%", escape="\\")
    if f.op == "not_contains":
        return or_(not_(text_col.ilike(f"%{pattern}%", escape="\\")), text_col.is_(None))
    if f.op == "starts":
        return text_col.ilike(f"{pattern}%", escape="\\")
    raise ValueError(f"Unbekannter Operator {f.op}")

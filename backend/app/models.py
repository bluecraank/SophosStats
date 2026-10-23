import enum
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    and_,
    func,
    literal_column,
    or_,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _ts(**kw) -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), **kw)


class Role(enum.StrEnum):
    admin = "admin"
    viewer = "viewer"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role"), default=Role.viewer)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret_enc: Mapped[str | None] = mapped_column(Text)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = _ts(nullable=True)
    last_login: Mapped[datetime | None] = _ts(nullable=True)
    created_at: Mapped[datetime] = _ts(server_default=func.now())


class UserSession(Base):
    __tablename__ = "user_sessions"

    # SHA-256 des Cookie-Tokens – das Token selbst wird nie gespeichert
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = _ts(server_default=func.now())
    expires_at: Mapped[datetime] = _ts()
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))


class Firewall(Base):
    __tablename__ = "firewalls"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    host: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # XML-API
    api_port: Mapped[int] = mapped_column(Integer, default=4444)
    api_username: Mapped[str] = mapped_column(String(100))
    api_password_enc: Mapped[str] = mapped_column(Text)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=False)

    # SNMP v3
    snmp_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    snmp_port: Mapped[int] = mapped_column(Integer, default=161)
    snmp_username: Mapped[str | None] = mapped_column(String(100))
    snmp_auth_protocol: Mapped[str] = mapped_column(String(16), default="SHA256")
    snmp_auth_key_enc: Mapped[str | None] = mapped_column(Text)
    snmp_priv_protocol: Mapped[str] = mapped_column(String(16), default="AES128")
    snmp_priv_key_enc: Mapped[str | None] = mapped_column(Text)

    # Syslog: Absender-IP, über die eingehende Logs dieser Firewall zugeordnet werden
    syslog_source_ip: Mapped[str | None] = mapped_column(String(64))
    # Zusätzliche interne Netze dieses Standorts (CIDR, Komma/Zeilen getrennt) – ergänzt die automatisch
    # aus den Interfaces erkannten Netze für die standortübergreifende Auswertung
    site_networks: Mapped[str | None] = mapped_column(Text)
    # Zone, über die die anderen Standorte erreicht werden (z.B. WireGuard-Tunnel); leer = automatisch erkennen
    site_link_zone: Mapped[str | None] = mapped_column(String(100))

    metrics_interval_s: Mapped[int] = mapped_column(Integer, default=60)
    config_interval_s: Mapped[int] = mapped_column(Integer, default=900)

    # Vom Collector gepflegt
    model: Mapped[str | None] = mapped_column(String(100))
    firmware: Mapped[str | None] = mapped_column(String(100))
    serial: Mapped[str | None] = mapped_column(String(100))
    api_version: Mapped[str | None] = mapped_column(String(32))
    last_metrics_at: Mapped[datetime | None] = _ts(nullable=True)
    last_metrics_error: Mapped[str | None] = mapped_column(Text)
    last_config_at: Mapped[datetime | None] = _ts(nullable=True)
    last_config_error: Mapped[str | None] = mapped_column(Text)
    last_config_warning: Mapped[str | None] = mapped_column(Text)
    last_log_at: Mapped[datetime | None] = _ts(nullable=True)
    poll_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _ts(server_default=func.now())


class ConfigObject(Base):
    """Aktueller Stand eines Konfigurationsobjekts (Regel, NAT, Interface, Host, …)."""

    __tablename__ = "config_objects"

    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), primary_key=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[dict] = mapped_column(JSONB)
    hash: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = _ts(server_default=func.now())


class ConfigChange(Base):
    __tablename__ = "config_changes"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    time: Mapped[datetime] = _ts(server_default=func.now(), index=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(16))  # added | removed | modified
    # Zeitpunkt des vorherigen Abrufs: die Änderung erfolgte irgendwann zwischen window_start und time
    window_start: Mapped[datetime | None] = _ts(nullable=True)
    old: Mapped[dict | None] = mapped_column(JSONB)
    new: Mapped[dict | None] = mapped_column(JSONB)


class FindingAck(Base):
    """Bewusst akzeptierter Audit-Befund. Gilt nur, solange die Regel unverändert ist (rule_hash)."""

    __tablename__ = "finding_acks"
    __table_args__ = (UniqueConstraint("firewall_id", "kind", "rule_name", name="uq_finding_ack"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    firewall_id: Mapped[int] = mapped_column(ForeignKey("firewalls.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    rule_name: Mapped[str] = mapped_column(String(255))
    rule_hash: Mapped[str | None] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = _ts(server_default=func.now())
    expires_at: Mapped[datetime | None] = _ts(nullable=True)


# --- Zeitreihen (TimescaleDB-Hypertables, Primärschlüssel enthält immer `time`) ---


class Metric(Base):
    __tablename__ = "metrics"

    firewall_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    time: Mapped[datetime] = _ts(primary_key=True)
    value: Mapped[float] = mapped_column(Float)


class InterfaceMetric(Base):
    __tablename__ = "interface_metrics"

    firewall_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    interface: Mapped[str] = mapped_column(String(64), primary_key=True)
    time: Mapped[datetime] = _ts(primary_key=True)
    in_bps: Mapped[float | None] = mapped_column(Float)
    out_bps: Mapped[float | None] = mapped_column(Float)
    in_octets: Mapped[int] = mapped_column(BigInteger)
    out_octets: Mapped[int] = mapped_column(BigInteger)
    oper_up: Mapped[bool | None] = mapped_column(Boolean)


class LogEntry(Base):
    __tablename__ = "log_entries"
    __table_args__ = (
        Index("ix_log_fw_time", "firewall_id", "time"),
        Index("ix_log_rule", "firewall_id", "rule_id", "time"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    time: Mapped[datetime] = _ts(primary_key=True)
    firewall_id: Mapped[int | None] = mapped_column(Integer)
    source_ip: Mapped[str] = mapped_column(String(64))
    log_type: Mapped[str | None] = mapped_column(String(64))
    log_component: Mapped[str | None] = mapped_column(String(64))
    log_subtype: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str | None] = mapped_column(String(32))
    rule_id: Mapped[int | None] = mapped_column(Integer)
    rule_name: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(64))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str | None] = mapped_column(String(64))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    user_name: Mapped[str | None] = mapped_column(String(255))
    sent_bytes: Mapped[int | None] = mapped_column(BigInteger)
    recv_bytes: Mapped[int | None] = mapped_column(BigInteger)
    message: Mapped[str | None] = mapped_column(Text)
    fields: Mapped[dict] = mapped_column(JSONB)


class AdminEvent(Base):
    """Admin-Aktionen aus dem Syslog, getrennt von den Roh-Logs gespeichert: "wer hat geändert" durchsucht
    dann wenige Einträge statt Millionen Logzeilen ohne passenden Index."""

    __tablename__ = "admin_events"
    __table_args__ = (Index("ix_admin_fw_time", "firewall_id", "time"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    time: Mapped[datetime] = _ts(primary_key=True)
    firewall_id: Mapped[int] = mapped_column(Integer)
    user_name: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(64))
    component: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str | None] = mapped_column(Text)


class RuleLastSeen(Base):
    """Eine Zeile pro Regel: erstmals/zuletzt in den Logs gesehen. Erspart das Gruppieren der gesamten
    stündlichen Nutzungshistorie für "zuletzt genutzt" und "ungenutzt"."""

    __tablename__ = "rule_last_seen"

    firewall_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_name: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime] = _ts()
    last_seen: Mapped[datetime] = _ts()


class RuleUsageHourly(Base):
    """Pro Stunde aggregierte Regelnutzung, aus den Firewall-Logs berechnet."""

    __tablename__ = "rule_usage_hourly"

    firewall_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    time: Mapped[datetime] = _ts(primary_key=True)
    rule_name: Mapped[str | None] = mapped_column(String(255))
    hits: Mapped[int] = mapped_column(BigInteger, default=0)
    denied: Mapped[int] = mapped_column(BigInteger, default=0)
    sent_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    recv_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    sent_pkts: Mapped[int] = mapped_column(BigInteger, default=0)
    recv_pkts: Mapped[int] = mapped_column(BigInteger, default=0)
    last_seen: Mapped[datetime] = _ts()


def denied_firewall_logs():
    """Abgelehnte Firewall-Verbindungen. Mit festen Literalen (keine Bind-Parameter) formuliert, damit
    PostgreSQL den Teilindex ix_log_denied nutzen kann – dessen Bedingung muss exakt so lauten."""
    lit = literal_column
    return and_(
        LogEntry.log_type == lit("'Firewall'"),
        or_(
            LogEntry.log_subtype.in_([lit("'Denied'"), lit("'Drop'")]),
            LogEntry.status.in_([lit("'Deny'"), lit("'Drop'")]),
        ),
    )

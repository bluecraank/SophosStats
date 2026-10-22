from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models import Role

AuthProto = Literal["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"]
PrivProto = Literal["NONE", "DES", "3DES", "AES128", "AES192", "AES256"]
Password = Field(min_length=12, max_length=256)


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    totp_code: str | None = Field(default=None, max_length=10)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: Role
    is_active: bool
    totp_enabled: bool
    last_login: datetime | None
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.@-]{3,64}$")
    password: str = Password
    role: Role = Role.viewer


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)
    reset_totp: bool = False


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Password


class TotpSetupOut(BaseModel):
    secret: str
    uri: str


class TotpCode(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class TotpDisable(BaseModel):
    password: str


class FirewallBase(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=255)
    enabled: bool = True
    api_port: int = Field(default=4444, ge=1, le=65535)
    api_username: str = Field(min_length=1, max_length=100)
    verify_tls: bool = False
    snmp_enabled: bool = True
    snmp_port: int = Field(default=161, ge=1, le=65535)
    snmp_username: str | None = Field(default=None, max_length=100)
    snmp_auth_protocol: AuthProto = "SHA256"
    snmp_priv_protocol: PrivProto = "AES128"
    syslog_source_ip: str | None = Field(default=None, max_length=64)
    site_networks: str | None = Field(default=None, max_length=4000)
    site_link_zone: str | None = Field(default=None, max_length=100)
    metrics_interval_s: int = Field(default=60, ge=15, le=3600)
    config_interval_s: int = Field(default=900, ge=60, le=86400)


class FirewallCreate(FirewallBase):
    api_password: str = Field(min_length=1, max_length=256)
    snmp_auth_key: str | None = Field(default=None, min_length=8, max_length=256)
    snmp_priv_key: str | None = Field(default=None, min_length=8, max_length=256)


class FirewallUpdate(BaseModel):
    """Alle Felder optional. Leere/fehlende Secrets bleiben unverändert."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    enabled: bool | None = None
    api_port: int | None = Field(default=None, ge=1, le=65535)
    api_username: str | None = None
    api_password: str | None = None
    verify_tls: bool | None = None
    snmp_enabled: bool | None = None
    snmp_port: int | None = Field(default=None, ge=1, le=65535)
    snmp_username: str | None = None
    snmp_auth_protocol: AuthProto | None = None
    snmp_auth_key: str | None = None
    snmp_priv_protocol: PrivProto | None = None
    snmp_priv_key: str | None = None
    syslog_source_ip: str | None = None
    site_networks: str | None = Field(default=None, max_length=4000)
    site_link_zone: str | None = Field(default=None, max_length=100)
    metrics_interval_s: int | None = Field(default=None, ge=15, le=3600)
    config_interval_s: int | None = Field(default=None, ge=60, le=86400)


class FirewallOut(FirewallBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    model: str | None
    firmware: str | None
    serial: str | None
    api_version: str | None
    last_metrics_at: datetime | None
    last_metrics_error: str | None
    last_config_at: datetime | None
    last_config_error: str | None
    last_config_warning: str | None
    last_log_at: datetime | None
    created_at: datetime


class TestResult(BaseModel):
    xml_api_ok: bool
    xml_api_message: str
    snmp_ok: bool | None
    snmp_message: str

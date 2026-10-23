from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+asyncpg://sophosstats:sophosstats@localhost:5432/sophosstats"

    # Fernet-Key zum Verschlüsseln von Firewall-Zugangsdaten und TOTP-Secrets.
    # Erzeugen: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    encryption_key: SecretStr

    # Erster Admin, wird nur angelegt wenn noch kein Benutzer existiert
    initial_admin_username: str = "admin"
    initial_admin_password: SecretStr | None = None

    session_ttl_hours: int = 12
    session_cookie_name: str = "sophosstats_session"
    # Hinter HTTPS-Reverse-Proxy auf True lassen
    cookie_secure: bool = True

    login_max_failures: int = 5
    login_lockout_minutes: int = 15

    # Collector
    scheduler_tick_seconds: int = 5
    syslog_udp_port: int = 5514
    syslog_tcp_port: int = 5514
    syslog_bind: str = "0.0.0.0"  # noqa: S104 - Collector muss Syslog von den Firewalls annehmen
    log_flush_seconds: float = 3.0
    log_flush_batch: int = 2000

    # Aufbewahrung (TimescaleDB retention policies)
    retention_metrics_days: int = 90
    retention_logs_days: int = 30
    retention_rule_usage_days: int = 400
    retention_blocked_days: int = 90

    cors_origins: list[str] = Field(default_factory=list)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]

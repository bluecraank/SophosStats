import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_db
from app.models import Role, User, UserSession

_hasher = PasswordHasher()
_fernet = Fernet(get_settings().encryption_key.get_secret_value().encode())

# Hash zum Vergleich, damit Logins mit unbekanntem Benutzer gleich lange dauern
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def encrypt(value: str) -> str:
    return _fernet.encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return _fernet.decrypt(value.encode()).decode()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SophosStats")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_session(db: AsyncSession, user: User, request: Request) -> str:
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            token_hash=_token_hash(token),
            user_id=user.id,
            expires_at=datetime.now(UTC) + timedelta(hours=settings.session_ttl_hours),
            ip=request.client.host if request.client else None,
            user_agent=(request.headers.get("user-agent") or "")[:255],
        )
    )
    # Abgelaufene Sessions bei Gelegenheit aufräumen
    await db.execute(delete(UserSession).where(UserSession.expires_at < datetime.now(UTC)))
    return token


async def revoke_session(db: AsyncSession, token: str) -> None:
    await db.execute(delete(UserSession).where(UserSession.token_hash == _token_hash(token)))


async def revoke_user_sessions(db: AsyncSession, user_id: int, keep_token: str | None = None) -> None:
    stmt = delete(UserSession).where(UserSession.user_id == user_id)
    if keep_token:
        stmt = stmt.where(UserSession.token_hash != _token_hash(keep_token))
    await db.execute(stmt)


_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


async def current_user(request: Request, db: Annotated[AsyncSession, Depends(get_db)]) -> User:
    settings = get_settings()
    # CSRF-Schutz zusätzlich zu SameSite=Strict: schreibende Requests brauchen einen Custom-Header,
    # den ein fremdes Formular nicht setzen kann.
    if request.method not in _SAFE_METHODS and request.headers.get("x-requested-with") != "SophosStats":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF-Header fehlt")

    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Nicht angemeldet")
    row = (
        await db.execute(
            select(User, UserSession)
            .join(UserSession, UserSession.user_id == User.id)
            .where(UserSession.token_hash == _token_hash(token))
        )
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sitzung ungültig")
    user, session = row
    if session.expires_at < datetime.now(UTC) or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sitzung abgelaufen")
    return user


async def require_admin(user: Annotated[User, Depends(current_user)]) -> User:
    if user.role != Role.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Nur für Administratoren")
    return user


CurrentUser = Annotated[User, Depends(current_user)]
AdminUser = Annotated[User, Depends(require_admin)]
DB = Annotated[AsyncSession, Depends(get_db)]

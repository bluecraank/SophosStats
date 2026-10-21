from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from app import security
from app.config import get_settings
from app.models import User
from app.schemas import LoginIn, PasswordChange, TotpCode, TotpDisable, TotpSetupOut, UserOut
from app.security import DB, CurrentUser

router = APIRouter(prefix="/api/auth", tags=["auth"])

_INVALID = "Benutzername, Passwort oder Code falsch"


def _set_cookie(response: Response, token: str) -> None:
    s = get_settings()
    response.set_cookie(
        s.session_cookie_name,
        token,
        max_age=s.session_ttl_hours * 3600,
        httponly=True,
        secure=s.cookie_secure,
        samesite="strict",
        path="/",
    )


async def _register_failure(db: DB, user: User) -> None:
    s = get_settings()
    user.failed_logins += 1
    if user.failed_logins >= s.login_max_failures:
        user.locked_until = datetime.now(UTC) + timedelta(minutes=s.login_lockout_minutes)
        user.failed_logins = 0
    await db.commit()


@router.post("/login", response_model=UserOut)
async def login(body: LoginIn, request: Request, response: Response, db: DB) -> User:
    if request.headers.get("x-requested-with") != "SophosStats":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF-Header fehlt")

    user = (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    password_ok = security.verify_password(body.password, user.password_hash if user else None)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID)
    if user.locked_until and user.locked_until > datetime.now(UTC):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Konto vorübergehend gesperrt")
    if not password_ok:
        await _register_failure(db, user)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID)

    if user.totp_enabled:
        if not body.totp_code:
            # Passwort war korrekt, zweiter Faktor fehlt noch
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "totp_required")
        if not security.verify_totp(security.decrypt(user.totp_secret_enc or ""), body.totp_code):
            await _register_failure(db, user)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID)

    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(body.password)
    user.failed_logins = 0
    user.locked_until = None
    user.last_login = datetime.now(UTC)
    token = await security.create_session(db, user, request)
    await db.commit()
    _set_cookie(response, token)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, db: DB, _user: CurrentUser) -> None:
    name = get_settings().session_cookie_name
    if token := request.cookies.get(name):
        await security.revoke_session(db, token)
        await db.commit()
    response.delete_cookie(name, path="/")


@router.get("/me", response_model=UserOut | None)
async def me(request: Request, db: DB) -> User | None:
    """Angemeldeter Benutzer oder null – kein 401, damit der Login-Check beim Laden keinen Fehler erzeugt."""
    try:
        return await security.current_user(request, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            return None
        raise


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(body: PasswordChange, request: Request, db: DB, user: CurrentUser) -> None:
    if not security.verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Aktuelles Passwort falsch")
    user.password_hash = security.hash_password(body.new_password)
    # Alle anderen Sitzungen abmelden
    await security.revoke_user_sessions(db, user.id, keep_token=request.cookies.get(get_settings().session_cookie_name))
    await db.commit()


@router.post("/totp/setup", response_model=TotpSetupOut)
async def totp_setup(db: DB, user: CurrentUser) -> TotpSetupOut:
    if user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "2FA ist bereits aktiv")
    secret = security.new_totp_secret()
    user.totp_secret_enc = security.encrypt(secret)
    await db.commit()
    return TotpSetupOut(secret=secret, uri=security.totp_uri(secret, user.username))


@router.post("/totp/enable", response_model=UserOut)
async def totp_enable(body: TotpCode, db: DB, user: CurrentUser) -> User:
    if user.totp_enabled or not user.totp_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Zuerst Einrichtung starten")
    if not security.verify_totp(security.decrypt(user.totp_secret_enc), body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Code ungültig")
    user.totp_enabled = True
    await db.commit()
    return user


@router.post("/totp/disable", response_model=UserOut)
async def totp_disable(body: TotpDisable, db: DB, user: CurrentUser) -> User:
    if not security.verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Passwort falsch")
    user.totp_enabled = False
    user.totp_secret_enc = None
    await db.commit()
    return user

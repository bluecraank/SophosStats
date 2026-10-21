from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from app import security
from app.models import Role, User
from app.schemas import UserCreate, UserOut, UserUpdate
from app.security import DB, AdminUser

router = APIRouter(prefix="/api/users", tags=["users"])


async def _active_admins(db: DB) -> int:
    return await db.scalar(select(func.count()).where(User.role == Role.admin, User.is_active)) or 0


async def _get(db: DB, user_id: int) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Benutzer nicht gefunden")
    return user


@router.get("", response_model=list[UserOut])
async def list_users(db: DB, _admin: AdminUser) -> list[User]:
    return list((await db.execute(select(User).order_by(User.username))).scalars())


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(body: UserCreate, db: DB, _admin: AdminUser) -> User:
    if await db.scalar(select(User.id).where(User.username == body.username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Benutzername existiert bereits")
    user = User(username=body.username, password_hash=security.hash_password(body.password), role=body.role)
    db.add(user)
    await db.commit()
    return user


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(user_id: int, body: UserUpdate, db: DB, admin: AdminUser) -> User:
    user = await _get(db, user_id)
    loses_admin = (body.role is not None and body.role != Role.admin) or body.is_active is False
    if loses_admin and user.role == Role.admin:
        if user.id == admin.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Eigene Admin-Rechte können nicht entzogen werden")
        if await _active_admins(db) <= 1:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Mindestens ein aktiver Admin muss bleiben")

    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password:
        user.password_hash = security.hash_password(body.password)
        user.locked_until = None
        user.failed_logins = 0
    if body.reset_totp:
        user.totp_enabled = False
        user.totp_secret_enc = None
    if body.password or body.is_active is False or body.reset_totp:
        await security.revoke_user_sessions(db, user.id)
    await db.commit()
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: int, db: DB, admin: AdminUser) -> None:
    user = await _get(db, user_id)
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Eigenes Konto kann nicht gelöscht werden")
    await db.delete(user)
    await db.commit()

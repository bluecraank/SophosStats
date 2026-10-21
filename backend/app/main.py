import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text

from app.api import auth, compliance, firewalls, graph, stats, users
from app.config import get_settings
from app.db import SessionLocal, init_schema
from app.models import Role, User
from app.security import hash_password

log = logging.getLogger("api")


async def _bootstrap_admin() -> None:
    settings = get_settings()
    async with SessionLocal() as db:
        if await db.scalar(select(func.count()).select_from(User)):
            return
        if settings.initial_admin_password is None:
            log.warning("Keine Benutzer vorhanden und INITIAL_ADMIN_PASSWORD nicht gesetzt – kein Login möglich")
            return
        db.add(
            User(
                username=settings.initial_admin_username,
                password_hash=hash_password(settings.initial_admin_password.get_secret_value()),
                role=Role.admin,
            )
        )
        await db.commit()
        log.info("Initialer Admin '%s' angelegt", settings.initial_admin_username)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    await init_schema()
    await _bootstrap_admin()
    yield


app = FastAPI(
    title="SophosStats",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

if get_settings().cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


for r in (auth.router, users.router, firewalls.router, stats.router, compliance.router, graph.router):
    app.include_router(r)


@app.get("/api/health", tags=["system"])
async def health() -> dict:
    async with SessionLocal() as db:
        await db.execute(text("SELECT 1"))
    return {"status": "ok"}

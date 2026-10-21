from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from sqlalchemy import select

from app.api.firewalls import get_firewall
from app.api.stats import rules_overview
from app.models import ConfigObject
from app.security import DB, CurrentUser
from app.services.graph import NODE_TYPES, build_graph

router = APIRouter(prefix="/api", tags=["graph"])


@router.get("/firewalls/{fw_id}/graph")
async def graph(fw_id: int, db: DB, _user: CurrentUser) -> dict:
    """Beziehungen zwischen Zonen, Interfaces, Netzobjekten, Diensten und Regeln (inkl. Nutzung 30 Tage)."""
    await get_firewall(db, fw_id)
    rows = (
        await db.execute(
            select(ConfigObject)
            .where(ConfigObject.firewall_id == fw_id, ConfigObject.entity_type.in_(list(NODE_TYPES)))
            .order_by(ConfigObject.entity_type, ConfigObject.position)
        )
    ).scalars()
    objects = [(o.entity_type, o.name, o.data) for o in rows]

    overview = await rules_overview(db, fw_id, datetime.now(UTC) - timedelta(days=30))
    usage = {
        r["name"]: {**(r["usage"] or {}), "position": r["position"], "last_seen_ever": r["last_seen_ever"]}
        for r in overview["rules"]
    }
    return build_graph(objects, usage)

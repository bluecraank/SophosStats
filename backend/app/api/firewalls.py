from fastapi import APIRouter, HTTPException, status
from sqlalchemy import delete, select

from app.collectors import poller
from app.models import AdminEvent, Firewall, InterfaceMetric, LogEntry, Metric, RuleLastSeen, RuleUsageHourly
from app.schemas import FirewallCreate, FirewallOut, FirewallUpdate, TestResult
from app.security import DB, AdminUser, CurrentUser, encrypt

router = APIRouter(prefix="/api/firewalls", tags=["firewalls"])

_SECRETS = {
    "api_password": "api_password_enc",
    "snmp_auth_key": "snmp_auth_key_enc",
    "snmp_priv_key": "snmp_priv_key_enc",
}


async def get_firewall(db: DB, fw_id: int) -> Firewall:
    fw = await db.get(Firewall, fw_id)
    if fw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Firewall nicht gefunden")
    return fw


async def _ensure_unique_name(db: DB, name: str, exclude_id: int | None = None) -> None:
    stmt = select(Firewall.id).where(Firewall.name == name)
    if exclude_id:
        stmt = stmt.where(Firewall.id != exclude_id)
    if await db.scalar(stmt):
        raise HTTPException(status.HTTP_409_CONFLICT, "Name bereits vergeben")


@router.get("", response_model=list[FirewallOut])
async def list_firewalls(db: DB, _user: CurrentUser) -> list[Firewall]:
    return list((await db.execute(select(Firewall).order_by(Firewall.name))).scalars())


@router.get("/{fw_id}", response_model=FirewallOut)
async def read_firewall(fw_id: int, db: DB, _user: CurrentUser) -> Firewall:
    return await get_firewall(db, fw_id)


@router.post("", response_model=FirewallOut, status_code=status.HTTP_201_CREATED)
async def create_firewall(body: FirewallCreate, db: DB, _admin: AdminUser) -> Firewall:
    await _ensure_unique_name(db, body.name)
    data = body.model_dump(exclude=set(_SECRETS))
    fw = Firewall(**data)
    for field, column in _SECRETS.items():
        value = getattr(body, field)
        setattr(fw, column, encrypt(value) if value else None)
    db.add(fw)
    await db.commit()
    return fw


@router.patch("/{fw_id}", response_model=FirewallOut)
async def update_firewall(fw_id: int, body: FirewallUpdate, db: DB, _admin: AdminUser) -> Firewall:
    fw = await get_firewall(db, fw_id)
    changes = body.model_dump(exclude_unset=True)
    if "name" in changes:
        await _ensure_unique_name(db, changes["name"], fw.id)
    for field, value in changes.items():
        if field in _SECRETS:
            if value:  # leer = unverändert
                setattr(fw, _SECRETS[field], encrypt(value))
        else:
            setattr(fw, field, value)
    await db.commit()
    return fw


@router.delete("/{fw_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_firewall(fw_id: int, db: DB, _admin: AdminUser) -> None:
    fw = await get_firewall(db, fw_id)
    # Zeitreihen-Tabellen haben keinen Fremdschlüssel (Hypertables) und werden explizit geleert
    for model in (Metric, InterfaceMetric, LogEntry, RuleUsageHourly, RuleLastSeen, AdminEvent):
        await db.execute(delete(model).where(model.firewall_id == fw.id))
    await db.delete(fw)
    await db.commit()


@router.post("/{fw_id}/poll", status_code=status.HTTP_202_ACCEPTED)
async def request_poll(fw_id: int, db: DB, _admin: AdminUser) -> dict:
    fw = await get_firewall(db, fw_id)
    fw.poll_requested = True
    await db.commit()
    return {"status": "Abruf angefordert"}


@router.post("/{fw_id}/test", response_model=TestResult)
async def test_firewall(fw_id: int, db: DB, _admin: AdminUser) -> TestResult:
    fw = await get_firewall(db, fw_id)
    try:
        version, missing = await poller.xml_client(fw).test()
        xml_ok = not missing
        xml_msg = f"Login erfolgreich (API-Version {version or '?'})"
        if missing:
            xml_msg += f", aber keine Leserechte für: {', '.join(missing)} – Admin-Profil des API-Benutzers prüfen"
    except Exception as exc:
        xml_ok, xml_msg = False, f"{type(exc).__name__}: {exc}"

    snmp_ok: bool | None = None
    snmp_msg = "SNMP deaktiviert"
    if fw.snmp_enabled:
        try:
            res = await poller.snmp_client(fw).poll(with_interfaces=False)
            snmp_ok = bool(res.metrics)
            snmp_msg = (
                f"{res.device.get('model', '?')} – Firmware {res.device.get('firmware', '?')}, {len(res.metrics)} Werte"
                if snmp_ok
                else "Verbunden, aber keine SFOS-Werte erhalten"
            )
        except Exception as exc:
            snmp_ok, snmp_msg = False, f"{type(exc).__name__}: {exc}"
    return TestResult(xml_api_ok=xml_ok, xml_api_message=xml_msg, snmp_ok=snmp_ok, snmp_message=snmp_msg)

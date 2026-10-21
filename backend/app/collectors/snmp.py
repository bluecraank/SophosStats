"""SNMP-v3-Abfrage von Systemwerten (SFOS-FIREWALL-MIB + Standard-MIBs).

Auf der Firewall: Administration > SNMP > SNMPv3-Benutzer anlegen und SNMP auf der Zone
(Administration > Device access) erlauben, über die dieser Server kommt.
"""

from dataclasses import dataclass, field

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usm3DESEDEPrivProtocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoPrivProtocol,
)

AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}
PRIV_PROTOCOLS = {
    "NONE": usmNoPrivProtocol,
    "DES": usmDESPrivProtocol,
    "3DES": usm3DESEDEPrivProtocol,
    "AES128": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}

_SFOS = "1.3.6.1.4.1.2604.5.1"

DEVICE_OIDS = {
    "name": f"{_SFOS}.1.1.0",
    "model": f"{_SFOS}.1.2.0",
    "firmware": f"{_SFOS}.1.3.0",
    "serial": f"{_SFOS}.1.4.0",
}

# Metrikname -> OID. Prozentwerte 0-100, Kapazitäten in MB, Uptime in Timeticks (1/100 s).
SCALAR_METRICS = {
    "uptime_ticks": f"{_SFOS}.2.2.0",
    "disk_capacity_mb": f"{_SFOS}.2.4.1.0",
    "disk_percent": f"{_SFOS}.2.4.2.0",
    "memory_capacity_mb": f"{_SFOS}.2.5.1.0",
    "memory_percent": f"{_SFOS}.2.5.2.0",
    "swap_capacity_mb": f"{_SFOS}.2.5.3.0",
    "swap_percent": f"{_SFOS}.2.5.4.0",
    "live_users": f"{_SFOS}.2.6.0",
}

HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"  # HOST-RESOURCES-MIB, Last pro Kern
UCD_CPU_IDLE = "1.3.6.1.4.1.2021.11.11.0"  # UCD-SNMP-MIB ssCpuIdle (Fallback)

IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"


class SnmpError(Exception):
    pass


@dataclass
class InterfaceSample:
    name: str
    in_octets: int
    out_octets: int
    oper_up: bool | None


@dataclass
class SnmpResult:
    device: dict[str, str] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)
    interfaces: list[InterfaceSample] = field(default_factory=list)


def _has_value(val) -> bool:
    # noSuchObject / noSuchInstance / endOfMibView sind Klassen aus pysnmp.proto.rfc1905
    return type(val).__name__ not in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null")


class SnmpClient:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        auth_protocol: str,
        auth_key: str | None,
        priv_protocol: str,
        priv_key: str | None,
        timeout: float = 5.0,
        retries: int = 1,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        priv = PRIV_PROTOCOLS[priv_protocol.upper()] if priv_key else usmNoPrivProtocol
        self.auth = UsmUserData(
            username,
            authKey=auth_key or None,
            privKey=priv_key or None,
            authProtocol=AUTH_PROTOCOLS[auth_protocol.upper()],
            privProtocol=priv,
        )

    async def _target(self) -> UdpTransportTarget:
        return await UdpTransportTarget.create((self.host, self.port), timeout=self.timeout, retries=self.retries)

    async def _get(self, engine: SnmpEngine, oids: dict[str, str]) -> dict[str, object]:
        err_ind, err_status, err_idx, var_binds = await get_cmd(
            engine,
            self.auth,
            await self._target(),
            ContextData(),
            *(ObjectType(ObjectIdentity(oid)) for oid in oids.values()),
        )
        if err_ind:
            raise SnmpError(str(err_ind))
        if err_status:
            raise SnmpError(f"{err_status.prettyPrint()} bei Index {err_idx}")
        by_oid = {str(name): val for name, val in var_binds}
        return {key: by_oid.get(oid) for key, oid in oids.items() if _has_value(by_oid.get(oid))}

    async def _walk(self, engine: SnmpEngine, base_oid: str) -> dict[str, object]:
        """Gibt {index-suffix: wert} für alle Einträge unterhalb von base_oid zurück."""
        result: dict[str, object] = {}
        async for err_ind, err_status, _idx, var_binds in bulk_walk_cmd(
            engine,
            self.auth,
            await self._target(),
            ContextData(),
            0,
            25,
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        ):
            if err_ind:
                raise SnmpError(str(err_ind))
            if err_status:
                break
            for name, val in var_binds:
                if _has_value(val):
                    result[str(name)[len(base_oid) + 1 :]] = val
        return result

    async def _cpu_percent(self, engine: SnmpEngine) -> float | None:
        loads = await self._walk(engine, HR_PROCESSOR_LOAD)
        if loads:
            values = [int(v) for v in loads.values()]
            return sum(values) / len(values)
        idle = await self._get(engine, {"idle": UCD_CPU_IDLE})
        if "idle" in idle:
            return 100.0 - float(idle["idle"])
        return None

    async def poll(self, with_interfaces: bool = True) -> SnmpResult:
        engine = SnmpEngine()
        try:
            res = SnmpResult()
            device = await self._get(engine, DEVICE_OIDS)
            res.device = {k: str(v) for k, v in device.items()}
            scalars = await self._get(engine, SCALAR_METRICS)
            res.metrics = {k: float(v) for k, v in scalars.items()}
            cpu = await self._cpu_percent(engine)
            if cpu is not None:
                res.metrics["cpu_percent"] = cpu

            if with_interfaces:
                names = await self._walk(engine, IF_NAME)
                ins = await self._walk(engine, IF_HC_IN)
                outs = await self._walk(engine, IF_HC_OUT)
                oper = await self._walk(engine, IF_OPER_STATUS)
                for idx, name in names.items():
                    if idx not in ins or idx not in outs:
                        continue
                    res.interfaces.append(
                        InterfaceSample(
                            name=str(name),
                            in_octets=int(ins[idx]),
                            out_octets=int(outs[idx]),
                            oper_up=(int(oper[idx]) == 1) if idx in oper else None,
                        )
                    )
            return res
        finally:
            engine.close_dispatcher()

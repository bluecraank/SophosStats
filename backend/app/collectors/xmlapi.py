"""Client für die Sophos SFOS XML-API (https://<fw>:4444/webconsole/APIController).

Voraussetzungen auf der Firewall: Administration > Backup & firmware > API aktiviert und
die IP dieses Servers in der Allowlist. Die API ist zustandslos – jeder Request enthält den Login.
"""

from dataclasses import dataclass
from typing import Any
from xml.etree.ElementTree import Element
from xml.sax.saxutils import escape

import httpx
from defusedxml import ElementTree

# Entitäten, die regelmäßig gesichert werden. Nicht jede Firmware kennt alle – unbekannte
# Entitäten liefern einen Fehlerstatus und werden übersprungen.
CONFIG_ENTITIES = [
    "FirewallRule",
    "FirewallRuleGroup",
    "NATRule",
    "Interface",
    "VLAN",
    "Zone",
    "IPHost",
    "IPHostGroup",
    "FQDNHost",
    "Services",
    "ServiceGroup",
    "IPSecConnection",
    "Gateway",
    "UnicastRoute",
]


class XmlApiError(Exception):
    pass


@dataclass
class EntityResult:
    entity: str
    items: list[dict[str, Any]]
    error: str | None = None


def element_to_value(el: Element) -> Any:
    """Wandelt ein XML-Element in dict/list/str. Wiederholte Kind-Tags werden zu Listen."""
    children = list(el)
    if not children:
        return (el.text or "").strip()
    result: dict[str, Any] = {}
    for child in children:
        value = element_to_value(child)
        if child.tag in result:
            existing = result[child.tag]
            if not isinstance(existing, list):
                result[child.tag] = [existing]
            result[child.tag].append(value)
        else:
            result[child.tag] = value
    return result


class SophosXmlApi:
    def __init__(self, host: str, port: int, username: str, password: str, verify_tls: bool = False):
        self.url = f"https://{host}:{port}/webconsole/APIController"
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.api_version: str | None = None

    def _request_xml(self, body: str) -> str:
        return (
            '<Request APIVersion="2000.1">'
            f"<Login><Username>{escape(self.username)}</Username>"
            f"<Password>{escape(self.password)}</Password></Login>"
            f"{body}</Request>"
        )

    async def _call(self, client: httpx.AsyncClient, body: str) -> Element:
        resp = await client.post(self.url, data={"reqxml": self._request_xml(body)})
        resp.raise_for_status()
        root = ElementTree.fromstring(resp.content)
        self.api_version = root.get("APIVersion") or self.api_version

        # Globale Fehler, z.B. "API operations are not allowed from the requester IP address"
        status_el = root.find("Status")
        if status_el is not None and root.find("Login") is None:
            raise XmlApiError(f"{status_el.get('code', '')} {(status_el.text or '').strip()}".strip())
        login_status = (root.findtext("Login/status") or "").strip()
        if login_status and "success" not in login_status.lower():
            raise XmlApiError(f"Login fehlgeschlagen: {login_status}")
        return root

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(verify=self.verify_tls, timeout=httpx.Timeout(30.0, connect=10.0))

    async def test(self) -> str | None:
        """Prüft Login. Gibt die API-Version zurück."""
        async with self._client() as client:
            await self._call(client, "<Get><Zone></Zone></Get>")
        return self.api_version

    async def get_entity(self, client: httpx.AsyncClient, entity: str) -> EntityResult:
        try:
            root = await self._call(client, f"<Get><{entity}></{entity}></Get>")
        except XmlApiError:
            raise
        except (httpx.HTTPError, ElementTree.ParseError) as exc:
            return EntityResult(entity, [], f"{type(exc).__name__}: {exc}")

        items: list[dict[str, Any]] = []
        for el in root.findall(entity):
            value = element_to_value(el)
            if isinstance(value, dict):
                # Einträge, die nur einen Status enthalten, sind Fehlermeldungen ("No. of records Zero" o.ä.)
                if set(value) == {"Status"}:
                    continue
                items.append(value)
        error = None
        if not items:
            st = root.find(f"{entity}/Status")
            if st is not None and st.get("code") not in (None, "200", "526"):
                error = f"{st.get('code')} {(st.text or '').strip()}"
        return EntityResult(entity, items, error)

    async def get_config(self, entities: list[str] | None = None) -> list[EntityResult]:
        results = []
        async with self._client() as client:
            for entity in entities or CONFIG_ENTITIES:
                results.append(await self.get_entity(client, entity))
        return results

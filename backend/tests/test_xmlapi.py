from urllib.parse import parse_qs

import httpx

from app.collectors.xmlapi import SophosXmlApi

LOGIN = "<Login><status>Authentication Successful</status></Login>"
RESPONSES = {
    "Zone": f'<Response APIVersion="2000.1">{LOGIN}<Zone><Status code="599">You do not have permission '
    "for the requested entity</Status></Zone></Response>",
    "Gateway": f'<Response APIVersion="2000.1">{LOGIN}<Gateway><Status code="529">Input request module is '
    "Invalid</Status></Gateway></Response>",
    "IPHost": f'<Response APIVersion="2000.1">{LOGIN}<IPHost transactionid=""><Name>srv1</Name>'
    "<IPAddress>10.0.0.1</IPAddress></IPHost></Response>",
}


def _handler(request: httpx.Request) -> httpx.Response:
    reqxml = parse_qs(request.content.decode())["reqxml"][0]
    entity = next(e for e in RESPONSES if f"<Get><{e}>" in reqxml)
    return httpx.Response(200, content=RESPONSES[entity].encode())


async def test_entity_status_codes():
    api = SophosXmlApi("fw", 4444, "user", "pw")
    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        zone = await api.get_entity(client, "Zone")
        gateway = await api.get_entity(client, "Gateway")
        host = await api.get_entity(client, "IPHost")

    assert zone.no_permission and not zone.items
    assert gateway.unsupported
    assert host.error is None and host.items == [{"Name": "srv1", "IPAddress": "10.0.0.1"}]
    assert api.api_version == "2000.1"

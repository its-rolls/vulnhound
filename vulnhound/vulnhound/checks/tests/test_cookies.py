import httpx

from vulnhound.checks.base import ScanContext
from vulnhound.checks.cookies import CookieFlagsCheck


def test_session_cookie_without_flags():
    def handler(request):
        return httpx.Response(200, headers={"Set-Cookie": "PHPSESSID=abc123; path=/"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    ctx = ScanContext(client=client, base_url="http://localhost:8080/", pages=[], transport=transport)
    titles = {f.title for f in CookieFlagsCheck().run(ctx)}
    assert titles == {"Cookie PHPSESSID missing HttpOnly", "Cookie PHPSESSID missing SameSite"}


def test_well_configured_cookie():
    def handler(request):
        return httpx.Response(200, headers={"Set-Cookie": "sid=abc; HttpOnly; SameSite=Lax; Path=/"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    ctx = ScanContext(client=client, base_url="http://localhost:8080/", pages=[], transport=transport)
    assert CookieFlagsCheck().run(ctx) == []
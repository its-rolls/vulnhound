"""Checks are tested against a fake server, so no Docker is needed to run these."""

import httpx

from vulnhound.checks.base import ScanContext
from vulnhound.checks.dir_listing import DirectoryListingCheck, parent_directories
from vulnhound.checks.exposed_files import ExposedFilesCheck
from vulnhound.checks.headers import SecurityHeadersCheck
from vulnhound.crawler import Page

BASE = "http://localhost:8080/"


def make_ctx(handler, pages=None) -> ScanContext:
    """A ScanContext whose client talks to `handler` instead of the network."""
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    return ScanContext(client=client, base_url=BASE, pages=pages or [], transport=transport)


def test_missing_headers_and_version_banner():
    def handler(request):
        return httpx.Response(200, headers={"Server": "Apache/2.4.25 (Debian)"}, text="hi")

    findings = SecurityHeadersCheck().run(make_ctx(handler))
    titles = {f.title for f in findings}
    assert "Missing content-security-policy header" in titles
    assert "Version disclosed in server header" in titles


def test_no_findings_when_headers_are_good():
    good = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Server": "Apache",
    }

    def handler(request):
        return httpx.Response(200, headers=good, text="hi")

    assert SecurityHeadersCheck().run(make_ctx(handler)) == []


def test_exposed_git_head_is_found():
    def handler(request):
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n")
        return httpx.Response(404, text="not found")

    findings = ExposedFilesCheck().run(make_ctx(handler))
    assert [f.title for f in findings] == ["Git repository exposed"]


def test_soft_404_is_not_a_finding():
    # Like Juice Shop: every path returns 200 with the same app page.
    def handler(request):
        return httpx.Response(200, text="<html>my single page app</html>")

    assert ExposedFilesCheck().run(make_ctx(handler)) == []


def test_parent_directories():
    assert parent_directories("http://h/a/b/c.php") == ["http://h/a/", "http://h/a/b/"]
    assert parent_directories("http://h/a/b/") == ["http://h/a/", "http://h/a/b/"]


def test_directory_listing_found():
    def handler(request):
        if request.url.path == "/docs/":
            return httpx.Response(200, text="<html><title>Index of /docs</title></html>")
        return httpx.Response(404)

    pages = [Page(url="http://localhost:8080/docs/readme.html", status=200)]
    findings = DirectoryListingCheck().run(make_ctx(handler, pages))
    assert [f.url for f in findings] == ["http://localhost:8080/docs/"]
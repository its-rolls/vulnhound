"""Folders where the server shows a clickable list of every file inside."""

from urllib.parse import urljoin, urlparse

import httpx

from vulnhound.checks import register
from vulnhound.checks.base import Check, ScanContext
from vulnhound.findings import Finding, Severity

LISTING_MARKERS = ("<title>Index of /", "Directory listing for /", "[To Parent Directory]")


def parent_directories(url: str) -> list[str]:
    """http://h/a/b/c.php -> [http://h/a/, http://h/a/b/]"""
    parsed = urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    if parsed.path and not parsed.path.endswith("/"):
        parts = parts[:-1]  # drop the file name
    root = f"{parsed.scheme}://{parsed.netloc}/"
    return [urljoin(root, "/".join(parts[: i + 1]) + "/") for i in range(len(parts))]


@register
class DirectoryListingCheck(Check):
    id = "dir-listing"
    name = "Directory listing enabled"

    def run(self, ctx: ScanContext) -> list[Finding]:
        directories = sorted({d for page in ctx.pages for d in parent_directories(page.url)})
        findings = []
        for url in directories:
            try:
                response = ctx.client.get(url, follow_redirects=False)
            except httpx.HTTPError:
                continue
            marker = next((m for m in LISTING_MARKERS if m in response.text), None)
            if response.status_code == 200 and marker:
                findings.append(Finding(self.id, "Directory listing enabled", Severity.LOW, url,
                                        f"Page contains {marker!r}",
                                        "Turn off directory indexes (Apache: Options -Indexes)."))
        return findings
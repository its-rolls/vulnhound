"""Files that should never be reachable from the internet."""

import re
import uuid
from urllib.parse import urljoin

import httpx

from vulnhound.checks import register
from vulnhound.checks.base import Check, ScanContext
from vulnhound.findings import Finding, Severity

# path -> (severity, title, signature that proves it's the real file)
# The signature is the important part: without it, every "200 OK" would be a finding.
SENSITIVE_FILES = {
    ".git/HEAD": (Severity.HIGH, "Git repository exposed", re.compile(r"^ref: refs/")),
    ".git/config": (Severity.HIGH, "Git config exposed", re.compile(r"\[core\]")),
    ".env": (Severity.HIGH, "Environment file exposed", re.compile(r"^[A-Z_][A-Z0-9_]*=", re.M)),
    "phpinfo.php": (Severity.MEDIUM, "phpinfo() page exposed", re.compile(r"PHP Version")),
    "server-status": (Severity.MEDIUM, "Apache server-status exposed", re.compile(r"Apache Server Status")),
    ".DS_Store": (Severity.LOW, "macOS .DS_Store file exposed", re.compile(r"Bud1")),
}


@register
class ExposedFilesCheck(Check):
    id = "exposed-files"
    name = "Exposed sensitive files"

    def run(self, ctx: ScanContext) -> list[Finding]:
        base = ctx.base_url if ctx.base_url.endswith("/") else ctx.base_url + "/"
        baseline = self._not_found_body(ctx.client, base)
        findings = []

        for path, (severity, title, signature) in SENSITIVE_FILES.items():
            url = urljoin(base, path)
            try:
                response = ctx.client.get(url, follow_redirects=False)
            except httpx.HTTPError:
                continue
            body = response.text
            if response.status_code != 200 or body == baseline:
                continue  # missing, or a "soft 404" (same page the server gives for anything)
            match = signature.search(body)
            if match:
                findings.append(Finding(self.id, title, severity, url,
                                        f"HTTP 200, content matches {signature.pattern!r}: {match.group(0)[:60]!r}",
                                        f"Block public access to {path} in the web server config, or remove it."))
        return findings

    @staticmethod
    def _not_found_body(client: httpx.Client, base: str) -> str | None:
        """Ask for a page that can't exist to learn what this server's 'not found' looks like."""
        try:
            response = client.get(urljoin(base, f"vulnhound-{uuid.uuid4().hex}"), follow_redirects=False)
        except httpx.HTTPError:
            return None
        return response.text if response.status_code == 200 else None
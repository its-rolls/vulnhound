"""Security headers the browser uses to protect users, and headers that leak info."""

import re

import httpx

from vulnhound.checks import register
from vulnhound.checks.base import Check, ScanContext
from vulnhound.findings import Finding, Severity

# header name -> (severity if missing, why it matters / how to fix)
REQUIRED = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Add a Content-Security-Policy. It is the strongest browser-side defence against XSS.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Add X-Frame-Options: DENY (or CSP frame-ancestors) so the site can't be framed for clickjacking.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Add X-Content-Type-Options: nosniff so browsers don't guess file types (MIME sniffing).",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Add Referrer-Policy: strict-origin-when-cross-origin so URLs aren't leaked to other sites.",
    ),
}
LEAKY = ("server", "x-powered-by", "x-aspnet-version")


@register
class SecurityHeadersCheck(Check):
    id = "headers"
    name = "Security headers"

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            response = ctx.client.get(ctx.base_url)
        except httpx.HTTPError:
            return []
        url = str(response.url)
        headers = response.headers  # httpx headers are case-insensitive
        findings = []

        for name, (severity, fix) in REQUIRED.items():
            if name not in headers:
                findings.append(Finding(self.id, f"Missing {name} header", severity, url,
                                        f"Response has no {name} header", fix))

        # HSTS only means something over HTTPS.
        if url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append(Finding(self.id, "Missing strict-transport-security header", Severity.MEDIUM,
                                    url, "HTTPS response has no HSTS header",
                                    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"))

        # A version number in a banner tells attackers exactly which exploits to try.
        for name in LEAKY:
            value = headers.get(name)
            if value and re.search(r"\d", value):
                findings.append(Finding(self.id, f"Version disclosed in {name} header", Severity.LOW,
                                        url, f"{name}: {value}",
                                        f"Remove the version from the {name} header (e.g. ServerTokens Prod, expose_php = Off)."))
        return findings
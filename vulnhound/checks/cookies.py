"""Cookies without the flags that stop scripts and other sites from abusing them."""

import httpx

from vulnhound.checks import register
from vulnhound.checks.base import Check, ScanContext
from vulnhound.findings import Finding, Severity


@register
class CookieFlagsCheck(Check):
    id = "cookie-flags"
    name = "Insecure cookie flags"

    def run(self, ctx: ScanContext) -> list[Finding]:
        # A logged-out client, so the server hands us brand-new cookies.
        with ctx.fresh_client() as fresh:
            try:
                response = fresh.get(ctx.base_url)
            except httpx.HTTPError:
                return []

        findings = []
        # Cookies can be set on any hop of a redirect chain, so look at all of them.
        for hop in [*response.history, response]:
            for raw in hop.headers.get_list("set-cookie"):
                name = raw.split("=", 1)[0].strip()
                flags = raw.lower()
                url = str(hop.url)
                if "httponly" not in flags:
                    findings.append(Finding(self.id, f"Cookie {name} missing HttpOnly", Severity.MEDIUM, url, raw,
                                            "Set HttpOnly so JavaScript (and therefore XSS) can't read the cookie."))
                if "samesite" not in flags:
                    findings.append(Finding(self.id, f"Cookie {name} missing SameSite", Severity.LOW, url, raw,
                                            "Set SameSite=Lax (or Strict) to stop the cookie being sent on cross-site requests (CSRF)."))
                if url.startswith("https://") and "secure" not in flags:
                    findings.append(Finding(self.id, f"Cookie {name} missing Secure", Severity.MEDIUM, url, raw,
                                            "Set Secure so the cookie is never sent over plain HTTP."))
        return findings
"""Runs every check against the crawl results. Knows nothing about any specific check."""

from vulnhound.checks import all_checks
from vulnhound.checks.base import ScanContext
from vulnhound.findings import Finding


def run_checks(ctx: ScanContext, only: list[str] | None = None) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    for check in all_checks():
        if only and check.id not in only:
            continue
        try:
            findings.extend(check.run(ctx))
        except Exception as err:  # one broken check must not kill the whole scan
            errors.append(f"{check.id}: {type(err).__name__}: {err}")
    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings, errors
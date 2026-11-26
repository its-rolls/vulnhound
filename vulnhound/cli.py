import httpx
import typer

from vulnhound.checks import all_checks
from vulnhound.checks.base import ScanContext
from vulnhound.crawler import Crawler
from vulnhound.engine import run_checks
from vulnhound.findings import Severity
from vulnhound.scope import check_target

app = typer.Typer(help="VulnHound: a web vulnerability scanner for authorised targets only.")

COLOURS = {
    Severity.CRITICAL: typer.colors.BRIGHT_RED,
    Severity.HIGH: typer.colors.RED,
    Severity.MEDIUM: typer.colors.YELLOW,
    Severity.LOW: typer.colors.CYAN,
    Severity.INFO: typer.colors.WHITE,
}


@app.callback()
def main() -> None:
    """VulnHound command line."""


def parse_cookies(raw: list[str]) -> dict[str, str]:
    """Turn ["PHPSESSID=abc", "security=low"] into {"PHPSESSID": "abc", "security": "low"}."""
    cookies = {}
    for item in raw:
        name, sep, value = item.partition("=")
        if not sep:
            raise typer.BadParameter(f"Cookie must look like name=value, got: {item}")
        cookies[name.strip()] = value.strip()
    return cookies


@app.command()
def checks() -> None:
    """List every check VulnHound can run."""
    for check in all_checks():
        typer.echo(f"{check.id:<15} {check.name}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Base URL, e.g. http://localhost:8080"),
    timeout: float = typer.Option(10.0, help="Seconds to wait for each response"),
    max_pages: int = typer.Option(100, help="Stop crawling after this many pages"),
    delay: float = typer.Option(0.1, help="Seconds to wait between requests"),
    cookie: list[str] = typer.Option([], "--cookie", "-c", help="Session cookie name=value (repeatable)"),
    exclude: list[str] = typer.Option([], "--exclude", "-x", help="Never visit URLs containing this text (repeatable)"),
    only: list[str] = typer.Option([], "--only", help="Run only this check id (repeatable)"),
    show_pages: bool = typer.Option(False, "--show-pages", help="Also print every crawled page and form"),
    allow_remote: bool = typer.Option(
        False, "--i-have-permission", help="Allow a non-local target you are authorised to test"
    ),
) -> None:
    """Crawl a target, then run every check against what was found."""
    try:
        check_target(target, allow_remote)
    except ValueError as err:
        typer.secho(f"Refusing to scan: {err}", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    headers = {"User-Agent": "VulnHound/0.1 (learning project)"}
    with httpx.Client(
        timeout=timeout, follow_redirects=True, headers=headers, cookies=parse_cookies(cookie)
    ) as client:
        typer.echo(f"Crawling {target} ...")
        pages = Crawler(client, target, max_pages=max_pages, delay=delay, exclude=tuple(exclude)).crawl()
        typer.echo(f"Crawled {len(pages)} pages. Running checks ...\n")
        ctx = ScanContext(client=client, base_url=target, pages=pages)
        findings, errors = run_checks(ctx, only=only or None)

    if show_pages:
        for page in pages:
            typer.secho(f"[{page.status}] {page.url}", bold=True)
            for form in page.forms:
                names = ", ".join(i.name for i in form.inputs) or "(no named inputs)"
                typer.echo(f"    form: {form.method} {form.action}  inputs: {names}")
        typer.echo("")

    for f in findings:
        typer.secho(f"[{f.severity.name:<8}] {f.title}", fg=COLOURS[f.severity], bold=True)
        typer.echo(f"    where:    {f.url}")
        typer.echo(f"    evidence: {f.evidence}")
        typer.echo(f"    fix:      {f.remediation}")

    for e in errors:
        typer.secho(f"Check crashed: {e}", fg=typer.colors.MAGENTA)

    counts = {s.name: sum(f.severity == s for f in findings) for s in reversed(Severity)}
    summary = ", ".join(f"{n} {name.lower()}" for name, n in counts.items() if n)
    typer.secho(f"\n{len(findings)} findings ({summary or 'none'})", fg=typer.colors.GREEN)
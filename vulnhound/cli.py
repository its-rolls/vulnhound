import httpx
import typer

from vulnhound.crawler import Crawler
from vulnhound.scope import check_target

app = typer.Typer(help="VulnHound: a web vulnerability scanner for authorised targets only.")


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
def scan(
    target: str = typer.Argument(..., help="Base URL, e.g. http://localhost:8080"),
    timeout: float = typer.Option(10.0, help="Seconds to wait for each response"),
    max_pages: int = typer.Option(100, help="Stop crawling after this many pages"),
    delay: float = typer.Option(0.1, help="Seconds to wait between requests"),
    cookie: list[str] = typer.Option([], "--cookie", "-c", help="Session cookie name=value (repeatable)"),
    exclude: list[str] = typer.Option([], "--exclude", "-x", help="Never visit URLs containing this text (repeatable)"),
    allow_remote: bool = typer.Option(
        False, "--i-have-permission", help="Allow a non-local target you are authorised to test"
    ),
) -> None:
    """Crawl a target and list every page, parameter and form found."""
    try:
        check_target(target, allow_remote)
    except ValueError as err:
        typer.secho(f"Refusing to scan: {err}", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    headers = {"User-Agent": "VulnHound/0.1 (learning project)"}
    with httpx.Client(
        timeout=timeout, follow_redirects=True, headers=headers, cookies=parse_cookies(cookie)
    ) as client:
        pages = Crawler(client, target, max_pages=max_pages, delay=delay, exclude=tuple(exclude)).crawl()

    total_forms = 0
    for page in pages:
        typer.secho(f"[{page.status}] {page.url}", bold=True)
        if page.params:
            typer.echo(f"    params: {', '.join(page.params)}")
        for form in page.forms:
            total_forms += 1
            names = ", ".join(i.name for i in form.inputs) or "(no named inputs)"
            typer.echo(f"    form: {form.method} {form.action}  inputs: {names}")

    typer.secho(f"\n{len(pages)} pages, {total_forms} forms", fg=typer.colors.GREEN) 
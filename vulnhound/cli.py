import httpx
import typer

from vulnhound.scope import check_target

app = typer.Typer(help="VulnHound: a web vulnerability scanner for authorised targets only.")


@app.callback()
def main() -> None:
    """VulnHound command line."""


@app.command()
def scan(
    target: str = typer.Argument(..., help="Base URL, e.g. http://localhost:8080"),
    timeout: float = typer.Option(10.0, help="Seconds to wait for each response"),
    allow_remote: bool = typer.Option(
        False, "--i-have-permission", help="Allow a non-local target you are authorised to test"
    ),
) -> None:
    """Scan a target. For now it only fetches the first page."""
    try:
        check_target(target, allow_remote)
    except ValueError as err:
        typer.secho(f"Refusing to scan: {err}", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    headers = {"User-Agent": "VulnHound/0.1 (learning project)"}
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers) as client:
        try:
            response = client.get(target)
        except httpx.HTTPError as err:
            typer.secho(f"Could not reach {target}: {err}", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    typer.echo(f"Status : {response.status_code}")
    typer.echo(f"Final  : {response.url}")
    typer.echo(f"Server : {response.headers.get('server', 'not disclosed')}")
    typer.echo(f"Size   : {len(response.content)} bytes")
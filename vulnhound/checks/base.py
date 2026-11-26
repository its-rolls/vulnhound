"""The contract every check must follow. The engine only ever talks to this."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from vulnhound.crawler import Page
from vulnhound.findings import Finding


@dataclass
class ScanContext:
    """Everything a check may need, handed over in one object."""
    client: httpx.Client
    base_url: str
    pages: list[Page]
    transport: httpx.BaseTransport | None = None  # only set by tests, to fake the server

    def fresh_client(self) -> httpx.Client:
        """A new client with the same settings but an EMPTY cookie jar (i.e. logged out).

        Use it inside `with`, so it is closed afterwards. It never touches the main
        client's cookies, so the logged-in session stays intact.
        """
        return httpx.Client(headers=self.client.headers, timeout=self.client.timeout,
                            follow_redirects=True, transport=self.transport)


class Check(ABC):
    id: str = ""      # short machine name, e.g. "headers"
    name: str = ""    # human name, e.g. "Missing security headers"

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Look for one kind of problem and return what was found (maybe nothing)."""
"""Find every page, URL parameter and form on a target, without leaving scope."""

import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

# Files that can't contain forms or links worth testing.
SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js",
    ".pdf", ".zip", ".woff", ".woff2", ".ttf", ".mp4",
)
# Links a crawler must never click, or it logs itself out or breaks the target.
DANGEROUS_WORDS = ("logout", "logoff", "signout", "sign-out", "delete", "remove")


@dataclass
class FormInput:
    name: str
    type: str
    value: str


@dataclass
class Form:
    page_url: str   # page the form was found on
    action: str     # URL it submits to
    method: str     # GET or POST
    inputs: list[FormInput] = field(default_factory=list)


@dataclass
class Page:
    url: str
    status: int
    params: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)


def in_scope(url: str, base_url: str) -> bool:
    """Same scheme, host and port as where we started."""
    a, b = urlparse(url), urlparse(base_url)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def is_dangerous(url: str, extra_words: tuple[str, ...] = ()) -> bool:
    return any(word in url.lower() for word in DANGEROUS_WORDS + extra_words)


def dedup_key(url: str) -> str:
    """page.php?id=1 and page.php?id=2 are the same page for testing purposes."""
    parsed = urlparse(url)
    param_names = sorted(parse_qs(parsed.query, keep_blank_values=True))
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(param_names)}"


def parse_page(page_url: str, html: str) -> tuple[list[str], list[Form]]:
    """Pull out absolute links and forms from one HTML page."""
    soup = BeautifulSoup(html, "html.parser")

    links = []
    for tag in soup.find_all("a", href=True):
        absolute, _fragment = urldefrag(urljoin(page_url, tag["href"]))
        links.append(absolute)

    forms = []
    for tag in soup.find_all("form"):
        inputs = [
            FormInput(
                name=field_tag["name"],
                type=(field_tag.get("type") or field_tag.name).lower(),
                value=field_tag.get("value", ""),
            )
            for field_tag in tag.find_all(["input", "textarea", "select"])
            if field_tag.get("name")
        ]
        forms.append(
            Form(
                page_url=page_url,
                action=urljoin(page_url, tag.get("action") or page_url),
                method=(tag.get("method") or "GET").upper(),
                inputs=inputs,
            )
        )
    return links, forms


class Crawler:
    def __init__(self, client: httpx.Client, base_url: str, max_pages: int = 100, delay: float = 0.1,
                 exclude: tuple[str, ...] = ()):
        self.client = client
        self.base_url = base_url
        self.max_pages = max_pages
        self.delay = delay
        self.exclude = exclude

    def crawl(self) -> list[Page]:
        queue = deque([self.base_url])   # breadth-first: nearest pages first
        seen = {dedup_key(self.base_url)}
        pages: list[Page] = []

        while queue and len(pages) < self.max_pages:
            url = queue.popleft()
            try:
                response = self.client.get(url)
            except httpx.HTTPError:
                continue
            time.sleep(self.delay)  # be polite: don't hammer the server

            final_url = str(response.url)
            if not in_scope(final_url, self.base_url):
                continue  # a redirect took us outside scope

            page = Page(url=final_url, status=response.status_code)
            page.params = sorted(parse_qs(urlparse(final_url).query, keep_blank_values=True))

            if "text/html" in response.headers.get("content-type", ""):
                links, page.forms = parse_page(final_url, response.text)
                for link in links:
                    key = dedup_key(link)
                    if (
                        key not in seen
                        and in_scope(link, self.base_url)
                        and not is_dangerous(link, self.exclude)
                        and not urlparse(link).path.lower().endswith(SKIP_EXTENSIONS)
                    ):
                        seen.add(key)
                        queue.append(link)

            pages.append(page)
        return pages
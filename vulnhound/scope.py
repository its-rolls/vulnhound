from urllib.parse import urlparse

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def check_target(url: str, allow_remote: bool = False) -> None:
    """Raise ValueError if we are not allowed to scan this URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("URL has no host")
    if parsed.hostname not in LOCAL_HOSTS and not allow_remote:
        raise ValueError(
            f"{parsed.hostname} is not a local address. Only scan targets you are "
            "authorised to test, and pass --i-have-permission if you are."
        )
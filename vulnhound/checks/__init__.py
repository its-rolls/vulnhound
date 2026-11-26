"""The check registry: the one place that lists which checks exist."""

from vulnhound.checks.base import Check

REGISTRY: list[type[Check]] = []


def register(cls: type[Check]) -> type[Check]:
    """Class decorator: @register puts a check into the registry."""
    REGISTRY.append(cls)
    return cls


def all_checks() -> list[Check]:
    return [cls() for cls in REGISTRY]


# Importing the modules runs their @register lines. Add new checks here.
from vulnhound.checks import headers, exposed_files, dir_listing  # noqa: E402,F401
"""What a check reports, in one shape every part of the scanner understands."""

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    # IntEnum so severities can be compared and sorted: Severity.HIGH > Severity.LOW
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    check_id: str        # which check found it, e.g. "headers"
    title: str           # one line a human understands
    severity: Severity
    url: str             # where it was found
    evidence: str        # proof: what we saw that made us report it
    remediation: str     # how to fix it
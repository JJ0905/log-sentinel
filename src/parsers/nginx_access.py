"""Parser for nginx access logs in the default "combined" format.

Example line:
    203.0.113.50 - - [12/Nov/2026:14:05:07 +0000] "GET /products?id=7 HTTP/1.1" 200 5120 "-" "curl/8.4.0"

Timestamps become naive datetimes (the log's own wall-clock time) so web
events sort alongside SSH events.
"""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, List, Optional

LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)


@dataclass(frozen=True)
class WebEvent:
    timestamp: datetime
    ip: str
    method: str
    path: str          # raw request target, still URL-encoded
    status: int
    size: int
    referer: str
    user_agent: str
    raw: str


def parse_line(line: str) -> Optional[WebEvent]:
    """Parse one access-log line. Returns None if it does not match."""
    line = line.rstrip("\n")
    m = LINE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        return None
    size = m.group("size")
    return WebEvent(
        timestamp=ts,
        ip=m.group("ip"),
        method=m.group("method"),
        path=m.group("path"),
        status=int(m.group("status")),
        size=0 if size == "-" else int(size),
        referer=m.group("referer") or "",
        user_agent=m.group("agent") or "",
        raw=line,
    )


def parse_lines(lines: Iterable[str]) -> Iterator[WebEvent]:
    for line in lines:
        event = parse_line(line)
        if event is not None:
            yield event


def parse_file(path: str) -> List[WebEvent]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return list(parse_lines(f))

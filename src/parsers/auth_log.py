"""Parser for SSH log lines in `journalctl -u ssh` (short) format.

Example line:
    Nov 03 15:09:27 log-lab sshd-session[1359]: Failed password for invalid user fakeuser from 127.0.0.1 port 47592 ssh2

Journal timestamps have no year, so the caller supplies one.
"""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, List, Optional

# Common prefix: "Nov 03 15:09:27 host proc[pid]: message"
PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w\-.]+)\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)

# Message patterns, checked in order. Each captures user / ip / port.
MESSAGE_PATTERNS = [
    ("failed_password", re.compile(
        r"^Failed password for (?P<invalid>invalid user )?(?P<user>\S+) "
        r"from (?P<ip>\S+) port (?P<port>\d+)")),
    ("accepted_login", re.compile(
        r"^Accepted (?P<method>password|publickey) for (?P<user>\S+) "
        r"from (?P<ip>\S+) port (?P<port>\d+)")),
    ("invalid_user", re.compile(
        r"^Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")),
    ("connection_closed_preauth", re.compile(
        r"^Connection closed by (?P<invalid>invalid user )?(?:authenticating user )?"
        r"(?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+) \[preauth\]")),
]


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    process: str
    pid: int
    event_type: str   # failed_password | accepted_login | invalid_user | connection_closed_preauth
    user: str
    ip: str
    port: int
    user_exists: bool  # False when sshd says "invalid user"
    raw: str


def parse_line(line: str, year: int) -> Optional[AuthEvent]:
    """Parse one log line. Returns None if it is not an event we track."""
    line = line.rstrip("\n")
    m = PREFIX.match(line)
    if not m:
        return None

    message = m.group("message")
    for event_type, pattern in MESSAGE_PATTERNS:
        mm = pattern.match(message)
        if not mm:
            continue
        groups = mm.groupdict()
        try:
            ts = datetime.strptime(
                f"{year} {m.group('month')} {m.group('day')} {m.group('time')}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            return None
        # "Invalid user X ..." lines always mean the user does not exist.
        user_exists = not (groups.get("invalid") or event_type == "invalid_user")
        return AuthEvent(
            timestamp=ts,
            host=m.group("host"),
            process=m.group("process"),
            pid=int(m.group("pid")),
            event_type=event_type,
            user=groups["user"],
            ip=groups["ip"],
            port=int(groups["port"]),
            user_exists=user_exists,
            raw=line,
        )
    return None


def parse_lines(lines: Iterable[str], year: int) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event


def parse_file(path: str, year: int) -> List[AuthEvent]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return list(parse_lines(f, year))

"""Detect successful SSH logins outside expected working hours.

A login at 3 AM is not proof of an attack, but it is a classic thing an
analyst wants to look at, especially for an account that normally works
9 to 5.

The window is configurable. It also supports overnight windows: with
work_start=22 and work_end=6, hours 22:00 through 05:59 are "expected".

Note: journal timestamps are in the server's timezone, so the hours here
are server time. Set the window to match.
"""
from typing import Iterable, List

from src.detections.brute_force import Alert
from src.parsers.auth_log import AuthEvent

RULE_NAME = "ssh_unusual_hours"


def _in_window(hour: int, start: int, end: int) -> bool:
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end  # overnight window


def detect_unusual_hours(
    events: Iterable[AuthEvent],
    work_start: int = 7,
    work_end: int = 19,
) -> List[Alert]:
    if not (0 <= work_start <= 23 and 0 <= work_end <= 24):
        raise ValueError("work_start must be 0-23 and work_end must be 0-24")
    if work_start == work_end:
        raise ValueError("work_start and work_end must be different")

    alerts: List[Alert] = []
    for event in sorted(events, key=lambda e: e.timestamp):
        if event.event_type != "accepted_login":
            continue
        if _in_window(event.timestamp.hour, work_start, work_end):
            continue
        alerts.append(Alert(
            rule=RULE_NAME,
            severity="medium",
            ip=event.ip,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            count=1,
            users=(event.user,),
            description=(
                f"Login for '{event.user}' from {event.ip} at "
                f"{event.timestamp.strftime('%H:%M:%S')}, outside expected hours "
                f"({work_start:02d}:00-{work_end:02d}:00)."
            ),
        ))
    return alerts

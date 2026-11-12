"""Detect a successful login that follows repeated failures.

A brute-force attempt that FAILS is noise. One that eventually SUCCEEDS
means someone now has valid access, which is when an analyst must look.

How it works:
  - Walk events in time order, tracking recent failed logins per
    (source IP, username) pair.
  - On a successful login, count that pair's failures inside the lookback
    window. If there are `min_failures` or more, raise an alert.
  - After any success, clear that pair's failures so a second quick login
    does not re-alert on the same attempts.
"""
from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable, List

from src.detections.brute_force import Alert
from src.parsers.auth_log import AuthEvent

RULE_NAME = "ssh_success_after_failures"


def detect_success_after_failures(
    events: Iterable[AuthEvent],
    min_failures: int = 3,
    window_seconds: int = 300,
) -> List[Alert]:
    window = timedelta(seconds=window_seconds)
    recent_failures = defaultdict(deque)  # (ip, user) -> failure timestamps
    alerts: List[Alert] = []

    for event in sorted(events, key=lambda e: e.timestamp):
        key = (event.ip, event.user)

        if event.event_type == "failed_password":
            recent_failures[key].append(event.timestamp)

        elif event.event_type == "accepted_login":
            failures = recent_failures[key]
            while failures and event.timestamp - failures[0] > window:
                failures.popleft()

            if len(failures) >= min_failures:
                alerts.append(Alert(
                    rule=RULE_NAME,
                    severity="high",
                    ip=event.ip,
                    first_seen=failures[0],
                    last_seen=event.timestamp,
                    count=len(failures),
                    users=(event.user,),
                    description=(
                        f"Successful login for '{event.user}' from {event.ip} at "
                        f"{event.timestamp.strftime('%H:%M:%S')} after {len(failures)} "
                        f"failed attempts in the previous {window_seconds}s. "
                        f"Possible compromised credentials."
                    ),
                ))
            failures.clear()

    return alerts

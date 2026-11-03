"""Brute-force detection: N failed SSH logins from one IP within a time window.

How it works:
  1. Keep only failed-password events and group them by source IP.
  2. Slide a time window over each IP's failures (oldest first).
  3. When the window holds `threshold` or more failures, open an alert.
  4. Keep extending that alert while failures keep arriving within
     `window_seconds` of each other, so one sustained attack = one alert,
     not dozens.
"""
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List, Tuple

from src.parsers.auth_log import AuthEvent

RULE_NAME = "ssh_brute_force"


@dataclass
class Alert:
    rule: str
    severity: str
    ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    users: Tuple[str, ...]
    description: str


def _build_alert(ip: str, state: dict, threshold: int, window_seconds: int) -> Alert:
    users = tuple(sorted(state["users"]))
    severity = "high" if state["count"] >= threshold * 2 else "medium"
    description = (
        f"{state['count']} failed SSH logins from {ip} between "
        f"{state['first'].strftime('%H:%M:%S')} and {state['last'].strftime('%H:%M:%S')} "
        f"(rule: {threshold}+ failures within {window_seconds}s). "
        f"Targeted users: {', '.join(users)}."
    )
    return Alert(
        rule=RULE_NAME,
        severity=severity,
        ip=ip,
        first_seen=state["first"],
        last_seen=state["last"],
        count=state["count"],
        users=users,
        description=description,
    )


def detect_brute_force(
    events: Iterable[AuthEvent],
    threshold: int = 5,
    window_seconds: int = 60,
) -> List[Alert]:
    """Return one Alert per sustained burst of failed logins from a single IP."""
    window = timedelta(seconds=window_seconds)

    failures_by_ip = defaultdict(list)
    for event in events:
        if event.event_type == "failed_password":
            failures_by_ip[event.ip].append(event)

    alerts: List[Alert] = []
    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: e.timestamp)
        recent = deque()
        active = None  # the alert currently being extended, if any

        for event in failures:
            recent.append(event)
            while event.timestamp - recent[0].timestamp > window:
                recent.popleft()

            # Still inside an ongoing attack: extend it.
            if active and event.timestamp - active["last"] <= window:
                active["last"] = event.timestamp
                active["count"] += 1
                active["users"].add(event.user)
                continue

            # Gap was too long: the previous attack is over, so close it.
            if active:
                alerts.append(_build_alert(ip, active, threshold, window_seconds))
                active = None

            # Enough failures inside one window: open a new alert.
            if len(recent) >= threshold:
                active = {
                    "first": recent[0].timestamp,
                    "last": event.timestamp,
                    "count": len(recent),
                    "users": {e.user for e in recent},
                }

        if active:
            alerts.append(_build_alert(ip, active, threshold, window_seconds))

    alerts.sort(key=lambda a: a.first_seen)
    return alerts

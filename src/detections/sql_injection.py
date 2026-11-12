"""Detect SQL injection attempts in web access logs.

Approach: URL-decode each request target (twice, to catch double encoding),
then match it against patterns for well-known SQL injection techniques.
Suspicious requests from one IP, less than `window_seconds` apart, are
merged into a single alert.

Limits: this only sees the URL. Injection in POST bodies never shows up in
an access log, and a determined attacker can obfuscate past simple patterns.
"""
import re
from collections import defaultdict
from datetime import timedelta
from typing import Iterable, List
from urllib.parse import unquote_plus

from src.detections.brute_force import Alert
from src.parsers.nginx_access import WebEvent

RULE_NAME = "web_sql_injection"

PATTERNS = {
    "union_select": re.compile(r"\bunion\b(?:\s|/\*.*?\*/)+(?:all\s+)?select\b"),
    "tautology": re.compile(
        r"['\"]\s*or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|\b(?:or|and)\s+\d+\s*=\s*\d+"),
    "quote_comment": re.compile(r"['\"]\s*(?:--|#|/\*)"),
    "time_based": re.compile(r"\b(?:sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay"),
    "stacked_query": re.compile(r";\s*(?:drop|insert|update|delete|alter|create)\s"),
    "schema_probe": re.compile(r"information_schema|sqlite_master"),
    "file_access": re.compile(r"load_file\s*\(|into\s+(?:out|dump)file"),
}


def _decode(path: str) -> str:
    """URL-decode up to twice (attackers sometimes double-encode), lowercased."""
    text = path
    for _ in range(2):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text.lower()


def classify(path: str) -> List[str]:
    """Return the names of every SQL injection technique found in a request."""
    text = _decode(path)
    return [name for name, rx in PATTERNS.items() if rx.search(text)]


def _printable(text: str, limit: int = 80) -> str:
    """Make attacker-controlled text safe to print (no terminal escape codes)."""
    clean = "".join(c if c.isprintable() else "?" for c in text)
    return clean[:limit]


def _build_alert(ip: str, burst: list) -> Alert:
    techniques = sorted({t for _, found in burst for t in found})
    succeeded = sum(1 for event, _ in burst if 200 <= event.status < 300)
    first, last = burst[0][0], burst[-1][0]
    description = (
        f"{len(burst)} suspicious web request(s) from {ip} between "
        f"{first.timestamp.strftime('%H:%M:%S')} and {last.timestamp.strftime('%H:%M:%S')}. "
        f"Techniques: {', '.join(techniques)}. {succeeded} returned HTTP 2xx. "
        f"Example: {_printable(first.path)}"
    )
    return Alert(
        rule=RULE_NAME,
        severity="high" if succeeded else "medium",
        ip=ip,
        first_seen=first.timestamp,
        last_seen=last.timestamp,
        count=len(burst),
        users=(),
        description=description,
    )


def detect_sql_injection(events: Iterable[WebEvent], window_seconds: int = 300) -> List[Alert]:
    """One alert per burst of SQL injection attempts from a single IP."""
    window = timedelta(seconds=window_seconds)

    hits_by_ip = defaultdict(list)
    for event in events:
        found = classify(event.path)
        if found:
            hits_by_ip[event.ip].append((event, found))

    alerts: List[Alert] = []
    for ip, hits in hits_by_ip.items():
        hits.sort(key=lambda h: h[0].timestamp)
        burst = [hits[0]]
        for hit in hits[1:]:
            if hit[0].timestamp - burst[-1][0].timestamp <= window:
                burst.append(hit)
            else:
                alerts.append(_build_alert(ip, burst))
                burst = [hit]
        alerts.append(_build_alert(ip, burst))

    alerts.sort(key=lambda a: a.first_seen)
    return alerts

"""Summaries of alerts: a plain-text CLI summary and a standalone HTML report.

Alert fields (usernames, request paths) come from log files, so an attacker
controls them. Everything is cleaned or HTML-escaped before it is shown.
"""
import html
from collections import Counter
from typing import Iterable, List

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
KNOWN_SEVERITIES = set(SEVERITY_ORDER)


def clean(text: str, limit: int = 300) -> str:
    """Replace non-printable characters (such as terminal escape codes)."""
    return "".join(c if c.isprintable() else "?" for c in str(text))[:limit]


def _severity_sort_key(severity: str):
    if severity in SEVERITY_ORDER:
        return (SEVERITY_ORDER.index(severity), severity)
    return (len(SEVERITY_ORDER), severity)


def summary_text(alerts: Iterable) -> str:
    alerts = list(alerts)
    if not alerts:
        return "No alerts."

    by_severity = Counter(a.severity for a in alerts)
    by_rule = Counter(a.rule for a in alerts)
    by_ip = Counter(a.ip for a in alerts)

    severities = sorted(by_severity, key=_severity_sort_key)
    lines: List[str] = [
        f"Total alerts: {len(alerts)}",
        "By severity: " + ", ".join(f"{clean(s)}={by_severity[s]}" for s in severities),
        "By rule:",
    ]
    for rule, n in by_rule.most_common():
        lines.append(f"  {clean(rule)}: {n}")
    lines.append("Top source IPs:")
    for ip, n in by_ip.most_common(5):
        lines.append(f"  {clean(ip)}: {n} alert(s)")
    return "\n".join(lines)


CSS = """
body { font-family: -apple-system, system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
h1 { margin-bottom: 0.25rem; }
.cards { display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }
.card { border: 1px solid #ccc; border-radius: 8px; padding: 0.75rem 1.25rem; }
.card b { display: block; font-size: 1.8rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
th, td { border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f3f3f3; }
.sev { font-weight: 600; text-transform: uppercase; }
.sev-critical, .sev-high { color: #b00020; }
.sev-medium { color: #b26a00; }
.sev-low, .sev-other { color: #555; }
.wrap { word-break: break-word; }
"""


def html_report(alerts: Iterable, title: str = "log-sentinel report") -> str:
    alerts = list(alerts)
    esc = html.escape

    by_severity = Counter(a.severity for a in alerts)
    cards = [f'<div class="card"><b>{len(alerts)}</b>total alerts</div>']
    for severity in sorted(by_severity, key=_severity_sort_key):
        cards.append(
            f'<div class="card"><b>{by_severity[severity]}</b>{esc(clean(severity))}</div>')

    if alerts:
        rows = []
        for a in alerts:
            sev_class = a.severity if a.severity in KNOWN_SEVERITIES else "other"
            rows.append(
                "<tr>"
                f'<td class="sev sev-{sev_class}">{esc(clean(a.severity))}</td>'
                f"<td>{esc(clean(a.rule))}</td>"
                f"<td>{esc(clean(a.ip))}</td>"
                f"<td>{esc(a.first_seen.isoformat(sep=' '))}</td>"
                f"<td>{esc(a.last_seen.isoformat(sep=' '))}</td>"
                f"<td>{a.count}</td>"
                f"<td>{esc(clean(', '.join(a.users)))}</td>"
                f'<td class="wrap">{esc(clean(a.description))}</td>'
                "</tr>"
            )
        table = (
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Source IP</th>"
            "<th>First seen</th><th>Last seen</th><th>Count</th><th>Users</th>"
            "<th>Description</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    else:
        table = "<p>No alerts.</p>"

    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{esc(title)}</title><style>{CSS}</style></head><body>"
        f"<h1>{esc(title)}</h1>"
        f'<div class="cards">{"".join(cards)}</div>{table}</body></html>\n'
    )

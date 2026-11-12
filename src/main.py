"""Command-line entry point.

Examples:
    python3 -m src.main sample_logs/ssh_journal_sample.log --year 2026 --threshold 3
    python3 -m src.main --web-log sample_logs/nginx_access_sample.log
"""
import argparse
from datetime import datetime

from src import storage
from src.detections.brute_force import detect_brute_force
from src.detections.sql_injection import detect_sql_injection
from src.detections.success_after_failures import detect_success_after_failures
from src.parsers.auth_log import parse_file
from src.parsers.nginx_access import parse_file as parse_web_file


def main() -> None:
    parser = argparse.ArgumentParser(description="log-sentinel: SSH and web log analysis")
    parser.add_argument("logfile", nargs="?",
                        help="path to a journalctl-format SSH log")
    parser.add_argument("--web-log", help="path to an nginx access log (combined format)")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year of the SSH log (journal timestamps omit it)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed logins that trigger an alert (default 5)")
    parser.add_argument("--window", type=int, default=60,
                        help="time window in seconds (default 60)")
    parser.add_argument("--min-failures", type=int, default=3,
                        help="failures before a success that count as suspicious (default 3)")
    parser.add_argument("--success-window", type=int, default=300,
                        help="lookback in seconds for failures before a success (default 300)")
    parser.add_argument("--web-window", type=int, default=300,
                        help="seconds between web requests that still count as one attack (default 300)")
    parser.add_argument("--db", default="alerts.db", help="SQLite file for alerts")
    args = parser.parse_args()

    if not args.logfile and not args.web_log:
        parser.error("provide an SSH log, a --web-log, or both")

    alerts = []
    ssh_events = []
    web_events = []

    if args.logfile:
        ssh_events = parse_file(args.logfile, args.year)
        alerts += detect_brute_force(ssh_events, args.threshold, args.window)
        alerts += detect_success_after_failures(ssh_events, args.min_failures, args.success_window)

    if args.web_log:
        web_events = parse_web_file(args.web_log)
        alerts += detect_sql_injection(web_events, args.web_window)

    alerts.sort(key=lambda a: a.first_seen)

    conn = storage.connect(args.db)
    new = storage.save_alerts(conn, alerts)

    print(f"Parsed {len(ssh_events)} SSH events and {len(web_events)} web requests, "
          f"raised {len(alerts)} alert(s), {new} new.")
    for a in alerts:
        print(f"  [{a.severity.upper()}] {a.description}")


if __name__ == "__main__":
    main()

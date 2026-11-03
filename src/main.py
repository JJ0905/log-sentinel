"""Command-line entry point.

Example:
    python3 -m src.main sample_logs/ssh_journal_sample.log --year 2026 --threshold 3
"""
import argparse
from datetime import datetime

from src import storage
from src.detections.brute_force import detect_brute_force
from src.parsers.auth_log import parse_file


def main() -> None:
    parser = argparse.ArgumentParser(description="log-sentinel: SSH log analysis")
    parser.add_argument("logfile", help="path to a journalctl-format SSH log")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year of the log (journal timestamps omit it)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed logins that trigger an alert (default 5)")
    parser.add_argument("--window", type=int, default=60,
                        help="time window in seconds (default 60)")
    parser.add_argument("--db", default="alerts.db", help="SQLite file for alerts")
    args = parser.parse_args()

    events = parse_file(args.logfile, args.year)
    alerts = detect_brute_force(events, args.threshold, args.window)

    conn = storage.connect(args.db)
    new = storage.save_alerts(conn, alerts)

    print(f"Parsed {len(events)} events, raised {len(alerts)} alert(s), {new} new.")
    for a in alerts:
        print(f"  [{a.severity.upper()}] {a.description}")


if __name__ == "__main__":
    main()

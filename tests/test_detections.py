import unittest
from datetime import datetime, timedelta
from pathlib import Path

from src import storage
from src.detections.brute_force import detect_brute_force
from src.parsers.auth_log import AuthEvent, parse_file

SAMPLE = Path(__file__).parent.parent / "sample_logs" / "ssh_journal_sample.log"
BASE = datetime(2026, 11, 3, 12, 0, 0)


def failed(seconds, ip="10.0.0.5", user="root"):
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=seconds), host="h", process="sshd",
        pid=1, event_type="failed_password", user=user, ip=ip, port=1,
        user_exists=True, raw="",
    )


class TestBruteForce(unittest.TestCase):
    def test_below_threshold_no_alert(self):
        events = [failed(s) for s in (0, 10, 20, 30)]  # 4 failures
        self.assertEqual(detect_brute_force(events, threshold=5, window_seconds=60), [])

    def test_at_threshold_raises_alert(self):
        events = [failed(s) for s in (0, 10, 20, 30, 40)]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].ip, "10.0.0.5")
        self.assertEqual(alerts[0].count, 5)
        self.assertEqual(alerts[0].rule, "ssh_brute_force")

    def test_slow_attempts_do_not_alert(self):
        # 5 failures, but never 5 inside any single 60-second window.
        events = [failed(s) for s in (0, 20, 40, 60, 80)]
        self.assertEqual(detect_brute_force(events, threshold=5, window_seconds=60), [])

    def test_sustained_attack_is_one_alert(self):
        events = [failed(s) for s in (0, 10, 20, 30, 40, 70)]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 6)

    def test_separate_attacks_are_separate_alerts(self):
        first = [failed(s) for s in (0, 5, 10, 15, 20)]
        second = [failed(s) for s in (500, 505, 510, 515, 520)]
        alerts = detect_brute_force(first + second, threshold=5, window_seconds=60)
        self.assertEqual(len(alerts), 2)

    def test_ips_are_tracked_separately(self):
        events = [failed(s, ip="1.1.1.1") for s in (0, 5, 10, 15, 20)]
        events += [failed(s, ip="2.2.2.2") for s in (0, 5)]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        self.assertEqual([a.ip for a in alerts], ["1.1.1.1"])

    def test_non_failed_events_are_ignored(self):
        ok = AuthEvent(BASE, "h", "sshd", 1, "accepted_login", "root",
                       "10.0.0.5", 1, True, "")
        self.assertEqual(detect_brute_force([ok] * 10, threshold=5), [])

    def test_high_severity_for_large_bursts(self):
        events = [failed(s) for s in range(0, 10)]  # 10 failures = 2x threshold
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        self.assertEqual(alerts[0].severity, "high")

    def test_real_lab_log(self):
        events = parse_file(str(SAMPLE), 2026)
        # Real lab data: 9 failures in short bursts, never 5 within 60 seconds.
        self.assertEqual(detect_brute_force(events, threshold=5, window_seconds=60), [])
        alerts = detect_brute_force(events, threshold=3, window_seconds=60)
        self.assertEqual([a.count for a in alerts], [3, 6])
        self.assertEqual(alerts[1].users, ("fakeuser", "junior"))


class TestStorage(unittest.TestCase):
    def setUp(self):
        events = [failed(s) for s in (0, 10, 20, 30, 40)]
        self.alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        self.conn = storage.connect(":memory:")

    def test_save_and_list(self):
        self.assertEqual(storage.save_alerts(self.conn, self.alerts), 1)
        rows = storage.list_alerts(self.conn)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "10.0.0.5")
        self.assertEqual(rows[0]["count"], 5)

    def test_rerun_does_not_duplicate(self):
        storage.save_alerts(self.conn, self.alerts)
        self.assertEqual(storage.save_alerts(self.conn, self.alerts), 0)
        self.assertEqual(len(storage.list_alerts(self.conn)), 1)

    def test_filter_by_severity(self):
        storage.save_alerts(self.conn, self.alerts)
        self.assertEqual(len(storage.list_alerts(self.conn, severity="medium")), 1)
        self.assertEqual(storage.list_alerts(self.conn, severity="high"), [])

    def test_hostile_username_is_stored_safely(self):
        # A username that looks like SQL must be stored as plain text.
        evil = "x'); DROP TABLE alerts;--"
        events = [failed(s, user=evil) for s in (0, 5, 10, 15, 20)]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        storage.save_alerts(self.conn, alerts)
        rows = storage.list_alerts(self.conn)
        self.assertEqual(len(rows), 1)
        self.assertIn("DROP TABLE", rows[0]["users"])


if __name__ == "__main__":
    unittest.main()

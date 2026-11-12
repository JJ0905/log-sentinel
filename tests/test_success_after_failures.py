import unittest
from datetime import datetime, timedelta
from pathlib import Path

from src.detections.success_after_failures import detect_success_after_failures
from src.parsers.auth_log import AuthEvent, parse_file

SAMPLE = Path(__file__).parent.parent / "sample_logs" / "ssh_journal_sample.log"
BASE = datetime(2026, 11, 3, 12, 0, 0)


def event(kind, seconds, ip="10.0.0.5", user="alice"):
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=seconds), host="h", process="sshd",
        pid=1, event_type=kind, user=user, ip=ip, port=1, user_exists=True, raw="",
    )


def fails(*seconds, **kw):
    return [event("failed_password", s, **kw) for s in seconds]


def success(seconds, **kw):
    return event("accepted_login", seconds, **kw)


class TestSuccessAfterFailures(unittest.TestCase):
    def test_success_after_enough_failures_alerts(self):
        events = fails(0, 10, 20) + [success(30)]
        alerts = detect_success_after_failures(events, min_failures=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule, "ssh_success_after_failures")
        self.assertEqual(alerts[0].severity, "high")
        self.assertEqual(alerts[0].count, 3)
        self.assertEqual(alerts[0].users, ("alice",))
        self.assertEqual(alerts[0].last_seen, BASE + timedelta(seconds=30))

    def test_too_few_failures_no_alert(self):
        events = fails(0, 10) + [success(30)]
        self.assertEqual(detect_success_after_failures(events, min_failures=3), [])

    def test_success_with_no_failures_no_alert(self):
        self.assertEqual(detect_success_after_failures([success(5)]), [])

    def test_old_failures_outside_window_ignored(self):
        events = fails(0, 10, 20) + [success(1000)]
        self.assertEqual(
            detect_success_after_failures(events, min_failures=3, window_seconds=300), [])

    def test_failures_for_other_user_do_not_count(self):
        events = fails(0, 10, 20, user="bob") + [success(30, user="alice")]
        self.assertEqual(detect_success_after_failures(events, min_failures=3), [])

    def test_failures_from_other_ip_do_not_count(self):
        events = fails(0, 10, 20, ip="9.9.9.9") + [success(30, ip="10.0.0.5")]
        self.assertEqual(detect_success_after_failures(events, min_failures=3), [])

    def test_failures_after_success_do_not_count(self):
        events = [success(0)] + fails(10, 20, 30)
        self.assertEqual(detect_success_after_failures(events, min_failures=3), [])

    def test_second_login_does_not_realert(self):
        events = fails(0, 10, 20) + [success(30), success(40)]
        self.assertEqual(len(detect_success_after_failures(events, min_failures=3)), 1)

    def test_unsorted_input_is_handled(self):
        events = [success(30)] + fails(20, 10, 0)
        self.assertEqual(len(detect_success_after_failures(events, min_failures=3)), 1)

    def test_real_lab_log(self):
        events = parse_file(str(SAMPLE), 2026)
        alerts = detect_success_after_failures(events, min_failures=3, window_seconds=300)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].users, ("junior",))
        self.assertEqual(alerts[0].count, 3)
        self.assertEqual(alerts[0].first_seen, datetime(2026, 11, 3, 15, 12, 20))
        self.assertEqual(alerts[0].last_seen, datetime(2026, 11, 3, 15, 13, 18))


if __name__ == "__main__":
    unittest.main()

import unittest
from datetime import datetime
from pathlib import Path

from src.detections.brute_force import Alert
from src.detections.unusual_hours import detect_unusual_hours
from src.parsers.auth_log import AuthEvent, parse_file
from src.report import clean, html_report, summary_text

SAMPLE = Path(__file__).parent.parent / "sample_logs" / "ssh_journal_sample.log"


def login(hour, minute=0, kind="accepted_login", user="alice", ip="10.0.0.5"):
    return AuthEvent(
        timestamp=datetime(2026, 11, 3, hour, minute, 0), host="h", process="sshd",
        pid=1, event_type=kind, user=user, ip=ip, port=1, user_exists=True, raw="",
    )


def alert(severity="high", rule="r1", ip="1.1.1.1", users=("bob",),
          description="something happened"):
    return Alert(rule=rule, severity=severity, ip=ip,
                 first_seen=datetime(2026, 11, 3, 12, 0, 0),
                 last_seen=datetime(2026, 11, 3, 12, 5, 0),
                 count=2, users=users, description=description)


class TestUnusualHours(unittest.TestCase):
    def test_night_login_alerts(self):
        alerts = detect_unusual_hours([login(3)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule, "ssh_unusual_hours")
        self.assertEqual(alerts[0].users, ("alice",))

    def test_daytime_login_ok(self):
        self.assertEqual(detect_unusual_hours([login(10)]), [])

    def test_window_boundaries(self):
        self.assertEqual(detect_unusual_hours([login(7, 0)]), [])         # start is inside
        self.assertEqual(len(detect_unusual_hours([login(19, 0)])), 1)    # end is outside
        self.assertEqual(detect_unusual_hours([login(18, 59)]), [])

    def test_failed_logins_are_ignored(self):
        self.assertEqual(detect_unusual_hours([login(3, kind="failed_password")]), [])

    def test_overnight_window(self):
        events = [login(23), login(2), login(12)]
        alerts = detect_unusual_hours(events, work_start=22, work_end=6)
        self.assertEqual([a.first_seen.hour for a in alerts], [12])

    def test_invalid_window_raises(self):
        with self.assertRaises(ValueError):
            detect_unusual_hours([], work_start=9, work_end=9)
        with self.assertRaises(ValueError):
            detect_unusual_hours([], work_start=25, work_end=5)

    def test_alerts_are_sorted_by_time(self):
        alerts = detect_unusual_hours([login(23), login(2)])
        self.assertEqual([a.first_seen.hour for a in alerts], [2, 23])

    def test_real_lab_log(self):
        events = parse_file(str(SAMPLE), 2026)
        # The one real login is at 15:13 server time.
        self.assertEqual(detect_unusual_hours(events), [])
        alerts = detect_unusual_hours(events, work_start=9, work_end=15)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].users, ("junior",))


class TestSummary(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(summary_text([]), "No alerts.")

    def test_counts(self):
        alerts = [alert("high", "r1", "1.1.1.1"), alert("high", "r1", "1.1.1.1"),
                  alert("medium", "r2", "2.2.2.2")]
        text = summary_text(alerts)
        self.assertIn("Total alerts: 3", text)
        self.assertIn("high=2, medium=1", text)
        self.assertIn("r1: 2", text)
        self.assertIn("1.1.1.1: 2 alert(s)", text)

    def test_severity_order_is_stable(self):
        alerts = [alert("low"), alert("high"), alert("medium")]
        self.assertIn("high=1, medium=1, low=1", summary_text(alerts))

    def test_clean_strips_control_characters(self):
        self.assertNotIn("\x1b", clean("bad\x1b[2Jtext"))
        self.assertEqual(clean("normal text"), "normal text")


class TestHtmlReport(unittest.TestCase):
    def test_contains_alert_data(self):
        page = html_report([alert(ip="9.9.9.9", description="three failures")])
        self.assertIn("9.9.9.9", page)
        self.assertIn("three failures", page)
        self.assertIn("<table>", page)

    def test_empty_report(self):
        self.assertIn("No alerts.", html_report([]))

    def test_hostile_content_is_escaped(self):
        evil = '<script>alert("xss")</script>'
        page = html_report([alert(users=(evil,), description=evil, ip=evil, rule=evil,
                                  severity=evil)])
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_has_content_security_policy_and_no_external_resources(self):
        page = html_report([alert()])
        self.assertIn("Content-Security-Policy", page)
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)

    def test_unknown_severity_cannot_inject_css_class(self):
        page = html_report([alert(severity='x" onmouseover="evil()')])
        self.assertIn("sev-other", page)
        self.assertNotIn('onmouseover="evil()"', page)


if __name__ == "__main__":
    unittest.main()

import unittest
from datetime import datetime
from pathlib import Path

from src.parsers.auth_log import parse_file, parse_line

SAMPLE = Path(__file__).parent.parent / "sample_logs" / "ssh_journal_sample.log"


class TestAuthLogParser(unittest.TestCase):
    def test_failed_password_invalid_user(self):
        line = ("Nov 03 15:09:27 log-lab sshd-session[1359]: Failed password for "
                "invalid user fakeuser from 127.0.0.1 port 47592 ssh2")
        e = parse_line(line, 2026)
        self.assertEqual(e.event_type, "failed_password")
        self.assertEqual(e.user, "fakeuser")
        self.assertFalse(e.user_exists)
        self.assertEqual(e.ip, "127.0.0.1")
        self.assertEqual(e.port, 47592)
        self.assertEqual(e.pid, 1359)
        self.assertEqual(e.timestamp, datetime(2026, 11, 3, 15, 9, 27))

    def test_failed_password_real_user(self):
        line = ("Nov 03 15:12:20 log-lab sshd-session[1393]: Failed password for "
                "junior from 127.0.0.1 port 56064 ssh2")
        e = parse_line(line, 2026)
        self.assertEqual(e.event_type, "failed_password")
        self.assertEqual(e.user, "junior")
        self.assertTrue(e.user_exists)

    def test_invalid_user_line(self):
        line = "Nov 03 15:08:54 log-lab sshd-session[1359]: Invalid user fakeuser from 127.0.0.1 port 47592"
        e = parse_line(line, 2026)
        self.assertEqual(e.event_type, "invalid_user")
        self.assertFalse(e.user_exists)

    def test_connection_closed_preauth(self):
        line = ("Nov 03 15:09:49 log-lab sshd-session[1359]: Connection closed by "
                "invalid user fakeuser 127.0.0.1 port 47592 [preauth]")
        e = parse_line(line, 2026)
        self.assertEqual(e.event_type, "connection_closed_preauth")
        self.assertEqual(e.user, "fakeuser")
        self.assertFalse(e.user_exists)

    def test_accepted_login_synthetic(self):
        # Synthetic line in standard sshd format; replace with a real one from your VM.
        line = "Nov 03 15:14:02 log-lab sshd-session[1401]: Accepted password for junior from 127.0.0.1 port 56070 ssh2"
        e = parse_line(line, 2026)
        self.assertEqual(e.event_type, "accepted_login")
        self.assertEqual(e.user, "junior")

    def test_irrelevant_and_garbage_lines_return_none(self):
        self.assertIsNone(parse_line("", 2026))
        self.assertIsNone(parse_line("not a log line at all", 2026))
        self.assertIsNone(parse_line(
            "Nov 03 15:00:00 log-lab sshd[1]: Server listening on 0.0.0.0 port 22.", 2026))

    def test_sample_file_counts(self):
        events = parse_file(str(SAMPLE), 2026)
        self.assertEqual(len(events), 13)
        self.assertEqual(sum(e.event_type == "failed_password" for e in events), 9)
        self.assertEqual(sum(e.event_type == "invalid_user" for e in events), 2)
        self.assertEqual(sum(e.event_type == "connection_closed_preauth" for e in events), 2)


if __name__ == "__main__":
    unittest.main()

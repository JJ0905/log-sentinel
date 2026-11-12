import unittest
from datetime import datetime, timedelta
from pathlib import Path

from src import storage
from src.detections.sql_injection import classify, detect_sql_injection
from src.parsers.nginx_access import WebEvent, parse_file, parse_line

SAMPLE = Path(__file__).parent.parent / "sample_logs" / "nginx_access_sample.log"
BASE = datetime(2026, 11, 12, 14, 0, 0)

LINE = ('203.0.113.50 - - [12/Nov/2026:14:05:07 +0000] "GET /products?id=7 HTTP/1.1" '
        '200 5120 "http://shop.local/" "curl/8.4.0"')


def hit(seconds, path, ip="203.0.113.50", status=200):
    return WebEvent(BASE + timedelta(seconds=seconds), ip, "GET", path, status,
                    0, "", "", "")


class TestNginxParser(unittest.TestCase):
    def test_parses_all_fields(self):
        e = parse_line(LINE)
        self.assertEqual(e.ip, "203.0.113.50")
        self.assertEqual(e.method, "GET")
        self.assertEqual(e.path, "/products?id=7")
        self.assertEqual(e.status, 200)
        self.assertEqual(e.size, 5120)
        self.assertEqual(e.referer, "http://shop.local/")
        self.assertEqual(e.user_agent, "curl/8.4.0")
        self.assertEqual(e.timestamp, datetime(2026, 11, 12, 14, 5, 7))
        self.assertIsNone(e.timestamp.tzinfo)

    def test_dash_size_becomes_zero(self):
        line = '10.0.0.1 - - [12/Nov/2026:14:05:07 +0000] "GET / HTTP/1.1" 304 - "-" "x"'
        self.assertEqual(parse_line(line).size, 0)

    def test_common_format_without_referer_or_agent(self):
        line = '10.0.0.1 - - [12/Nov/2026:14:05:07 +0000] "GET / HTTP/1.1" 200 12'
        e = parse_line(line)
        self.assertEqual(e.user_agent, "")

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("not a log line"))
        self.assertIsNone(parse_line('1.2.3.4 - - [bad date] "GET / HTTP/1.1" 200 1'))


class TestClassify(unittest.TestCase):
    def test_union_select(self):
        self.assertIn("union_select", classify("/p?id=7%20UNION%20SELECT%20a,b%20FROM%20users"))

    def test_union_select_with_comment_padding(self):
        self.assertIn("union_select", classify("/p?id=7%20UNION/**/SELECT%20a"))

    def test_tautology_with_quotes(self):
        self.assertIn("tautology", classify("/p?id=7%27%20OR%20%271%27%3D%271"))

    def test_tautology_numeric(self):
        self.assertIn("tautology", classify("/p?id=7%20AND%201%3D1"))

    def test_quote_comment(self):
        self.assertIn("quote_comment", classify("/login?user=admin%27--"))

    def test_time_based(self):
        self.assertIn("time_based", classify("/p?id=7%20AND%20SLEEP(5)--"))

    def test_stacked_query(self):
        self.assertIn("stacked_query", classify("/p?id=1;%20DROP%20TABLE%20users"))

    def test_schema_probe(self):
        self.assertIn("schema_probe", classify("/p?q=information_schema.tables"))

    def test_double_encoding_is_decoded(self):
        # %2527 decodes to %27, which decodes to a quote.
        self.assertIn("quote_comment", classify("/login?user=admin%2527--"))

    def test_mixed_case_is_caught(self):
        self.assertIn("union_select", classify("/p?id=7%20uNiOn%20sElEcT%20a"))

    def test_benign_requests_not_flagged(self):
        for path in ("/", "/about", "/products?id=7", "/search?q=blue+shirt",
                     "/search?q=they%27re+great", "/p?id=7%27"):
            self.assertEqual(classify(path), [], path)


class TestDetector(unittest.TestCase):
    def test_burst_is_one_alert(self):
        events = [hit(0, "/p?id=1%20AND%201%3D1"), hit(10, "/p?id=1%20AND%20SLEEP(5)")]
        alerts = detect_sql_injection(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 2)
        self.assertEqual(alerts[0].rule, "web_sql_injection")

    def test_distant_attempts_are_separate_alerts(self):
        events = [hit(0, "/p?id=1%20AND%201%3D1"), hit(5000, "/p?id=1%20AND%201%3D1")]
        self.assertEqual(len(detect_sql_injection(events, window_seconds=300)), 2)

    def test_ips_are_tracked_separately(self):
        events = [hit(0, "/p?id=1%20AND%201%3D1", ip="1.1.1.1"),
                  hit(1, "/p?id=1%20AND%201%3D1", ip="2.2.2.2")]
        self.assertEqual(sorted(a.ip for a in detect_sql_injection(events)), ["1.1.1.1", "2.2.2.2"])

    def test_severity_high_when_a_request_succeeded(self):
        events = [hit(0, "/p?id=1%20AND%201%3D1", status=200)]
        self.assertEqual(detect_sql_injection(events)[0].severity, "high")

    def test_severity_medium_when_all_requests_failed(self):
        events = [hit(0, "/p?id=1%20AND%201%3D1", status=403)]
        self.assertEqual(detect_sql_injection(events)[0].severity, "medium")

    def test_clean_traffic_raises_nothing(self):
        events = [hit(0, "/"), hit(1, "/products?id=7"), hit(2, "/search?q=shoes")]
        self.assertEqual(detect_sql_injection(events), [])

    def test_description_strips_control_characters(self):
        # Log content is attacker-controlled; terminal escape codes must not survive.
        events = [hit(0, "/p?id=1 or 1=1\x1b[2J")]
        description = detect_sql_injection(events)[0].description
        self.assertNotIn("\x1b", description)

    def test_sample_log(self):
        events = parse_file(str(SAMPLE))
        self.assertEqual(len(events), 9)
        alerts = detect_sql_injection(events)
        self.assertEqual([a.ip for a in alerts], ["203.0.113.50", "198.51.100.9"])
        self.assertEqual([a.count for a in alerts], [3, 1])
        self.assertEqual([a.severity for a in alerts], ["high", "medium"])

    def test_web_alert_can_be_stored(self):
        alerts = detect_sql_injection(parse_file(str(SAMPLE)))
        conn = storage.connect(":memory:")
        self.assertEqual(storage.save_alerts(conn, alerts), 2)
        self.assertEqual(len(storage.list_alerts(conn)), 2)


if __name__ == "__main__":
    unittest.main()

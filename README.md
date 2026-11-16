# log-sentinel

A small log analysis tool in Python. It parses SSH logs and nginx web logs, runs detection rules against them, and stores the alerts in SQLite. It can print a summary and write a standalone HTML report.

I built it while studying Information Technology at Northeastern, as a hands-on way to learn how SOC detection logic works: raw logs in, structured events, rules, alerts out.

## What it does

- **Parses** SSH logs from `journalctl -u ssh` and nginx access logs (combined format) into structured events.
- **Detects SSH brute force:** N failed logins from one IP within a time window. A sustained attack raises one alert instead of dozens.
- **Detects success after failures:** a successful login that follows repeated failures for the same user and IP, the pattern that suggests a guessed password.
- **Detects unusual-hours logins:** successful logins outside a configurable window, including overnight windows.
- **Detects SQL injection** in web requests: UNION SELECT, tautologies like `' OR '1'='1`, quote-and-comment tricks, time-based probes, stacked queries, and schema probing, including double-encoded and mixed-case variants.
- **Stores** alerts in SQLite, with duplicate protection so re-running on the same log doesn't double-count.
- **Reports** with a text summary (`--summary`) and a standalone HTML report (`--html`).
- **Tested** with 71 unit tests.

## Example

SSH log from my lab VM (an Ubuntu Server VM I attacked with deliberate bad logins):

```
$ python3 -m src.main sample_logs/ssh_journal_sample.log --year 2026 --threshold 3
Parsed 14 SSH events and 0 web requests, raised 3 alert(s), 3 new.
  [MEDIUM] 3 failed SSH logins from 127.0.0.1 between 15:09:27 and 15:09:47 (rule: 3+ failures within 60s). Targeted users: fakeuser.
  [HIGH] 6 failed SSH logins from 127.0.0.1 between 15:10:52 and 15:12:31 (rule: 3+ failures within 60s). Targeted users: fakeuser, junior.
  [HIGH] Successful login for 'junior' from 127.0.0.1 at 15:13:18 after 3 failed attempts in the previous 300s. Possible compromised credentials.
```

Web log (a hand-written sample that mimics a sqlmap-style scan, since I have no live web server):

```
$ python3 -m src.main --web-log sample_logs/nginx_access_sample.log
Parsed 0 SSH events and 9 web requests, raised 2 alert(s), 2 new.
  [HIGH] 3 suspicious web request(s) from 203.0.113.50 between 14:05:04 and 14:05:11. Techniques: tautology, time_based, union_select. 3 returned HTTP 2xx. Example: /products?id=7%27%20OR%20%271%27%3D%271
  [MEDIUM] 1 suspicious web request(s) from 198.51.100.9 between 14:20:45 and 14:20:45. Techniques: quote_comment. 0 returned HTTP 2xx. Example: /login?user=admin%27--&pass=x
```

Both logs with a summary:

```
$ python3 -m src.main sample_logs/ssh_journal_sample.log --year 2026 --threshold 3 \
    --web-log sample_logs/nginx_access_sample.log --summary
...
Total alerts: 5
By severity: high=3, medium=2
By rule:
  ssh_brute_force: 2
  web_sql_injection: 2
  ssh_success_after_failures: 1
Top source IPs:
  127.0.0.1: 3 alert(s)
  203.0.113.50: 1 alert(s)
  198.51.100.9: 1 alert(s)
```

Unusual-hours detection, with a narrow window so the 15:13 login falls outside it:

```
$ python3 -m src.main sample_logs/ssh_journal_sample.log --year 2026 --work-start 9 --work-end 15
...
  [MEDIUM] Login for 'junior' from 127.0.0.1 at 15:13:18, outside expected hours (09:00-15:00).
```

With the default threshold of 5 failures in 60 seconds, the SSH sample raises no brute-force alert, because the attempts came in slow bursts of three. That is intended, and the threshold is configurable.

## Usage

Requires Python 3.9+ and no third-party packages.

```
python3 -m src.main [logfile] [--web-log FILE] [--year YEAR] [--threshold N] [--window SECONDS]
                    [--min-failures N] [--success-window SECONDS]
                    [--work-start H] [--work-end H] [--web-window SECONDS]
                    [--summary] [--html FILE] [--db alerts.db]
```

Provide an SSH log, a web log, or both.

| Option | Default | Meaning |
|---|---|---|
| `logfile` | none | SSH log in `journalctl` format |
| `--web-log` | none | nginx access log in combined format |
| `--year` | current year | Journal timestamps omit the year, so it is supplied here |
| `--threshold` | 5 | Failed logins that trigger a brute-force alert |
| `--window` | 60 | Brute-force time window in seconds |
| `--min-failures` | 3 | Failures before a success that make the success suspicious |
| `--success-window` | 300 | How far back (seconds) to look for those failures |
| `--work-start` | 7 | First expected login hour (0-23), in the server's timezone |
| `--work-end` | 19 | End of expected login hours (0-24). Start greater than end means an overnight window |
| `--web-window` | 300 | Seconds between web requests that still count as one attack |
| `--summary` | off | Print alert counts by severity, rule, and source IP |
| `--html` | none | Write a standalone HTML report to this file |
| `--db` | `alerts.db` | SQLite file where alerts are saved |

To produce your own SSH input on an Ubuntu machine you own:

```
sudo journalctl -u ssh > ssh.log
```

## How the detection works

### Rule 1: SSH brute force

1. Keep only failed-password events and group them by source IP.
2. Slide a time window over each IP's failures, oldest first.
3. When the window holds `threshold` or more failures, open an alert.
4. Keep extending that alert while failures continue within `window` seconds of each other.
5. Rate the alert `high` if it reaches twice the threshold, otherwise `medium`.

### Rule 2: success after failures

1. Track recent failed logins per (source IP, username) pair.
2. When that same pair logs in successfully, count its failures inside the lookback window.
3. If there are `--min-failures` or more, raise a `high` alert.
4. Clear the pair's failures after any success, so a second quick login does not alert twice.

### Rule 3: SQL injection in web requests

1. URL-decode each request target, twice, to catch double encoding, and lowercase it.
2. Match it against patterns for known injection techniques.
3. Merge suspicious requests from one IP into a single alert while they stay within `--web-window` seconds of each other.
4. Rate the alert `high` if any injected request returned HTTP 2xx (the application processed it), otherwise `medium`.

Known limits: this rule only sees the URL, so injection in POST bodies never appears in an access log. Pattern matching can also be obfuscated past. A lone apostrophe is deliberately not flagged, because that would bury analysts in false alarms from ordinary searches.

### Rule 4: unusual-hours logins

Every successful login outside `--work-start` to `--work-end` raises a `medium` alert. Hours are the server's local time, because journal timestamps carry no timezone. The window is global rather than learned per user, which is simple and predictable but cannot tell a night-shift worker from an intruder.

## Project structure

```
src/
  parsers/auth_log.py                   # SSH log line -> AuthEvent
  parsers/nginx_access.py               # web log line -> WebEvent
  detections/brute_force.py             # rule 1
  detections/success_after_failures.py  # rule 2
  detections/sql_injection.py           # rule 3
  detections/unusual_hours.py           # rule 4
  report.py                             # text summary and HTML report
  storage.py                            # SQLite persistence
  main.py                               # command-line entry point
tests/                                  # 71 unit tests
sample_logs/                            # SSH log from my lab VM; hand-written nginx sample
```

## Running the tests

```
python3 -m unittest discover -s tests -t .
```

## Security notes

- All SQL uses parameterized queries. Log fields such as usernames are attacker-controlled input, and one test stores a username containing a SQL injection string to confirm it is saved as plain text.
- Output is treated as untrusted. Terminal output strips control characters, and the HTML report escapes every field, uses a Content-Security-Policy, and loads no external resources. Tests feed it a `<script>` payload to prove it.
- The sample logs contain only data from my own throwaway lab VM and invented documentation-range IPs.
- Only run attack simulations against systems you own or have permission to test.

## Lessons learned

- Modern Ubuntu logs SSH through `journald` with the process name `sshd-session`, so tutorials written for the classic `/var/log/auth.log` format don't match real output. I wrote the parser against the real lines from my VM.
- Journal timestamps have no year or timezone, which has to be handled explicitly.
- Collapsing a sustained attack into a single alert matters more than it first seems. A naive sliding window fires on every extra failure and floods the analyst.
- Detection is a trade-off between false positives and false negatives. Flagging every apostrophe would catch more probes and drown real alerts.
- A tool that reads attacker-controlled logs is itself an attack surface, so reports have to escape what they display.

## Future ideas

- Learn each user's normal login hours instead of using one global window
- Support the classic `/var/log/auth.log` format and Apache access logs
- Enrich source IPs with geolocation and known-bad-IP lists
- Run continuously against a live log instead of one file at a time

# log-sentinel

A small SSH log analysis tool in Python. It parses `journalctl` SSH logs, detects brute-force login attempts, and stores alerts in SQLite.

I built it while studying Information Technology at Northeastern, as a hands-on way to learn how SOC detection logic works: raw logs in, structured events, rules, alerts out.

## What it does

- **Parses** SSH log lines from `journalctl -u ssh` into structured events (timestamp, user, source IP, port, event type).
- **Detects** brute-force attacks: N failed logins from one IP within a time window. A sustained attack raises one alert instead of dozens.
- **Detects** a successful login that follows repeated failures for the same user and IP, the pattern that suggests a guessed password.
- **Stores** alerts in SQLite, with duplicate protection so re-running on the same log doesn't double-count.
- **Tested** with 30 unit tests, including a test run against real logs from my own lab VM.

## Example

Run against logs from my lab VM (an Ubuntu Server VM I attacked with deliberate bad logins):

```
$ python3 -m src.main sample_logs/ssh_journal_sample.log --year 2026 --threshold 3
Parsed 14 events, raised 3 alert(s), 3 new.
  [MEDIUM] 3 failed SSH logins from 127.0.0.1 between 15:09:27 and 15:09:47 (rule: 3+ failures within 60s). Targeted users: fakeuser.
  [HIGH] 6 failed SSH logins from 127.0.0.1 between 15:10:52 and 15:12:31 (rule: 3+ failures within 60s). Targeted users: fakeuser, junior.
  [HIGH] Successful login for 'junior' from 127.0.0.1 at 15:13:18 after 3 failed attempts in the previous 300s. Possible compromised credentials.
```

With the default threshold of 5 failures in 60 seconds, this particular log raises no brute-force alert, because the attempts came in slow bursts of three. That is the intended behavior, and the threshold is configurable.

## Usage

Requires Python 3.9+ and no third-party packages.

```
python3 -m src.main <logfile> [--year YEAR] [--threshold N] [--window SECONDS]
                    [--min-failures N] [--success-window SECONDS] [--db alerts.db]
```

| Option | Default | Meaning |
|---|---|---|
| `--year` | current year | Journal timestamps omit the year, so it is supplied here |
| `--threshold` | 5 | Failed logins that trigger an alert |
| `--window` | 60 | Time window in seconds |
| `--min-failures` | 3 | Failures before a success that make the success suspicious |
| `--success-window` | 300 | How far back (seconds) to look for those failures |
| `--db` | `alerts.db` | SQLite file where alerts are saved |

To produce your own input on an Ubuntu machine you own:

```
sudo journalctl -u ssh > ssh.log
```

## How the detection works

### Rule 1: brute force

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

## Project structure

```
src/
  parsers/auth_log.py                   # log line -> AuthEvent
  detections/brute_force.py             # rule 1: events -> alerts
  detections/success_after_failures.py  # rule 2
  storage.py                            # SQLite persistence
  main.py                               # command-line entry point
tests/                                  # 30 unit tests
sample_logs/                            # real lab VM logs (fake usernames only)
```

## Running the tests

```
python3 -m unittest discover -s tests -t .
```

## Security notes

- All SQL uses parameterized queries. Log fields such as usernames are attacker-controlled input, and one test stores a username containing a SQL injection string to confirm it is saved as plain text.
- The sample log contains only data from my own throwaway lab VM.
- Only run attack simulations against systems you own or have permission to test.

## Lessons learned

- Modern Ubuntu logs SSH through `journald` with the process name `sshd-session`, so tutorials written for the classic `/var/log/auth.log` format don't match real output. I wrote the parser against the real lines from my VM.
- Journal timestamps have no year, which has to be handled explicitly.
- Collapsing a sustained attack into a single alert matters more than it first seems. A naive sliding window fires on every extra failure and floods the analyst.

## Roadmap

- [x] Detect failed logins followed by a successful login from the same user and IP
- [ ] nginx access log parser
- [ ] SQL injection pattern detection in web requests
- [ ] Unusual-hours login detection
- [ ] HTML or CLI summary report

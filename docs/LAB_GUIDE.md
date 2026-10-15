# Reproduce the analyst investigation

## Purpose and environment

Investigate synthetic authentication activity using Python and SQLite. No cloud account,
paid subscription, credentials, network access or third-party Python package is required.
Use Python 3.11 or newer with SQLite 3.38 or newer (the SQL uses `unixepoch`).
The lab reads repository files and replaces generated files under `evidence/`.

```bash
git clone https://github.com/JamieChristian22/cybersecurity-analyst-portfolio.git
cd cybersecurity-analyst-portfolio
python -m lab.reproduce
```

Expected summary: **23 events, 4 alerts, 1 SQL correlation; tests passed.**
The command also checks six Windows events, thirteen packet records, and 72 labeled
rolling-rule scenarios. It exits nonzero if expected alerts differ, SQL disagrees, forensic
results differ, a labeled scenario fails, or any of the 82 unit/CLI tests fails.
Run tests separately with `python -m unittest discover -s tests -v`.

## Files to inspect in order

1. [Raw synthetic events](../lab/auth_events.csv): UTC times, stable event IDs and documentation-only IP addresses.
2. [Expected alert identities](../lab/expected_alerts.json): authored independently of the detection run.
3. [Reference detector](../lab/detections.py): small, readable behavioral implementation.
4. [SQL correlation](../lab/correlation.sql): independently implemented temporal join.
5. [Generated alerts](../evidence/alerts.json): each alert names every supporting source event.
6. [Analyst casebook](CASEBOOK.md): explain what the alert establishes and what remains unknown.
7. [Validation manifest](../evidence/manifest.json): input/source hashes and environment version.

## Scenario expectations

| Events | Behavior | Expected result |
|---|---|---|
| A01–A06 | Five failures followed by success, same user/source | AUTH-001 at A05; AUTH-002 at A06 |
| B01–B04 | Success occurs before failures | No failure-then-success alert |
| C01–C04 | Failures age out of the five-minute window | No correlation |
| D01–D05 | Five distinct users fail from one source | AUTH-003 at D05 |
| E01–E02 | Successful logins change geography within 30 minutes | AUTH-004 review signal |
| F01–F02 | Same-geography successful logins | No alert |

## Safe experimentation

Copy the fixture before changing it. Change A06 to occur before A01 and confirm AUTH-002
is absent; change its IP and confirm correlation does not cross sources. Do not edit the
expected results merely to make a failed run pass. Explain the behavior change first.
These cases already have automated negative tests.

## Splunk ingestion and acceptance test

Splunk is optional and **has not been executed in the committed validation run**.
Use a separate lab index named `auth` and ingest `lab/auth_events.csv` once. Set CSV field
extraction, use `timestamp` as the time field, set the time format to `%Y-%m-%dT%H:%M:%SZ`,
and interpret it as UTC. Choose an absolute search range covering 2026-10-01 UTC rather
than “Last 24 hours.” Confirm 23 events and 23 distinct `event_id` values before testing.
Duplicate ingestion invalidates count thresholds.

Run the maintained [SPL files](../SOC%2C%20SIEM%2C%20Alert%20Handling/spl/).
AUTH-001 should yield alex / 203.0.113.10 with five failures; AUTH-002 should identify A06
with five prior failures; AUTH-003 should yield 203.0.113.40 with five distinct users;
AUTH-004 should identify E02. Aggregated rules return a bin-level row, whereas Python
emits at the threshold event, so their result shapes intentionally differ.

Export results with the query, Splunk version, time range, index/sourcetype and ingestion
configuration. Test the negative cases and time boundaries before marking any query
platform-validated. Confirm `streamstats` window limits fit event volume. Test scheduling,
lookback, late ingestion and deduplication separately; this is an offline lab, not a
production scheduling package. For scheduled correlation, include five minutes of history
before the evaluation interval and emit only successes inside the new interval.

## Troubleshooting

- Missing column / invalid action: fix the cited source row; validation intentionally fails closed.
- Naive timestamp: the canonical lab requires an explicit UTC offset. The legacy parser
  adapter explicitly assumes UTC for historical datasets without offsets.
- SQL function unavailable: inspect `python -c "import sqlite3; print(sqlite3.sqlite_version)"`.
- No Splunk results: verify timestamp extraction, absolute dates, index and CSV field names.
- More than four local alerts: compare fixture hashes and source changes with the manifest.

## Extended evidence and independent packet decoder

[CASE-004](FORENSIC_CASE.md) documents the endpoint/network investigation.
[Rolling evaluation](ROLLING_AND_EVALUATION.md) explains the 72 labeled cases.
To repeat the independent PCAP check, install the pinned optional package and run:

```bash
python -m pip install -r requirements-verification.txt
python -m lab.reproduce --with-independent-pcap
```

A default run does not silently claim independent decoding. The manifest records whether
that option was requested, while the separate verification file identifies the PCAP SHA-256
and dpkt version. Fixture regeneration is explicit, never a hidden part of validation:
`python -m lab.build_forensics` and `python -m lab.build_benchmark`.

# Community quick start — reproduce a synthetic SOC investigation

This is a learning exercise for security analysts, students, documentation contributors, and reviewers. The incidents and accounts are **synthetic**, not real incidents.

## 1. Reproduce the investigation locally

Requirements: Python 3.11+ and SQLite 3.38+ (for the documented SQL functions). The core lab does not require cloud credentials, a paid service, or third-party Python packages.

```bash
git clone https://github.com/JamieChristian22/cybersecurity-analyst-portfolio.git
cd cybersecurity-analyst-portfolio
python -m lab.reproduce
```

Run this in a fresh clone: the command regenerates tracked or local evidence outputs under `evidence/`. Read the [lab guide](LAB_GUIDE.md) before running additional verification options.

## 2. Answer three analyst questions

1. Open [synthetic source events](../lab/auth_events.csv) and [generated alerts](../evidence/alerts.json). Which event IDs support an alert?
2. Compare the [Python detector](../lab/detections.py) and [SQL correlation](../lab/correlation.sql). Where could ordering or timing boundaries matter?
3. Read the [casebook](CASEBOOK.md) and [validation limitations](VALIDATION.md). What extra information would be needed to decide whether an alert is malicious in a real environment?

The existing fixture is documented to produce **23 synthetic events and four alerts**; inspect actual outputs rather than assuming a run passed.

## 3. Improve the learning resource

Good first contributions can include:

- Fixing broken links, unclear commands, or accessibility issues in documentation.
- Adding a small **synthetic** edge-case fixture with a focused test and documented expected behavior.
- Clarifying a false-positive limitation or investigation decision in the casebook.

Read [CONTRIBUTING.md](../CONTRIBUTING.md) and check [existing issues](https://github.com/JamieChristian22/cybersecurity-analyst-portfolio/issues) before proposing a change. Open a focused issue to discuss larger additions.

**Security and integrity:** Use only systems and data you own or are authorized to test. Never submit private logs, access credentials, or sensitive data. Tests on synthetic data do not establish production detection accuracy, authorization to investigate third-party systems, or proof of real incidents.

[Back to repository overview](../README.md) · [Five-minute reviewer guide](REVIEWER_GUIDE.md)

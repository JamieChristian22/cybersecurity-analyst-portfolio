# 🛡️ Cybersecurity Analyst Portfolio

**Jamie Christian II · SOC Operations · Security Automation · Incident Response · GRC**

A cybersecurity learning portfolio with a reproducible authentication investigation,
Python and SQL detections, raw endpoint XML, a valid synthetic PCAP, tested automation,
and supporting security case studies.
All incidents, accounts and outcomes are simulated unless explicitly stated otherwise.

**Start here:** [Five-minute reviewer guide](docs/REVIEWER_GUIDE.md) ·
[Run the lab](docs/LAB_GUIDE.md) · [Investigation casebook](docs/CASEBOOK.md) ·
[Validation and limitations](docs/VALIDATION.md)

## 🔎 Flagship: authentication investigation

Trace 23 synthetic events through validation, detection, independent SQL correlation,
and analyst disposition. The fixture produces **four alerts across three investigation
scenarios**. Every alert links back to source event IDs.

```bash
python -m lab.reproduce
```

Use Python 3.11+ and SQLite 3.38+. No paid tools, dependencies or cloud account are needed.
Run from the repository root. The command checks expected results, runs **82 automated tests**,
and writes reproducible evidence. [Setup and Splunk acceptance steps →](docs/LAB_GUIDE.md)

| Evidence | What to inspect |
|---|---|
| [Source events](lab/auth_events.csv) | UTC timestamps, documented synthetic origin and stable event IDs |
| [Python reference detector](lab/detections.py) | Failures, ordered success correlation, spraying and geography review |
| [Independent SQL correlation](lab/correlation.sql) | Strict event ordering and a five-minute lookback |
| [Generated alerts](evidence/alerts.json) | Four expected alerts and supporting evidence IDs |
| [Casebook](docs/CASEBOOK.md) | Findings, uncertainty, scope, escalation and closure criteria |
| [Test results](evidence/test_results.txt) | Actual unit and CLI checks, including negative cases |
| [Run manifest](evidence/manifest.json) | Source hashes, interpreter version and validation counts |
| [Risk and control linkage](docs/RISK_AND_CONTROLS.md) | Evidence-based treatment, ownership and residual-risk caveats |

**Validation boundary:** local Python/SQLite execution is recorded. SPL files are supplied
for native acceptance testing; native Splunk execution is not claimed. Synthetic test
success does not establish production precision, recall or operational risk reduction.

## 🖥️ Endpoint and network investigation

[CASE-004](docs/FORENSIC_CASE.md) correlates six authored Windows-style event records
with a 13-packet synthetic capture. Process GUIDs link the endpoint evidence; packet
numbers link periodic connection attempts. A separate **dpkt decoder independently
verified the capture and IPv4/TCP checksums**.

- [Raw Windows event XML](lab/fixtures/endpoint/windows_events.xml)
- [PCAP file](lab/fixtures/network/traffic.pcap)
- [Endpoint alert evidence](evidence/endpoint/alerts.json)
- [Network findings](evidence/network/findings.json)
- [Independent packet verification](evidence/network/independent_verification.json)

The encoded lab command is harmless, and the analyst explains why the observations do
not establish compromise, persistence, successful connections or exfiltration.

## 📊 Rolling-window detection evaluation

[Rolling detections](lab/rolling.py) handle boundary-spanning bursts that the original
fixed-bin rules can miss. **72 labeled synthetic scenarios passed**, covering positive
and negative examples across three rules. [Evaluation design and full results →](docs/ROLLING_AND_EVALUATION.md)

Run the full suite with independent packet verification:

```bash
python -m pip install -r requirements-verification.txt
python -m lab.reproduce --with-independent-pcap
```

The core command remains dependency-free and includes endpoint/network analysis, all unit
tests and the labeled scenarios. Only the independent second decoder needs the pinned package.
These regression results are not a claim of production detection accuracy.

## ⚙️ Automation and detection assets

- [IP allowlist manager](System%20%26%20Automation/python/ip_allowlist_manager.py): IPv4/CIDR
  validation, duplicate handling, dry runs, output collision protection and change summaries.
- [Authentication parser](System%20%26%20Automation/python/security_log_parser.py): validates
  legacy CSV data, normalizes timestamps and emits evidence-linked alerts.
- [SPL catalog](docs/DETECTIONS.md): maintained thresholds, query paths, field prerequisites,
  false-positive considerations and explicit limitations.
- [Linux audit script](System%20%26%20Automation/bash/linux_security_audit.sh): read-only
  collection of host security signals. Syntax checked; no host-hardening claim.
- [CI workflow](.github/workflows/validate.yml): repeats the lab on Python 3.11–3.13 and
  archives run evidence. Check hosted run results rather than assuming workflow success.

## 🗂️ Supporting portfolio

| Area | Supporting work |
|---|---|
| [SOC, SIEM and Alert Handling](SOC%2C%20SIEM%2C%20Alert%20Handling/) | SPL, original screenshots, triage case studies and runbooks |
| [Incident Response and Forensics](Incident%20Response%20%26%20Forensics/) | Simulated investigations, response playbooks and evidence-handling guidance |
| [Governance and Risk](Governance%20%26%20Risk%20%28GRC%29/) | Risk assessments, control design, policy and threat modeling |
| [System and Automation](System%20%26%20Automation/) | Python, Bash, SQL, datasets and historical assessments |
| [Capstone Integration](Capstone%20Integration/) | Simulated enterprise security program and executive reporting |
| [Career and Professional Development](Career%20%26%20Professional%20Development/) | Training and supporting professional-development material |

Older reports remain available as educational material. [Current validation scope](docs/VALIDATION.md)
identifies what has and has not been executed. The [extended portfolio overview](PORTFOLIO_BACKGROUND.md)
preserves the broader background without making the homepage difficult to scan.

## 🎯 Skills demonstrated

**SOC:** event correlation, alert triage, evidence linkage, severity and escalation.

**Automation:** Python, CSV/JSON, input validation, safe dry runs and CLI tests.

**Data analysis:** SQL joins, aggregation, UTC handling and time-window boundaries.

**Risk communication:** defensible conclusions, control testing, ownership and explicit uncertainty.

## 📫 Contact

[GitHub](https://github.com/JamieChristian22) ·
[LinkedIn](https://www.linkedin.com/in/jamiechristian2/) ·
[Email](mailto:jamiechristian331@gmail.com)

**Integrity note:** This portfolio does not claim production incident ownership, employer
security outcomes, formal audit attestation or completed deployment of its proposed controls.

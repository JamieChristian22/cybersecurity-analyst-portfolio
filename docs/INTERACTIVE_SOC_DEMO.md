# Offline SOC Investigation Console

**[Open the interactive demo](../demo/soc-investigation.html)**. To interact locally, download the HTML and open it directly in a web browser. The demo is a self-contained file; no paid SIEM, cloud credentials, API connection or external JavaScript is required. The source links resolve when the repo directory layout is preserved.

## Demonstration

1. Filter the four synthetic reference alerts by rule, severity, username, source IP or evidence event ID.
2. Choose an alert and inspect its ordered supporting authentication events from the canonical fixture.
3. Select a **provisional disposition** and draft a note describing what is observed, what remains unknown, and what further evidence could support escalation or closure.
4. Copy the draft case note via the browser clipboard (where available), or reset the worksheet.

The worksheet is purely local UI state and is **not persisted or submitted**. No blocking, containment or live incident response occurs.

## Source parity and test contract

The demo embeds exactly the events in [lab/auth_events.csv](../lab/auth_events.csv), generated alerts in [evidence/alerts.json](../evidence/alerts.json), and independent expected rule/event identities in [lab/expected_alerts.json](../lab/expected_alerts.json). Test `tests/test_soc_explorer.py` compares these entire arrays against the repository files and re-runs `lab.detections.detect` to validate the reproduced output. The demo cannot assert passing checks if its embedded values drift. It also checks that supporting event IDs resolve and that the UI avoids remote JavaScript or unsafe HTML injection.

The fixture has 23 authentication events and 4 alerts representing **three investigation scenarios**. Four alerts are not necessarily four incidents. The related [casebook](CASEBOOK.md) deliberately avoids declaring compromise, impossible travel or successful attack where the source lacks proof. The 72 rolling scenarios are **selected synthetic regression examples**, not a representative measure of detection precision or recall.

## Automated CI

[.github/workflows/validate.yml](../.github/workflows/validate.yml) runs `python -m lab.reproduce --with-independent-pcap` across Python 3.11/3.12/3.13, validates exact counts, reproduces independent packet checksums with pinned dpkt, performs source/Bash syntax checks, and archives evidence. A separate job runs SHA-256-verified Gitleaks against Git history.

To reproduce:

```bash
python -m pip install -r requirements-verification.txt
python -m lab.reproduce --with-independent-pcap
python -m unittest discover -s tests -v
```

Inspect the current hosted Actions run before claiming that CI passed. Automated tests do **not** establish native Splunk SPL execution, production detection efficacy, endpoint telemetry collection or a real network capture. These remain separate validation goals. Interactive browser layout, clipboard permissions, and keyboard behavior still require manual review before publication.

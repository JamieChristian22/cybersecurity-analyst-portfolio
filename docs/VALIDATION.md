# Validation record and claim boundaries

## Executed locally

- `python -m lab.reproduce`: checks exact expected alert identities, SQL agreement and unit tests.
- 82 tests cover chronology, UTC normalization, 300-second boundaries, grouping isolation,
  fixed-bin limitations, fixture identity, input validation, allowlist CLI writes and dry runs,
  rolling thresholds, Windows event correlation and malformed packet handling.
- 72 labeled synthetic rolling-rule scenarios passed, with per-case results and target-rule confusion counts.
- Six Windows-style XML records and thirteen packet records reproduce one endpoint alert and one periodicity finding.
- `python -m lab.verify_pcap`: dpkt 1.9.8 independently decoded the capture and verified IPv4/TCP checksums.
- `bash -n 'System & Automation/bash/linux_security_audit.sh'`: syntax validation only.
- Legacy parser and allowlist test rerun; generated outputs replaced with fresh evidence.

The machine-readable [manifest](../evidence/manifest.json) names the Python version, source
hashes and result counts. [Test output](../evidence/test_results.txt) records actual executed
cases. CI repeats the suite on Python 3.11, 3.12 and 3.13 and uploads evidence per version.
A configured workflow is not itself evidence of a successful hosted run; inspect the PR checks.

## Not executed / not claimed

| Area | Status | Evidence needed to advance |
|---|---|---|
| Native Splunk query execution | Pending | Ingestion settings, exported search results, query/version and negative cases |
| Live Windows capture / EVTX acquisition | Not performed; authored event XML is executed through the local parser | Authorized host acquisition, native export provenance and OS/tool versions |
| Live network acquisition / Wireshark GUI | Not performed; synthetic PCAP analysis and independent dpkt verification passed | Authorized live capture provenance and native GUI exports if required |
| Linux hardening efficacy | Audit script syntax checked; no host hardened | Approved lab before/after effective settings and service verification |
| Enterprise GRC control effectiveness | Illustrative framework/risk design | Actual control evidence, test population, result, owner and exception handling |
| Production outcomes and detection precision | Not measured | Labeled representative data and repeatable measurement method |

The older PDFs and screenshots remain as supporting educational material. They are not
re-issued or newly execution-validated by this upgrade. Current behavior is defined by the
maintained source files and documentation in `docs/`, not historical embedded examples.

## Limitations worth explaining in an interview

1. A synthetic fixture proves specified examples and regression properties, not general efficacy.
2. Geography is an enrichment signal, not a conclusion about physical movement or compromise.
3. Fixed bins can miss boundary-spanning bursts; the test suite makes this explicit.
4. The original reference detector favors readability; the rolling alternative uses event queues. Neither has a production throughput SLA.
5. Passing Python/SQL tests does not validate SPL syntax or Splunk deployment settings.
6. Bash collection can be incomplete due to permissions or missing commands. Inspect failures;
   absence of output is not proof of a secure configuration. The script reads configuration
   text and does not resolve effective SSH configuration with includes and Match blocks.

## Expanded evidence scope

The new XML/PCAP case is distinct from the older PDF investigations. The XML is a valid
teaching input with Windows-style event fields, not evidence collected from Windows. The
PCAP contains valid authored packet bytes and was verified independently, but it is not a
live capture. This distinction preserves reproducibility without inventing deployment work.

The CI matrix includes the pinned optional packet decoder and invokes the full verification
command. Hosted CI remains unexecuted because repository write access was denied during the
previous delivery. All reported passing results are local, on the interpreter version recorded
in the manifest. No native Splunk, Windows, Wireshark GUI or production execution is implied.

# Linking findings to risk and controls

This is an illustrative risk register for the synthetic identity scenarios. Scores are
reasoned teaching examples using likelihood × impact (1–5 each), not measured enterprise risk.
Residual scores are **targets conditional on validated controls**, never achieved outcomes.

| Risk | Evidence / exposure | Inherent score | Treatment and accountable role | Validation and target |
|---|---|---:|---|---|
| R-01 Unauthorized account use | CASE-001; access follows repeated failures | 4×4 = 16 | Identity owner: MFA, session review, conditional access and recovery process | Test approved sign-in scenarios and verify enforcement; target 2×4 = 8 |
| R-02 Multi-account guessing | CASE-002; one source targets five users | 4×3 = 12 | IAM owner: throttling, monitoring and safe lockout policy | Authorized lab attempt thresholds; verify legitimate-user impact; target 2×3 = 6 |
| R-03 Poor alert interpretation | CASE-003 could be mislabeled compromise | 3×3 = 9 | SOC lead: enrichment checklist and peer review | Sample tickets for evidence-supported dispositions; target 2×2 = 4 |
| R-04 Undetected boundary-spanning burst | Fixed-bin limitation documented in tests | 3×3 = 9 | Detection owner: evaluate rolling-window alternative | Compare boundary fixtures and representative benign data; target not yet assigned |
| R-05 Automation changes wrong file | Allowlist input/output collision | 3×4 = 12 | Automation owner: destination validation and dry run | CLI tests reject collisions and preserve dry-run output; target 1×4 = 4 |

## Example control test record

**Control:** generated allowlist must not overwrite source inputs and a dry run must preserve
the existing output. **Evidence:** `tests/test_automation.py`, specifically the input-overwrite
and dry-run tests; execution log in `evidence/test_results.txt`. **Population:** temporary test
fixtures only. **Result:** refer to the committed execution log. **Limitation:** this does not
validate deployment approvals, filesystem ACLs, concurrent writers or recovery in production.

## Remediation and exception workflow

1. Assign an accountable owner and describe the affected asset or process.
2. Record scope, evidence, proposed change, impact and rollback.
3. Obtain the change/containment approval required by that environment.
4. Execute in an authorized lab, then verify expected and negative behavior.
5. Close only after validation, or document an approved exception with expiry and compensating controls.

## Suggested operational backlog

| Priority | Action | Completion evidence |
|---|---|---|
| P1 | Execute native Splunk acceptance cases | Exported query results and ingestion settings |
| P1 | Add device/MFA/session telemetry to CASE-001 | Event-linked scope and revised disposition |
| Completed locally | Evaluate rolling-window failures/spray on synthetic cases | 72 labeled scenarios and boundary tests; benign enterprise baseline still pending |
| P2 | Implement independently tested suppression and late-event handling | Replay tests and documented scheduling assumptions |
| Completed as simulation | Add endpoint/network investigation | Authored raw XML and PCAP, independent decoding, timeline and evidence-linked findings |

Rows marked completed refer only to the delivered local simulations. Other items are
visible development goals, not completed deployment work. Existing GRC PDFs provide broader policy context; this record connects the
executed lab to concrete evidence and ownership.

# Detection catalog and operating limits

**Status:** Python/SQLite lab executed locally. SPL reviewed and supplied for platform
acceptance testing; no claim of native Splunk execution or production effectiveness.

| ID | Behavior and threshold | Window / grouping | Meaning and next step |
|---|---|---|---|
| AUTH-001 | At least 5 failed logins | Fixed UTC 5-minute bin; user + source | Investigate guessing, stale credentials, retries and authorized tests |
| AUTH-002 | Success after at least 3 strictly earlier failures | Trailing inclusive 300 seconds; user + source | Review device, MFA, session and post-login activity; high-priority investigation |
| AUTH-003 | Failed logins for at least 5 distinct users | Fixed UTC 10-minute bin; source | Possible spraying, shared gateway or test; review ownership and auth context |
| AUTH-004 | Different geographic labels on consecutive successful logins | More than 0 and at most 60 minutes; user | Review VPN/proxy/device context; geography alone cannot prove compromise |

## Semantics and exceptions

- AUTH-001 and AUTH-003 use fixed bins: bursts spanning a boundary can be missed. Tests
  explicitly preserve this limitation. Rolling windows are a future improvement, not claimed here.
- AUTH-002 uses strict event order, including deterministic success-before-failure ordering
  for identical timestamps in SPL. Same-time failures cannot establish a prior sequence.
  Success does not reset history: multiple successes may each trigger while failures remain
  in the window. Suppression belongs in the deployment configuration, not hidden in the evidence.
- Python AUTH-001/AUTH-003 emit once per group/bin at threshold. SPL returns bin aggregates.
  Alert counts are not directly comparable without accounting for that distinction.
- AUTH-004's legacy file remains `05_impossible_travel.spl` for compatibility. It is a **rapid
  geography change** rule, not a distance/speed calculation. Simultaneous success events with
  conflicting geography are ambiguous and need manual review; this fixture avoids that ambiguity.
- Missing geography is rejected by the canonical fixture loader. VPN and proxy context is
  deliberately absent, so AUTH-004 remains unresolved in the casebook.
- The Python reference algorithm is O(n²), appropriate for a 23-event teaching fixture.
  It is not a streaming collector, scalable SIEM or production rule engine.
- Synthetic thresholds illustrate behavior. They have not been calibrated against a real
  organization's baseline, false-positive budget or identity topology.

## Existing supplemental SPL

`03_credential_stuffing.spl` detects multi-user authentication failure/success patterns.
It cannot establish that stolen credential pairs were used; treat the title as a hypothesis.
`06_suspicious_powershell.spl` matches several command strings, requires endpoint fields,
and is not covered by the authentication fixture. Encoded execution has benign uses and
alternate syntax may evade those strings. Validate with an authorized endpoint lab before
asserting detection coverage. Neither supplemental rule has native execution evidence here.

## Triage and escalation

1. Confirm telemetry completeness, UTC alignment and event identity.
2. Review user/source/host ownership, managed device, MFA, approved changes and VPN context.
3. Search successful sessions and downstream activity before declaring compromise.
4. Record a disposition with evidence, uncertainty and an explicit escalation reason.
5. Request containment authorization; preserve events before revoking sessions or isolating hosts.
6. Record revalidation, recovery and a review date for temporary exceptions.

ATT&CK interpretation: AUTH-001/002 may support a T1110 brute-force hypothesis;
AUTH-003 may support T1110.003 password spraying. Authentication events alone do not prove
password reuse, credential stuffing, actor identity, persistence or data theft.

## Primary reference

[Splunk streamstats reference](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/streamstats)
explains `current`, grouping, time windows and event ordering. Platform-specific acceptance
steps are in [the lab guide](LAB_GUIDE.md); code review is distinct from execution evidence.

## Additional implemented local rules

The [rolling-rule catalog](ROLLING_AND_EVALUATION.md) documents ROLL-001/002/003 and
72 labeled scenarios. The [forensic case](FORENSIC_CASE.md) documents ENDPOINT-001 and
NET-001, including benign controls and evidence pointers. These are executed Python rules;
they are not native Splunk implementations or proof that supplemental SPL was executed.

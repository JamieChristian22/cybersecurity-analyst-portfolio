# SOC casebook: authentication investigation

**Classification:** synthetic portfolio exercise. All accounts, events and decisions are
fictional. No containment action was executed, and no real incident or business outcome
is claimed. Analyst statements below are constrained to the available evidence.

## CASE-001 — Repeated failures followed by successful authentication

| Field | Analyst finding |
|---|---|
| User / source | alex / 203.0.113.10 |
| Timeline | A01–A05: 09:00–09:04 UTC failures; A06: 09:04:30 UTC success |
| Detection evidence | AUTH-001 at A05 and AUTH-002 at A06; source IDs in alerts.json |
| Independent validation | SQL returns A06 with 5 prior failures |
| Severity | High triage priority because access followed repeated failures |
| Disposition | Suspicious authentication; compromise unconfirmed |
| Known scope | One user and one source in the supplied fixture |
| Unknowns | User intent, device trust, MFA, source ownership, session actions and application scope |

**Analysis:** The sequence supports investigation of credential guessing but is also compatible
with a legitimate user correcting a password. The dataset has no device, MFA or endpoint fields.
Do not describe a successful login as confirmed attacker access without corroboration.

**Handoff:** Ask Tier 2 to review the session, user confirmation through a trusted channel,
identity-provider risk signals and post-login resource access. Request session revocation and
credential reset only if compromise is supported and the response process authorizes them.
Preserve original event IDs, timestamps and hashes. No password or token belongs in the ticket.

**Closure criteria:** Record either a documented benign explanation or corroborating evidence
of unauthorized access; validate any approved remediation; retain the investigation trail.
Current state: **open pending enrichment**, not “contained.”

## CASE-002 — Multi-user authentication failures

D01–D05 show five users failing from 203.0.113.40 between 10:00 and 10:04 UTC.
AUTH-003 triggers at D05. No successful authentication from that source is present.
Severity is medium; disposition is suspected spraying pending source ownership and identity
provider review. A shared gateway or authorized exercise could create a similar pattern.

Search a wider time range, review account lockouts and MFA challenges, and determine whether
successes followed from other sources. Blocking a shared gateway without context may interrupt
legitimate users. Escalate if account takeover indicators appear. Closure requires a supported
explanation and documented follow-up; no containment or successful compromise is claimed.

## CASE-003 — Rapid geography change

E01 and E02 show devon logging in from different geographic labels 30 minutes apart.
AUTH-004 is a medium-priority review signal. There are no coordinates, calculated distances,
VPN attributes or device IDs. Therefore “impossible travel” and “confirmed compromise” are
unsupported conclusions. Request device/session/MFA/VPN context. Keep the disposition
**unresolved** until additional evidence establishes a benign or malicious explanation.

## Negative controls

- B01 precedes B02–B04: an unordered “failure and success in the same group” search would
  be misleading. AUTH-002 does not fire.
- C04 occurs after the supporting failures expire: AUTH-002 does not fire.
- F01–F02 remain in the same geography: AUTH-004 does not fire.

## Executive update

The lab identified three investigation scenarios from 23 synthetic events. One scenario
produced two alerts, so four alerts do not mean four incidents. The strongest signal is a
successful login after five failures; its cause remains unconfirmed. The exercise demonstrates
triage and evidence linkage, not measured operational risk reduction or production MTTD/MTTR.

## Evidence handling

`evidence/manifest.json` records SHA-256 values for source inputs and lab logic. These hashes
support reproducibility, not an independently witnessed forensic chain of custody. Preserve
an immutable export and record acquisition operator/time/tool/version in a real investigation.
The fixture is authored simulation data, not captured endpoint or network evidence.

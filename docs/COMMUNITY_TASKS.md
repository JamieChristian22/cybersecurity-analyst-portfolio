# Three small cybersecurity community tasks

Start with the [free local walkthrough](COMMUNITY_START_HERE.md), [lab guide](LAB_GUIDE.md), and [contributor rules](../CONTRIBUTING.md). This repository uses synthetic events and learning scenarios, **not real customer incident data**. No GitHub sponsorship, cloud account or paid tool is needed.

## Task 1 — Confirm alert-to-source traceability

**Goal:** make it easy for a learner to understand why a synthetic alert fired.

1. Read [source authentication events](../lab/auth_events.csv) and [alert evidence](../evidence/alerts.json).
2. Follow one alert to its corresponding event ID(s); inspect the logic in [Python detections](../lab/detections.py).
3. Compare the explanation to the [investigation casebook](CASEBOOK.md).
4. If an explanation is ambiguous, propose **one** documentation correction with the source event ID, the relevant detector, and the limitation it resolves.

**Acceptance:** a reader can move from the alert to the exact synthetic inputs and back without assuming the alert proves malicious intent. Do not change existing case evidence just to make a narrative look stronger.

## Task 2 — Improve one edge-case explanation

**Goal:** identify a defensible test or documentation improvement around ordering, time boundaries, duplicate records, or absent fields.

1. Inspect the [correlation SQL](../lab/correlation.sql), [detector code](../lab/detections.py), and existing tests.
2. Propose one testable edge case with expected behavior and rationale.
3. Discuss the narrow change in a GitHub issue before making significant code or output changes.
4. Report **actual** test results, not assumed success.

**Acceptance:** the edge case can be reproduced with first-party synthetic inputs and does not loosen the lab's safety or evidence standards.

## Task 3 — Make the first ten minutes easier

**Goal:** reduce setup confusion for someone new to SOC investigations.

1. Walk through [COMMUNITY_START_HERE.md](COMMUNITY_START_HERE.md) and [LAB_GUIDE.md](LAB_GUIDE.md) in a fresh local clone.
2. Note one unclear command, unhelpful link, inaccessible explanation, or platform-specific prerequisite.
3. Submit a focused documentation PR describing the confusing step and what you personally verified.

**Acceptance:** beginners can understand the change without additional purchases or credentials.

## Suggested contributor process

- First read [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md), and existing [issues](https://github.com/JamieChristian22/cybersecurity-analyst-portfolio/issues).
- A task here is a **voluntary, educational contribution idea**, not an assigned or paid GitHub bounty. A funded engagement requires an explicit agreement with a verified payer.
- Never share secrets, sensitive records, or exploit details in a public issue.
- In a PR include the task, modified files, checks performed, results and known limitations.

Optional: [support the author's open educational work](https://github.com/sponsors/JamieChristian22). Sponsorship is not needed for participation.

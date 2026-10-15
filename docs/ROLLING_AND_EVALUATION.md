# Rolling detections and labeled regression evaluation

The original AUTH rules remain available to explain fixed-bin behavior. The new
[rolling implementation](../lab/rolling.py) addresses boundary-spanning authentication
bursts with timestamp-sorted deques and per-source distinct-user counts.

| Rule | Trigger | Window | Emission behavior |
|---|---|---|---|
| ROLL-001 | Five failed logins for one user/source | Inclusive trailing 300 seconds | Emit when the current event crosses the threshold |
| ROLL-002 | Successful login after three strictly earlier failures for same user/source | Inclusive trailing 300 seconds | Emit for each qualifying success |
| ROLL-003 | Five distinct users fail from one source | Inclusive trailing 600 seconds | Emit when distinct-user count crosses the threshold |

Successes sort before failures at the same timestamp. Equal-time failures cannot establish
that they preceded a success. State expires by event time; inactive keys are periodically
removed. The implementation consumes a finite offline replay and sorts its input; it is
not an unbounded streaming collector. Evidence lists and output volume still grow with
activity, and this lab does not claim a measured production throughput or memory SLA.

## Evaluation design

[72 authored scenarios](../lab/fixtures/benchmark/scenarios.json) contain 12 positive and
12 negative cases for each rule. Labels are generated from explicit scenario construction,
not by calling the detector. [Scenario code](../lab/build_benchmark.py) documents the
construction and [results](../evidence/benchmark/scenario_results.json) expose every outcome.

Coverage includes:

- Bursts that cross fixed UTC bin boundaries.
- Exactly enough failures versus one below the threshold.
- Success before failures versus after failures.
- Expired events and same-user/different-source isolation.
- Distinct-user counts versus repeated activity from fewer users.
- Time-spread attempts that must not accumulate indefinitely.

Separate unit tests cover tied timestamps, reordered input, rearming after history expiry,
exact evidence IDs, and the inclusive 300-second boundary.

## Recorded result

| Rule | True positive | True negative | False positive | False negative |
|---|---:|---:|---:|---:|
| ROLL-001 | 12 | 12 | 0 | 0 |
| ROLL-002 | 12 | 12 | 0 | 0 |
| ROLL-003 | 12 | 12 | 0 | 0 |

These are **target-rule, scenario-level regression results**. A case is scored only against
its named target rule; unrelated rule outputs are not used to inflate or penalize that score.
The scenarios are deterministic variants of a small number of behaviors, not 72 independent
real-world incidents. Zero errors on this suite is not evidence of 100% production accuracy.

## What remains outside the evaluation

Distributed attacks that remain below per-source thresholds; identity aliases; authentication
provider retries; ingestion loss; benign enterprise baselines; online late arrivals; scheduler
lookback overlap; durable suppression; and platform-specific SPL execution. Those require a
representative labeled dataset and an actual deployment environment.

For a real rollout, first replay an authorized benign baseline, define an alert budget with
the SOC lead, compare false positives by user/source category, and document time-limited
exceptions. Do not silently change thresholds merely to improve the fixture score.

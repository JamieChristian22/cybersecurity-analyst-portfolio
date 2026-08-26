# 🖥️ SOC, SIEM & Alert Handling

## Security Operations, Splunk Analysis, Detection Engineering & Tier 1 Alert Triage

**Jamie Christian II | Cybersecurity Analyst Portfolio**

This section demonstrates practical **Security Operations Center (SOC), SIEM, alert triage, detection analysis, log correlation, incident escalation, and security monitoring** through simulated hands-on cybersecurity investigations.

The goal is to show how a Tier 1 SOC or Cybersecurity Analyst can move from raw telemetry and alerts to an evidence-based disposition using a structured investigation process.

The core SOC workflow demonstrated throughout this section is:

> **Detection → Alert → Validate → Enrich → Scope → Severity → Disposition → Containment → Escalate / Close → Tune**

---

# 📌 Section Purpose

A SOC analyst does more than review alerts.

Effective security operations requires analysts to answer questions such as:

- What triggered the alert?
- Is the underlying telemetry valid?
- Which user, host, IP, domain, or process is involved?
- Is the activity malicious, suspicious, benign, or a false positive?
- Is there evidence of successful compromise?
- What additional data should be reviewed?
- What is the business impact?
- How severe is the alert?
- Should the activity be contained?
- Should the alert be escalated to Tier 2 or Incident Response?
- Does the detection need tuning?

This portfolio section demonstrates that full process.

---

# 🗂️ SOC, SIEM & Alert Handling Deliverables

| # | Deliverable | Primary Focus |
|---|---|---|
| 01 | **SOC Detection Catalog** | Detection logic, SPL, thresholds, ATT&CK, false positives, tuning |
| 02 | **SOC Alert Triage Casebook** | Completed Tier 1 investigations and dispositions |
| 03 | **Tier 1 SOC Investigation Runbook** | Repeatable alert-to-disposition workflow |
| 04 | **Alert Disposition & Tuning Tracker** | True positive, benign positive, false positive, tuning |
| 05 | **SOC Investigation Timeline** | Time-based authentication investigation |
| 06 | **SIEM Dashboard & SOC Metrics** | Dashboard design, monitoring, operational metrics |
| 07 | **Phishing Alert Investigation Ticket** | Email, identity, IOC, containment, escalation |
| 08 | **Detection Testing & Validation Report** | Rule testing, expected behavior, tuning validation |
| 09 | **SOC Severity, Disposition & Escalation Matrix** | Priority, escalation, handoff decisions |
| 10 | **Recruiter Quick View** | Fast overview of SOC capabilities |
| Data | **Authentication Log Dataset** | Synthetic SIEM-ready authentication events |
| SPL | **Splunk Detection Searches** | Reusable detection logic |

---

# 🔄 SOC Investigation Lifecycle

The SOC workflow follows:

```text
SECURITY TELEMETRY
        ↓
DETECTION LOGIC
        ↓
ALERT
        ↓
VALIDATE
        ↓
ENRICH
        ↓
SCOPE
        ↓
SEVERITY
        ↓
DISPOSITION
        ↓
CONTAIN / ESCALATE / CLOSE
        ↓
DETECTION TUNING
```

---

# 🔎 Tier 1 Investigation Workflow

A Tier 1 analyst should approach alerts systematically.

```text
Alert Generated
      ↓
Confirm Underlying Events
      ↓
Identify User / Host / IP / Process
      ↓
Review Context & Baseline
      ↓
Search Related Activity
      ↓
Determine Scope
      ↓
Assign Severity
      ↓
Determine Disposition
      ↓
Contain if Authorized
      ↓
Escalate or Close
      ↓
Document Findings
```

---

# 🧠 Detection Engineering

A professional detection should contain more than a query.

The portfolio uses the following structure:

> **Detection Name → Data Source → Detection Logic → Threshold → Time Window → Severity → ATT&CK → Investigation → False Positives → Tuning → Escalation**

---

# 📚 Detection Catalog

The detection catalog includes authentication, endpoint, and phishing use cases.

| Detection | Data Source | Trigger | Severity | ATT&CK |
|---|---|---|---|---|
| Brute Force | Authentication logs | Repeated failures from one source | Medium / High | T1110 |
| Password Spraying | Authentication logs | One source targeting multiple users | High | T1110.003 |
| Credential Stuffing | Authentication logs | Multi-user failures plus successful access | High | T1110.004 |
| Failed → Success | Authentication logs | Failures followed by success from same user/source | High | Credential Access / Valid Account investigation |
| Impossible Travel | Authentication logs | Successful logins from distant locations within short period | High | Valid Account investigation |
| Suspicious PowerShell | Endpoint telemetry | Encoded or download-oriented PowerShell | High | T1059.001 |
| Phishing Link | Email / identity | Suspicious link followed by identity activity | High | T1566.002 |

---

# 🔐 Brute-Force Detection

Brute-force analysis looks for repeated authentication failures.

Example SPL:

```spl
index=auth action=failure
| bin _time span=5m
| stats count AS failures
        dc(username) AS users
        values(username) AS usernames
  BY _time src_ip
| where failures >= 10
| eval severity=if(failures>=20,"high","medium")
| sort - failures
```

## Analyst Questions

- Is the source internal or external?
- How many users were targeted?
- Did any login succeed?
- Was a privileged account involved?
- Was MFA used?
- Is the source associated with approved testing?
- Does the activity continue across multiple time windows?

---

# 🧠 MITRE ATT&CK

### T1110 — Brute Force

Brute Force includes adversary attempts to gain account access by repeatedly trying credentials.

The portfolio uses ATT&CK mapping to describe observed or simulated behavior, not to claim actor attribution.

---

# 🌧️ Password Spraying

Password spraying targets multiple users with a small number of password attempts per account.

This technique may avoid per-user lockout thresholds.

Example SPL:

```spl
index=auth action=failure
| bin _time span=10m
| stats count AS failures
        dc(username) AS distinct_users
        values(username) AS targeted_users
  BY _time src_ip
| where distinct_users >= 5
  AND failures >= 5
| eval severity="high"
```

### MITRE ATT&CK

**T1110.003 — Password Spraying**

---

# 🔑 Credential Stuffing

Credential stuffing attempts previously exposed username/password combinations against accounts.

The portfolio detection looks for:

- Multiple usernames
- Authentication failures
- Repeated source IP
- At least one successful authentication

Example SPL:

```spl
index=auth
| bin _time span=10m
| stats count(eval(action="failure")) AS failures
        count(eval(action="success")) AS successes
        dc(username) AS distinct_users
        values(username) AS users
  BY _time src_ip
| where failures >= 8
  AND distinct_users >= 3
  AND successes >= 1
| eval severity="high"
```

### MITRE ATT&CK

**T1110.004 — Credential Stuffing**

---

# 🚨 Failed Authentication Followed by Success

A successful login following repeated failures may represent a higher-risk authentication event.

Example investigation logic:

```spl
index=auth
| transaction username src_ip maxspan=10m
| search action=failure action=success
| eval severity="high"
| table _time username src_ip duration eventcount action auth_method geo device
```

This detection should be prioritized because a successful authentication can indicate that credential-guessing activity succeeded.

---

# 🌍 Impossible Travel / Abnormal Login

Impossible-travel detections identify rapid successful logins from geographically distant locations.

Example logic:

```spl
index=auth action=success
| sort 0 username _time
| streamstats current=f
    last(_time) AS prev_time
    last(geo) AS prev_geo
    last(src_ip) AS prev_ip
  BY username
| eval delta_minutes=round((_time-prev_time)/60,1)
| where isnotnull(prev_geo)
  AND geo!=prev_geo
  AND delta_minutes<=60
| eval severity="high"
| table _time username prev_geo geo prev_ip src_ip delta_minutes auth_method device
```

---

# ⚠️ Impossible-Travel Guardrails

Geographic distance alone does not prove compromise.

Analysts should evaluate:

- VPN use
- Corporate proxy
- Mobile carrier routing
- Managed-device identity
- MFA
- Authentication method
- User travel
- Cloud-provider IP ranges
- Post-login activity

---

# 💻 Suspicious PowerShell Detection

PowerShell is a legitimate administrative tool that can also be abused.

The portfolio detection focuses on potentially suspicious command patterns.

Example SPL:

```spl
index=endpoint
(process_name="powershell.exe" OR process_name="pwsh.exe")
| eval cmd=lower(command_line)
| where like(cmd,"%encodedcommand%")
    OR like(cmd,"%frombase64string%")
    OR like(cmd,"%downloadstring%")
| eval severity="high"
| table _time host user parent_process process_name command_line severity
```

### MITRE ATT&CK

**T1059.001 — PowerShell**

---

# 🧠 PowerShell Investigation Context

Before escalating, review:

- Parent process
- User
- Host role
- Script signature
- Script path
- Command line
- Network connections
- Child processes
- Persistence
- Credential access
- Approved automation tools

Examples of legitimate PowerShell include:

- Software deployment
- System administration
- Endpoint-management tooling
- Security automation
- Login scripts

---

# 🎣 Phishing Alert Investigation

The phishing alert workflow demonstrates Tier 1 investigation of suspicious email and identity activity.

The investigation process follows:

```text
Email Alert
    ↓
Review Sender / Domain
    ↓
Inspect URL / Attachment
    ↓
Determine Delivery Scope
    ↓
Check User Interaction
    ↓
Review Authentication
    ↓
Review Endpoint Activity
    ↓
Determine Disposition
    ↓
Contain
    ↓
Escalate
```

---

# 📧 Phishing Evidence Sources

Potential evidence includes:

- Email sender
- Reply-To address
- Domain
- Message headers
- Email authentication
- URL
- Attachment
- Sandbox result
- Click telemetry
- Login history
- MFA events
- Mailbox rules
- OAuth grants
- Endpoint events

---

# 🔐 Phishing Containment

Potential actions include:

- Block sender
- Block domain
- Block URL
- Remove malicious messages
- Revoke user sessions
- Reset credentials
- Require MFA validation
- Remove unauthorized forwarding rules
- Revoke malicious OAuth grants
- Investigate affected endpoint

---

# 🧠 MITRE ATT&CK — Phishing

Examples include:

| Technique | Description |
|---|---|
| **T1566.001** | Spearphishing Attachment |
| **T1566.002** | Spearphishing Link |

---

# 🧾 Alert Triage Documentation

Every Tier 1 investigation should document:

- Alert ID
- Detection name
- Timestamp
- Affected user
- Affected host
- Source IP
- Destination
- Severity
- Evidence reviewed
- Analyst findings
- IOCs
- ATT&CK mapping
- Scope
- Disposition
- Containment
- Escalation reason
- Handoff notes

---

# ✅ Alert Disposition

A major SOC responsibility is deciding what an alert actually represents.

The portfolio uses the following disposition categories:

## True Positive — Escalated

Malicious or unauthorized activity is confirmed and requires additional response.

## True Positive — Contained

Malicious activity is confirmed and containment has been completed within analyst authority.

## Benign Positive

The detection correctly identified the target behavior, but the activity is authorized.

Examples:

- Approved vulnerability scanner
- Authorized administrative script
- Corporate VPN behavior
- Approved security testing

## False Positive

Detection logic incorrectly classified non-target activity as suspicious.

## Informational

Useful context that does not require response action.

---

# 📊 Alert Disposition Examples

| Detection | Disposition | Analyst Rationale |
|---|---|---|
| Brute Force + Success | True Positive — Escalated | Failure burst followed by abnormal successful login |
| Password Spray | True Positive — Contained | Multiple users targeted from unauthorized source |
| Impossible Travel | Benign Positive | Approved VPN and same managed device explain geography |
| Suspicious PowerShell | Benign Positive | Approved signed deployment script |
| Service Account Failures | False Positive | Stale credential caused scheduled-job retry loop |
| Credential Stuffing | True Positive — Escalated | Multi-user failures and successful login |
| Blocked Phishing URL | Informational | Message blocked and no user interaction |
| Abnormal Login | True Positive — Escalated | Unknown device, password-only auth, no VPN explanation |

---

# 🔧 Detection Tuning

Detection tuning should improve signal quality without removing meaningful coverage.

Effective tuning may use:

- Approved scanner ranges
- Known VPN infrastructure
- Managed device context
- Signed scripts
- Approved parent processes
- Service-account metadata
- Maintenance windows
- Asset role
- User role

---

# ⚠️ Tuning Guardrails

Do not suppress activity simply because it is noisy.

A good tuning decision should document:

- Why the activity is benign
- Which evidence supports that conclusion
- What context is safe to suppress
- Who owns the exception
- Whether the exception expires
- How the detection was retested

---

# 🧪 Detection Testing & Validation

Detection engineering should include positive and benign test cases.

Example validation matrix:

| Test | Expected Result |
|---|---|
| 14 failures in <5 min | Brute-force alert |
| 3 failures over 20 min | No brute-force alert |
| 5 users targeted by same source | Password-spray alert |
| Multi-user failures + success | Credential-stuffing alert |
| Failures followed by success | High-priority alert |
| Known VPN geographic shift | Alert reviewed as benign after enrichment |
| Unknown device + distant login | High-severity abnormal-login alert |
| Approved PowerShell deployment | Benign positive |
| Word → encoded PowerShell | High-severity endpoint alert |

---

# 📈 SOC Investigation Timeline

A strong investigation should preserve analyst actions chronologically.

Example:

```text
09:02 — Alert generated
09:04 — Tier 1 acknowledged
09:07 — Source IP reviewed
09:10 — Authentication history analyzed
09:13 — Successful login correlated
09:16 — Device and geography reviewed
09:19 — Scope expanded
09:22 — Severity raised
09:25 — Containment recommended
09:28 — Tier 2 escalation completed
```

---

# 🧾 Tier 2 Handoff Standard

A good escalation should allow the receiving analyst to continue without repeating Tier 1 work.

Handoff should include:

- Alert ID
- Detection
- Severity
- Analyst disposition
- Affected identity / asset
- Evidence
- Timeline
- IOCs
- Scope
- Containment completed
- ATT&CK mapping
- Remaining questions
- Requested Tier 2 actions

---

# 🚦 SOC Severity Model

| Severity | Criteria | Example |
|---|---|---|
| **Critical** | Active widespread compromise, major business impact, sensitive-data exposure | Widespread ransomware or destructive admin compromise |
| **High** | Confirmed malicious activity or strong compromise evidence | Successful brute force, phishing compromise, suspicious PowerShell with persistence |
| **Medium** | Suspicious activity requiring investigation | Failure-only brute force or isolated suspicious connection |
| **Low** | Informational, blocked, or known benign activity | Known scanner or blocked probe |

---

# 🚨 Escalation Criteria

Escalate regardless of initial alert severity when there is evidence of:

- Privileged account involvement
- Successful unauthorized authentication
- Persistence
- Lateral movement
- Credential access
- Remote execution
- Sensitive-data access
- Data exfiltration
- Multiple users or systems
- High business impact
- Anti-forensics
- Ongoing threat activity

---

# 📊 Splunk Dashboard Design

The SIEM dashboard is designed to help analysts quickly identify authentication and threat patterns.

Suggested panels include:

## Failed Logins Over Time

```spl
index=auth action=failure
| timechart span=15m count
```

## Top Failed Login Source IPs

```spl
index=auth action=failure
| stats count AS failures
        dc(username) AS users
  BY src_ip
| sort - failures
```

## Top Targeted Users

```spl
index=auth action=failure
| stats count AS failures
  BY username
| sort - failures
```

## Failures Followed by Success

```spl
index=auth
| transaction username src_ip maxspan=10m
| search action=failure action=success
| table _time username src_ip duration eventcount action
```

## Distinct Users Per Source

```spl
index=auth action=failure
| stats count AS failures
        dc(username) AS distinct_users
  BY src_ip
| sort - distinct_users
```

---

# 📈 SOC Metrics

Useful SOC metrics include:

## Alert Operations

- Mean Time to Acknowledge
- Mean Time to Disposition
- High-severity alerts open
- Alert backlog
- Backlog aging

## Detection Quality

- False-positive rate
- Benign-positive rate
- True-positive rate
- Escalation rate
- Detection coverage

## Triage Quality

- Complete alert documentation
- Correct severity assignment
- Investigation completeness
- Handoff completeness

---

# 🎯 Example Program Targets

| KPI | Example Target |
|---|---|
| High-Severity Mean Time to Acknowledge | **< 10 minutes** |
| High-Severity Mean Time to Disposition | **< 45 minutes** |
| High-Severity Alerts Older Than 4 Hours | **0** |
| Detection False-Positive Rate | **<20% after tuning** |
| Priority Log-Source Coverage | **100%** |
| Tier 1 Escalation Completeness | **≥95%** |

> These are simulated portfolio targets used to demonstrate security-operations measurement.

---

# 🧩 Log Sources

A mature SOC depends on visibility across multiple security technologies.

Relevant log sources include:

- Identity Provider
- Active Directory
- Windows Event Logs
- Endpoint Detection & Response
- Firewall
- DNS
- Web Application Firewall
- Proxy
- VPN
- Cloud Audit Logs
- SaaS Security Logs
- Application Logs
- Email Security Gateway
- Backup Platform

---

# 🗄️ Authentication Log Analysis

Authentication telemetry is used throughout this portfolio to investigate:

- Failed logins
- Repeated failures
- Successful authentication
- Source-IP behavior
- Multiple targeted users
- MFA
- Authentication method
- Device identity
- Geography
- Time of access

---

# 📁 Synthetic Authentication Dataset

The included authentication dataset demonstrates scenarios such as:

- Normal successful authentication
- Brute force
- Password spraying
- Credential stuffing
- Failed login followed by successful login
- Impossible travel
- Password-only abnormal login

The dataset is synthetic and contains no real employer or user telemetry.

---

# 🧠 Data Fields

Example fields include:

```text
timestamp
username
src_ip
action
auth_method
geo
device
```

These fields allow correlation across:

> **Identity → Source → Result → Authentication Method → Geography → Device → Time**

---

# 🌐 Wireshark & Network Analysis

The SOC portfolio also includes network-analysis concepts using Wireshark-style evidence.

Network investigations may examine:

- Source IP
- Destination IP
- DNS
- TCP
- UDP
- ICMP
- Ports
- Protocols
- Connection timing
- Packet frequency
- Suspicious destinations

---

# 🔍 Network-to-SIEM Correlation

Network evidence becomes more useful when correlated with:

```text
Firewall
   +
DNS
   +
Endpoint
   +
Authentication
   +
SIEM
   ↓
Higher-Confidence Investigation
```

---

# 📋 Tier 1 Investigation Runbook

The standard investigation process follows seven stages.

## 1. Acknowledge & Validate

- Confirm alert details
- Review underlying events
- Verify timestamp
- Identify user or asset
- Confirm severity

## 2. Establish Context

- Review baseline behavior
- Check device
- Check location
- Check role
- Check asset criticality

## 3. Scope

- Search source IP across users
- Search user across IPs
- Review related hosts
- Review related alerts
- Search indicators

## 4. Determine Disposition

- True Positive
- Benign Positive
- False Positive
- Informational

## 5. Contain / Escalate

- Block indicators
- Revoke sessions
- Disable accounts
- Isolate endpoint
- Remove malicious mail
- Escalate to Tier 2 / IR

## 6. Document

- Evidence
- Findings
- Timeline
- Severity
- Disposition
- ATT&CK
- Containment
- Handoff

## 7. Close / Hand Off

- Confirm disposition
- Document what was searched
- Recommend tuning
- Provide next analyst with complete context

---

# 🧠 Analyst Triage Questions

During every alert investigation, ask:

1. What triggered the alert?
2. Is the underlying telemetry valid?
3. What user or asset is involved?
4. Is the account privileged?
5. Is the system business-critical?
6. Is there evidence of successful compromise?
7. Is MFA present?
8. Is the device recognized?
9. Is the location expected?
10. Are other accounts affected?
11. Is there suspicious post-login activity?
12. What disposition is supported by evidence?
13. Should containment occur?
14. Should the case be escalated?
15. Does the detection need tuning?

---

# 🧠 MITRE ATT&CK Usage

MITRE ATT&CK is used throughout this portfolio to organize observed or simulated behavior.

Examples include:

| Technique | Description |
|---|---|
| **T1110** | Brute Force |
| **T1110.003** | Password Spraying |
| **T1110.004** | Credential Stuffing |
| **T1059.001** | PowerShell |
| **T1566.001** | Spearphishing Attachment |
| **T1566.002** | Spearphishing Link |

---

# ⚠️ ATT&CK Mapping Principles

- ATT&CK describes behavior.
- ATT&CK does not establish actor identity.
- A tool alone does not prove a technique.
- Map only activity supported by evidence.
- Use broader tactic-level mapping when evidence is incomplete.
- Document confidence and investigation gaps.

---

# 💼 SOC Analyst Skills Demonstrated

This portfolio demonstrates my ability to:

- Analyze SIEM alerts
- Search authentication logs
- Write Splunk SPL
- Detect brute force
- Detect password spraying
- Detect credential stuffing
- Correlate failures with successful login
- Investigate impossible travel
- Investigate suspicious PowerShell
- Investigate phishing
- Review IOCs
- Determine alert severity
- Assign alert disposition
- Distinguish true positives and false positives
- Identify benign positives
- Tune detections
- Build investigation timelines
- Scope users and assets
- Document analyst findings
- Recommend containment
- Escalate incidents
- Prepare Tier 2 handoffs
- Develop SOC metrics
- Use MITRE ATT&CK
- Correlate SIEM, identity, endpoint, and network evidence

---

# 🧰 Technical Skills & Tools

## SIEM & Security Operations

`Splunk Enterprise` • `SIEM` • `SOC Workflow` • `Alert Triage` • `Incident Escalation`

## Detection

`Brute Force Detection` • `Password Spraying` • `Credential Stuffing` • `Impossible Travel` • `Suspicious PowerShell`

## Splunk

`SPL` • `stats` • `timechart` • `transaction` • `streamstats` • `search` • `table`

## Security Analysis

`Log Correlation` • `IOC Analysis` • `Authentication Analysis` • `Network Analysis`

## Network Security

`Wireshark` • `PCAP Analysis` • `Firewall Logs` • `DNS Analysis`

## Frameworks

`MITRE ATT&CK` • `Incident Response Concepts` • `Security Operations`

---

# 🎯 Target Role Alignment

This section demonstrates skills relevant to:

- **SOC Analyst I**
- **Tier 1 SOC Analyst**
- **Security Operations Analyst**
- **Cybersecurity Analyst**
- **Information Security Analyst**
- **SIEM Analyst**
- **Junior Detection Analyst**
- **Junior Threat Hunter**
- **Incident Response Analyst**
- **Cyber Defense Analyst**

---

# 🔗 Related Portfolio Sections

This SOC work connects to the broader cybersecurity portfolio.

## 🚨 Incident Response & Forensics

SOC alerts escalate into deeper incident-response investigations, containment, evidence handling, and recovery.

## 🛡️ Governance & Risk (GRC)

Provides risk, controls, policies, ownership, and remediation governance.

## ⚙️ System & Automation

Supports SOC operations through Linux security, Python automation, Bash, SQL, and log processing.

## 🏆 Capstone Integration

Integrates SOC monitoring with IAM, vulnerability management, incident response, GRC, and executive reporting.

## 🎓 Career & Professional Development

Supports framework knowledge and analyst-readiness development.

---

# 🧠 Key SOC Principles

### Alerts Are Starting Points

An alert is not automatically an incident.

### Evidence Determines Disposition

Analysts should distinguish:

- True Positive
- Benign Positive
- False Positive
- Informational

### Successful Authentication Matters

Repeated failures become higher priority when followed by successful access.

### Context Reduces Noise

User, device, MFA, location, asset role, and business context improve investigation quality.

### Detection Tuning Is Continuous

Rules should improve as analysts learn from dispositions.

### Escalations Must Be Complete

Tier 2 should not have to repeat Tier 1 triage.

### Metrics Should Measure Quality

Alert count alone does not measure SOC effectiveness.

---

# 🔄 Complete SOC Workflow

```text
COLLECT
   ↓
DETECT
   ↓
ALERT
   ↓
VALIDATE
   ↓
ENRICH
   ↓
SCOPE
   ↓
DISPOSITION
   ↓
CONTAIN
   ↓
ESCALATE / CLOSE
   ↓
TUNE
```

---

# ⚠️ Portfolio Integrity

This section contains **simulated SOC, SIEM, alert-triage, detection, and security-monitoring work** created for portfolio and professional-development purposes.

Unless explicitly stated otherwise:

- Authentication logs are synthetic.
- Users, systems, IP addresses, devices, and locations are simulated.
- Documentation-range IP addresses are used where appropriate.
- Domains are example or defanged domains.
- Alert timelines are simulated.
- Detection thresholds are portfolio/lab starting points rather than universal production thresholds.
- ATT&CK mappings describe behavior and do not claim threat-actor attribution.
- No production SOC employment is claimed.
- No live customer threat-monitoring experience is claimed.
- No employer incident-response outcomes are claimed.

The purpose of this section is to demonstrate how I would **write detection logic, analyze security telemetry, investigate alerts, determine severity and disposition, recommend containment, escalate incidents, and improve detections in a SOC analyst environment**.

---

# 👤 About the Analyst

## Jamie Christian II

Cybersecurity professional focused on:

**SOC Operations • SIEM • Threat Detection • Incident Response • Security Analytics • Security Automation**

My portfolio emphasizes evidence-driven, interview-defensible cybersecurity work that demonstrates how logs, detections, analyst judgment, escalation, and response work together in a security operations environment.

### Connect

- **GitHub:** [github.com/JamieChristian22](https://github.com/JamieChristian22)
- **LinkedIn:** [linkedin.com/in/jamiechristian2](https://www.linkedin.com/in/jamiechristian2/)
- **Email:** [jamiechristian331@gmail.com](mailto:jamiechristian331@gmail.com)

---

# 🖥️ SOC Analyst Philosophy

### `DETECT → VALIDATE → INVESTIGATE → DECIDE → RESPOND → IMPROVE`

**This section demonstrates how SIEM telemetry, Splunk detection logic, analyst investigation, alert disposition, incident escalation, and continuous detection tuning work together in Security Operations.**

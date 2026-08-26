# ⚙️ System & Automation

## Linux Security, Python Automation, Bash Scripting & SQL Security Analytics

**Jamie Christian II | Cybersecurity Analyst Portfolio**

This section demonstrates practical **systems security, Linux hardening, security automation, scripting, SQL analysis, validation, and operational runbook development** through reproducible cybersecurity portfolio projects.

The goal is to show how a Cybersecurity Analyst or Security Operations Analyst can use **Linux, Python, Bash, SQL, structured logging, testing, and automation** to reduce repetitive work, improve consistency, validate security controls, and support investigations.

The core workflow demonstrated throughout this section is:

> **Assess → Automate → Validate → Log → Test → Review → Improve**

---

# 📌 Section Purpose

Security analysts frequently work with systems, logs, scripts, configuration data, and repetitive operational tasks.

This section focuses on applying automation and systems knowledge to questions such as:

- Is a Linux system securely configured?
- Are privileged accounts appropriately restricted?
- Are file permissions aligned with least privilege?
- Are unnecessary services exposed?
- Are allow-list entries valid and authorized?
- Can repetitive security-review steps be automated safely?
- Can security logs be queried efficiently?
- Can authentication activity be converted into actionable alerts?
- Are automation scripts tested and logged?
- Is there a rollback or validation process after automation runs?

This portfolio section demonstrates those capabilities with reproducible technical artifacts.

---

# 🗂️ System & Automation Deliverables

| # | Deliverable | Primary Focus |
|---|---|---|
| 01 | **Linux Security Hardening Assessment** | SSH, accounts, firewall, services, logging, patch posture |
| 02 | **Linux File Permissions & Least Privilege** | chmod, chown, ownership, groups, access validation |
| 03 | **Python IP Allow-List Automation** | IPv4 validation, CIDR checks, duplicates, logging, dry-run |
| 04 | **Bash Linux Security Audit** | Automated host-security evidence collection |
| 05 | **SQL Security Log Analysis** | Authentication queries, anomalies, incident-window analysis |
| 06 | **Python Log Parser & Alert Generator** | CSV parsing, time windows, security alerts |
| 07 | **Automation Testing & Error Handling** | Tests, validation, safe failure behavior |
| 08 | **System Hardening Checklist** | Operational hardening review and closure evidence |
| 09 | **Security Automation Runbook** | Safe execution, validation, rollback, maintenance |
| 10 | **Recruiter Quick View** | Fast overview of systems and automation capabilities |

---

# 🐧 Linux Security Hardening

The Linux hardening work demonstrates a structured system-security assessment.

The review process follows:

```text
System Inventory
      ↓
Account Review
      ↓
Privilege Review
      ↓
SSH Review
      ↓
Firewall Review
      ↓
Service Review
      ↓
File Permission Review
      ↓
Logging Review
      ↓
Patch Review
      ↓
Validation
```

---

# 🔐 Linux Security Control Areas

The portfolio evaluates security areas such as:

- Privileged accounts
- UID 0 accounts
- sudo access
- SSH root login
- Password authentication
- Public-key authentication
- Firewall status
- Listening ports
- Enabled services
- World-writable files
- File ownership
- Logging
- Patch posture
- Scheduled tasks
- Disk utilization
- Account changes

---

# 📋 Linux Hardening Assessment Structure

A practical system-hardening review should capture:

| Field | Purpose |
|---|---|
| Control Area | What is being evaluated |
| Review Command | How the analyst validates it |
| Current State | What was observed |
| Risk | Security concern |
| Recommendation | Required improvement |
| Validation | How closure is confirmed |

---

# 🧪 Example Linux Hardening Review

| Control Area | Evidence / Command | Simulated State | Risk | Recommendation |
|---|---|---|---|---|
| UID 0 Accounts | `/etc/passwd` review | Only root has UID 0 | Low | Maintain single authorized UID 0 account |
| SSH Root Login | `sshd_config` | `PermitRootLogin no` | Low | Keep root SSH login disabled |
| Password Authentication | `sshd_config` | Disabled | Low | Continue using public-key authentication |
| Firewall | `ufw` / `firewalld` | Active | Low | Maintain default-deny and required rules |
| Listening Services | `ss -tuln` | Required services only | Medium | Remove unnecessary listeners |
| World-Writable Files | `find ... -perm -0002` | No unexpected findings | Low | Continue recurring review |
| Logging | `rsyslog` / `journald` | Enabled | Medium | Forward critical logs centrally |
| Patching | Package manager review | Current in lab | Medium | Maintain risk-based patch SLA |
| Scheduled Tasks | cron review | Approved tasks only | Low | Monitor for unauthorized changes |

---

# 🛡️ Linux Hardening Priorities

Security hardening should focus first on:

1. Administrative access
2. Privileged accounts
3. SSH configuration
4. Network exposure
5. File permissions
6. Logging
7. Patch management
8. Unnecessary services
9. Scheduled-task review
10. Configuration validation

---

# 🔑 SSH Security

SSH is a common administrative entry point and should be hardened carefully.

Recommended controls include:

- Disable direct root login
- Use public-key authentication
- Restrict password authentication where feasible
- Reduce authentication retries
- Restrict administrative source networks
- Monitor authentication failures
- Log administrative sessions
- Use least-privileged administrative accounts

---

# 👤 Privileged Account Review

Analysts should review:

- UID 0 accounts
- sudo group membership
- Administrative accounts
- Service accounts
- Dormant privileged accounts
- Shared accounts
- Unnecessary standing privilege

A strong privileged-access model supports:

> **Named Account → Least Privilege → Strong Authentication → Logging → Periodic Review**

---

# 🔥 Firewall & Network Exposure

Host firewall review should determine:

- Is the firewall enabled?
- Which ports are open?
- Which services are listening?
- Which sources can connect?
- Are administrative ports restricted?
- Are unused services exposed?
- Does the configuration match business requirements?

Example review commands may include:

```bash
ss -tuln
ufw status
firewall-cmd --list-all
```

---

# 📁 Linux File Permissions & Least Privilege

The file-permission project demonstrates access-control review using:

- `ls -l`
- `stat`
- `chmod`
- `chown`
- User ownership
- Group ownership
- Least privilege

The goal is to ensure users and services receive only the access required for their role.

---

# 🔢 Linux Permission Model

Linux file permissions use:

```text
OWNER
GROUP
OTHER
```

Each can receive:

```text
r = Read
w = Write
x = Execute
```

Numeric values include:

```text
4 = Read
2 = Write
1 = Execute
```

Examples:

```text
600 = Owner read/write
640 = Owner read/write + Group read
660 = Owner and Group read/write
750 = Owner full + Group read/execute
```

---

# 🧩 Example Permission Scenarios

| File / Directory | Security Requirement | Recommended Mode |
|---|---|---|
| Application configuration | Root read/write; application group read | `640` |
| Startup script | Root full; application group execute | `750` |
| Application logs | Service write; security group read | `640` |
| Sensitive export | Owner only | `600` |
| Shared analyst report | Team read/write; no public access | `660` |

---

# 🧠 File Permission Review Questions

Analysts should ask:

- Who owns this file?
- Which group owns it?
- Who needs read access?
- Who needs write access?
- Who needs execute access?
- Is the file world-readable?
- Is the file world-writable?
- Does the current access follow least privilege?
- Are setuid or setgid permissions present?
- Could an attacker modify this file?

---

# 🐍 Python Security Automation

Python is used to automate repetitive security tasks and process security data.

The portfolio includes:

- IP allow-list automation
- Log parsing
- Authentication alert generation
- Input validation
- Structured output
- Logging
- Testing
- Error handling

---

# 🌐 Python IP Allow-List Automation

The IP allow-list project automates repetitive review of network access entries.

The workflow is:

```text
Read Allow List
      ↓
Validate IP Address
      ↓
Normalize Entry
      ↓
Check Duplicate
      ↓
Check Approved CIDR
      ↓
Approve / Remove
      ↓
Write Updated List
      ↓
Generate Log
      ↓
Generate Summary
```

---

# ✅ Automation Capabilities

The script demonstrates:

- IPv4 parsing
- CIDR membership checks
- Duplicate removal
- Invalid-entry detection
- Unauthorized-entry detection
- Output generation
- Structured logging
- JSON summary
- Dry-run concepts
- Deterministic output
- Unit-style testing

---

# 📁 Python Allow-List Files

Technical evidence includes:

```text
python/ip_allowlist_manager.py

data/sample_allowlist.txt

data/approved_networks.txt

outputs/updated_allowlist.txt

outputs/allowlist_change_summary.json

outputs/allowlist_automation.log

tests/test_ip_allowlist_manager.py
```

---

# 🧪 Example Allow-List Decisions

| Entry | Decision | Reason |
|---|---|---|
| `10.10.10.15` | Approved | Inside authorized CIDR |
| `10.10.10.21` | Approved | Inside authorized CIDR |
| `10.10.20.5` | Approved | Inside authorized CIDR |
| Duplicate valid IP | Removed | Duplicate entry |
| Unauthorized external IP | Removed | Outside approved networks |
| Malformed value | Removed | Invalid IPv4 format |

---

# 🛡️ Security Automation Guardrails

Automation should never make uncontrolled changes.

Good automation should include:

- Input validation
- Logging
- Dry-run capability
- Backups
- Error handling
- Testing
- Least privilege
- Output review
- Change summaries
- Rollback procedures

---

# 🧠 Why Dry-Run Matters

A dry-run allows analysts to review proposed changes without applying them.

The workflow becomes:

```text
Input
   ↓
Evaluate
   ↓
Generate Proposed Changes
   ↓
Human Review
   ↓
Approve
   ↓
Apply
```

This reduces the risk of unintended security changes.

---

# 🐚 Bash Linux Security Audit

The Bash security-audit script provides repeatable host-security evidence collection.

It reviews:

- System information
- Effective user
- Listening ports
- Firewall status
- SSH configuration
- UID 0 accounts
- World-writable files
- Enabled services
- Disk utilization
- Recent account entries

---

# 🖥️ Bash Security Audit Workflow

```text
Run Script
    ↓
Collect System Evidence
    ↓
Review Exposure
    ↓
Identify Abnormal State
    ↓
Document Finding
    ↓
Recommend Remediation
    ↓
Validate Change
```

---

# 📜 Example Bash Review Areas

| Check | Security Value |
|---|---|
| Listening Ports | Identifies exposed services |
| Firewall Status | Validates host filtering |
| SSH Configuration | Reviews administrative access |
| UID 0 Accounts | Identifies root-equivalent accounts |
| World-Writable Files | Finds tampering opportunities |
| Enabled Services | Measures attack surface |
| Disk Usage | Protects availability and logging |
| Account Review | Detects unauthorized account changes |

---

# 🧠 Bash Automation Design Principles

The audit script is intentionally read-only.

It does not automatically remediate findings.

This allows the analyst to:

- Review evidence
- Assess business impact
- Confirm system dependencies
- Approve remediation
- Validate changes afterward

---

# 🗄️ SQL Security Analytics

SQL is used to analyze structured authentication and security-log data.

The portfolio includes queries for:

- Failed logins
- Off-hours authentication
- Repeated failures
- Source-IP aggregation
- User targeting
- Successful login after failures
- Unusual geography
- Incident windows
- Top source IPs

---

# 📊 SQL Investigation Workflow

```text
Security Dataset
      ↓
Filter Events
      ↓
Aggregate
      ↓
Identify Pattern
      ↓
Correlate User / Source / Time
      ↓
Determine Risk
      ↓
Investigate Further
```

---

# 🔍 Failed Login Query

Example:

```sql
SELECT
    timestamp,
    username,
    src_ip,
    geo
FROM auth_events
WHERE action = 'failure'
ORDER BY timestamp;
```

---

# 🌙 Off-Hours Authentication

Example:

```sql
SELECT
    timestamp,
    username,
    src_ip,
    geo
FROM auth_events
WHERE action = 'success'
  AND (
      CAST(strftime('%H', timestamp) AS INTEGER) < 6
      OR CAST(strftime('%H', timestamp) AS INTEGER) >= 22
  )
ORDER BY timestamp;
```

Off-hours activity is not automatically malicious.

Analysts should consider:

- User role
- Business hours
- Time zone
- Travel
- VPN
- Scheduled work
- Maintenance windows

---

# 🚨 Repeated Failures by Source IP

Example:

```sql
SELECT
    src_ip,
    COUNT(*) AS failure_count,
    COUNT(DISTINCT username) AS targeted_users
FROM auth_events
WHERE action = 'failure'
GROUP BY src_ip
HAVING COUNT(*) >= 4
ORDER BY failure_count DESC;
```

This can help identify:

- Brute force
- Password spraying
- Misconfigured systems
- Automated testing
- Service-account failures

---

# 🔐 Successful Login After Failures

A successful authentication after repeated failures should receive higher priority.

Example investigation logic:

```text
Repeated Failures
       ↓
Same User
       ↓
Same Source
       ↓
Successful Authentication
       ↓
Review Device / MFA / Geography
       ↓
Determine Compromise Risk
```

---

# 📍 Incident Window Analysis

SQL can narrow large datasets to a specific investigation period.

Example:

```sql
SELECT *
FROM auth_events
WHERE timestamp BETWEEN
      '2026-08-21T02:00:00'
      AND
      '2026-08-21T02:30:00'
ORDER BY timestamp;
```

This helps build incident timelines.

---

# 📁 SQL Evidence

Included technical files may include:

```text
sql/security_log_queries.sql

data/security_events.csv

data/security_logs.db

outputs/sql_query_results.txt
```

---

# 🤖 Python Log Parser & Alert Generator

The Python log parser demonstrates simple security-event automation outside a SIEM platform.

The script:

- Reads authentication events
- Sorts events by time
- Tracks repeated failures
- Uses time windows
- Generates alert records
- Writes structured JSON output

---

# 🚨 Example Alert Logic

## Repeated Authentication Failures

Trigger:

```text
5 Failures
Same User
Same Source
Within 5 Minutes
```

Result:

```text
Severity: Medium
```

---

# 🔥 Failures Followed by Success

Trigger:

```text
3+ Recent Failures
        ↓
Successful Login
        ↓
Same User + Source
```

Result:

```text
Severity: High
```

This logic raises priority because account compromise becomes more plausible.

---

# 📁 Python Log Parser Evidence

```text
python/security_log_parser.py

data/auth_events_for_parser.csv

outputs/generated_alerts.json
```

---

# 🧪 Automation Testing

Security automation should be tested before it is trusted.

The portfolio includes tests covering:

- Valid input
- Invalid input
- Duplicate input
- Unauthorized input
- Expected output
- Error behavior
- Detection thresholds

---

# ✅ Example Test Cases

| Test | Expected Result |
|---|---|
| Valid IP inside approved CIDR | Approved |
| Duplicate valid IP | Duplicate removed |
| Valid IP outside approved network | Unauthorized |
| Invalid IP string | Rejected |
| 5 authentication failures | Medium alert |
| Failures followed by success | High alert |
| SQL repeated failure query | Expected aggregation returned |
| Missing optional Linux tool | Audit script continues safely |

---

# 🧠 Testing Principles

Automation testing should confirm:

- Correct output
- Correct failure behavior
- Safe handling of malformed input
- Deterministic behavior
- No silent data loss
- Logging accuracy
- Validation after changes

---

# ⚠️ Error Handling

Good security automation should fail safely.

Examples include:

- Required CLI arguments
- File-existence checks
- Input validation
- Exception handling
- Clear error messages
- Logging
- Controlled exits
- No silent failures

---

# 📋 System Hardening Checklist

The hardening checklist supports repeatable operational review.

Example domains include:

| Domain | Review |
|---|---|
| Accounts | Privileged users reviewed |
| SSH | Root login disabled |
| Authentication | Secure authentication configured |
| Network | Firewall enabled |
| Services | Unnecessary services disabled |
| Files | World-writable files reviewed |
| Logging | Security logs retained |
| Patching | Critical updates tracked |
| Cron | Scheduled tasks authorized |
| Recovery | Security configurations backed up |
| Monitoring | Configuration drift detectable |

---

# ✅ Hardening Closure Evidence

A security finding should not be considered closed solely because a task is marked complete.

Closure should include evidence such as:

- Command output
- Configuration file
- File permissions
- Port scan
- Firewall rules
- Service state
- Patch report
- Log event
- Test result

---

# 📖 Security Automation Runbook

Automation should be operated consistently and safely.

The runbook follows:

```text
PRE-RUN
   ↓
VALIDATE INPUT
   ↓
DRY RUN / TEST
   ↓
EXECUTE
   ↓
LOG
   ↓
VALIDATE OUTPUT
   ↓
REVIEW
   ↓
ROLLBACK IF NEEDED
   ↓
DOCUMENT
```

---

# 🔵 Pre-Run

Before automation:

- Confirm script version
- Confirm owner
- Confirm input
- Confirm output location
- Confirm required permissions
- Review change scope
- Test with non-production data

---

# 🟠 Execution

During execution:

- Use least privilege
- Capture output
- Log failures
- Do not hard-code secrets
- Stop on unexpected conditions
- Protect source data

---

# 🟢 Post-Run

After execution:

- Review output
- Compare before and after
- Validate system behavior
- Confirm expected changes
- Preserve logs
- Record issues
- Escalate unexpected results

---

# 🔄 Rollback

Rollback planning should include:

- Prior file/configuration backup
- Version control
- Known-good configuration
- Documented restore steps
- Evidence retention
- Root-cause review after failed run

---

# 📈 Security Automation Metrics

Useful automation metrics include:

- Successful run rate
- Failed run count
- Invalid input count
- Unauthorized entries identified
- Validation failures
- Number of manual interventions
- Test pass rate
- Script-error trends

Metrics should support quality, not inflated productivity claims.

---

# 🧰 Technical Skills Demonstrated

## Linux

`Linux` • `SSH` • `chmod` • `chown` • `File Permissions` • `System Hardening` • `Firewall Review` • `Service Review`

## Python

`Python` • `ipaddress` • `CSV Processing` • `JSON` • `Logging` • `Input Validation` • `Automation`

## Bash

`Bash` • `Shell Scripting` • `System Commands` • `Security Auditing` • `Evidence Collection`

## SQL

`SQL` • `SQLite` • `Filtering` • `Aggregation` • `Security Analytics` • `Incident Analysis`

## Automation

`Testing` • `Error Handling` • `Dry Run` • `Validation` • `Rollback` • `Operational Runbooks`

## Security Operations

`Authentication Analysis` • `Alert Generation` • `System Review` • `Least Privilege` • `Log Analysis`

---

# 📁 Reproducible Technical Evidence

This section includes actual technical artifacts rather than only project descriptions.

## Python

```text
python/ip_allowlist_manager.py
python/security_log_parser.py
```

## Bash

```text
bash/linux_security_audit.sh
```

## SQL

```text
sql/security_log_queries.sql
```

## Data

```text
data/sample_allowlist.txt
data/approved_networks.txt
data/security_events.csv
data/security_logs.db
data/auth_events_for_parser.csv
```

## Outputs

```text
outputs/updated_allowlist.txt
outputs/allowlist_change_summary.json
outputs/allowlist_automation.log
outputs/linux_security_audit_report.txt
outputs/sql_query_results.txt
outputs/generated_alerts.json
outputs/test_results.txt
```

## Tests

```text
tests/test_ip_allowlist_manager.py
```

---

# 💼 Security Analyst Skills Demonstrated

This portfolio demonstrates my ability to:

- Review Linux security configurations
- Apply least-privilege principles
- Analyze file permissions
- Review SSH hardening
- Review firewall status
- Identify exposed services
- Identify risky file permissions
- Automate security tasks with Python
- Write Bash security-audit scripts
- Analyze authentication logs with SQL
- Build simple alert-generation logic
- Validate IP addresses and CIDR networks
- Create structured logs
- Generate JSON output
- Handle invalid input
- Test security automation
- Document validation
- Create hardening checklists
- Develop automation runbooks
- Plan rollback
- Translate technical findings into remediation

---

# 🎯 Target Role Alignment

This section demonstrates skills relevant to:

- **Cybersecurity Analyst**
- **Security Operations Analyst**
- **SOC Analyst I**
- **Information Security Analyst**
- **Junior Security Automation Analyst**
- **Junior Systems Security Analyst**
- **Cloud Security Analyst**
- **Security Support Analyst**
- **Systems Administrator / Security-Focused**
- **Junior Detection Analyst**

---

# 🔗 Related Portfolio Sections

This System & Automation work supports the broader cybersecurity portfolio.

## 🖥️ SOC, SIEM & Alert Handling

Python, SQL, and log-processing capabilities support alert triage and detection analysis.

## 🚨 Incident Response & Forensics

System evidence, logs, automation, and Linux analysis support security investigations.

## 🛡️ Governance & Risk (GRC)

Technical validation supports control assessment, remediation, and evidence collection.

## 🏆 Capstone Integration

Systems security and automation are integrated into the broader enterprise security program.

## 🎓 Career & Professional Development

Supports continued development across scripting, systems, cloud, and security operations.

---

# 🧠 Key System & Automation Principles

### Automate Repetition, Not Judgment

Automation should reduce repetitive work without replacing analyst decision-making.

### Validate Before Change

Automation should include review and testing before modifying security-sensitive data.

### Least Privilege Applies to Scripts Too

Scripts should run with only the permissions they need.

### Logging Matters

A security automation process should record:

- What happened
- When it happened
- What changed
- What failed

### Test Edge Cases

Security inputs are rarely perfect.

Scripts should handle:

- Missing data
- Invalid values
- Duplicates
- Unauthorized values
- Missing dependencies

### Reproducibility Builds Credibility

Technical portfolio claims are stronger when recruiters can open the code, data, output, and tests.

---

# 🔄 Complete Systems Security Workflow

```text
ASSESS
   ↓
IDENTIFY GAP
   ↓
AUTOMATE
   ↓
TEST
   ↓
EXECUTE
   ↓
VALIDATE
   ↓
LOG
   ↓
REVIEW
   ↓
IMPROVE
```

---

# ⚠️ Portfolio Integrity

This section contains **simulated systems-security, Linux, Python, Bash, SQL, and automation work** created for portfolio and professional-development purposes.

Unless explicitly stated otherwise:

- Systems and hostnames are simulated.
- IP addresses use private or documentation ranges.
- Security datasets are synthetic.
- Audit outputs are lab examples.
- Scripts are portfolio security-operations tools.
- No production infrastructure is represented.
- No employer systems were modified.
- No production automation engineering experience is claimed.
- No unsupported productivity percentage or business-impact metric is claimed.

The purpose of this section is to demonstrate how I would **review systems, analyze logs, automate repetitive security tasks, validate output, test scripts, document evidence, and support security operations in a cybersecurity analyst environment**.

---

# 👤 About the Analyst

## Jamie Christian II

Cybersecurity professional focused on:

**Systems Security • Security Automation • Security Operations • Threat Detection • Incident Response • Risk Management**

My portfolio emphasizes reproducible, interview-defensible technical work that demonstrates how system security, scripting, log analysis, testing, and automation support broader cybersecurity operations.

### Connect

- **GitHub:** [github.com/JamieChristian22](https://github.com/JamieChristian22)
- **LinkedIn:** [linkedin.com/in/jamiechristian2](https://www.linkedin.com/in/jamiechristian2/)
- **Email:** [jamiechristian331@gmail.com](mailto:jamiechristian331@gmail.com)

---

# ⚙️ System & Automation Philosophy

### `ASSESS → AUTOMATE → TEST → VALIDATE → IMPROVE`

**This section demonstrates how Linux security, Python, Bash, SQL, testing, validation, and operational automation work together to support secure and repeatable cybersecurity operations.**

# 🚨 Incident Response & Forensics

## Cybersecurity Incident Investigation, Evidence Handling & Response Operations

**Jamie Christian II | Cybersecurity Analyst Portfolio**

This section demonstrates practical **Incident Response (IR), SOC escalation, digital evidence handling, network forensics, endpoint investigation, incident documentation, and post-incident analysis** through completed simulated cybersecurity investigations and operational playbooks.

The goal is to show how a cybersecurity analyst can move from an alert or suspicious event through investigation, containment, recovery, and lessons learned using a structured, evidence-driven process.

The core workflow demonstrated throughout this section is:

> **Alert → Triage → Evidence → Scope → Severity → Investigation → Containment → Eradication → Recovery → Root Cause → Corrective Actions**

---

# 📌 Section Purpose

Incident Response is more than reacting to an alert.

A strong response process requires analysts to determine:

- What happened?
- When did it happen?
- Which users, systems, and data were affected?
- Is malicious activity confirmed or only suspected?
- Is the threat still active?
- What evidence supports the conclusion?
- How severe is the incident?
- What should be contained immediately?
- What evidence must be preserved first?
- Who needs to be notified?
- How should systems be recovered?
- What control failed?
- What should change to prevent recurrence?

This portfolio section demonstrates that full process.

---

# 🗂️ Incident Response & Forensics Deliverables

| # | Deliverable | Primary Focus |
|---|---|---|
| 01 | **DDoS Incident Analysis** | Availability incident, network evidence, severity, containment, recovery |
| 02 | **Network Traffic Forensics** | DNS, connection analysis, IOC review, suspicious traffic |
| 03 | **Incident Response Playbooks** | Phishing, ransomware, insider-threat procedures |
| 04 | **E-Commerce Data Breach Investigation** | Scope, timeline, root cause, exposure analysis, remediation |
| 05 | **Windows Endpoint Compromise Investigation** | Process tree, PowerShell, discovery, persistence, host containment |
| 06 | **Digital Evidence & Chain of Custody** | Evidence integrity, hashing, preservation, transfer |
| 07 | **Incident Severity & Escalation Matrix** | SEV classification, response priority, stakeholder escalation |
| 08 | **IOC, Evidence & MITRE ATT&CK Guide** | Indicators, confidence, ATT&CK mapping, analyst guardrails |
| 09 | **Post-Incident Review & Corrective Actions** | Root cause, lessons learned, remediation ownership |
| 10 | **Recruiter Quick View** | Fast overview of IR and forensic capabilities |

---

# 🔄 Incident Response Lifecycle

The section follows a practical incident-response lifecycle:

```text
PREPARATION
    ↓
DETECTION
    ↓
TRIAGE
    ↓
INVESTIGATION
    ↓
CONTAINMENT
    ↓
ERADICATION
    ↓
RECOVERY
    ↓
POST-INCIDENT REVIEW
    ↓
CONTROL IMPROVEMENT
```

---

# 🧭 Incident Investigation Workflow

A completed investigation should move through:

```text
Alert
  ↓
Validate Event
  ↓
Collect Evidence
  ↓
Build Timeline
  ↓
Determine Scope
  ↓
Assign Severity
  ↓
Map Behaviors / IOCs
  ↓
Contain Threat
  ↓
Eradicate Root Cause
  ↓
Recover Systems
  ↓
Document Lessons Learned
  ↓
Track Corrective Actions
```

---

# 🚦 Incident Severity Model

The portfolio uses a practical four-level severity model.

| Severity | Criteria | Example |
|---|---|---|
| **SEV-1 — Critical** | Material outage, widespread compromise, ransomware, confirmed sensitive-data exposure, critical privileged compromise | Enterprise ransomware, major customer-data breach |
| **SEV-2 — High** | Confirmed malicious activity with significant but bounded impact | Privileged workstation compromise, serious DDoS, successful credential phishing |
| **SEV-3 — Medium** | Suspicious or malicious activity with limited scope | Single compromised endpoint or suspicious network activity |
| **SEV-4 — Low** | Informational, benign, blocked, or routine security activity | Known scanner, blocked probe, benign event |

---

# 📈 Severity Factors

Severity is influenced by:

- Business impact
- Number of affected users
- Number of affected systems
- Privileged-account involvement
- Sensitive-data access
- Service availability
- Threat persistence
- Lateral movement
- Regulatory implications
- Legal implications
- Scope uncertainty
- Ability to contain

---

# 🚨 Escalation Triggers

An incident should receive immediate escalation when evidence indicates:

- Privileged-account compromise
- Successful unauthorized authentication
- Ransomware
- Persistence
- Lateral movement
- Credential access
- Remote code execution
- Sensitive-data exposure
- Data exfiltration
- Business-critical outage
- Multiple affected systems
- Evidence destruction
- Ongoing attacker activity

---

# 🌐 DDoS Incident Analysis

The DDoS investigation demonstrates response to a simulated availability incident affecting a customer-facing web service.

## Investigation Objectives

- Confirm service impact
- Identify abnormal traffic behavior
- Correlate infrastructure metrics
- Determine incident severity
- Contain malicious traffic
- Restore service
- Preserve evidence
- Document lessons learned

---

# 🔍 DDoS Evidence Sources

Evidence reviewed includes:

- Availability monitoring
- Firewall logs
- Web-server logs
- Traffic volume
- HTTP error rates
- Connection queues
- CPU/resource utilization
- Source-IP patterns
- Request frequency
- Targeted application endpoints

---

# 📊 DDoS Investigation Workflow

```text
Availability Alert
       ↓
Confirm Service Impact
       ↓
Review Firewall / Web Logs
       ↓
Analyze Traffic Pattern
       ↓
Determine Scope
       ↓
Assign Severity
       ↓
Apply Filtering / Rate Controls
       ↓
Validate Recovery
       ↓
Post-Incident Review
```

---

# 🛡️ DDoS Containment Controls

Potential controls include:

- Web Application Firewall
- Rate limiting
- CDN controls
- DDoS protection
- Source filtering
- Connection thresholds
- Autoscaling
- Upstream provider mitigation
- Traffic anomaly monitoring

---

# 🔬 Network Traffic Forensics

The network-forensics investigation demonstrates analysis of suspicious workstation communications using simulated PCAP-style evidence.

The investigation focuses on:

- DNS behavior
- Outbound connections
- Source/destination analysis
- ICMP activity
- Connection frequency
- Network IOCs
- Host-to-network correlation

---

# 🧩 Network Evidence Types

| Evidence | Analyst Question |
|---|---|
| DNS Logs | Which domains did the host query? |
| Firewall Logs | Which connections were allowed or blocked? |
| PCAP | What traffic actually moved across the network? |
| Source IP | Which host initiated activity? |
| Destination IP | Where did the activity go? |
| Ports | Which services or protocols were involved? |
| Timing | Was activity periodic or burst-based? |
| Volume | Was traffic consistent with normal use? |

---

# 🔍 Network Investigation Principles

Suspicious network activity should be evaluated carefully.

A single unusual connection does not automatically prove compromise.

Analysts should correlate:

- Endpoint process
- User activity
- DNS
- Firewall events
- Authentication
- Asset role
- Known scanners
- VPN infrastructure
- Business applications

---

# 🧾 IOC Documentation

Indicators of Compromise should be documented with context.

| Field | Purpose |
|---|---|
| Indicator | IP, domain, URL, hash, account, process, host |
| Type | Network, endpoint, email, identity, file |
| Source | SIEM, EDR, DNS, firewall, email gateway |
| First Seen | Initial timestamp |
| Last Seen | Most recent timestamp |
| Confidence | Low, Medium, High |
| Context | Why the indicator matters |
| Scope | Where else it was searched |
| Disposition | Block, monitor, benign, unresolved |

---

# 🧠 IOC Analysis Guardrails

An IOC should not automatically be treated as malicious because:

- An IP can be shared
- A domain can be compromised temporarily
- A process can be dual-use
- A PowerShell command can be legitimate
- Reputation data can be outdated
- Infrastructure can be reused

IOC analysis should always be combined with behavioral evidence.

---

# 🖥️ Windows Endpoint Compromise Investigation

The endpoint-forensics case demonstrates investigation of suspicious PowerShell activity on a simulated Windows workstation.

The investigation includes:

- Process-tree analysis
- Parent/child process relationships
- PowerShell command-line review
- Authentication correlation
- Network connections
- Persistence analysis
- Scheduled-task review
- Account discovery
- Endpoint isolation
- Credential reset
- Recovery

---

# 🌳 Example Process Chain

```text
OUTLOOK.EXE
     ↓
WINWORD.EXE
     ↓
powershell.exe
     ↓
Encoded / Suspicious Command
     ↓
Outbound Network Connection
     ↓
Persistence Activity
```

This type of process relationship can help identify suspicious execution chains.

---

# 🔍 Endpoint Evidence Sources

Potential evidence includes:

- EDR telemetry
- Windows Event Logs
- Process trees
- PowerShell command lines
- Scheduled tasks
- Registry artifacts
- Network connections
- Authentication logs
- File hashes
- User context
- Service activity

---

# 🧠 MITRE ATT&CK Mapping

The portfolio uses MITRE ATT&CK to describe observed or simulated attacker behavior.

Example mappings include:

| Technique | Description |
|---|---|
| **T1566.001** | Spearphishing Attachment |
| **T1566.002** | Spearphishing Link |
| **T1059.001** | PowerShell |
| **T1087** | Account Discovery |
| **T1110** | Brute Force |

---

# ⚠️ ATT&CK Mapping Principles

MITRE ATT&CK is used carefully.

### Map Evidence, Not Assumptions

A technique should be mapped when behavior supports it.

### ATT&CK Does Not Prove Attribution

A technique may be used by many threat actors.

### Use Broader Mapping When Evidence Is Limited

If evidence supports only a tactic, the report should not force a specific technique.

### Document Confidence

Analysts should explain:

- What was observed
- Why the technique applies
- Which evidence supports it
- What additional evidence would strengthen confidence

---

# 🎣 Phishing Incident Response

The phishing-response playbook covers:

```text
Suspicious Email
      ↓
Preserve Message
      ↓
Review Headers
      ↓
Analyze URL / Attachment
      ↓
Check Delivery Scope
      ↓
Review User Interaction
      ↓
Review Authentication
      ↓
Contain Identity
      ↓
Remove Malicious Mail
      ↓
Escalate if Compromise Confirmed
```

---

# 📧 Phishing Evidence

Analysts may review:

- Sender
- Reply-to
- Domain
- Message headers
- Authentication results
- URLs
- Attachments
- User clicks
- Credential submission
- Login history
- MFA events
- Mailbox rules
- OAuth grants
- Endpoint activity

---

# 🛡️ Phishing Containment

Potential response actions include:

- Block sender
- Block domain
- Block URL
- Remove malicious messages
- Reset user password
- Revoke active sessions
- Require MFA validation
- Remove unauthorized mailbox rules
- Revoke malicious OAuth grants
- Investigate affected endpoint

---

# 🔐 Ransomware Incident Response

The ransomware playbook emphasizes rapid containment and evidence preservation.

## Initial Actions

- Isolate affected endpoints
- Identify impacted systems
- Disable compromised credentials
- Protect backup infrastructure
- Preserve EDR evidence
- Review lateral movement
- Identify encryption scope

---

# 🧨 Ransomware Evidence

Evidence may include:

- Ransom note
- File extensions
- File hashes
- EDR telemetry
- Process execution
- Network traffic
- Authentication logs
- Remote administration activity
- Backup activity
- Scheduled tasks
- Persistence mechanisms

---

# 🔄 Ransomware Recovery

Recovery should include:

- Removal of persistence
- Rebuilding untrusted systems
- Patching exploited vulnerabilities
- Credential rotation
- Restoration from trusted backups
- Validation before reconnecting
- Monitoring for recurrence

---

# 👤 Insider Threat Response

The insider-threat playbook addresses suspicious or unauthorized data access.

Potential indicators include:

- Unusual downloads
- Excessive database queries
- DLP alerts
- Removable-media activity
- Abnormal cloud sharing
- Suspicious administrative access
- Large data exports
- Access outside normal job duties

---

# ⚖️ Insider Threat Investigation Principles

Because insider cases may involve employment or legal matters:

- Preserve evidence before user confrontation
- Coordinate with HR and legal
- Limit investigation scope appropriately
- Protect confidentiality
- Document authorization
- Avoid unsupported conclusions
- Separate facts from assumptions

---

# 🛒 E-Commerce Data Breach Investigation

The simulated e-commerce breach case demonstrates a complete incident investigation involving possible customer-data exposure.

The investigation covers:

- WAF alert
- Application logs
- Authentication logs
- Vulnerable application component
- Data-export activity
- Session revocation
- Service isolation
- Patching
- Recovery
- Root-cause analysis

---

# 🧭 Breach Investigation Workflow

```text
WAF / SIEM Alert
       ↓
Validate Suspicious Activity
       ↓
Review Application Logs
       ↓
Identify Unauthorized Access
       ↓
Determine Data Scope
       ↓
Assign Severity
       ↓
Contain Application
       ↓
Revoke Credentials / Tokens
       ↓
Patch / Rebuild
       ↓
Validate Recovery
       ↓
Post-Incident Review
```

---

# 🔍 Root Cause Analysis

A strong root-cause analysis should distinguish between:

## Primary Root Cause

The direct control or technical failure that enabled the incident.

## Contributing Factors

Conditions that increased likelihood or impact.

Examples:

- Weak asset ownership
- Delayed patching
- Missing logs
- Excessive permissions
- Poor escalation
- Unclear responsibility

---

# 📊 Root Cause Confidence

| Confidence | Meaning |
|---|---|
| Confirmed | Direct evidence establishes the cause |
| Probable | Multiple evidence sources support the conclusion |
| Possible | Plausible but additional evidence is required |

Analysts should not present a possible cause as confirmed.

---

# 🔗 Digital Evidence & Chain of Custody

The forensics section includes evidence-handling concepts designed to preserve integrity.

A chain-of-custody record should include:

- Case ID
- Evidence ID
- Evidence description
- Source
- Collector
- Date/time
- Timezone
- Hash
- Storage location
- Transfer history
- Analysis actions
- Final disposition

---

# 🔐 Evidence Integrity

Cryptographic hashing can support evidence integrity.

Example:

```text
Evidence File
     ↓
SHA-256 Hash
     ↓
Record Hash
     ↓
Store Original
     ↓
Create Working Copy
     ↓
Verify Integrity
     ↓
Perform Analysis
```

---

# 🧾 Evidence Handling Principles

- Preserve original evidence
- Use working copies for analysis
- Record timestamps
- Document who accessed evidence
- Track transfers
- Avoid unnecessary modification
- Hash files where appropriate
- Maintain controlled storage
- Follow retention requirements

---

# 🗃️ Evidence Register Structure

| Field | Description |
|---|---|
| Evidence ID | Unique identifier |
| Case ID | Related investigation |
| Item | Evidence artifact |
| Source | System or location |
| Collector | Person collecting evidence |
| Date / Time | Collection timestamp |
| Hash | Integrity value |
| Storage | Evidence location |
| Status | Preserved, analyzed, transferred |
| Notes | Investigation context |

---

# 📋 Incident Response Playbooks

The portfolio includes repeatable playbooks for:

- Phishing
- Ransomware
- Insider threat

Each playbook follows:

```text
Trigger
  ↓
Triage
  ↓
Evidence Collection
  ↓
Containment
  ↓
Eradication
  ↓
Recovery
  ↓
Communication
  ↓
Closure
```

---

# 🎯 Playbook Design Principles

A useful playbook should define:

- Trigger
- Scope
- Owner
- Evidence required
- Decision points
- Containment actions
- Escalation criteria
- Communication requirements
- Recovery steps
- Closure requirements

---

# 🧠 Analyst Triage Questions

During investigation, analysts should ask:

1. What happened?
2. What evidence supports the alert?
3. Is malicious activity confirmed?
4. Which users or systems are affected?
5. Is the threat active?
6. Is privileged access involved?
7. Is sensitive data involved?
8. What can safely be contained now?
9. What evidence must be preserved?
10. Who needs to be notified?
11. What additional evidence is required?
12. What is the appropriate disposition?

---

# 📈 Incident Timeline Development

An investigation timeline should capture:

| Field | Example |
|---|---|
| Timestamp | 09:12 ET |
| Event | SIEM alert generated |
| Source | Authentication logs |
| Analyst Action | Reviewed user activity |
| Finding | Successful login followed repeated failures |
| Decision | Escalated to High severity |

---

# 📝 Incident Documentation Standard

Every completed incident should document:

- Incident ID
- Detection source
- Date/time
- Affected users
- Affected systems
- Severity
- Business impact
- Evidence
- IOCs
- ATT&CK mapping
- Timeline
- Scope
- Containment
- Eradication
- Recovery
- Root cause
- Corrective actions
- Final disposition

---

# 🔁 Post-Incident Review

Incident response should continue after technical recovery.

A Post-Incident Review evaluates:

- What happened?
- What worked?
- What failed?
- What delayed response?
- Was severity assigned correctly?
- Was containment effective?
- Was evidence preserved?
- Did recovery meet expectations?
- Which controls need improvement?
- Who owns corrective actions?

---

# 🛠️ Corrective Action Tracking

| Field | Purpose |
|---|---|
| Finding | What failed |
| Root Cause | Why it failed |
| Corrective Action | What must change |
| Owner | Accountable team |
| Priority | Critical / High / Medium / Low |
| Target Date | Completion expectation |
| Validation | How success will be verified |
| Status | Open / In Progress / Closed |

---

# 📊 Incident Response Metrics

Useful IR metrics include:

## Response

- Mean Time to Acknowledge
- Mean Time to Contain
- Mean Time to Recover
- High-severity incident count

## Investigation Quality

- Complete incident timelines
- Evidence completeness
- Escalation completeness
- Correct severity assignments

## Corrective Actions

- Open corrective actions
- Overdue corrective actions
- Repeat incidents
- Repeat root causes

## Recovery

- Restore success
- Recovery objective performance
- Recurrence after recovery

---

# 🛠️ Tools & Technical Concepts

## Network Analysis

`Wireshark` • `PCAP Analysis` • `DNS Analysis` • `Firewall Logs` • `Network Traffic Analysis`

## Endpoint Investigation

`Windows Event Logs` • `EDR Concepts` • `Process Trees` • `PowerShell Analysis` • `Persistence Review`

## Security Monitoring

`SIEM` • `Splunk Concepts` • `Alert Correlation` • `IOC Analysis`

## Incident Response

`Triage` • `Containment` • `Eradication` • `Recovery` • `Escalation` • `Post-Incident Review`

## Digital Forensics

`Evidence Preservation` • `Chain of Custody` • `SHA-256` • `Timeline Analysis`

## Threat Analysis

`MITRE ATT&CK` • `IOC Analysis` • `Behavior Mapping` • `Incident Scoping`

---

# 📚 Frameworks & Methods

This section references concepts from:

- **NIST incident-response principles**
- **NIST Cybersecurity Framework**
- **MITRE ATT&CK**
- **ISO/IEC 27035 incident-management concepts**
- **Digital evidence integrity practices**

Framework references are used to structure analyst methodology rather than to claim formal certification.

---

# 💼 Incident Response Analyst Skills Demonstrated

This portfolio demonstrates my ability to:

- Validate security alerts
- Investigate suspicious activity
- Classify incidents
- Assign severity
- Develop investigation timelines
- Analyze network evidence
- Analyze endpoint behavior
- Document IOCs
- Use MITRE ATT&CK
- Scope affected users and systems
- Recommend containment
- Preserve digital evidence
- Apply chain-of-custody concepts
- Develop phishing playbooks
- Develop ransomware playbooks
- Analyze data-exposure scenarios
- Perform root-cause analysis
- Track corrective actions
- Document post-incident lessons learned
- Prepare Tier 2 / IR handoffs
- Communicate technical findings clearly

---

# 🎯 Target Role Alignment

This section demonstrates skills relevant to:

- **Incident Response Analyst**
- **SOC Analyst I / Tier 1**
- **Cybersecurity Analyst**
- **Security Operations Analyst**
- **Information Security Analyst**
- **Junior Digital Forensics Analyst**
- **Network Security Analyst**
- **Junior Threat Hunter**
- **Security Analyst**
- **Cyber Defense Analyst**

---

# 🔗 Related Portfolio Sections

This Incident Response & Forensics work connects to the broader cybersecurity portfolio.

## 🖥️ SOC, SIEM & Alert Handling

Provides detections, alert triage, SPL investigations, severity, and escalation into IR.

## 🛡️ Governance & Risk (GRC)

Provides risk-management, control ownership, policy, and remediation governance.

## ⚙️ System & Automation

Provides Linux, Python, Bash, SQL, hardening, and security-automation evidence.

## 🏆 Capstone Integration

Combines incident response with GRC, SOC, IAM, vulnerability management, and executive reporting.

## 🎓 Career & Professional Development

Supports framework knowledge and analyst-readiness development.

---

# 🧠 Key Incident Response Principles

### Evidence Before Assumptions

Conclusions should be supported by evidence.

### Severity Is Based on Impact

A high-volume alert is not automatically a high-severity incident.

### Containment Must Be Deliberate

Containment should reduce risk while preserving evidence when possible.

### Scope Can Change

Analysts should continue searching for affected users, hosts, and data as new evidence appears.

### Attribution Requires Evidence

Malicious behavior does not automatically establish threat-actor identity.

### Recovery Must Be Validated

Systems should not return to production simply because they start successfully.

### Incidents Should Improve Controls

Every major incident should produce lessons learned and corrective actions.

---

# 🔄 Complete IR Workflow

```text
PREPARE
   ↓
DETECT
   ↓
TRIAGE
   ↓
INVESTIGATE
   ↓
SCOPE
   ↓
CLASSIFY
   ↓
CONTAIN
   ↓
ERADICATE
   ↓
RECOVER
   ↓
REVIEW
   ↓
IMPROVE
```

---

# ⚠️ Portfolio Integrity

This section contains **simulated cybersecurity incident-response and forensic investigations** created for portfolio and professional-development purposes.

Unless explicitly stated otherwise:

- Organizations are simulated.
- Users and hosts are synthetic.
- IP addresses use documentation ranges where appropriate.
- Domains use example or defanged indicators.
- Incident timelines are simulated.
- Evidence is portfolio evidence.
- Example hashes are not represented as hashes from real malware unless an actual source file exists.
- MITRE ATT&CK mappings describe behavior and do not claim threat-actor attribution.
- No production incident-response employment is claimed.
- No customer breach investigation is claimed.
- No law-enforcement forensic examination is claimed.

The purpose of this section is to demonstrate how I would **validate alerts, collect evidence, investigate incidents, determine severity, contain threats, recover systems, and document corrective actions in a cybersecurity analyst environment**.

---

# 👤 About the Analyst

## Jamie Christian II

Cybersecurity professional focused on:

**Incident Response • Security Operations • Threat Detection • Digital Forensics • Risk Management • Security Automation**

My portfolio emphasizes evidence-driven, interview-defensible cybersecurity work that connects technical investigation to business impact, containment, recovery, and security improvement.

### Connect

- **GitHub:** [github.com/JamieChristian22](https://github.com/JamieChristian22)
- **LinkedIn:** [linkedin.com/in/jamiechristian2](https://www.linkedin.com/in/jamiechristian2/)
- **Email:** [jamiechristian331@gmail.com](mailto:jamiechristian331@gmail.com)

---

# 🚨 Incident Response Philosophy

### `DETECT → INVESTIGATE → CONTAIN → RECOVER → IMPROVE`

**This section demonstrates how evidence, analyst judgment, incident response, digital forensics, escalation, recovery, and corrective actions work together during cybersecurity investigations.**

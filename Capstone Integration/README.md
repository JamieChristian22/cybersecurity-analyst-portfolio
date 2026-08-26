# 🏆 Cybersecurity Capstone Integration

## Enterprise Security Program Case Study

**Jamie Christian II | Cybersecurity Analyst Portfolio**

This capstone is the **flagship project** in my cybersecurity portfolio. It integrates **Governance, Risk & Compliance (GRC), SOC/SIEM Operations, Incident Response, Vulnerability Management, Identity & Access Management (IAM), Security Automation, System Hardening, Security Architecture, and Executive Reporting** into one simulated enterprise cybersecurity program.

The project demonstrates how individual cybersecurity functions connect across the complete security lifecycle:

> **Business Risk → Security Controls → Architecture → Monitoring → Detection → Investigation → Incident Response → Remediation → Validation → Executive Reporting**

---

## 📌 Executive Summary

This case study models the cybersecurity program of a growing e-commerce organization operating customer-facing applications, cloud services, employee systems, identity infrastructure, third-party integrations, and payment-processing workflows.

Rapid digital growth creates several security challenges:

- Privileged-account compromise
- Credential theft and phishing
- Internet-facing vulnerabilities
- Incomplete centralized security logging
- Excessive user and service-account permissions
- Ransomware and recovery risk
- Third-party access risk
- Sensitive-data exposure
- Delayed incident detection and escalation
- Security governance and control gaps

The objective of this capstone is to design a practical cybersecurity program capable of:

- Identifying and prioritizing security risks
- Establishing security controls and ownership
- Protecting identities, systems, applications, and data
- Centralizing security telemetry
- Detecting suspicious activity
- Investigating security alerts
- Responding to incidents
- Managing vulnerabilities
- Validating remediation
- Measuring security performance
- Communicating cybersecurity risk to leadership

> **Portfolio Note:** All organizations, users, systems, IP addresses, incidents, risk values, metrics, architecture details, and business scenarios in this capstone are simulated for portfolio and educational purposes.

---

# 🎯 Security Program Objectives

## 1. Protect Identity

Strengthen authentication and authorization through:

- Multi-Factor Authentication (MFA)
- Role-Based Access Control (RBAC)
- Least privilege
- Privileged-access reviews
- Joiner/Mover/Leaver processes
- Service-account governance
- Third-party access controls
- Administrative activity monitoring

---

## 2. Reduce Attack Surface

Identify and remediate security weaknesses through:

- Vulnerability scanning
- Risk-based remediation
- Security hardening
- Patch-management SLAs
- Firewall controls
- Secure administrative access
- Service reduction
- Configuration validation

---

## 3. Improve Security Visibility

Centralize security telemetry from:

- Identity systems
- Endpoints
- Firewalls
- DNS
- Web Application Firewalls
- Cloud environments
- SaaS platforms
- Applications
- Backup platforms

---

## 4. Strengthen Detection & Response

Develop repeatable workflows for:

- Alert triage
- Threat detection
- Investigation
- Incident classification
- Severity assignment
- Containment
- Escalation
- Recovery
- Post-incident review

---

## 5. Improve Cyber Resilience

Strengthen recovery capabilities through:

- Backup validation
- Restore testing
- Incident-response playbooks
- Recovery objectives
- Business continuity considerations
- Post-incident corrective actions

---

## 6. Improve Security Governance

Establish:

- Risk ownership
- Control ownership
- Remediation tracking
- Security metrics
- Compliance-readiness mapping
- Executive reporting
- Evidence-based control validation

---

# 🗂️ Capstone Deliverables

| # | Deliverable | Security Focus |
|---|---|---|
| 01 | **Executive Cybersecurity Program Overview** | Business risk, priorities, program objectives, security strategy |
| 02 | **Enterprise Risk & Control Summary** | Risk assessment, ownership, treatment, residual risk, validation |
| 03 | **Security Architecture & Data Flow** | Trust boundaries, identity, applications, data, monitoring, recovery |
| 04 | **SOC Detection & Monitoring Plan** | SIEM, log sources, detection coverage, alert monitoring |
| 05 | **Incident Response Operating Model** | Severity, escalation, RACI, containment, recovery |
| 06 | **Vulnerability Management Program** | Scanning, prioritization, remediation SLAs, exceptions, validation |
| 07 | **IAM & Access Governance Plan** | MFA, RBAC, JML, privileged access, service accounts |
| 08 | **Compliance & Control Crosswalk** | NIST, ISO, SOC 2, PCI DSS, GDPR alignment |
| 09 | **30/60/90-Day Security Roadmap** | Priorities, ownership, dependencies, implementation |
| 10 | **Executive Security Metrics Dashboard** | Security KPIs, risk metrics, SOC metrics, IAM and recovery |
| 11 | **Security Program Maturity Review** | Current state, target maturity, lessons learned |
| 12 | **Recruiter Quick View** | High-level summary of skills and deliverables |

---

# 🏗️ Security Architecture & Data Flow

The simulated environment models a typical e-commerce security architecture.

```text
                         INTERNET
                            │
                            ▼
                   ┌────────────────┐
                   │   CDN / WAF    │
                   │ DDoS Protection│
                   └────────┬───────┘
                            │
                            ▼
                   ┌────────────────┐
                   │ Web / API Tier │
                   │ E-Commerce App │
                   └────────┬───────┘
                            │
                            ▼
                   ┌────────────────┐
                   │   Data Tier    │
                   │ Customer Data  │
                   │ Encrypted DB   │
                   └────────────────┘
                            │
                            │
                  Payment Transactions
                            │
                            ▼
                   ┌────────────────┐
                   │Payment Provider│
                   │ Tokenization   │
                   └────────────────┘


Employees
    │
    ▼
┌────────────────┐
│ Managed        │
│ Endpoints      │
│ EDR            │
└───────┬────────┘
        │
        ▼
┌────────────────┐
│ Identity / IdP │
│ SSO + MFA      │
│ RBAC + JML     │
└───────┬────────┘
        │
        ▼
┌────────────────┐
│ SaaS / Admin   │
│ Cloud Services │
└───────┬────────┘
        │
        │ Security Logs
        ▼
┌─────────────────────────┐
│ Security Monitoring     │
│ SIEM + EDR + Telemetry  │
└────────────┬────────────┘
             │
             │ Alerts
             ▼
      ┌────────────────┐
      │    SOC / IR    │
      │ Investigation  │
      │ & Response     │
      └────────┬───────┘
               │
               ▼
      ┌────────────────┐
      │ Remediation &  │
      │ Recovery       │
      └────────────────┘
```

### Primary Security Controls

- Web Application Firewall
- DDoS protection
- TLS encryption
- Identity provider
- Multi-Factor Authentication
- Role-Based Access Control
- Least privilege
- Endpoint Detection & Response
- SIEM
- Centralized logging
- Network firewall
- Vulnerability scanning
- Security hardening
- Backup and recovery controls
- Security monitoring

---

# ⚠️ Enterprise Risk Management

The capstone applies a structured risk-management process:

```text
Risk Identification
        ↓
Inherent Risk
        ↓
Existing Controls
        ↓
Control Gap Analysis
        ↓
Risk Treatment
        ↓
Control Ownership
        ↓
Remediation
        ↓
Validation
        ↓
Residual Risk
        ↓
Continuous Monitoring
```

## Priority Risk Scenarios

| Priority | Risk | Potential Business Impact | Primary Security Treatment |
|---|---|---|---|
| 1 | Privileged-account compromise | Unauthorized administrative access, data exposure, service disruption | MFA, least privilege, access reviews, admin logging |
| 2 | Critical internet-facing vulnerability | Application compromise, downtime, customer-data exposure | Scanning, patching, WAF, remediation SLA |
| 3 | Incomplete centralized logging | Delayed detection, weak investigations, poor auditability | SIEM onboarding and log-retention standards |
| 4 | Ransomware | Business interruption, data loss, recovery impact | EDR, segmentation, backups, IR playbooks |
| 5 | Weak access governance | Excess privileges, orphan accounts, unauthorized access | RBAC, JML, quarterly access reviews |
| 6 | Credential phishing | Account compromise, fraud, cloud/SaaS misuse | MFA, email security, awareness, identity monitoring |
| 7 | Third-party access | Unauthorized external access and supply-chain exposure | Vendor review, MFA, expiration, sponsorship |
| 8 | Sensitive-data exposure | Privacy, financial, reputational, and regulatory impact | Encryption, RBAC, DLP, monitoring |

---

# 🛡️ Risk Governance

Security risks are managed using:

- Named risk owners
- Defined control owners
- Inherent-risk ratings
- Residual-risk ratings
- Remediation target dates
- Compensating controls
- Risk exceptions
- Validation evidence
- Periodic management review

### Risk Closure Standard

A security risk is not considered closed simply because a remediation ticket is completed.

Closure requires evidence that the control is operating as intended, such as:

- Configuration evidence
- Access reports
- Security logs
- Rescan results
- Test results
- Approval records
- Restore-test evidence
- Monitoring validation

---

# 🔍 SOC & SIEM Monitoring

The SOC portion of the capstone demonstrates how security telemetry can be transformed into actionable detections.

## Priority Log Sources

| Priority | Log Source | Security Value |
|---|---|---|
| P1 | Identity / IdP | Authentication, MFA, risky sign-ins, admin activity |
| P1 | Endpoint / EDR | Execution, malware, persistence, endpoint behavior |
| P1 | WAF / Web | Application attacks, exploit attempts, DDoS activity |
| P1 | Firewall / DNS | Network connections, blocked traffic, suspicious destinations |
| P1 | Cloud Audit Logs | Administrative and configuration activity |
| P2 | Application Logs | Business-context security events |
| P2 | Backup Platform | Recovery failures and administrative activity |

---

# 🔎 Detection Use Cases

The monitoring strategy includes detections for:

- Brute-force authentication
- Password spraying
- Credential stuffing
- Repeated authentication failures
- Failed-login-to-success correlation
- Impossible travel
- Suspicious PowerShell activity
- Phishing activity
- Privilege changes
- Suspicious administrative activity
- Sensitive-data exports
- DDoS and availability anomalies

---

# 🧠 MITRE ATT&CK Alignment

Example techniques incorporated into detection analysis include:

| Technique | Description |
|---|---|
| **T1110** | Brute Force |
| **T1110.001** | Password Guessing |
| **T1110.003** | Password Spraying |
| **T1059.001** | PowerShell |
| **T1566.001** | Spearphishing Attachment |
| **T1566.002** | Spearphishing Link |

Detection documentation follows:

> **Detection Logic → Evidence → Investigation → False Positives → Tuning → Severity → Escalation**

---

# 📊 SOC Metrics

Example program targets include:

| KPI | 90-Day Target |
|---|---|
| High-Severity Mean Time to Acknowledge | **< 10 minutes** |
| High-Severity Mean Time to Disposition | **< 45 minutes** |
| High-Severity Alerts Older Than 4 Hours | **0** |
| Detection False-Positive Rate | **< 20% after tuning** |
| Priority Log-Source Coverage | **100%** |
| Tier 1 Escalation Completeness | **≥ 95%** |

> These are simulated program targets used to demonstrate security-operations measurement.

---

# 🚨 Incident Response Operating Model

The capstone implements a structured incident-response lifecycle.

```text
Preparation
    ↓
Detection & Analysis
    ↓
Containment
    ↓
Eradication
    ↓
Recovery
    ↓
Post-Incident Review
    ↓
Control Improvement
```

## Incident Response Activities

- Alert validation
- Incident classification
- Severity assignment
- Scope determination
- Investigation timelines
- Evidence preservation
- Containment
- Credential reset
- Session revocation
- Endpoint isolation
- Eradication
- Recovery
- Stakeholder escalation
- Post-incident review
- Corrective-action tracking

---

# 🚦 Incident Severity Model

| Severity | Criteria | Example |
|---|---|---|
| **SEV-1 — Critical** | Material outage, widespread compromise, ransomware, confirmed sensitive-data exposure | Major breach or widespread ransomware |
| **SEV-2 — High** | Confirmed malicious activity with significant but bounded impact | Privileged compromise or successful phishing |
| **SEV-3 — Medium** | Suspicious or malicious activity with limited scope | Single compromised endpoint or repeated attack activity |
| **SEV-4 — Low** | Informational, benign, blocked, or routine activity | Known scanner or blocked probe |

---

# 👥 Incident Response Ownership

| Activity | SOC Tier 1 | IR Lead | IT / Cloud | Legal / Privacy | Business Owner |
|---|---|---|---|---|---|
| Alert Triage | Responsible | Consulted | Consulted | — | — |
| High-Severity Incident | Consulted | Accountable | Responsible | Consulted | Consulted |
| Containment | Responsible within runbook | Accountable | Responsible | Consulted when required | Consulted |
| Evidence Preservation | Responsible | Accountable | Consulted | Consulted | — |
| Recovery | Consulted | Accountable | Responsible | Consulted | Responsible |
| Post-Incident Review | Consulted | Accountable | Responsible | Consulted | Responsible |

---

# 🛠️ Vulnerability Management Program

The vulnerability-management lifecycle follows:

```text
Asset Discovery
      ↓
Security Scanning
      ↓
Risk Prioritization
      ↓
Remediation
      ↓
Validation / Rescan
      ↓
Closure
      ↓
Continuous Monitoring
```

## Remediation Targets

| Vulnerability Severity / Context | Target |
|---|---|
| Critical — Internet Facing / Known Exploited | **7 Days** |
| Critical — Internal | **14 Days** |
| High | **30 Days** |
| Medium | **60 Days** |
| Low | **90 Days / Risk-Based** |

## Vulnerability Prioritization Factors

Prioritization considers:

- CVSS severity
- Known exploitation
- Exploit availability
- Internet exposure
- Asset criticality
- Privilege requirements
- Sensitive-data access
- Business impact
- Existing compensating controls

---

# 📈 Vulnerability Management Metrics

Example program metrics include:

- Internet-facing critical vulnerabilities past SLA
- Critical vulnerabilities with named owners
- Mean days to remediate critical vulnerabilities
- Validated closure rate
- Asset scanning coverage
- Expired vulnerability exceptions
- High-risk remediation backlog

---

# 🔐 Identity & Access Management

The IAM program applies security controls across authentication, authorization, privileged access, identity lifecycle, and service accounts.

## Authentication

- Multi-Factor Authentication
- Strong authentication for privileged users
- Conditional-access concepts
- Secure administrative authentication
- Risky-sign-in monitoring

## Authorization

- Role-Based Access Control
- Least privilege
- Privileged-access management concepts
- Separation of duties
- Quarterly access reviews

---

# 👤 Identity Lifecycle

```text
JOINER
   ↓
Approved Role
   ↓
Role-Based Access
   ↓
MOVER
   ↓
Access Reassessment
   ↓
LEAVER
   ↓
Account Disablement
   ↓
Session / Token Revocation
```

### Joiner

- Manager-approved access
- Role-based permissions
- Least privilege
- MFA enrollment

### Mover

- Review existing access
- Remove obsolete privileges
- Grant only required new access

### Leaver

- Disable accounts promptly
- Revoke active sessions
- Revoke tokens
- Review shared credentials
- Transfer ownership of required business resources

---

# 🔑 Privileged Access

Privileged accounts require:

- Strong MFA
- Named ownership
- Least privilege
- Administrative activity logging
- Quarterly recertification
- Restricted administrative pathways
- Removal of unnecessary standing privilege

---

# 🤖 Service Account Governance

Service accounts require:

- Named owner
- Documented business purpose
- Least privilege
- Credential/secret rotation
- Usage monitoring
- Periodic access review
- Removal when no longer required

---

# 🐍 Security Automation

Automation supports repeatable security operations and reduces unnecessary manual processing.

## Python Security Automation

Projects demonstrate:

- IP allow-list management
- IPv4 validation
- CIDR validation
- Duplicate detection
- Unauthorized-entry identification
- Authentication-log parsing
- Alert generation
- Structured logging
- JSON output
- Error handling
- Dry-run concepts
- Testing

---

# 🐧 Bash Security Automation

Linux security automation reviews:

- Listening ports
- Firewall status
- SSH configuration
- UID 0 accounts
- World-writable files
- Enabled services
- Disk utilization
- User-account information
- Security-hardening signals

---

# 🗄️ SQL Security Analytics

Security investigations include:

- Failed-login analysis
- Repeated authentication failures
- Off-hours authentication
- Source-IP aggregation
- Success after repeated failures
- Unusual login geography
- Multi-user targeting
- Incident-window filtering
- Authentication trend analysis

---

# 🐧 Linux Security Hardening

The capstone incorporates Linux security concepts including:

- SSH hardening
- Root-login restrictions
- Public-key authentication
- File permissions
- `chmod`
- `chown`
- User and group ownership
- Least privilege
- Firewall review
- Listening-service review
- UID 0 account review
- World-writable file identification
- Logging
- Patch posture
- Scheduled-task review

---

# 📋 Governance, Risk & Compliance

The capstone connects technical controls to broader security governance and compliance-readiness objectives.

## Frameworks & Standards Referenced

- **NIST Cybersecurity Framework 2.0**
- **NIST SP 800-53**
- **NIST Risk Management Framework concepts**
- **ISO/IEC 27001**
- **SOC 2**
- **PCI DSS**
- **GDPR**
- **COBIT**
- **MITRE ATT&CK**

---

# 🧩 Control Areas

The program addresses:

- Governance
- Enterprise risk management
- Identity and access management
- Security monitoring
- Incident response
- Vulnerability management
- Secure configuration
- Data protection
- Recovery
- Third-party risk
- Security awareness
- Logging and monitoring
- Access governance

> Framework mappings demonstrate security-control alignment and readiness methodology. They do **not** represent formal certification, audit attestation, or organizational compliance.

---

# 🔗 Compliance & Control Crosswalk

| Program Area | NIST CSF | NIST 800-53 Examples | ISO 27001 Themes | Additional Relevance |
|---|---|---|---|---|
| Governance & Risk | Govern / Identify | PM, RA, PL | Risk Management | SOC 2 governance, GDPR accountability |
| Identity & Access | Protect | AC, IA | Access Control | SOC 2 CC6, PCI access controls |
| Logging & Monitoring | Detect | AU, SI | Logging & Monitoring | SOC 2 CC7, PCI logging |
| Incident Response | Respond | IR | Incident Management | SOC 2 CC7, PCI IR, GDPR breach response |
| Recovery | Recover | CP | Business Continuity | Availability and resilience |
| Vulnerability Management | Identify / Protect | RA, SI, CM | Technical Vulnerability Management | PCI vulnerability controls |
| Data Protection | Protect | SC, AC, MP | Classification & Cryptography | PCI data protection, GDPR security |
| Third-Party Risk | Govern | SR | Supplier Relationships | Vendor and processor oversight |

---

# 🗓️ 30 / 60 / 90-Day Security Roadmap

## 🔴 Days 1–30 — Reduce Immediate Risk

### Identity

- Enforce privileged MFA
- Review privileged access
- Remove unnecessary administrative permissions

### Vulnerability Management

- Identify critical internet-facing assets
- Assign asset owners
- Remediate critical vulnerabilities
- Establish remediation SLAs

### Incident Response

- Validate incident contacts
- Establish severity standards
- Confirm escalation procedures

### Recovery

- Review critical-system backups
- Establish restore-test schedule

### Success Criteria

- 100% privileged-user MFA coverage in simulated scope
- No critical internet-facing finding beyond target SLA
- Incident severity matrix documented
- Incident contact tree validated
- Critical backup inventory reviewed

---

# 🟠 Days 31–60 — Improve Visibility & Response

### SOC

- Onboard priority SIEM log sources
- Implement authentication detections
- Implement endpoint detections
- Implement phishing detections
- Validate escalation workflows

### IAM

- Inventory service accounts
- Assign service-account owners
- Reduce excessive service-account privileges
- Establish credential-rotation expectations

### Incident Response

- Conduct tabletop exercise
- Validate containment procedures
- Track corrective actions

### Success Criteria

- Priority identity, endpoint, WAF, firewall, and cloud logs searchable
- Tier 1 investigation runbooks tested
- Critical service accounts have named owners
- Incident tabletop completed

---

# 🟢 Days 61–90 — Mature Security Operations

### Data Protection

- Strengthen data classification
- Implement sensitive-data monitoring
- Validate DLP workflow

### Third-Party Risk

- Tier vendors by risk
- Review high-risk vendors
- Validate third-party access expiration

### Recovery

- Conduct restore exercise
- Document recovery performance

### Executive Reporting

- Establish security dashboard
- Report risk, SOC, vulnerability, IAM, and recovery metrics

### Success Criteria

- High-risk data-sharing scenario tested
- High-risk vendors reviewed
- Restore exercise completed
- Executive security scorecard established

---

# 📊 Executive Security Metrics

The capstone demonstrates how technical security operations can be translated into measurable program KPIs.

| Domain | KPI | Simulated Baseline | 90-Day Target |
|---|---|---:|---:|
| Risk | Critical risks without active treatment | 3 | 0 |
| Vulnerability | Internet-facing critical findings past SLA | 4 | 0 |
| IAM | Privileged MFA coverage | 72% | 100% |
| IAM | Privileged access-review completion | 55% | 100% |
| Monitoring | Priority log-source coverage | 40% | 100% |
| SOC | High alerts acknowledged within 10 minutes | 68% | ≥95% |
| SOC | Detection false-positive rate | 38% | <20% |
| IR | High-severity incidents with complete timeline/handoff | 60% | ≥95% |
| Recovery | Critical-system restore tests completed | 25% | 100% |
| Vendor Risk | High-risk vendors with current review | 50% | 100% |

> All baseline and target values above are simulated case-study metrics used to demonstrate security-program reporting.

---

# 📈 Security Program Maturity

| Capability | Simulated Current State | 90-Day Target |
|---|---|---|
| Governance & Risk | Developing | Defined |
| Identity & Access | Developing | Defined |
| Vulnerability Management | Developing | Defined |
| SOC Monitoring | Initial / Developing | Defined |
| Incident Response | Developing | Defined |
| Recovery | Developing | Defined |
| Data Protection | Developing | Defined |
| Third-Party Risk | Initial / Developing | Developing |

---

# 🧠 Key Lessons Learned

This capstone demonstrates several important cybersecurity principles:

### Security Requires Ownership

Controls are stronger when they have:

- Named owners
- Defined responsibilities
- Validation criteria
- Review cadence
- Escalation procedures

### Detection Depends on Visibility

A SOC cannot reliably investigate activity that is not logged.

Centralized logging is therefore a dependency for:

- Detection
- Investigation
- Incident response
- Threat hunting
- Audit readiness

### Risk Determines Priority

Not every vulnerability or alert deserves the same response.

Prioritization requires context such as:

- Severity
- Exploitability
- Asset criticality
- Exposure
- Identity privilege
- Data sensitivity
- Business impact

### Automation Requires Guardrails

Security automation should include:

- Input validation
- Error handling
- Logging
- Testing
- Dry-run capability where appropriate
- Change review
- Rollback planning

### Security Metrics Must Drive Decisions

Useful security metrics should have:

- Defined owner
- Reliable data source
- Review cadence
- Target
- Corrective action when performance falls below target

---

# 🧰 Technical Skills Demonstrated

## Security Operations & SIEM

`Splunk` • `SIEM` • `Alert Triage` • `Log Analysis` • `Detection Logic` • `Threat Detection` • `Incident Escalation` • `Security Monitoring`

## Incident Response

`Incident Triage` • `Investigation` • `Containment` • `Eradication` • `Recovery` • `Evidence Handling` • `Incident Timelines` • `IR Playbooks`

## Security Automation

`Python` • `Bash` • `SQL` • `SQLite` • `CSV` • `JSON` • `Input Validation` • `Logging` • `Testing` • `Error Handling`

## Systems Security

`Linux` • `SSH` • `File Permissions` • `Least Privilege` • `Firewall Review` • `System Hardening` • `Access Control`

## Identity & Access Management

`MFA` • `RBAC` • `Least Privilege` • `JML` • `Privileged Access` • `Service Accounts` • `Access Reviews`

## Vulnerability Management

`Asset Ownership` • `Vulnerability Prioritization` • `Remediation SLAs` • `Exception Management` • `Validation`

## Governance & Risk

`Risk Assessment` • `Risk Register` • `Risk Treatment` • `Residual Risk` • `Control Mapping` • `Security Policies` • `Compliance Readiness`

## Frameworks

`NIST CSF 2.0` • `NIST SP 800-53` • `MITRE ATT&CK` • `ISO/IEC 27001` • `SOC 2` • `PCI DSS` • `GDPR` • `COBIT`

---

# 💼 Cybersecurity Analyst Skills Demonstrated

This capstone demonstrates my ability to:

- Identify cybersecurity risks
- Analyze technical and business impact
- Develop risk-treatment recommendations
- Recommend security controls
- Analyze authentication and security logs
- Develop detection logic
- Investigate security alerts
- Determine incident severity
- Document investigation timelines
- Escalate security incidents
- Apply least-privilege principles
- Analyze vulnerabilities
- Prioritize remediation
- Validate corrective actions
- Automate repetitive security tasks
- Use Python for security automation
- Use Bash for system-security reviews
- Use SQL for security analytics
- Apply Linux security-hardening concepts
- Develop IAM governance controls
- Map security controls to frameworks
- Build security metrics
- Develop implementation roadmaps
- Create executive-level security documentation
- Connect GRC, SOC, IR, IAM, vulnerability management, and security operations

---

# 🎯 Target Role Alignment

This project demonstrates skills relevant to:

- **Cybersecurity Analyst**
- **SOC Analyst I**
- **Tier 1 SOC Analyst**
- **Security Operations Analyst**
- **Information Security Analyst**
- **Incident Response Analyst**
- **GRC Analyst**
- **IT Risk Analyst**
- **Vulnerability Management Analyst**
- **Junior Security Automation Analyst**
- **Junior Security Program Analyst**
- **Systems Security Analyst**

---

# 🔗 Related Portfolio Sections

This capstone integrates work demonstrated throughout my cybersecurity portfolio.

## 🛡️ Governance & Risk (GRC)

Risk assessments, risk registers, policies, controls, threat modeling, compliance mapping, and remediation planning.

## 🖥️ SOC, SIEM & Alert Handling

Splunk investigations, SPL searches, detection logic, alert triage, MITRE ATT&CK mapping, escalation, and tuning.

## 🚨 Incident Response & Forensics

Incident investigations, timelines, phishing analysis, DDoS analysis, containment, escalation, and response playbooks.

## ⚙️ System & Automation

Linux hardening, Python security automation, Bash scripting, SQL security analytics, testing, and operational runbooks.

## 🎓 Career & Professional Development

Professional development, cybersecurity training, career preparation, and supporting documentation.

---

# 🔄 End-to-End Security Workflow

```text
IDENTIFY
   ↓
PROTECT
   ↓
DETECT
   ↓
INVESTIGATE
   ↓
RESPOND
   ↓
RECOVER
   ↓
IMPROVE
```

### IDENTIFY

- Assets
- Risks
- Vulnerabilities
- Threats
- Business impact

### PROTECT

- MFA
- RBAC
- Least privilege
- Hardening
- Patching
- Security policies

### DETECT

- SIEM
- EDR
- Centralized logging
- Detection logic
- Security alerts

### INVESTIGATE

- Alert validation
- Log correlation
- Timeline development
- Scope determination
- Evidence analysis

### RESPOND

- Containment
- Credential revocation
- Endpoint isolation
- Escalation
- Remediation

### RECOVER

- Trusted restoration
- Backup validation
- Monitoring
- Business recovery

### IMPROVE

- Lessons learned
- Detection tuning
- Control improvements
- Automation
- Risk updates

---

# ⚠️ Portfolio Integrity & Disclaimer

This project is a **simulated cybersecurity case study** created to demonstrate practical cybersecurity-analysis methodology.

Unless explicitly stated otherwise:

- Organizations and business scenarios are simulated.
- Users, hosts, systems, IP addresses, incidents, and datasets are synthetic.
- Security metrics and program targets are illustrative.
- Risk ratings are simulated.
- Architecture details are simulated.
- Framework mappings demonstrate control-alignment methodology.
- No formal SOC 2, PCI DSS, ISO 27001, GDPR, NIST, or other compliance certification is claimed.
- The project does not claim production incident ownership.
- The project does not claim employer security outcomes.
- The project does not claim measured business improvements that were not directly tested.

The purpose of this project is to demonstrate how I would **analyze, document, prioritize, and communicate cybersecurity work in an analyst environment** while keeping every portfolio claim accurate and interview-defensible.

---

# 👤 About the Analyst

## Jamie Christian II

Cybersecurity professional focused on:

**Security Operations • Threat Detection • Incident Response • Risk Management • System Security • Security Automation**

My portfolio emphasizes hands-on evidence and demonstrates how technical cybersecurity work connects to broader organizational risk and security objectives.

### Connect

- **GitHub:** [github.com/JamieChristian22](https://github.com/JamieChristian22)
- **LinkedIn:** [linkedin.com/in/jamiechristian2](https://www.linkedin.com/in/jamiechristian2/)
- **Email:** [jamiechristian331@gmail.com](mailto:jamiechristian331@gmail.com)

---

## 🛡️ From Risk Identification to Detection, Response & Recovery

### `IDENTIFY → PROTECT → DETECT → INVESTIGATE → RESPOND → RECOVER → IMPROVE`

**This capstone demonstrates how cybersecurity controls, people, processes, technology, and business risk connect to form an integrated security program.**

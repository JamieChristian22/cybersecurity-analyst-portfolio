# 🛡️ Governance & Risk (GRC)

## Cybersecurity Governance, Risk Management, Controls & Compliance Readiness

**Jamie Christian II | Cybersecurity Analyst Portfolio**

This section demonstrates practical **Governance, Risk & Compliance (GRC)** capabilities through completed portfolio work focused on cybersecurity risk assessment, control evaluation, access governance, vulnerability management, policy development, threat modeling, compliance readiness, and remediation planning.

The goal is to show how cybersecurity risks can be identified, documented, prioritized, treated, validated, and communicated to both technical and business stakeholders.

The core GRC workflow demonstrated throughout this section is:

> **Identify Risk → Assess Impact → Evaluate Controls → Prioritize Treatment → Assign Ownership → Remediate → Validate → Monitor Residual Risk**

---

# 📌 Section Purpose

Governance, Risk & Compliance connects cybersecurity activity to business objectives.

A strong GRC program helps an organization answer questions such as:

- What are our most important cybersecurity risks?
- Which systems, users, and business processes are affected?
- Who owns each risk?
- Which controls already exist?
- Are those controls operating effectively?
- What gaps remain?
- Which risks require immediate remediation?
- Which risks can be accepted?
- What evidence supports the control?
- How should leadership understand residual risk?
- How do technical controls align to frameworks and compliance obligations?

This portfolio section demonstrates a structured approach to those questions.

---

# 🗂️ GRC Portfolio Deliverables

| # | Deliverable | Primary Focus |
|---|---|---|
| 01 | **Security Risk Assessment Report** | Risk identification, scoring, treatment, residual risk |
| 02 | **Enterprise Security Risk Register** | Risk ownership, treatment, review cadence, accountability |
| 03 | **Vulnerability Assessment Report** | Risk-based prioritization, remediation SLAs, validation |
| 04 | **PASTA Threat Model** | Threat analysis, attack paths, vulnerabilities, controls |
| 05 | **Security Policy Drafts** | Authentication, acceptable use, data handling |
| 06 | **Access Control Assessment** | RBAC, MFA, least privilege, JML, service accounts |
| 07 | **Data Leak Risk Analysis** | Data protection, DLP, encryption, evidence, response |
| 08 | **Controls & Compliance Readiness Assessment** | Evidence review, control gaps, remediation, audit readiness |
| 09 | **Botium Toys Risk Assessment** | End-to-end cybersecurity risk case study |
| 10 | **Recruiter Quick View** | Fast summary of GRC skills and deliverables |

---

# ⚠️ Enterprise Cybersecurity Risk Management

The risk-management process used throughout this portfolio follows a structured lifecycle:

```text
Business Asset / Process
        ↓
Threat
        ↓
Vulnerability
        ↓
Likelihood
        ↓
Impact
        ↓
Inherent Risk
        ↓
Existing Controls
        ↓
Risk Treatment
        ↓
Residual Risk
        ↓
Owner
        ↓
Validation
        ↓
Ongoing Review
```

---

# 📊 Risk Scoring Method

A simple 5 × 5 risk model is used throughout the portfolio.

## Likelihood

| Score | Rating | Description |
|---|---|---|
| 1 | Rare | Unlikely under normal operating conditions |
| 2 | Unlikely | Possible but not expected |
| 3 | Possible | Credible and reasonably plausible |
| 4 | Likely | Expected under current exposure |
| 5 | Almost Certain | Highly probable or actively exposed |

## Impact

| Score | Rating | Description |
|---|---|---|
| 1 | Minimal | Negligible business or data impact |
| 2 | Minor | Limited disruption |
| 3 | Moderate | Material team or service impact |
| 4 | Major | Significant operational, financial, or data impact |
| 5 | Severe | Enterprise, legal, customer, or major financial impact |

---

# 🚦 Risk Rating

Risk is evaluated using:

> **Likelihood × Impact = Risk Score**

Example interpretation:

| Score | Rating |
|---|---|
| 1–4 | Low |
| 5–9 | Medium |
| 10–14 | High |
| 15–25 | Critical |

Risk scores are not used in isolation.

Final prioritization also considers:

- Internet exposure
- Asset criticality
- Sensitive-data access
- Privileged access
- Known exploitation
- Business dependency
- Regulatory impact
- Compensating controls
- Detection capability
- Recovery capability

---

# 📋 Enterprise Risk Register

A professional risk register should capture more than a risk title.

The portfolio uses a structure such as:

| Field | Purpose |
|---|---|
| Risk ID | Unique identifier |
| Asset / Process | What is exposed |
| Threat | What may cause harm |
| Vulnerability | Weakness enabling the threat |
| Likelihood | Probability of occurrence |
| Impact | Business consequence |
| Inherent Risk | Risk before treatment |
| Existing Controls | Current protections |
| Treatment | Mitigate, avoid, transfer, accept |
| Residual Risk | Remaining risk |
| Owner | Accountable business or technical owner |
| Review Date | Next formal review |
| Validation | Evidence that remediation works |

---

# 🔥 Priority Cybersecurity Risk Scenarios

Examples assessed in this portfolio include:

| Risk | Potential Impact | Primary Treatment |
|---|---|---|
| Privileged-account compromise | Administrative takeover, data exposure, service disruption | MFA, PAM, least privilege, access review |
| Critical internet-facing vulnerability | Application compromise, downtime, customer-data exposure | Scanning, patching, WAF, SLA enforcement |
| Missing security logs | Delayed detection and poor incident evidence | Centralized SIEM logging |
| Ransomware | Service interruption, data loss, recovery failure | EDR, segmentation, immutable backups |
| Phishing | Credential theft and unauthorized access | MFA, email controls, awareness |
| Cloud misconfiguration | Sensitive-data exposure | Secure defaults, CSPM, encryption |
| Third-party compromise | Vendor-driven data or system exposure | Vendor reviews, access controls, contracts |
| Excessive user access | Unauthorized activity and privilege misuse | RBAC, least privilege, access reviews |
| Weak recovery readiness | Extended outage | Restore testing, RTO/RPO validation |

---

# 🧭 Risk Treatment Options

Risk treatment is documented using four primary options.

## Mitigate

Reduce likelihood or impact using controls.

Examples:

- MFA
- Patching
- WAF
- EDR
- SIEM
- Access reviews
- Encryption
- Backups

## Avoid

Stop the activity that creates unacceptable risk.

Example:

- Retire an unsupported internet-facing system

## Transfer

Shift defined financial or operational exposure.

Examples:

- Cyber insurance
- Contractual responsibility

> Risk accountability is not fully transferred simply because financial exposure is shifted.

## Accept

A business owner may accept residual risk when:

- The risk is understood
- Treatment is not currently feasible
- Compensating controls exist
- Business rationale is documented
- Approval is recorded
- A review or expiration date is assigned

---

# 👤 Risk Ownership

Cybersecurity risk requires clear accountability.

| Role | Responsibility |
|---|---|
| Business Risk Owner | Makes final risk-treatment decision |
| Security / GRC | Assesses and documents risk |
| Technical Owner | Implements technical remediation |
| Control Owner | Maintains the control |
| Executive Leadership | Reviews material organizational risks |
| Internal Audit / Assurance | Independently evaluates evidence where applicable |

---

# 🔍 Vulnerability Management

The vulnerability-management process follows:

```text
Asset Discovery
      ↓
Security Scanning
      ↓
Finding Validation
      ↓
Risk Prioritization
      ↓
Remediation
      ↓
Rescan / Validation
      ↓
Closure
```

---

# 🛠️ Vulnerability Prioritization

A strong vulnerability program should not rely only on CVSS.

Prioritization considers:

- Vulnerability severity
- Internet exposure
- Known exploitation
- Exploit availability
- Asset criticality
- Data sensitivity
- Privilege required
- Business function
- Compensating controls
- Detection capability

---

# ⏱️ Example Remediation SLAs

| Severity / Context | Target |
|---|---|
| Critical — Internet Facing / Known Exploited | **7 Days** |
| Critical — Internal | **14 Days** |
| High | **30 Days** |
| Medium | **60 Days** |
| Low | **90 Days / Risk-Based** |

---

# ✅ Vulnerability Closure Standard

A vulnerability should not be considered closed because a ticket says **Completed**.

Closure should require validation such as:

- Rescan
- Configuration verification
- Version review
- Access test
- Network test
- Application test
- Evidence review

---

# 📈 Vulnerability Management Metrics

Useful metrics include:

- Critical vulnerabilities past SLA
- High vulnerabilities past SLA
- Mean days to remediate
- Percentage of assets covered by authenticated scanning
- Repeat findings
- Exception aging
- Validated closure rate
- Vulnerabilities by business-critical asset

---

# 🧠 PASTA Threat Modeling

The portfolio uses the **Process for Attack Simulation and Threat Analysis (PASTA)** to demonstrate structured threat modeling.

The methodology connects technical attack scenarios to business risk.

---

# 🧩 PASTA Stages

## Stage 1 — Define Business Objectives

Determine what the organization is protecting.

Examples:

- Customer data
- Payment information
- Account integrity
- Service availability
- Business reputation

---

## Stage 2 — Define Technical Scope

Identify systems and components such as:

- Web application
- APIs
- Identity provider
- Database
- Cloud storage
- Administrative portals
- Third-party services

---

## Stage 3 — Application Decomposition

Review:

- Trust boundaries
- Data flows
- Authentication paths
- Administrative pathways
- Service dependencies

---

## Stage 4 — Threat Analysis

Identify possible threats such as:

- Credential stuffing
- Phishing
- Account takeover
- Injection
- Broken authorization
- Session theft
- Cloud misconfiguration

---

## Stage 5 — Vulnerability Analysis

Identify weaknesses such as:

- Weak rate limiting
- Excessive permissions
- Inconsistent authorization
- Poor secret rotation
- Incomplete logging

---

## Stage 6 — Attack Modeling

Document:

- Attack path
- Entry point
- Required conditions
- Likelihood
- Potential impact

---

## Stage 7 — Risk & Impact Analysis

Translate attack scenarios into:

- Business risk
- Security controls
- Remediation priorities
- Residual risk

---

# 🔐 Identity & Access Governance

Identity and access management is a major part of the GRC portfolio.

Key concepts include:

- Role-Based Access Control
- Multi-Factor Authentication
- Least privilege
- Separation of duties
- Privileged access
- Joiner/Mover/Leaver processes
- Service-account governance
- Third-party access
- Access recertification

---

# 👥 Role-Based Access Control

RBAC should align permissions to job responsibilities.

Example:

| Role | Customer Data | Financial Data | User Administration | Security Logs | Production Changes |
|---|---|---|---|---|---|
| Support Analyst | Limited Read | None | Password Reset Only | None | None |
| Finance Analyst | Limited Read | Read / Export | None | None | None |
| System Administrator | Technical Access | None | Admin Technical Accounts | Operational Read | Approved Changes |
| SOC Analyst | Investigation-Only | None | Disable / Escalate | Read / Search | None |
| Security Administrator | Security Need | None | Security Administration | Read / Admin | Security Tooling |

---

# 🔄 Joiner / Mover / Leaver Lifecycle

```text
JOINER
   ↓
Manager Approval
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
Token / Session Revocation
```

---

# 🔑 Privileged Access

Privileged access requires stronger governance.

Controls include:

- Separate administrative accounts
- Strong MFA
- Least privilege
- Administrative logging
- Quarterly reviews
- Time-limited elevation where supported
- Rapid revocation
- Exception tracking

---

# 🤖 Service Account Governance

Service accounts require:

- Named technical owner
- Named business owner
- Documented purpose
- Least privilege
- Secret rotation
- Usage monitoring
- Restricted interactive login
- Periodic review

---

# 📝 Security Policy Development

The portfolio includes security-policy work covering:

- Password & Authentication
- Acceptable Use
- Data Handling & Classification

A professional policy should define:

```text
Purpose
   ↓
Scope
   ↓
Requirements
   ↓
Ownership
   ↓
Exceptions
   ↓
Enforcement
   ↓
Review Cycle
```

---

# 🔐 Password & Authentication Policy

Key requirements include:

- Unique credentials
- No credential sharing
- MFA for privileged and remote access
- Approved password-manager use
- Default credentials disabled
- Terminated-user access revoked promptly
- Credentials rotated when compromise is suspected
- Administrative accounts separated from standard accounts

---

# 💻 Acceptable Use Policy

Key expectations include:

- Company systems used for authorized activity
- Security controls must not be bypassed
- Unauthorized tools must not be installed
- Company data must remain in approved systems
- Suspicious phishing or malware should be reported
- Removable media should follow security policy
- Monitoring may be performed for legitimate security purposes

---

# 🗃️ Data Classification

Example classification model:

| Classification | Example | Handling |
|---|---|---|
| Public | Approved marketing information | May be publicly shared |
| Internal | Procedures and internal operations | Approved company systems |
| Confidential | Customer records, contracts, financial data | Least privilege + encryption |
| Restricted | Secrets, highly sensitive or regulated data | Strict need-to-know + enhanced monitoring |

---

# 🧬 Data Leak Risk Analysis

The portfolio evaluates data exposure across:

- Applications
- Databases
- Email
- Endpoints
- Cloud storage
- Administrative access
- Removable media

---

# 🛡️ Data Protection Controls

Controls include:

- Least privilege
- Data classification
- Encryption at rest
- Encryption in transit
- Data Loss Prevention
- Access logging
- Sharing restrictions
- Security monitoring
- Incident response

---

# 📦 Data Leak Investigation Factors

When evaluating possible data exposure, consider:

- Data classification
- Number of records
- Destination
- User identity
- Business need
- Evidence of download
- External sharing
- Encryption
- Legal or contractual obligations
- Ongoing exposure

---

# 📚 Governance Frameworks

This portfolio references multiple cybersecurity and compliance frameworks.

---

# 🟦 NIST Cybersecurity Framework 2.0

The NIST CSF includes:

```text
GOVERN
   ↓
IDENTIFY
   ↓
PROTECT
   ↓
DETECT
   ↓
RESPOND
   ↓
RECOVER
```

### Portfolio Alignment

**Govern**

- Risk ownership
- Security policy
- Third-party governance
- Roles and responsibilities

**Identify**

- Risk assessment
- Asset ownership
- Vulnerability identification

**Protect**

- MFA
- RBAC
- Least privilege
- Data security

**Detect**

- Logging
- Security monitoring
- Control monitoring

**Respond**

- Incident escalation
- Containment
- Communications

**Recover**

- Backups
- Restore testing
- Lessons learned

---

# 📖 NIST SP 800-53

Common control families used throughout this portfolio include:

| Family | Area |
|---|---|
| AC | Access Control |
| AU | Audit & Accountability |
| CM | Configuration Management |
| CP | Contingency Planning |
| IA | Identification & Authentication |
| IR | Incident Response |
| MP | Media Protection |
| PM | Program Management |
| RA | Risk Assessment |
| SC | System & Communications Protection |
| SI | System & Information Integrity |
| SR | Supply Chain Risk Management |

---

# 🌐 ISO/IEC 27001

Key concepts include:

- Information Security Management System
- Security governance
- Risk assessment
- Risk treatment
- Access control
- Information classification
- Supplier security
- Incident management
- Business continuity
- Continual improvement

---

# 🧩 CIS Controls

Relevant CIS Control areas include:

- Enterprise asset inventory
- Software inventory
- Data protection
- Secure configuration
- Account management
- Access control
- Vulnerability management
- Audit logs
- Malware defenses
- Recovery
- Security awareness
- Incident response

---

# 💳 PCI DSS

Relevant areas include:

- Network security
- Secure configuration
- Cardholder-data protection
- Vulnerability management
- Strong access control
- MFA
- Logging
- Monitoring
- Incident response

---

# 📊 SOC 2

Relevant Trust Services Criteria include:

- Security
- Availability
- Confidentiality
- Processing Integrity
- Privacy

Portfolio examples align to:

- Access control
- Logging
- Monitoring
- Incident response
- Risk mitigation
- Vendor oversight

---

# 🔏 GDPR

Security-relevant GDPR concepts include:

- Data minimization
- Access control
- Encryption
- Security of processing
- Processor oversight
- Breach response
- Accountability
- Data protection

---

# 🏛️ COBIT

Relevant governance concepts include:

- Enterprise governance
- Accountability
- IT/security alignment
- Risk management
- Performance management
- Control ownership

---

# 🔗 Framework Crosswalk

| Security Area | NIST CSF | NIST 800-53 | ISO 27001 | CIS | SOC 2 | PCI DSS | GDPR |
|---|---|---|---|---|---|---|---|
| Governance | Govern | PM / PL | ISMS | Governance | CC1 / CC2 | Governance | Accountability |
| Risk | Identify / Govern | RA | Risk Assessment | Risk-Based Controls | Risk Assessment | Risk Analysis | Risk-Based Security |
| Identity | Protect | AC / IA | Access Control | Controls 5 / 6 | CC6 | Access Control | Security of Processing |
| Logging | Detect | AU | Logging | Control 8 | CC7 | Logging | Security Monitoring |
| Vulnerabilities | Identify / Protect | RA / SI | Vulnerability Mgmt | Control 7 | Risk Mitigation | Vulnerability Mgmt | Security Risk |
| IR | Respond | IR | Incident Mgmt | Control 17 | CC7 | IR | Breach Response |
| Recovery | Recover | CP | Business Continuity | Control 11 | Availability | Recovery | Resilience |
| Data | Protect | SC / MP | Classification / Crypto | Control 3 | Confidentiality | Cardholder Data | Data Protection |
| Third Party | Govern | SR | Supplier Security | Service Providers | Vendor Oversight | Service Providers | Processors |

---

# 🔍 Controls & Compliance Readiness

The control-assessment process follows:

> **Control → Requirement → Evidence → Status → Gap → Risk → Remediation → Owner → Validation**

---

# 📋 Example Control Assessment

| Domain | Expected Evidence | Representative Gap | Risk | Remediation |
|---|---|---|---|---|
| IAM | Access exports, approvals, MFA settings | Privileged reviews incomplete | High | Quarterly access recertification |
| Encryption | TLS and storage encryption evidence | Coverage incomplete | High | Validate encryption and key management |
| Logging | SIEM sources, retention, alert rules | Admin activity not centralized | High | Onboard critical log sources |
| Incident Response | IR plan, exercise records | Escalation workflow not tested | High | Run tabletop and track actions |
| Recovery | Restore tests, RTO/RPO | Restore evidence stale | Medium | Conduct and document recovery test |
| Vendor Risk | Security reviews, contracts | High-risk vendor reassessment inconsistent | Medium | Tier vendors and perform recurring reviews |

---

# 📁 Evidence Quality Standard

Strong control evidence should be:

- Current
- Traceable
- Relevant to the assessed system
- Appropriate to the review period
- Repeatable
- Attributable to a control owner
- Sufficient to demonstrate operation

Examples include:

- Access exports
- Configuration screenshots
- System-generated logs
- SIEM events
- Tickets
- Approval records
- Vulnerability scans
- Restore-test results
- Policy acknowledgements
- Security exercise results

---

# ✅ Control Status Definitions

| Status | Meaning |
|---|---|
| Effective | Control is appropriately designed and operating based on available evidence |
| Partially Effective | Control exists but evidence, scope, or consistency needs improvement |
| Not Effective | Control is absent or does not sufficiently address the objective |
| Not Applicable | Control does not apply and rationale is documented |

---

# 📌 Remediation Tracking

Every material finding should include:

- Finding ID
- Security domain
- Business impact
- Risk rating
- Remediation action
- Owner
- Target date
- Status
- Exception status
- Validation method

---

# ⏱️ Example Remediation Priorities

## 0–30 Days

- Privileged MFA gaps
- Internet-facing critical vulnerabilities
- Missing administrative logging
- Critical encryption gaps
- Incident contact validation

## 31–60 Days

- Access recertification
- Incident-response tabletop
- Restore testing
- High-risk vulnerability closure
- Service-account ownership

## 61–90 Days

- Vendor reassessment
- Data-retention review
- Security-metric reporting
- Residual-risk review
- Control-effectiveness validation

---

# 🧸 Botium Toys Risk Assessment

The Botium Toys project demonstrates an end-to-end GRC case study.

The assessment evaluates a simulated small business environment across:

- Employee access
- Customer information
- Payment-related data
- Network security
- Endpoint security
- Inventory systems
- Business applications
- Security monitoring
- Recovery

---

# 🔥 Botium Toys Priority Findings

| Risk | Priority | Recommended Treatment |
|---|---|---|
| Weak access controls | Critical | MFA, RBAC, least privilege, quarterly reviews |
| Limited encryption | High | TLS, encryption at rest, key governance |
| Limited monitoring | High | Centralized logs, EDR, network monitoring |
| Weak backup validation | High | Restore tests and recovery evidence |
| Patch exposure | High | Vulnerability scanning and remediation SLAs |
| Phishing risk | High | MFA, awareness, email security |
| Third-party access | High | Vendor review, MFA, access expiry |

---

# 📊 Management Metrics

Useful GRC metrics include:

## Risk

- Number of Critical risks
- Number of High risks
- Risks without active treatment
- Risk exception aging
- Residual-risk trends

## Vulnerability

- Critical findings past SLA
- High findings past SLA
- Mean remediation time
- Validated closure rate

## IAM

- Privileged MFA coverage
- Access-review completion
- Orphan accounts
- Service-account ownership

## Compliance

- Effective controls
- Partially effective controls
- Open control gaps
- Overdue remediation actions
- Evidence completeness

## Recovery

- Restore-test completion
- Failed recovery tests
- RTO/RPO validation

## Third-Party Risk

- High-risk vendors assessed
- Vendor findings past due
- Third-party access reviewed

---

# 📈 GRC Analyst Workflow

This portfolio demonstrates the following analyst workflow:

```text
DEFINE SCOPE
     ↓
IDENTIFY RISK
     ↓
COLLECT EVIDENCE
     ↓
ASSESS CONTROLS
     ↓
IDENTIFY GAPS
     ↓
RATE RISK
     ↓
RECOMMEND REMEDIATION
     ↓
ASSIGN OWNER
     ↓
VALIDATE CLOSURE
     ↓
REPORT RESIDUAL RISK
```

---

# 💼 GRC Analyst Skills Demonstrated

This portfolio demonstrates my ability to:

- Perform structured cybersecurity risk assessments
- Maintain risk registers
- Distinguish inherent and residual risk
- Recommend risk-treatment options
- Assess security controls
- Identify control gaps
- Define control evidence
- Review access-control risk
- Apply least-privilege principles
- Evaluate privileged access
- Develop security policies
- Analyze data-leak risk
- Perform threat modeling
- Prioritize vulnerabilities
- Define remediation SLAs
- Map controls to cybersecurity frameworks
- Develop compliance-readiness assessments
- Track remediation
- Communicate risk to technical and business stakeholders
- Document governance and accountability
- Validate corrective actions

---

# 🧰 Tools, Methods & Concepts

## Governance & Risk

`Risk Assessment` • `Risk Register` • `Inherent Risk` • `Residual Risk` • `Risk Treatment` • `Risk Acceptance`

## Security Controls

`MFA` • `RBAC` • `Least Privilege` • `Encryption` • `Logging` • `Monitoring` • `Backups`

## Vulnerability Management

`CVSS-Informed Prioritization` • `Remediation SLAs` • `Exception Management` • `Validation`

## Identity & Access

`IAM` • `Privileged Access` • `Joiner/Mover/Leaver` • `Access Reviews` • `Service Accounts`

## Data Protection

`Data Classification` • `DLP` • `Encryption` • `Access Logging` • `Security Monitoring`

## Threat Modeling

`PASTA` • `Attack Paths` • `Threat Analysis` • `Business Impact`

## Frameworks

`NIST CSF 2.0` • `NIST SP 800-53` • `NIST RMF Concepts` • `ISO/IEC 27001` • `SOC 2` • `PCI DSS` • `GDPR` • `COBIT` • `CIS Controls`

---

# 🎯 Target Role Alignment

This GRC portfolio demonstrates skills relevant to:

- **GRC Analyst**
- **IT Risk Analyst**
- **Security Compliance Analyst**
- **Cybersecurity Analyst**
- **Information Security Analyst**
- **Junior Third-Party Risk Analyst**
- **Vulnerability Management Analyst**
- **IAM / Access Governance Analyst**
- **Security Controls Analyst**
- **Risk & Compliance Analyst**

---

# 🔗 Related Portfolio Sections

This GRC work connects to the broader cybersecurity portfolio.

## 🏆 Capstone Integration

Uses GRC concepts to build an integrated enterprise security program.

## 🖥️ SOC, SIEM & Alert Handling

Provides operational detection and monitoring evidence for security controls.

## 🚨 Incident Response & Forensics

Supports Respond and Recover capabilities, evidence handling, and corrective actions.

## ⚙️ System & Automation

Provides technical validation through Linux security, Python automation, Bash, and SQL.

## 🎓 Career & Professional Development

Supports framework knowledge, governance understanding, and analyst-readiness development.

---

# 🧠 Key GRC Principles

### Risk Must Have an Owner

A risk without accountability is unlikely to be managed effectively.

### Controls Need Evidence

A policy or ticket alone does not prove that a control is operating.

### Residual Risk Matters

Security controls reduce risk; they rarely eliminate it completely.

### Compliance Is Not the Same as Security

Framework alignment can improve structure and assurance, but effective controls must work in practice.

### Exceptions Must Expire

Security exceptions should include:

- Owner
- Business reason
- Compensating control
- Approval
- Expiration
- Review date

### Validation Is Required

Remediation should be tested before closure.

---

# ⚠️ Portfolio Integrity

This section contains simulated cybersecurity risk, governance, compliance, and control-assessment work created for portfolio and professional-development purposes.

Unless explicitly stated otherwise:

- Organizations and environments are simulated.
- Risk values are illustrative.
- Findings are portfolio case-study findings.
- Framework mappings demonstrate control-alignment methodology.
- No formal audit opinion is provided.
- No SOC 2 attestation is claimed.
- No PCI DSS certification is claimed.
- No ISO/IEC 27001 certification is claimed.
- No GDPR compliance determination is claimed.
- No production employer risk-management outcomes are claimed.

The goal of this section is to demonstrate how I would **identify risk, evaluate controls, document evidence, recommend remediation, assign ownership, and communicate residual risk in a cybersecurity analyst environment**.

---

# 👤 About the Analyst

## Jamie Christian II

Cybersecurity professional focused on:

**Governance & Risk • Security Operations • Incident Response • Vulnerability Management • Identity & Access • Security Automation**

My portfolio emphasizes practical, interview-defensible cybersecurity work that connects technical security controls to business risk and organizational objectives.

### Connect

- **GitHub:** [github.com/JamieChristian22](https://github.com/JamieChristian22)
- **LinkedIn:** [linkedin.com/in/jamiechristian2](https://www.linkedin.com/in/jamiechristian2/)
- **Email:** [jamiechristian331@gmail.com](mailto:jamiechristian331@gmail.com)

---

# 🛡️ GRC Workflow

### `IDENTIFY → ASSESS → CONTROL → REMEDIATE → VALIDATE → MONITOR`

**This section demonstrates how cybersecurity risk, governance, controls, evidence, compliance readiness, and remediation work together to reduce organizational security risk.**

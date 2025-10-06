# 🖥 Security Operations (SOC) / SIEM / Alert Handling

This section demonstrates my practical experience in **Security Operations (SOC)** workflows — including **log analysis**, **alert triage**, and **threat detection** using **Splunk SIEM**.  
Each deliverable reflects real-world blue-team operations: identifying brute-force attempts, credential stuffing, and impossible travel anomalies through structured queries and dashboards.

---

## 📄 Projects Included

### 1. **Alert Ticket – Phishing Escalation**
**Goal:** Triage and document a simulated phishing incident through a SOC alert workflow.  
**Highlights:**
- Reviewed phishing indicators from SIEM-generated alert.  
- Verified malicious sender domain and embedded URL.  
- Escalated to Tier 2 with incident categorization and recommended containment.  
- Documented full escalation path in a professional alert ticket format.  

---

### 2. **Splunk SIEM Log Analysis Project**
**Goal:** Detect and visualize authentication anomalies within enterprise login data.  
**Dataset:** `auth_logs.csv`  

**Highlights:**
- Created Splunk queries to identify:  
  - **Brute-force attempts** (multiple failed logins from the same IP).  
  - **Credential stuffing** (failed → success sequences).  
  - **Impossible travel** (logins from distant locations within minutes).  
- Built dashboards for visualization:
  - `Failed Logins by Username`
  - `Failed Logins by IP`
  - `Failed Logins Over Time`
  - `Brute Force Check`
- Included screenshots of raw events, bar charts, and time series visualizations.  

---

### 3. **SOC Dashboard Visualization**
**Goal:** Present threat activity visually for executive and SOC-level monitoring.  
**Highlights:**
- 3-panel Splunk dashboard integrating:  
  1. Top failed IPs (brute force)  
  2. Failed→Success (credential stuffing)  
  3. Impossible travel (geo anomalies)  
- Applied filtering and stats commands (`stats`, `timechart`, `transaction`).  
- Enhanced analyst visibility and situational awareness.  

---

## 🧭 Key Outcomes
- Developed strong understanding of **SIEM query logic** and **SOC detection workflows**.  
- Built Splunk dashboards that transform logs into actionable insights.  
- Demonstrated ability to document alerts and escalate incidents per SOC standards.  
- Reinforced skills in **threat detection**, **log correlation**, and **response prioritization**.  

---

**Tools & Frameworks:**  
`Splunk Enterprise` · `SIEM` · `SOC Workflow` · `Incident Escalation` · `Brute Force Detection` · `Credential Stuffing` · `Impossible Travel` · `Dashboards` · `CSV Log Analysis`

---

**Folder Path:**  
`/SOC_SIEM_Alert_Handling/`  

This directory contains hands-on SOC deliverables that combine **technical investigation, automation, and real-world SIEM use cases**, proving capability in live threat monitoring and analysis.

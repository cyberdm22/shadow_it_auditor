# AI Shadow-IT Log Auditor

**Data Loss Prevention (DLP) Engine Mapped to the Information Technology (Reasonable Security Practices and Procedures and Sensitive Personal Data or Information) Rules, 2011 (India).**

---

## 📑 Executive Summary

The proliferation of public generative AI models (ChatGPT, Claude, Gemini) has introduced severe Data Loss Prevention (DLP) challenges for modern enterprises. Employees frequently utilize these unauthorized "Shadow IT" tools to process corporate data, unintentionally exposing highly sensitive information to external data lakes.

The **AI Shadow-IT Log Auditor** is a Python-based forensic analysis engine. It ingests unstructured corporate proxy and firewall logs, utilizes advanced Regular Expressions (Regex) to filter out benign web traffic, and surgically hunts for unauthorized exfiltration of Sensitive Personal Data or Information (SPDI). 

Crucially, this tool does not merely flag anomalies; it acts as an automated Governance, Risk, and Compliance (GRC) auditor by strictly mapping every detected leak to the explicit statutory definitions outlined in **Rule 3 of the Information Technology (Reasonable security practices and procedures and sensitive personal data or information) Rules, 2011 (India)**.

---

## 🏗️ Architecture & Execution Flow

1. **Log Ingestion:** Parses unstructured `.txt` proxy logs simulating enterprise edge-router traffic.
2. **Regex Logic Engine:** Applies distinct mathematical text-stencils and keyword triggers to isolate structured (e.g., Credit Cards) and unstructured (e.g., Medical diagnoses) data leaks.
3. **Capture Group Extraction:** Surgically extracts the specific `violator_ip` and `target_destination` from the raw string.
4. **JSON Serialization:** Outputs a structured, SIEM-ready `audit_report.json` file for automated SOC ingestion and legal ticketing.

---

## ⚖️ Statutory Mapping (IT Rules 2011)

The Regex dictionary is hardcoded to enforce the specific subsections of the Indian IT Rules 2011 regarding SPDI:

| Technical Signature Hunted | Statutory Mapping | Threat Categorization |
| :--- | :--- | :--- |
| `pwd=`, `password=` | **Rule 3(i)** | Password / Corporate Credential Leak |
| `\b\d{4}-\d{4}-\d{4}-\d{4}\b` | **Rule 3(ii)** | Financial Information Leak |
| `diagnosis`, `patient_id` | **Rule 3(iii) & 3(v)**| Physical/Mental Health & Medical Records Exfiltration |
| `fingerprint_hash`, `retina` | **Rule 3(vi)** | Biometric Data Exfiltration |

*(Note: The logic engine utilizes case-insensitive `(?i)` flags and word boundary `\b` operators to prevent false positives and capture varied user inputs).*

---

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/cyberdm22/shadow_it_auditor.git](https://github.com/cyberdm22/shadow_it_auditor.git)
cd shadow_it_auditor
```

### 2. Generate the Test Environment
Because actual corporate proxy logs contain sensitive data, this suite includes a factory script to generate safe, realistic testing data.
```bash
python3 generate_logs.py
```
*(This will generate a `proxy_logs.txt` file simulating edge-router traffic).*

### 3. Execute the Audit
```bash
python3 auditor.py
```

### 4. Review the Output
The engine will print immediate critical alerts to the terminal for Incident Responders, and simultaneously generate `audit_report.json` for GRC archiving.

---

## 🗺️ Future Roadmap (v2.0)

* **SIEM Integration:** Formatting the JSON output to integrate directly with Splunk Enterprise Security via API.
* **Fuzzy Hashing Expansion:** Implementing fuzzy logic to catch partially obfuscated data (e.g., users adding spaces to credit card numbers).
* **Automated Remediation:** Adding a module that automatically emails the violator's manager based on the extracted IP address.

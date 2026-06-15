# auditor.py
import re
import json

def analyze_logs():
    print("--- Starting IT Rules 2011 Compliance Audit ---\n")
    
    # ==========================================
    # IT RULES 2011 - SPDI REGEX DICTIONARY
    # ==========================================
    
    # Rule 3(i): Password (Looks for 'password=' or 'pwd=' followed by characters)
    pwd_pattern = r'(?i)(password|pwd|pass)\s*=\s*([^\s&]+)'
    
    # Rule 3(ii): Financial Information (Credit Card shape)
    financial_pattern = r'\b\d{4}-\d{4}-\d{4}-\d{4}\b'
    
    # Rule 3(iii) & (v): Health and Medical Records (Keyword triggers)
    medical_pattern = r'(?i)\b(diagnosis|patient_id|medical_history|prescription|disease)\b'
    
    # Rule 3(vi): Biometric Information (Keyword triggers)
    biometric_pattern = r'(?i)\b(fingerprint_hash|retina_scan|facial_template|biometrics)\b'
    
    # Extraction Capture Groups
    ip_capture_pattern = r'IP:\s*([\d\.]+)'
    dest_capture_pattern = r'DEST:\s*([a-zA-Z0-9\.-]+)'

    audit_findings = []

    with open("proxy_logs.txt", "r") as file:
        for line in file:
            clean_line = line.strip()

            source_ip = "UNKNOWN_IP"
            target_ai = "UNKNOWN_AI"
            violation_type = None
            legal_statute = None

            # 1. The Logic Engine: Check the line against our legal dictionary
            if re.search(financial_pattern, clean_line):
                violation_type = "Financial Information Leak"
                legal_statute = "IT Rules 2011 - Rule 3(ii)"
            
            elif re.search(pwd_pattern, clean_line):
                violation_type = "Password / Credential Leak"
                legal_statute = "IT Rules 2011 - Rule 3(i)"
                
            elif re.search(medical_pattern, clean_line):
                violation_type = "Medical Record Exfiltration"
                legal_statute = "IT Rules 2011 - Rule 3(iii) / 3(v)"
                
            elif re.search(biometric_pattern, clean_line):
                violation_type = "Biometric Data Exfiltration"
                legal_statute = "IT Rules 2011 - Rule 3(vi)"

            # 2. If any violation triggered, extract metadata and create the report
            if violation_type:
                ip_match = re.search(ip_capture_pattern, clean_line)
                if ip_match:
                    source_ip = ip_match.group(1)

                dest_match = re.search(dest_capture_pattern, clean_line)
                if dest_match:
                    target_ai = dest_match.group(1)

                print(f"🚨 [{legal_statute}] IP: {source_ip} -> {target_ai}")
                
                incident_report = {
                    "statutory_violation": legal_statute,
                    "threat_type": violation_type,
                    "violator_ip": source_ip,
                    "target_destination": target_ai,
                    "raw_evidence": clean_line
                }
                audit_findings.append(incident_report)

    # 3. Export the structured JSON
    if audit_findings:
        print("\n[INFO] Generating formal JSON audit report...")
        with open("audit_report.json", "w") as report_file:
            json.dump(audit_findings, report_file, indent=4)
        print("[SUCCESS] Report saved as 'audit_report.json'")
    else:
        print("\n[INFO] No violations found. System is compliant.")

    print("\n--- Audit Complete ---")

if __name__ == "__main__":
    analyze_logs()
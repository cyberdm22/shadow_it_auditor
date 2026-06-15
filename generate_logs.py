# generate_logs.py
import datetime

def create_fake_logs():
    with open("proxy_logs.txt", "w") as file:
        # Noise
        file.write("[2026-06-15 08:01:12] IP: 192.168.1.55 | DEST: google.com | PAYLOAD: search?q=python+regex\n")
        
        # Rule 3(i): Password Leak
        file.write("[2026-06-15 08:12:05] IP: 192.168.1.102 | DEST: chat.openai.com | PAYLOAD: Can you debug this connection string? db_url=admin:password=SuperSecret123@database.internal\n")
        
        # Rule 3(ii): Financial Information Leak
        file.write("[2026-06-15 08:15:42] IP: 192.168.1.20 | DEST: chat.openai.com | PAYLOAD: summarize this client profile: John Doe, Card: 4532-1122-3344-5566, Exp: 12/28\n")
        
        # Rule 3(v): Medical Records Leak
        file.write("[2026-06-15 08:33:10] IP: 192.168.1.88 | DEST: claude.ai | PAYLOAD: Draft an email to patient_id=99281 regarding their recent diagnosis of Type 2 Diabetes.\n")
        
        # Rule 3(vi): Biometric Information Leak
        file.write("[2026-06-15 08:50:22] IP: 192.168.1.55 | DEST: gemini.google.com | PAYLOAD: Optimize this code block for processing user fingerprint_hash data.\n")

    print("Success: Updated 'proxy_logs.txt' with IT Rules 2011 SPDI vectors.")

if __name__ == "__main__":
    create_fake_logs()
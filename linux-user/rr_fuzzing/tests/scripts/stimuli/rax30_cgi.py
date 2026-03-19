#!/usr/bin/env python3
import requests
import time
import sys

def stimulate(base_url):
    print(f"[*] Starting stimulus on {base_url}...")
    
    # Wait a bit for server to be ready
    time.sleep(2)
    
    try:
        # 1. Access Home Page
        print("[*] Accessing Home Page...")
        r = requests.get(f"{base_url}/index.html", timeout=5)
        print(f"[+] Home page status: {r.status_code}")
        
        # 2. POST to CGI (rex_cgi is a common endpoint)
        print("[*] POSTing to rex_cgi...")
        payload = {
            "id": "1",
            "method": "get",
            "params": {"test": "data"}
        }
        r = requests.post(f"{base_url}/cgi-bin/rex_cgi", json=payload, timeout=5)
        print(f"[+] CGI status: {r.status_code}")
        
    except Exception as e:
        print(f"[-] Stimulus failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    stimulate(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080")

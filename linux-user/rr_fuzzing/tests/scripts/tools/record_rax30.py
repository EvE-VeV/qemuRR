import os
import sys
import subprocess
import time

# Configuration
QEMU_PATH = "/home/webfuzz/Documents/qemu/build/qemu-arm"
SIM_ROOT = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/RAX30/sim_root"
TARGET_BIN = "usr/sbin/lighttpd"
TRACE_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/traces/rax30_exploit.trace"
CONFIG = "etc/lighttpd/fuzz_lighttpd.conf"

def record_trace():
    print("[*] Recording trace for RAX30 rex_cgi...")
    
    # Ensure trace directory exists
    os.makedirs(os.path.dirname(TRACE_FILE), exist_ok=True)
    
    env = os.environ.copy()
    env["RR_MODE"] = "RECORD"
    env["RR_TRACE_FILE"] = TRACE_FILE
    env["LD_LIBRARY_PATH"] = f"{SIM_ROOT}/lib:{SIM_ROOT}/usr/lib:."
    
    # Kill any existing instances first
    subprocess.run(["pkill", "-f", "qemu-arm"], stderr=subprocess.DEVNULL)
    time.sleep(1)

    cmd = [
        QEMU_PATH,
        "-L", SIM_ROOT,
        f"{SIM_ROOT}/{TARGET_BIN}",
        "-D", "-f", f"{SIM_ROOT}/{CONFIG}"
    ]
    
    try:
        # Start lighttpd in background
        print(f"[*] Starting lighttpd with command: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, env=env, cwd=SIM_ROOT)
        time.sleep(3) # Wait for startup
        
        # Trigger the vulnerability (rex_cgi via POST)
        print("[*] Triggering rex_cgi via curl POST...")
        # We use a payload that might trigger the buffer overflow or at least valid parsing
        payload = '{"test": "' + "A" * 100 + '"}'
        curl_cmd = [
            "curl", "-v", 
            "-H", "Content-Type: application/json",
            "-d", payload,
            "http://127.0.0.1:8080/cgi-bin/rex_cgi"
        ]
        subprocess.run(curl_cmd)
        
        time.sleep(2)
        # We need to make sure the trace is flushed
        subprocess.run(["pkill", "-f", "qemu-arm"]) 
        print(f"[+] Trace recorded to {TRACE_FILE}")
        
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        if 'proc' in locals():
            proc.terminate()

if __name__ == "__main__":
    record_trace()

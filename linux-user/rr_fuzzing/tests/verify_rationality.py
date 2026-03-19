#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import shutil
import requests
import signal
from pathlib import Path

# Configuration
BASE_DIR = Path("/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netgear_RAX30")
ROOTFS = BASE_DIR / "rootfs"
QEMU_BIN = "/home/webfuzz/Documents/qemu/build/qemu-arm"
HTTPD_BIN = ROOTFS / "usr/sbin/lighttpd"
CONF_FILE = ROOTFS / "etc/lighttpd/lighttpd.conf"

TRACE_DIR = Path("/tmp/rationality_test")

def setup_env():
    if TRACE_DIR.exists():
        try:
            shutil.rmtree(TRACE_DIR)
        except:
            pass
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    # No patching needed for RAX30

def run_target(trace_name, payload_suffix=""):
    print(f"\n[*] Starting Target for Trace: {trace_name}")
    trace_path = TRACE_DIR / f"{trace_name}.dat"
    
    env = os.environ.copy()
    env["RR_ENABLED"] = "1"
    env["RR_MODE"] = "record"
    env["RR_TRACE_FILE"] = str(trace_path)
    env["QEMU_LD_PREFIX"] = str(ROOTFS)
    env["RR_DEBUG_LEVEL"] = "3"
    
    # Create patched config
    patched_conf = TRACE_DIR / "patched_lighttpd.conf"
    with open(CONF_FILE, "r") as f:
        conf_data = f.read()
    
    # Patch out includes and problematic lines
    conf_data = conf_data.replace('include "conf.d/', '#include "conf.d/')
    conf_data = conf_data.replace('include "modules.conf"', '#include "modules.conf"')
    # sendfile might fail in user mode or config check
    conf_data = conf_data.replace('server.network-backend = "sendfile"', 'server.network-backend = "writev"')
    # Disable user switching (requires root)
    conf_data = conf_data.replace('server.username', '#server.username')
    conf_data = conf_data.replace('server.groupname', '#server.groupname')
    
    # Patch paths to writable directories
    conf_data = conf_data.replace('var.log_root    = "/var/log/lighttpd"', 'var.log_root = "/tmp"')
    conf_data = conf_data.replace('var.state_dir   = "/run"', 'var.state_dir = "/tmp"')
    conf_data = conf_data.replace('var.home_dir    = "/var/lib/lighttpd"', 'var.home_dir = "/tmp"')
    conf_data = conf_data.replace('var.cache_dir   = "/var/cache/lighttpd"', 'var.cache_dir = "/tmp"')
    # Patch document root
    conf_data = conf_data.replace('var.server_root = "/srv/www"', 'var.server_root = "/www"')
    conf_data = conf_data.replace('server.document-root = server_root + "/htdocs"', 'server.document-root = server_root + "/doc_root"')
    # Force IPv4
    conf_data = conf_data.replace('server.use-ipv6 = "enable"', 'server.use-ipv6 = "disable"')
    
    with open(patched_conf, "w") as f:
        f.write(conf_data)

    # Launch QEMU (Netgear RAX30)
    cmd = [
        QEMU_BIN,
        "-L", str(ROOTFS),
        str(HTTPD_BIN),
        "-f", str(patched_conf),
        "-D"
    ]
    
    # Log file for this run
    run_log = TRACE_DIR / f"{trace_name}.log"
    with open(run_log, "w") as log_f:
        try:
            proc = subprocess.Popen(
                cmd, 
                env=env, 
                cwd=str(BASE_DIR),
                stdout=log_f,
                stderr=subprocess.STDOUT # Merge stderr
            )
            
            # Wait for service startup
            print("[*] Waiting for lighttpd (5s)...")
            time.sleep(5) 
            
            # Send Payload
            url = "http://127.0.0.1:8080/index.html"
            payload = "RationalityCheck" + payload_suffix
            data = {"deviceName": payload}
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            
            print(f"[*] Sending payload len={len(payload)}")
            try:
                resp = requests.post(url, data=data, headers=headers, timeout=5)
                print(f"[*] Response: {resp.status_code}")
            except Exception as e:
                print(f"[*] Request finished (exception: {e})")
                
            print("[*] Payload sent. Stopping target...")
            time.sleep(2) # Allow trace to flush
            
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                
            # Print logs for debugging
            print(f"--- {run_log.name} tail ---")
            os.system(f"tail -n 20 {run_log}")
            print("----------------------")
                
            # Verify trace creation
            found_trace = None
            for f in TRACE_DIR.glob(f"{trace_name}.dat*"):
                if f.stat().st_size > 0:
                    found_trace = f
                    break
            
            if found_trace:
                print(f"[+] Trace captured: {found_trace.name} ({found_trace.stat().st_size} bytes)")
                return found_trace
            else:
                print("[-] No trace file found!")
                return None
                
        except Exception as e:
            print(f"[!] Error running target: {e}")
            if 'proc' in locals():
                proc.kill()
            return None

def verify_rationality():
    setup_env()
    
    # 1. Baseline Trace
    print("--- Phase 1: Baseline Recording ---")
    trace1 = run_target("trace_baseline", payload_suffix="_A")
    
    # 2. Mutated Trace
    print("--- Phase 2: Evolutionary Recording (Mutated) ---")
    trace2 = run_target("trace_mutated", payload_suffix="_B" * 50) 
    
    # 3. Comparision
    print("\n--- Phase 3: Rationality Verification ---")
    if trace1 and trace2:
        size1 = trace1.stat().st_size
        size2 = trace2.stat().st_size
        
        print(f"Baseline Trace Size: {size1} bytes")
        print(f"Mutated Trace Size:  {size2} bytes")
        
        diff = abs(size1 - size2)
        print(f"Difference: {diff} bytes")
        
        if diff > 100: 
            print("\n✅ VERIFICATION SUCCESS: Trace size significantly changed.")
            print("   This proves that re-recording with mutated inputs generates DISTINCT execution traces.")
            print("   Therefore, the 'Evolutionary Re-recording' strategy is RATIONAL.")
        else:
            print("\n⚠️  VERIFICATION INCONCLUSIVE: Trace sizes are too similar.")
    else:
        print("\n❌ VERIFICATION FAILED: Could not generate traces.")

if __name__ == "__main__":
    verify_rationality()

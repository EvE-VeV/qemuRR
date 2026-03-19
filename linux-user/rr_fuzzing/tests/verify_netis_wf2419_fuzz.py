#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import signal

# Configuration
CORE_ROOT = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
TARGET_CONFIG = os.path.join(CORE_ROOT, "fuzzing/config/targets/netis_wf2419.json")
OUTPUT_DIR = os.path.join(CORE_ROOT, "tests/fuzz_output_netis")

def run_fuzzing():
    print("[*] Starting Netis WF2419 Fuzzing Campaign...")
    
    # Ensure output directory is clean
    if os.path.exists(OUTPUT_DIR):
        print(f"[*] Removing old output directory: {OUTPUT_DIR}")
        subprocess.run(["rm", "-rf", OUTPUT_DIR], check=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Start the fuzzer (using the correct entry point fuzz_main.py)
    env = os.environ.copy()
    env["RR_DEBUG_LEVEL"] = "3"
    
    cmd = [
        "python3", "fuzzing/fuzz_main.py",
        "--qemu", "/home/webfuzz/Documents/qemu/build/qemu-mips",
        "--target", "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netis_WF2419/rootfs/bin/boa",
        "--trace", "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/seeds/Netis_WF2419/netis_wf2419_seed.bin",
        "--output", OUTPUT_DIR,
        "--workers", "2",
        "--infinite",
        "--ld-prefix", "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netis_WF2419/rootfs",
        "--dictionary", "fuzzing/config/dicts/totolink_http.dict",
        "--word-size", "32",
        "--endian", "little",
        "--args", "-p /bin/boa -f /etc/boa.conf"
    ]
    
    print(f"[*] Command: {' '.join(cmd)}")
    
    # Run in sub-process
    proc = subprocess.Popen(cmd, cwd=CORE_ROOT)
    
    try:
        while True:
            if proc.poll() is not None:
                print("[!] Fuzzing process exited early.")
                break
                
            # Check for crashes
            crashes_path = os.path.join(OUTPUT_DIR, "crashes")
            if os.path.exists(crashes_path):
                crash_count = len([f for f in os.listdir(crashes_path) if f.endswith(".json")])
                if crash_count > 0:
                    print(f"[*] Found {crash_count} crashes!")
            
            time.sleep(10)
    except KeyboardInterrupt:
        print("[*] Stopping fuzzing...")
        proc.send_signal(signal.SIGINT)
        proc.wait()

if __name__ == "__main__":
    run_fuzzing()

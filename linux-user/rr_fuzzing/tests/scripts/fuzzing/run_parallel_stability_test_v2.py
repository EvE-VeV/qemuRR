#!/usr/bin/env python3
import os
import sys
import time
import json
import signal
import subprocess
from pathlib import Path
from multiprocessing import Process

# Setup paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "fuzzing"))

from conductor.target_profile import TargetProfile
from conductor.lifecycle_manager import TargetLifecycleManager

# Targets Configuration
TARGETS = {
    "rax30": {
        "profile": "fuzzing/config/targets/rax30.json",
        "qemu": "/home/webfuzz/Documents/qemu/build/qemu-arm",
        "trace": "tests/seeds/Netgear_RAX30/rax30_cgi_seed.bin",
        "output": "fuzz_output_parallel/rax30",
        "workers": 2,
        "args": "-D -f /tmp/fuzz_lighttpd.conf" # As defined in profile replacements
    },
    "totolink": {
        "profile": "fuzzing/config/targets/totolink_fuzz.json",
        "qemu": "/home/webfuzz/Documents/qemu/build/qemu-mips",
        "trace": "tests/seeds/TOTOLINK/boa_totolink_v2.trace",
        "output": "fuzz_output_parallel/totolink",
        "workers": 2,
        "args": "-c /etc/boa" # Default for boa
    }
}

active_processes = []

def signal_handler(signum, frame):
    print(f"\n[*] Received signal {signum}, shutting down campaigns...")
    for p in active_processes:
        if p.poll() is None:
            print(f"[*] Terminating {p.pid}...")
            p.terminate()
    sys.exit(0)

def init_rax30():
    print("[*] Initializing RAX30 environment (patching configs)...")
    profile = TargetProfile.from_json(str(PROJECT_ROOT / TARGETS["rax30"]["profile"]))
    lm = TargetLifecycleManager(profile, TARGETS["rax30"]["qemu"])
    lm.patch_environment()
    print("[+] RAX30 patches applied.")

def run_fuzzer(name, conf):
    print(f"[*] Starting {name} campaign...")
    
    # Environment
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT / "fuzzing")
    
    # Target-specific env from profile
    profile_data = json.load(open(str(PROJECT_ROOT / conf["profile"])))
    for k, v in profile_data.get("env", {}).items():
        env[k] = v
        
    cmd = [
        "python3", str(PROJECT_ROOT / "fuzzing/fuzz_main.py"),
        "--qemu", conf["qemu"],
        "--target", str(Path(profile_data["rootfs_path"]) / profile_data["binary_path"]),
        "--trace", str(PROJECT_ROOT / conf["trace"]),
        "--args", conf["args"],
        "--output", str(PROJECT_ROOT / conf["output"]),
        "--workers", str(conf["workers"]),
        "--ld-prefix", profile_data["ld_prefix"],
        "--infinite"
    ]
    
    if profile_data.get("dictionary"):
        cmd += ["--dictionary", str(PROJECT_ROOT / profile_data["dictionary"])]

    print(f"[*] CMD: {' '.join(cmd)}")
    
    # Launch in background
    return subprocess.Popen(cmd, env=env)

def monitor():
    print("\n" + "="*80)
    print("      RR-Fuzz Dual-Target Parallel Stability Monitor (2-Hour Test)")
    print("="*80)
    
    start_time = time.time()
    duration = 2 * 3600 # 2 hours
    
    try:
        while True:
            elapsed = time.time() - start_time
            remaining = max(0, duration - elapsed)
            
            # Simple status line
            print(f"\r[Time: {int(elapsed)}s / {duration}s] Targets Active: {len([p for p in active_processes if p.poll() is None])}", end="")
            
            if elapsed >= duration:
                print("\n\n[!] Stability test duration reached. Shutting down...")
                break
                
            # Check if anyone exited early
            for p in active_processes:
                if p.poll() is not None:
                    print(f"\n[!] ALERT: Process {p.pid} exited with code {p.returncode}")
            
            time.sleep(10)
            
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 0. Clean old output
    # subprocess.run(["rm", "-rf", "fuzz_output_parallel"])
    
    # 1. Init
    init_rax30()
    
    # 2. Launch
    for name, conf in TARGETS.items():
        p = run_fuzzer(name, conf)
        active_processes.append(p)
        time.sleep(1) # Stagger
        
    # 3. Monitor
    monitor()
    
    # 4. Cleanup
    signal_handler(signal.SIGINT, None)

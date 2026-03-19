#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "fuzzing"))

from conductor.target_profile import TargetProfile
from conductor.lifecycle_manager import TargetLifecycleManager

def verify_crash(target_name, crash_bin):
    print(f"[*] Verifying crash for target: {target_name}")
    print(f"[*] Crash bin: {crash_bin}")
    
    if target_name == "rax30":
        profile_path = PROJECT_ROOT / "fuzzing/config/targets/rax30.json"
        qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-arm"
    elif target_name == "totolink":
        profile_path = PROJECT_ROOT / "fuzzing/config/targets/totolink_fuzz.json"
        qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-mips"
    else:
        print(f"[-] Unknown target: {target_name}")
        return

    # Load profile
    profile = TargetProfile.from_json(str(profile_path))
    
    # Setup environment (patching for RAX30 if needed)
    lm = TargetLifecycleManager(profile, qemu_path)
    if target_name == "rax30":
        print("[*] Patching RAX30 environment...")
        lm.patch_environment()
    
    # Environment variables
    env = os.environ.copy()
    env["RR_MODE"] = "fuzzing"
    env["RR_USE_FORK_SERVER"] = "0" # Disable fork server for replay
    env["RR_TRACE_FILE"] = str(Path(crash_bin).resolve())
    env["RR_DEBUG_LEVEL"] = "1"
    env["QEMU_LD_PREFIX"] = profile.ld_prefix
    
    # Target-specific env
    for k, v in profile.env.items():
        env[k] = v

    # Construct QEMU command
    binary = str(Path(profile.rootfs_path) / profile.binary_path)
    args = profile.start_command[1:] # Drop binary itself
    
    cmd = [qemu_path, binary] + args
    
    print(f"[*] Executing: {' '.join(cmd)}")
    print(f"[*] Environment: RR_MODE=fuzzing RR_TRACE_FILE={env['RR_TRACE_FILE']}")
    
    # Run
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=15)
        
        print("\n--- STDOUT ---")
        print(stdout.decode(errors='replace'))
        print("\n--- STDERR ---")
        print(stderr.decode(errors='replace'))
        print(f"\n[*] Exit Code: {proc.returncode}")
        
        if proc.returncode in [139, -11]:
            print("\n[+] SUCCESS: Crash reproduced (Segmentation Fault).")
        elif proc.returncode != 0:
            print(f"\n[?] Target exited with code {proc.returncode}")
        else:
            print("\n[-] FAILURE: Target exited normally (No crash reproduced).")
            
    except subprocess.TimeoutExpired:
        proc.kill()
        print("\n[-] FAILURE: Replay timed out.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python verify_crash_manual.py <target> <crash_bin>")
        print("Targets: rax30, totolink")
        sys.exit(1)
        
    verify_crash(sys.argv[1], sys.argv[2])

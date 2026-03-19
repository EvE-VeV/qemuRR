#!/usr/bin/env python3
import os
import json
import subprocess
import time
import signal
import argparse
from pathlib import Path

def patch_configs(profile):
    rootfs = Path(profile['rootfs_path'])
    for patch in profile.get('config_patches', []):
        src = rootfs / patch['source']
        dst = Path(patch['target'])
        
        if not src.exists():
            print(f"[-] Patch source {src} not found, skipping.")
            continue
            
        print(f"[*] Patching {src} -> {dst}")
        with open(src, 'r') as f:
            content = f.read()
            
        for k, v in patch['replacements'].items():
            v = v.replace("{{ROOTFS}}", str(rootfs))
            content = content.replace(k, v)
            
        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(dst, 'w') as f:
            f.write(content)

def run_recording(profile, stimulus_script, output_name):
    qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-arm"
    target_bin = str(Path(profile['rootfs_path']) / profile['binary_path'])
    
    env = os.environ.copy()
    env.update(profile.get('env', {}))
    env['RR_MODE'] = 'record'
    env['RR_ENABLED'] = '1'
    env['RR_TRACE_FILE'] = f"/tmp/{output_name}.bin"
    env['RR_LOG_LEVEL'] = '1'
    env['QEMU_LD_PREFIX'] = profile['rootfs_path']
    
    # Resolve binary path
    orig_cmd = profile['start_command']
    if not orig_cmd[0].startswith("/"):
        binary = str(Path(profile['rootfs_path']) / orig_cmd[0])
    else:
        binary = orig_cmd[0]
        
    cmd = [qemu_path, "-L", profile['rootfs_path'], binary] + orig_cmd[1:]
    
    print(f"[*] Starting QEMU RECORD: {' '.join(cmd)}")
    log_file = open(f"/tmp/qemu_{output_name}.log", "w")
    proc = subprocess.Popen(cmd, env=env, stdout=log_file, stderr=log_file)
    
    # Wait for server to start
    print("[*] Waiting 5 seconds for server to initialize...")
    time.sleep(5)
    try:
        # Run stimulus
        print(f"[*] Running stimulus script: {stimulus_script}")
        # Using 8082 as observed in netstat
        stim_proc = subprocess.run(["python3", stimulus_script, "http://127.0.0.1:9090"], capture_output=True, text=True)
        print(stim_proc.stdout)
        if stim_proc.stderr:
            print(f"DEBUG: {stim_proc.stderr}")
            
        # Give it a tiny bit more time
        time.sleep(1)
    finally:
        print("[*] Stopping QEMU...")
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("[!] QEMU didn't stop in time, killing...")
            proc.kill()
            proc.wait()
        log_file.close()
            
    trace_file = Path(f"/tmp/{output_name}.bin")
    if trace_file.exists():
        print(f"[+] Recording successful! Trace saved to {trace_file}")
        # Copy to a logical place
        target_dir = Path("tests/seeds") / profile['name']
        target_dir.mkdir(parents=True, exist_ok=True)
        shutil_copy = subprocess.run(["cp", str(trace_file), str(target_dir / f"{output_name}.bin")])
        print(f"[+] Seed moved to {target_dir / f'{output_name}.bin'}")
    else:
        print("[-] Recording failed: Trace file not found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--stimulus", required=True)
    parser.add_argument("--output", default="seed_1")
    args = parser.parse_args()
    
    with open(args.profile, 'r') as f:
        profile_data = json.load(f)
        
    patch_configs(profile_data)
    run_recording(profile_data, args.stimulus, args.output)

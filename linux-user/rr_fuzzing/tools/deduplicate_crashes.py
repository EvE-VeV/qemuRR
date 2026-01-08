#!/usr/bin/env python3
import os
import sys
import argparse
import subprocess
import hashlib
import json
import shutil
from pathlib import Path
from collections import defaultdict

def get_crash_hashed_signature(crash_file, qemu_path, target_path, timeout=5):
    """
    Replays a crash and extracts a unique signature based on the crash output/signal.
    For a more advanced version, this would parse the register state (RIP/EIP) from log.
    For now, it uses the qemu output signature.
    """
    env = os.environ.copy()
    env["RR_MODE"] = "replay"
    env["RR_TRACE_FILE"] = str(crash_file)
    
    cmd = [qemu_path, target_path]
    
    try:
        # Run QEMU in replay mode
        result = subprocess.run(
            cmd, 
            env=env, 
            capture_output=True, 
            timeout=timeout
        )
        
        # Combine stdout (app output) and stderr (RR/QEMU debug info)
        output = result.stdout + result.stderr
        
        # Simple signature: Exit Code + Signal + Last 3 lines of output (often contains crash addr)
        # In a real scenario, we would grep for "Segmentation fault" or specific addresses
        lines = output.strip().split(b'\n')
        last_lines = b'\n'.join(lines[-3:]) if lines else b""
        
        sig_data = f"{result.returncode}_{last_lines}"
        return hashlib.md5(sig_data.encode('utf-8', errors='ignore')).hexdigest(), output
        
    except subprocess.TimeoutExpired:
        return "timeout", b"Timeout during replay"
    except Exception as e:
        return "error", str(e).encode()

def main():
    parser = argparse.ArgumentParser(description="Standalone Crash Deduplicator for RR-Fuzz")
    parser.add_argument("--crashes-dir", required=True, help="Directory containing crash .bin files")
    parser.add_argument("--output-dir", required=True, help="Directory to save unique crashes")
    parser.add_argument("--qemu", required=True, help="Path to QEMU binary")
    parser.add_argument("--target", required=True, help="Path to target binary")
    
    args = parser.parse_args()
    
    crashes_dir = Path(args.crashes_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    crash_files = list(crashes_dir.glob("*.bin"))
    print(f"[*] Found {len(crash_files)} crash files in {crashes_dir}")
    
    unique_crashes = {}
    stats = defaultdict(int)
    
    for i, crash_file in enumerate(crash_files):
        print(f"[{i+1}/{len(crash_files)}] Processing {crash_file.name}...", end="\r")
        
        sig, output = get_crash_hashed_signature(crash_file, args.qemu, args.target)
        stats[sig] += 1
        
        if sig not in unique_crashes:
            unique_crashes[sig] = crash_file
            # Save unique crash
            shutil.copy(crash_file, output_dir / f"unique_{sig}.bin")
            
            # Save debug log
            with open(output_dir / f"unique_{sig}.log", "wb") as f:
                f.write(output)
                
    print(f"\n[*] Processing complete!")
    print(f"[*] Total input crashes: {len(crash_files)}")
    print(f"[*] Unique crashes found: {len(unique_crashes)}")
    print(f"[*] Unique crashes saved to: {output_dir}")
    print("\n[+] Distribution:")
    for sig, count in stats.items():
        print(f"    Hash {sig}: {count} occurrences")

if __name__ == "__main__":
    main()

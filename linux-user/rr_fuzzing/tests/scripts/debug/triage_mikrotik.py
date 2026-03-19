#!/usr/bin/env python3
import os
import json
from pathlib import Path
from collections import Counter

def triage_crashes(sync_dir):
    sync_path = Path(sync_dir)
    crash_dir = sync_path / 'crashes'
    
    if not crash_dir.exists():
        print(f"Error: Crash directory {crash_dir} not found.")
        return

    unique_crashes = {}
    total_files = 0
    
    # Iterate through all worker directories
    for worker_dir in crash_dir.glob('worker*'):
        for meta_file in worker_dir.glob('*.meta'):
            total_files += 1
            try:
                with open(meta_file, 'r') as f:
                    data = json.load(f)
                
                signal = data.get('signal', 'unknown')
                pc = data.get('pc', 'unknown')
                fault_addr = data.get('fault_address', 'unknown')
                
                key = (signal, pc, fault_addr)
                if key not in unique_crashes:
                    unique_crashes[key] = {
                        'count': 0,
                        'sample_trace': str(meta_file.with_suffix('.bin')),
                        'sample_meta': str(meta_file)
                    }
                unique_crashes[key]['count'] += 1
            except Exception as e:
                print(f"Error reading {meta_file}: {e}")

    print(f"\nProcessing {total_files} crash files from {sync_dir}...")
    print("-" * 80)
    print(f"{'Signal':<10} | {'PC':<18} | {'Fault Addr':<18} | {'Count':<6}")
    print("-" * 80)
    
    # Sort by count descending
    for (sig, pc, addr), info in sorted(unique_crashes.items(), key=lambda x: x[1]['count'], reverse=True):
        pc_str = f"0x{pc:x}" if isinstance(pc, int) else str(pc)
        addr_str = f"0x{addr:x}" if isinstance(addr, int) else str(addr)
        print(f"{sig:<10} | {pc_str:<18} | {addr_str:<18} | {info['count']:<6}")

    print("-" * 80)
    print(f"Total Unique Crash Types: {len(unique_crashes)}")

if __name__ == "__main__":
    import sys
    sync_dir = "tests/verified_targets/MikroTik_6.48.6/sync"
    if len(sys.argv) > 1:
        sync_dir = sys.argv[1]
    triage_crashes(sync_dir)

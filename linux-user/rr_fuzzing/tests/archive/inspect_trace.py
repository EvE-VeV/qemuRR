#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Setup paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "fuzzing"))

from conductor.trace_analyzer import TraceAnalyzer

def bytes_to_int(b, endian):
    return int.from_bytes(b, 'little' if endian == 'little' else 'big')

def main():
    trace_file = sys.argv[1] if len(sys.argv) > 1 else "/tmp/rax30_cgi_seed.bin"
    start_idx = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    end_idx = int(sys.argv[3]) if len(sys.argv) > 3 else 999999
    
    if not os.path.exists(trace_file):
        print(f"File not found: {trace_file}")
        return

    # print(f"[*] Analyzing {trace_file} (Range: {start_idx} to {end_idx})...")
    # ARM32 is 32-bit
    analyzer = TraceAnalyzer(trace_file, word_size=32)
    
    for sc in analyzer.syscalls:
        if sc.index < start_idx or sc.index > end_idx:
            continue
            
        name = sc.name
        print(f"[{sc.index}] {name}({sc.syscall_nr}) ret={sc.retval}")
        
        # Merge arg_data and aux_entries for printing
        all_data = {f"arg[{idx}]": data for idx, data in sc.arg_data.items()}
        for i, (kind, arg_mask, data) in enumerate(sc.aux_entries):
             label = f"aux[{i}] (kind={kind}, arg_mask={arg_mask})"
             all_data[label] = data
             
        for label, data in all_data.items():
            try:
                s = data.decode('utf-8', errors='replace').rstrip('\0')
                if any(c.isprintable() for c in s) and len(s) > 0:
                    print(f"    {label}: {s}")
                else:
                    print(f"    {label}: {data.hex()}")
            except:
                print(f"    {label}: {data.hex()}")
        
        if name == 'bind':
            for label, data in all_data.items():
                if len(data) >= 8:
                     family = bytes_to_int(data[0:2], analyzer.detected_endian)
                     if family in [2, 512, 0x0200]:
                         port = int.from_bytes(data[2:4], 'big')
                         print(f"    BIND-INFO: family={family}, port={port}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "fuzzing/conductor"))

from trace_analyzer import TraceAnalyzer

def dump_trace_io(trace_path, target_indices=None):
    print(f"[*] Analyzing trace: {trace_path}")
    if not os.path.exists(trace_path):
        print(f"[-] File not found: {trace_path}")
        return

    # Initialize analyzer
    analyzer = TraceAnalyzer(trace_path)
    
    print(f"[*] Total Syscalls: {len(analyzer.syscalls)}")
    
    for sc in analyzer.syscalls:
        if target_indices and sc.index not in target_indices:
            continue
            
        content = b""
        for kind, mask, data in sc.aux_entries:
            content += data
        for arg_idx, data in sc.arg_data.items():
            if arg_idx == 1:
                content += data
        
        if content:
            print(f"[{sc.index:04d}] {sc.name}(retval={sc.retval}):")
            # Safe representation
            safe_text = "".join([chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in content])
            print(f"    DATA: {safe_text[:500]}...")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 dump_trace_payload.py <trace_bin> [indices...]")
        sys.exit(1)
    
    indices = None
    if len(sys.argv) > 2:
        indices = [int(i) for i in sys.argv[2:]]
        
    dump_trace_io(sys.argv[1], indices)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 dump_trace_payload.py <trace_bin>")
        sys.exit(1)
    dump_trace_io(sys.argv[1])

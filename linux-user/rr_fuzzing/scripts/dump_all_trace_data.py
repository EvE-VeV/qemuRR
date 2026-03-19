#!/usr/bin/env python3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "fuzzing/conductor"))
from trace_analyzer import TraceAnalyzer

def dump_all(trace_path):
    print(f"Analyzing {trace_path}...")
    analyzer = TraceAnalyzer(trace_path)
    print(f"Total syscalls: {len(analyzer.syscalls)}")
    
    for sc in analyzer.syscalls:
        chunk = b""
        # 1. Aux entries
        for kind, mask, data in sc.aux_entries:
            chunk += data
        # 2. Arg data
        for idx, data in sc.arg_data.items():
            chunk += data
            
        if chunk:
            # Simple ASCII printable filter
            printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            if any(c != "." for c in printable):
                print(f"[{sc.index:03d}] {sc.name:<12} (len={len(chunk)}): {printable[:100]}")

if __name__ == "__main__":
    dump_all(sys.argv[1])

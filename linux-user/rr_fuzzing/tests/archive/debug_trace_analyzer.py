#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Setup paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "fuzzing"))

from conductor.trace_analyzer import TraceAnalyzer

def inspect_trace(trace_path):
    print(f"[*] Analyzing trace: {trace_path}")
    # Force MIPS 32-bit Big Endian
    analyzer = TraceAnalyzer(trace_path, endian='big', word_size=32)
    
    print(f"[*] Total Syscalls: {len(analyzer.syscalls)}")
    print(f"[*] Detected Architecture: {analyzer.detected_word_size}-bit {analyzer.detected_endian}")
    
    print("\n[*] First 20 Syscalls:")
    for i, sc in enumerate(analyzer.syscalls[:20]):
        print(f"  [{i}] NR={sc.syscall_nr} Name={sc.name} Ret={sc.retval}")

    print("\n[*] Searching for IO Syscalls:")
    io_count = 0
    for sc in analyzer.syscalls:
        if sc.name in ['read', 'write', 'recv', 'send', 'ioctl']:
            io_count += 1
            if io_count <= 10:
                print(f"  [{sc.index}] NR={sc.syscall_nr} Name={sc.name}")
    print(f"[*] Total IO Syscalls found: {io_count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./debug_trace_analyzer.py <trace_file>")
        sys.exit(1)
    
    inspect_trace(sys.argv[1])

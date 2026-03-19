#!/usr/bin/env python3
import sys
import os

# Add relevant paths
sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing')

from fuzzing.trace_analyzer import TraceAnalyzer

def debug_trace(path):
    print(f"Debugging trace: {path}")
    analyzer = TraceAnalyzer(path)
    
    print(f"Header count: {analyzer.stats['total']}")
    print(f"Actual records read: {len(analyzer.syscalls)}")
    
    if len(analyzer.syscalls) > 0:
        first = analyzer.syscalls[0]
        last = analyzer.syscalls[-1]
        print(f"First record: index={first.index}, nr={first.syscall_nr} ({first.name})")
        print(f"Last record:  index={last.index}, nr={last.syscall_nr} ({last.name})")
        
        # Check for non-sequential indices
        expected = 0
        gaps = 0
        for i, rec in enumerate(analyzer.syscalls):
            if rec.index != expected:
                if gaps < 5:
                    print(f"Gap found at array index {i}: expected record index {expected}, found {rec.index}")
                gaps += 1
                expected = rec.index + 1
            else:
                expected += 1
        
        if gaps > 0:
            print(f"Total gaps/mismatches: {gaps}")
        else:
            print("All record indices are sequential.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        debug_trace(sys.argv[1])
    else:
        debug_trace("verified_targets/MikroTik_6.48.6/traces/init.txt.new")

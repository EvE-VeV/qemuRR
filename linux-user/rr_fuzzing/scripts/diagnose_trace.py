#!/usr/bin/env python3
import sys
from pathlib import Path
import os

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "fuzzing/conductor"))

from trace_analyzer import TraceAnalyzer

def diagnose(trace_path):
    analyzer = TraceAnalyzer(trace_path)
    socket_fds = set()
    
    print(f"{'Index':<6} | {'NR':<6} | {'Syscall':<15} | {'FD':<4} | {'Ret':<6} | {'Data Preview'}")
    print("-" * 80)
    
    for sc in analyzer.syscalls:
        # Better FD detection
        fd = sc.args[0] if (sc.uses_fd or sc.creates_fd or sc.name in ['read', 'write', 'recvfrom', 'sendto', 'recv', 'send', 'recvmsg', 'sendmsg', 'accept', 'bind', 'connect']) else -1
        
        # Track socket creation
        if sc.name == 'socket':
            if sc.retval >= 0:
                socket_fds.add(sc.retval)
        elif sc.name == 'accept':
            if sc.retval >= 0:
                socket_fds.add(sc.retval)
        
        data = b""
        for k, m, d in sc.aux_entries:
            data += d
        for idx, d in sc.arg_data.items():
            if idx == 1: data += d
            
        if data:
            preview = repr(data[:40])
            print(f"{sc.index:<6} | {sc.syscall_nr:<6} | {sc.name:<15} | {fd:<4} | {sc.retval:<6} | {preview}")

if __name__ == "__main__":
    diagnose(sys.argv[1])

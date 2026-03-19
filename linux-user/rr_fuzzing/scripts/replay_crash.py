#!/usr/bin/env python3
"""
Replay a crash from crash_db to verify PC control.

Usage:
    python3 replay_crash.py <crash_json> [--pattern <hex_pattern>]

The script:
  1. Reads the crash JSON to extract the mutation recipe
  2. Applies the mutations to build the mutated syscall data
  3. Runs QEMU with those mutations via the fuzzing framework
  4. Reports the actual PC if a crash is captured
"""
import sys
import os
import json
import subprocess
import tempfile
import struct
import time
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'fuzzing'))

from conductor.trace_analyzer import TraceAnalyzer
from conductor.qemu_executor import QEMUExecutor, FuzzInstruction
from conductor.shared_memory import FuzzSharedMemory

QEMU_ARM = "/home/webfuzz/Documents/qemu/build/qemu-arm"
ROOTFS = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/TPLink_AXE75/rootfs"
TARGET = f"{ROOTFS}/usr/sbin/uhttpd"
TRACE = "tests/seeds/TPLink_AXE75.trace"

def parse_instruction_str(instr_str):
    """Parse a FuzzInstruction repr string back into an object."""
    # Quick-and-dirty eval of the repr
    import re
    # Format: FuzzInstruction(syscall_index=X, cmd=Y, arg_index=Z, data=b'...', offset=O, size=S, mutation_type='T')
    pattern = r"FuzzInstruction\(syscall_index=(\d+), cmd=(\d+), arg_index=(\d+), data=(b'[^']*'|b\"[^\"]*\"), offset=(\d+), size=(\d+), mutation_type='([^']+)'\)"
    matches = re.findall(pattern, instr_str)
    result = []
    for m in matches:
        syscall_index, cmd, arg_index, data_str, offset, size, mutation_type = m
        try:
            data = eval(data_str)
        except Exception:
            data = b'\x00'
        result.append(FuzzInstruction(
            syscall_index=int(syscall_index),
            cmd=int(cmd),
            arg_index=int(arg_index),
            data=data,
            offset=int(offset),
            size=int(size),
            mutation_type=mutation_type
        ))
    return result

def main():
    crash_json = sys.argv[1]
    pattern = sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == '--pattern' else None

    with open(crash_json) as f:
        crash = json.load(f)

    print(f"[*] Crash: {crash.get('crash_id')}")
    print(f"[*] Signal: {crash.get('signal_name')} at PC=0x{crash.get('pc', 0):x}")
    print(f"[*] Exploitability: {crash.get('exploitability')}")

    mutation_recipe = crash.get('mutation_recipe', {})
    mutation_strs = mutation_recipe.get('mutations', [])

    instructions = []
    for mut_str in mutation_strs:
        instructions.extend(parse_instruction_str(mut_str))

    if pattern:
        pat_bytes = bytes.fromhex(pattern)
        print(f"\n[*] Substituting data with pattern: {pat_bytes[:8].hex()}...")
        for instr in instructions:
            if instr.mutation_type == 'replace_buffer_large':
                instr.data = (pat_bytes * (len(instr.data) // len(pat_bytes) + 1))[:len(instr.data)]
                print(f"    Applied pattern to syscall_index={instr.syscall_index}")

    print(f"\n[*] Replaying with {len(instructions)} mutation instructions")
    for i, instr in enumerate(instructions):
        print(f"    [{i}] syscall={instr.syscall_index} cmd={instr.cmd} type={instr.mutation_type} size={len(instr.data)}")

    # Execute via QEMUExecutor
    executor = QEMUExecutor(
        qemu_path=QEMU_ARM,
        target_binary=TARGET,
        persistent_mode=True,
        log_file="/tmp/replay_crash_debug.log",
        ld_prefix=ROOTFS,
        timeout=5.0
    )

    try:
        result = executor.execute(trace_file=TRACE, mutations=instructions, iteration_id=99999)
        print(f"\n[*] Result: status={result.status_name}, crashed={result.crashed}")
        print(f"[*] PC from SHM: 0x{result.pc:x}")
        if result.pc == 0x41414141 or result.pc == 0x4141:
            print("[!!!] CONTROLLED PC! 0x41414141 — Confirmed code execution primitive")
        else:
            print(f"[*] PC value suggests partial control or offset needed")
    except Exception as e:
        print(f"[!] Execution error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        executor.stop_persistent_mode()

if __name__ == '__main__':
    main()

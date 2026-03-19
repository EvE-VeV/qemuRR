#!/usr/bin/env python3
"""
Direct crash replayer using QEMU -d cpu to observe register state at crash.

Usage:
    python3 replay_crash_direct.py <crash_json> [cyclic|original]
"""
import sys
import os
import json
import subprocess
import tempfile
import time
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'fuzzing'))
from conductor.trace_analyzer import TraceAnalyzer

QEMU_ARM = "/home/webfuzz/Documents/qemu/build/qemu-arm"
ROOTFS = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/TPLink_AXE75/rootfs"
TARGET  = f"{ROOTFS}/usr/sbin/uhttpd"
TRACE   = "tests/seeds/TPLink_AXE75.trace"

# Generate a De Bruijn cyclic pattern (simple version)
def cyclic(length, n=4):
    alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    out = b''
    for i in range(length):
        out += bytes([alphabet[(i // (len(alphabet)**k) % len(alphabet))] for k in range(n)])[:1]
    return out[:length]

def parse_instruction_str(instr_str):
    import re
    from conductor.qemu_executor import FuzzInstruction
    pattern = r"FuzzInstruction\(syscall_index=(\d+), cmd=(\d+), arg_index=(\d+), data=(b(?:'[^']*'|\"[^\"]*\")), offset=(\d+), size=(\d+), mutation_type='([^']+)'\)"
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
    from conductor.qemu_executor import FuzzInstruction
    
    crash_json = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else 'original'

    with open(crash_json) as f:
        crash = json.load(f)

    print(f"[*] Crash: {crash.get('crash_id')}")
    print(f"[*] Signal: {crash.get('signal_name')} at PC=0x{crash.get('pc', 0):x}")

    mutation_recipe = crash.get('mutation_recipe', {})
    mutation_strs = mutation_recipe.get('mutations', [])

    instructions = []
    print(f"[*] Raw mutations list length: {len(mutation_strs)}")
    for mut_str in mutation_strs:
        print(f"[*] Parsing mutation string (length {len(mut_str)})...")
        # Robust parsing: eval the list of instructions
        # We need FuzzInstruction in scope for eval to work
        try:
            # Handle cases where mut_str might already be a list or a string representation of a list
            if isinstance(mut_str, str):
                # Clean up string if it's wrapped in extra quotes or has weird formatting
                mut_str = mut_str.strip()
                if mut_str.startswith('[') and mut_str.endswith(']'):
                    list_instr = eval(mut_str, {"FuzzInstruction": FuzzInstruction, "b": bytes})
                    instructions.extend(list_instr)
                else:
                    # Try parsing as a single instruction if it's not a list
                    instr = eval(mut_str, {"FuzzInstruction": FuzzInstruction, "b": bytes})
                    if isinstance(instr, FuzzInstruction):
                        instructions.append(instr)
            elif isinstance(mut_str, list):
                instructions.extend(mut_str)
        except Exception as e:
            print(f"[!] Warning: Failed to parse mutation string via eval: {e}")
            # Fallback to regex if eval fails
            import re
            pattern = r"FuzzInstruction\(syscall_index=(\d+), cmd=(\d+), arg_index=(\d+), data=(b(?:'[^']*'|\"[^\"]*\")), offset=(\d+), size=(\d+), mutation_type='([^']+)'\)"
            matches = re.findall(pattern, str(mut_str))
            for m in matches:
                try:
                    instructions.append(FuzzInstruction(
                        syscall_index=int(m[0]), cmd=int(m[1]), arg_index=int(m[2]),
                        data=eval(m[3]), offset=int(m[4]), size=int(m[5]), mutation_type=m[6]
                    ))
                except Exception as e2:
                    print(f"    [!] Failed regex fallback for match: {e2}")

    print(f"[*] Parsed {len(instructions)} instructions")

    if mode == 'cyclic':
        pattern = cyclic(1024)
        print(f"[*] Using cyclic pattern (first 8 bytes: {pattern[:8].hex()})")
        for instr in instructions:
            if instr.mutation_type in ('replace_buffer_large', 'boundary_value', 'interesting_value'):
                instr.data = pattern[:len(instr.data)]
                print(f"    Cyclic pattern applied to syscall_index={instr.syscall_index}")
    else:
        print("[*] Using original crash payload")

    # Build mutated trace file for RR_TRACE_FILE use
    # We need to write the mutations using the shared memory approach.
    # Instead: replay via qemu with RR_MODE=REPLAY and apply mutations via the SHM
    from conductor.qemu_executor import QEMUExecutor, FuzzInstruction
    from conductor.shared_memory import FuzzSharedMemory

    log_path = f"/tmp/replay_crash_{mode}.log"
    executor = QEMUExecutor(
        qemu_path=QEMU_ARM,
        target_binary=TARGET,
        persistent_mode=True,
        log_file=log_path,
        ld_prefix=ROOTFS,
        timeout=15.0,
        extra_qemu_args=["-d", "cpu"]
    )

    print(f"\n[*] Running replay (log: {log_path})...")
    os.environ["RR_DEBUG_LEVEL"] = "4"
    
    try:
        result = executor.execute(trace_file=TRACE, mutations=instructions, iteration_id=99998)
        print(f"\n[*] Result: status={result.status_name}, crashed={result.crashed}")
        if result.pc:
            print(f"[*] Captured PC from SHM: 0x{result.pc:x}")
            # Check for cyclic pattern in PC
            if mode == 'cyclic':
                pc_bytes = result.pc.to_bytes(4, 'little')
                if pc_bytes in pattern:
                    offset = pattern.index(pc_bytes)
                    print(f"\n[!!!] CONTROLLED PC! Pattern at offset {offset}")
                    print(f"      PC=0x{result.pc:x} = '{pc_bytes.decode('latin1', errors='replace')}'")
                elif result.pc == 0x41414141 or result.pc == 0x61616161:
                    print(f"\n[!!!] CONTROLLED PC! Value 0x{result.pc:x}")
                else:
                    print(f"\n[?] PC value: 0x{result.pc:x} — may be internal or partial control")
        else:
            print("[*] No PC captured via SHM")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            executor.stop_persistent_qemu()
        except:
            pass

    # Parse log for last syscall index
    import re
    last_idx = -1
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            for line in f:
                # [RR-INFO] rr_replay_syscall:1045 Successfully replayed syscall 116: 322 -> 5
                match = re.search(r"Successfully replayed syscall (\d+)", line)
                if match:
                    last_idx = int(match.group(1))
    print(f"[*] Last syscall index reached: {last_idx}")

    # Capture and show the final CPU state from the log if available
    # QEMU -d cpu prints to stderr, which is redirected to log_path by QEMUExecutor
    print(f"\n[*] Final CPU State ({log_path}):")
    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()
            # Find the last block of "R00=" or similar CPU state markers
            cpu_state_start = -1
            for i in range(len(lines) - 1, -1, -1):
                if "R00=" in lines[i] or "PC =" in lines[i]:
                    cpu_state_start = i
                    # Go back to find the start of the register block (usually several lines)
                    while cpu_state_start > 0 and ("R" in lines[cpu_state_start-1] or "PC" in lines[cpu_state_start-1]):
                        cpu_state_start -= 1
                    break
            
            if cpu_state_start != -1:
                print(''.join(lines[cpu_state_start:]))
            else:
                print("(No CPU state found in log. Ensure -d cpu was passed if debugging)")
                # Print tail anyway
                print("--- Log Tail ---")
                print(''.join(lines[-20:]))
    except FileNotFoundError:
        print("(log file not found)")

if __name__ == '__main__':
    main()

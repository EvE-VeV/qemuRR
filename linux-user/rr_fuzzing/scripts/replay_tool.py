#!/usr/bin/env python3
import sys
import os
import json
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'fuzzing'))
from conductor.qemu_executor import QEMUExecutor, FuzzInstruction

def main():
    if len(sys.argv) < 5:
        print("Usage: python3 replay_tool.py <qemu_path> <target_path> <ld_prefix> <trace_path> <crash_json>")
        sys.exit(1)

    qemu_path = sys.argv[1]
    target_path = sys.argv[2]
    ld_prefix = sys.argv[3]
    trace_path = sys.argv[4]
    crash_json = sys.argv[5]

    with open(crash_json) as f:
        crash = json.load(f)

    print(f"[*] Replaying {crash_json}")
    print(f"[*] Expected: {crash.get('signal_name')} at PC=0x{crash.get('pc', 0):x}")

    mutation_recipe = crash.get('mutation_recipe', {})
    mutation_strs = mutation_recipe.get('mutations', [])

    instructions = []
    for mut_str in mutation_strs:
        try:
            if isinstance(mut_str, str):
                mut_str = mut_str.strip()
                if mut_str.startswith('[') and mut_str.endswith(']'):
                    list_instr = eval(mut_str, {"FuzzInstruction": FuzzInstruction, "b": bytes})
                    instructions.extend(list_instr)
                else:
                    instr = eval(mut_str, {"FuzzInstruction": FuzzInstruction, "b": bytes})
                    if isinstance(instr, FuzzInstruction):
                        instructions.append(instr)
            elif isinstance(mut_str, list):
                instructions.extend(mut_str)
        except Exception as e:
            print(f"[!] Parse error: {e}")

    executor = QEMUExecutor(
        qemu_path=qemu_path,
        target_binary=target_path,
        persistent_mode=True,
        log_file="/tmp/replay_generic.log",
        ld_prefix=ld_prefix,
        timeout=10.0,
        extra_qemu_args=["-d", "cpu"]
    )

    try:
        result = executor.execute(trace_file=trace_path, mutations=instructions, iteration_id=777)
        print(f"[*] Result: status={result.status_name}, crashed={result.crashed}, signal={result.signal}, pc=0x{result.pc:x}")
        if result.crashed:
            print("[+] SUCCESS: Crash reproduced!")
        else:
            print("[-] FAILURE: Crash not reproduced.")
    finally:
        executor.stop_persistent_qemu()

if __name__ == '__main__':
    main()

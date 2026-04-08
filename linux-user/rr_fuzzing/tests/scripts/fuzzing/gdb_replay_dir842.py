#!/usr/bin/env python3
"""
GDB replay: NB-DL842-01 — D-Link DIR-842 jjhttpd crash (PC=0x2b..., SIGSEGV)

Terminal 1 (this script):
  cd rr_fuzzing/fuzzing && python3 ../tests/scripts/fuzzing/gdb_replay_dir842.py

Terminal 2 (GDB):
  gdb-multiarch tests/images/DLink/DIR-842/DIR842A1_FW105B02.bin.extracted/_DIR842A1_FW105B02.bin.extracted/squashfs-root/sbin/jjhttpd
  (gdb) target remote :9998
  (gdb) continue
  # SIGSEGV 后:
  (gdb) info registers
  (gdb) bt
  (gdb) x/5i $pc-8
  (gdb) info symbol $pc
  (gdb) x/16wx $sp
"""
import sys, json, os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'fuzzing'))

from conductor.qemu_executor import QEMUExecutor
from conductor.mutator import FuzzInstruction

SIM   = str(ROOT)
BUILD = str(ROOT / '../../build')
GDB_PORT = 9998

ROOTFS = f'{SIM}/tests/images/DLink/DIR-842/DIR842A1_FW105B02.bin.extracted/_DIR842A1_FW105B02.bin.extracted/squashfs-root'
BINARY = f'{ROOTFS}/sbin/jjhttpd'
TRACE  = f'{SIM}/tests/seeds/DLink_DIR842_RevA.trace'
CRASH  = f'{SIM}/fuzz_output_dir842/crashes/crash_w0_199625_a6a68051.json'

def load_mutations():
    d = json.load(open(CRASH))
    raw = d['mutation_recipe']['mutations'][0]
    return eval(raw, {'FuzzInstruction': FuzzInstruction, '__builtins__': {}})

def main():
    mutations = load_mutations()
    print(f'[*] NB-DL842-01 GDB replay')
    print(f'[*] binary : {BINARY}')
    print(f'[*] trace  : {TRACE}')
    print(f'[*] mutations: {len(mutations)} instructions')
    print(f'[*] GDB port : {GDB_PORT}')
    print()
    print(f'Connect GDB in another terminal:')
    print(f'  gdb-multiarch {BINARY}')
    print(f'  (gdb) target remote :{GDB_PORT}')
    print(f'  (gdb) continue')
    print(f'  # after SIGSEGV:')
    print(f'  (gdb) info registers')
    print(f'  (gdb) bt')
    print(f'  (gdb) info symbol $pc')
    print(f'  (gdb) x/5i $pc-8')
    print(f'  (gdb) x/16wx $sp')
    print()

    executor = QEMUExecutor(
        qemu_path=f'{BUILD}/qemu-mips',
        target_binary=BINARY,
        ld_prefix=ROOTFS,
        target_args='',
        persistent_mode=True,
        timeout=60.0,
        extra_qemu_args=['-g', str(GDB_PORT)],
    )

    print('[*] Starting QEMU with gdbserver — waiting for GDB to connect...')
    results = executor.execute_fork(
        trace_file=TRACE,
        fork_point=0,
        mutation_variants=[mutations],
        depth=0,
        iteration_id=0,
    )
    if results:
        r = results[0]
        crashed = getattr(r, 'crashed', False)
        sig = getattr(r, 'signal_number', None)
        pc = hex(getattr(r, 'pc', 0) or 0)
        print(f'\n[{"CRASH" if crashed else "NO CRASH"}] signal={sig}  pc={pc}')
    executor.stop_persistent_qemu()

if __name__ == '__main__':
    main()

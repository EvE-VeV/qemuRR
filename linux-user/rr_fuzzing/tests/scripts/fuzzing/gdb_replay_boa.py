#!/usr/bin/env python3
"""
GDB replay: NB-BOA-01 — TOTOLINK A720R boa fstat aux injection (SIGSEGV, PC=0x2b76fc44)

Terminal 1 (this script):
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/gdb_replay_boa.py [--gdb]

Terminal 2 (GDB, only if --gdb):
  gdb-multiarch tests/images/Totolink/extracted_firmware/sim_root/bin/boa
  (gdb) set architecture mips
  (gdb) target remote :9998
  (gdb) continue
  # On SIGSEGV:
  (gdb) info registers
  (gdb) bt
  (gdb) x/10i $pc-16
  (gdb) info symbol $pc
  (gdb) x/4wx $sp
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'fuzzing'))

from conductor.qemu_executor import QEMUExecutor
from conductor.mutator import FuzzInstruction

SIM_ROOT   = str(ROOT / 'tests/images/Totolink/extracted_firmware/sim_root')
BUILD      = str(ROOT / '../../build')
BINARY     = f'{SIM_ROOT}/bin/boa'
TRACE      = str(ROOT / 'tests/seeds/TOTOLINK/boa_totolink_v2.trace')
GDB_PORT   = 9998
# DFC selected fork_point=41 during V4_boa campaign (read syscall idx=41)
FORK_POINT = 41

# NB-BOA-01 recipe from V4_boa campaign crash_w0_200976_e5554230
# Key: fstat aux injection at idx=72 with 'ifconfig %s-vxd down' → st_size corruption
MUTATIONS = [
    FuzzInstruction(syscall_index=41,  cmd=11, arg_index=1,
                    data=b'\x0e\x7f', offset=0, size=2,
                    mutation_type='overwrite_offset'),
    FuzzInstruction(syscall_index=99,  cmd=8,  arg_index=1,
                    data=b'\x00\x01\x00\x00', offset=0, size=4,
                    mutation_type='extend'),
    FuzzInstruction(syscall_index=131, cmd=7,  arg_index=1,
                    data=b'\x04\x00\x00\x00', offset=0, size=4,
                    mutation_type='truncate'),
    FuzzInstruction(syscall_index=162, cmd=7,  arg_index=1,
                    data=b'\x01\x00\x00\x00', offset=0, size=4,
                    mutation_type='truncate'),
    FuzzInstruction(syscall_index=146, cmd=11, arg_index=1,
                    data=b'\x0e\xe4', offset=0, size=2,
                    mutation_type='overwrite_offset'),
    FuzzInstruction(syscall_index=78,  cmd=5,  arg_index=1,
                    data=b'\x02\x00\x00\x00', offset=0, size=4,
                    mutation_type='aux_buffer'),
    FuzzInstruction(syscall_index=48,  cmd=11, arg_index=1,
                    data=b'\x0b\xeb', offset=0, size=2,
                    mutation_type='overwrite_offset'),
    FuzzInstruction(syscall_index=72,  cmd=2,  arg_index=1,
                    data=b'ifconfig %s-vxd down', offset=0, size=20,
                    mutation_type='dictionary_aux'),  # ← fstat aux injection: st_size corrupt
]


def main():
    gdb_mode = '--gdb' in sys.argv
    max_rounds = int(next((sys.argv[i+1] for i, a in enumerate(sys.argv)
                           if a == '--rounds'), 20))

    print(f'[*] NB-BOA-01 GDB replay')
    print(f'[*] binary     : {BINARY}')
    print(f'[*] trace      : {TRACE}')
    print(f'[*] mutations  : {len(MUTATIONS)} instructions')
    print(f'[*] key        : fstat aux injection idx=72 → st_size corruption → heap overflow → PC=0x2b76fc44')

    extra_args = ['-g', str(GDB_PORT)] if gdb_mode else []
    if gdb_mode:
        print(f'\nConnect GDB:')
        print(f'  gdb-multiarch {BINARY}')
        print(f'  (gdb) set architecture mips')
        print(f'  (gdb) target remote :{GDB_PORT}')
        print(f'  (gdb) continue\n')

    executor = QEMUExecutor(
        qemu_path=f'{BUILD}/qemu-mips',   # MIPS BE (big-endian)
        target_binary=BINARY,
        ld_prefix=SIM_ROOT,
        timeout=60.0,
        extra_qemu_args=extra_args,
    )

    crashes = 0
    for i in range(max_rounds):
        results = executor.execute_fork(
            trace_file=TRACE,
            fork_point=FORK_POINT,
            mutation_variants=[MUTATIONS],
            depth=0,
            iteration_id=i,
        )
        if results:
            r = results[0]
            crashed = getattr(r, 'crashed', False)
            sig     = getattr(r, 'signal_number', None)
            pc      = hex(getattr(r, 'pc', 0) or 0)
            if crashed:
                crashes += 1
                print(f'[CRASH #{crashes}] round={i} signal={sig} pc={pc}')
                if gdb_mode:
                    break
        if not gdb_mode and (i+1) % 5 == 0:
            print(f'  round {i+1}/{max_rounds}  crashes={crashes}')

    print(f'\n[Done] {crashes}/{max_rounds} rounds crashed  (expected pc=0x2b76fc44)')
    executor.stop_persistent_qemu()


if __name__ == '__main__':
    main()

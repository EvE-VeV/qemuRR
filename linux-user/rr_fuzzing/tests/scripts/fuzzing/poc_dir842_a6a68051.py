#!/usr/bin/env python3
"""
poc_dir842_a6a68051.py — PoC for NB-DIR842-01

Crash:    SIGSEGV at PC=0x2b6f7468 (jjhttpd MIPS shared lib region)
Signal:   SIGSEGV (11)
Count:    76,922 reproductions in rq3_auth_barrier campaign
Mutation: NO extend/truncate — io_return_value + replace_buffer at sc=41 only
Target:   D-Link DIR-842 RevA jjhttpd (MIPS BE, uclibc)
Trace:    tests/seeds/DLink_DIR842_RevA.trace

Classification: FILE-FD-ONLY FALSE POSITIVE
  sc=41 in DLink_DIR842_RevA.trace is network=False, forbidden=False (regular
  file fd, not the HTTP socket). The io_return_value mutation inflates the
  retval of a file read, not a network read. This mutation is not physically
  achievable via network attack.

  The crash at PC=0x2b6f7468 is reproducible with RR-Fuzz mutations but the
  triggering mutation premise is invalid. Retained for documentation only.

Exploitability: NOT NETWORK-EXPLOITABLE (FILE-FD-ONLY)

Usage:
  cd rr_fuzzing
  python3 tests/scripts/fuzzing/poc_dir842_a6a68051.py [--max-rounds N]
"""
import sys, argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'fuzzing'))

from conductor.qemu_executor import QEMUExecutor
from conductor.conductor_types import FuzzInstruction

ROOTFS     = str(ROOT / 'tests/verified_targets/DLink_DIR842_RevA/rootfs')
BUILD      = str(ROOT / '../../build')
BINARY     = f'{ROOTFS}/sbin/jjhttpd'
TRACE      = str(ROOT / 'tests/seeds/DLink_DIR842_RevA.trace')
FORK_POINT = 41
GDB_PORT   = 9998

# Campaign recipe: crash_w0_199625_a6a68051
# Signal=SIGSEGV(11) PC=0x2b6f7468 — 76,922 reproductions
MUTATIONS = [
    FuzzInstruction(syscall_index=41, cmd=1, arg_index=255,
                    data=b'\x81\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=41, cmd=2, arg_index=1,
                    data=b'CRASH_ME\x00', offset=0, size=9,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=41, cmd=1, arg_index=255,
                    data=b'\xc8\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=41, cmd=2, arg_index=1,
                    data=b'TLSv1_server_method', offset=0, size=19,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=41, cmd=1, arg_index=255,
                    data=b'\x80\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=41, cmd=2, arg_index=1,
                    data=bytes(range(128)) + b'\x80\x81', offset=0, size=130,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=41, cmd=1, arg_index=255,
                    data=b'\x96\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=41, cmd=2, arg_index=1,
                    data=b'\x00' * 8, offset=0, size=8,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=41, cmd=1, arg_index=255,
                    data=b'\x50\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=41, cmd=2, arg_index=1,
                    data=b'../../../etc/passwd', offset=0, size=19,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=41, cmd=1, arg_index=255,
                    data=b'\x82\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=41, cmd=2, arg_index=1,
                    data=b'<?xml', offset=0, size=5,
                    mutation_type='replace_buffer'),
]


def run(max_rounds: int = 5, gdb: bool = False) -> None:
    extra = ['-g', str(GDB_PORT)] if gdb else []
    executor = QEMUExecutor(
        qemu_path=f'{BUILD}/qemu-mips',
        target_binary=BINARY,
        ld_prefix=ROOTFS,
        timeout=15.0,
        extra_qemu_args=extra,
    )

    print(f'[*] NB-DIR842-01 PoC')
    print(f'[*] Target : {BINARY}')
    print(f'[*] Trace  : {TRACE}')
    print(f'[*] Expect : SIGSEGV(11) PC=0x2b6f7468')
    print()

    crashes = 0
    for rnd in range(1, max_rounds + 1):
        results = executor.execute_fork(
            trace_file=TRACE,
            fork_point=FORK_POINT,
            mutation_variants=[MUTATIONS],
            depth=0,
            iteration_id=rnd,
        )
        if not results:
            print(f'  round {rnd}: no result')
            continue
        r = results[0]
        crashed = getattr(r, 'crashed', False)
        sig = getattr(r, 'signal_number', None)
        pc  = hex(getattr(r, 'pc', 0) or 0)
        if crashed:
            crashes += 1
            print(f'  round {rnd}: *** CRASH ***  signal={sig} pc={pc}')
            if gdb:
                break
        else:
            print(f'  round {rnd}: {getattr(r, "status_name", "ok")}')

    executor.stop_persistent_qemu()
    print()
    if crashes > 0:
        print(f'DIR842 a6a68051 crash reproduced ({crashes}/{max_rounds} rounds): SIGSEGV at 0x2b6f7468')
        print('NOTE: This is a FILE-FD-ONLY false positive (sc=41 network=False).')
        print('      Crash is reproducible but not network-exploitable.')
    else:
        print('DIR842 a6a68051: NOT reproduced — check trace/binary/QEMU path')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--max-rounds', type=int, default=5)
    p.add_argument('--gdb', action='store_true')
    args = p.parse_args()
    run(max_rounds=args.max_rounds, gdb=args.gdb)

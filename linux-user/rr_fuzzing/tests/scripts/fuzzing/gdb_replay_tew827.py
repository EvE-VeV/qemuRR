#!/usr/bin/env python3
"""
GDB replay: NB-TEW827-01/02 — TRENDnet TEW-827DRU uhttpd POST crash (SIGBUS)

Terminal 1 (this script):
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/gdb_replay_tew827.py [d0de57e2|e4196d86]

Terminal 2 (GDB):
  gdb-multiarch tests/verified_targets/Trendnet_TEW827DRU/rootfs/usr/sbin/uhttpd
  (gdb) set architecture mips
  (gdb) target remote :9998
  (gdb) continue
  # SIGBUS 后:
  (gdb) info registers
  (gdb) bt
  (gdb) x/10i $pc-16
  (gdb) info symbol $pc
  (gdb) x/16wx $sp
"""
import sys, json, glob
from pathlib import Path

ROOT   = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'fuzzing'))

from conductor.qemu_executor import QEMUExecutor
from conductor.mutator import FuzzInstruction

ROOTFS   = str(ROOT / 'tests/verified_targets/Trendnet_TEW827DRU/rootfs')
BUILD    = str(ROOT / '../../build')
BINARY   = f'{ROOTFS}/usr/sbin/uhttpd'
TRACE    = str(ROOT / 'tests/seeds/Trendnet_TEW827_post.trace')
GDB_PORT = 9998
FORK_POINT = 1112

CRASH_DIR = str(ROOT / 'evaluation/rq5_vulns/tew827_post/crashes')


def load_mutations(crash_hash):
    files = glob.glob(f'{CRASH_DIR}/crash_*_{crash_hash}.json')
    if not files:
        raise FileNotFoundError(f'No crash file for {crash_hash} in {CRASH_DIR}')
    d = json.load(open(files[0]))
    raw_list = d['mutation_recipe']['mutations']
    # Each element is a repr string of one FuzzInstruction
    mutations = [eval(r, {'FuzzInstruction': FuzzInstruction, '__builtins__': {}})
                 for r in raw_list]
    return mutations


def main():
    crash_hash = sys.argv[1] if len(sys.argv) > 1 else 'd0de57e2'
    gdb_mode = '--gdb' in sys.argv

    mutations = load_mutations(crash_hash)

    print(f'[*] NB-TEW827 replay ({crash_hash})')
    print(f'[*] binary     : {BINARY}')
    print(f'[*] trace      : {TRACE}')
    print(f'[*] fork_point : {FORK_POINT}')
    print(f'[*] mutations  : {len(mutations)} instructions')
    for i, m in enumerate(mutations):
        print(f'    [{i}] {m}')

    extra_args = ['-g', str(GDB_PORT)] if gdb_mode else []
    if gdb_mode:
        print(f'\nConnect GDB in another terminal:')
        print(f'  gdb-multiarch {BINARY}')
        print(f'  (gdb) set architecture mips')
        print(f'  (gdb) target remote :{GDB_PORT}')
        print(f'  (gdb) continue\n')
        print(f'[*] Starting QEMU with gdbserver — waiting for GDB to connect...')

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

    if results:
        r = results[0]
        crashed = getattr(r, 'crashed', False)
        sig     = getattr(r, 'signal_number', None)
        pc      = hex(getattr(r, 'pc', 0) or 0)
        print(f'\n[{"CRASH" if crashed else "NO CRASH"}] signal={sig}  pc={pc}')
    else:
        print('\n[NO RESULT]')

    executor.stop_persistent_qemu()


if __name__ == '__main__':
    main()

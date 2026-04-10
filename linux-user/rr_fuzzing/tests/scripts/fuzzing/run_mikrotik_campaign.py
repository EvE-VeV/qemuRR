#!/usr/bin/env python3
"""
MikroTik RouterOS 6.48.6 RRFuzz campaign launcher.

Target : /nova/bin/www  (i386/x86-32, uClibc, web interface)
Arch   : x86-32 (i386) — NEW architecture, extends paper cross-arch claim
Trace  : tests/verified_targets/MikroTik_6.48.6/traces/init.txt.new (TRRR format)

Previous campaign: sync/crashes/ found c716a47b (ELF loader, file-FD, 1102 hits).
This campaign runs longer with net-FD isolation to find network-exploitable bugs.

Usage:
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/run_mikrotik_campaign.py [--iterations N]
"""
import os
import sys
import argparse
from pathlib import Path

ROOT    = Path(__file__).resolve().parents[3]
FUZZING = ROOT / 'fuzzing'
sys.path.insert(0, str(FUZZING))

MIKRO_ROOT = Path('/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/MikroTik/system_pkg')
BINARY     = str(MIKRO_ROOT / 'nova/bin/www')
ROOTFS     = str(MIKRO_ROOT)
QEMU       = str(ROOT / '../../build/qemu-i386')

# Use the newer trace (init.txt.new, same size as init.txt but updated 2026-01-20)
TRACE_FILE  = str(ROOT / 'tests/verified_targets/MikroTik_6.48.6/traces/init.txt.new')
OUTPUT_DIR  = str(FUZZING / 'fuzz_output_mikrotik')


def check_prerequisites():
    errors = []
    if not Path(BINARY).exists():
        errors.append(f'Binary not found: {BINARY}')
    if not Path(QEMU).exists():
        errors.append(f'qemu-i386 not found: {QEMU}')
    if not Path(TRACE_FILE).exists():
        errors.append(f'Trace not found: {TRACE_FILE}')
    if errors:
        for e in errors:
            print(f'❌ {e}')
        return False

    # Verify trace magic
    with open(TRACE_FILE, 'rb') as f:
        magic = f.read(4)
    if magic != b'TRRR':
        print(f'❌ Unexpected trace magic: {magic!r} (expected TRRR)')
        return False

    print(f'✅ Binary : {BINARY}')
    print(f'✅ QEMU   : {QEMU}')
    print(f'✅ Trace  : {TRACE_FILE} (TRRR magic OK)')
    return True


def run_campaign(iterations: int):
    from conductor.fuzzing_core import FuzzingCore

    # Sanitize environment
    keep = {'PATH', 'HOME', 'USER', 'LANG'}
    for k in list(os.environ.keys()):
        if k not in keep and not k.startswith('RR_'):
            try:
                del os.environ[k]
            except Exception:
                pass
    os.environ['RR_ENABLED'] = '1'

    print(f'[Fuzz] MikroTik RouterOS 6.48.6 campaign')
    print(f'[Fuzz] Architecture: i386 (x86-32)')
    print(f'[Fuzz] Iterations  : {iterations}')
    print(f'[Fuzz] Output      : {OUTPUT_DIR}')

    core = FuzzingCore(
        qemu_path=QEMU,
        target_binary=BINARY,
        initial_trace=TRACE_FILE,
        output_dir=OUTPUT_DIR,
        ld_prefix=ROOTFS,
    )
    core.run(max_iterations=iterations)

    # Summary
    try:
        import json
        db_path = Path(OUTPUT_DIR) / 'crashes' / 'crash_db.json'
        if db_path.exists():
            db = json.load(open(db_path))
            print(f'\n[Result] {len(db)} unique crash signatures')
            for k, v in db.items():
                print(f'  {k[:8]} sig={v.get("signal_name")} pc={hex(v.get("pc",0) or 0)} '
                      f'count={v.get("count",0)}')
    except Exception as e:
        print(f'[Result] crash_db read error: {e}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--iterations', type=int, default=10000)
    args = parser.parse_args()

    if not check_prerequisites():
        sys.exit(1)

    run_campaign(args.iterations)


if __name__ == '__main__':
    main()

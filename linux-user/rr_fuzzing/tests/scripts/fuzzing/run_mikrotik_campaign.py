#!/usr/bin/env python3
"""
MikroTik RouterOS 6.48.6 RRFuzz campaign launcher.

Target : /tmp/www_patched  (i386/x86-32, patched to bypass integrity checks)
Arch   : x86-32 (i386)
Trace  : tests/verified_targets/MikroTik_6.48.6/traces/http_seed.trace
         Recorded with full Nova IPC + HTTP GET / -> 7184 bytes response
         232 syscalls, 77KB — includes accept/recv/send for HTTP path

Requirements:
  - mock_supervisor.py must be running (handles Nova IPC handshake)
  - www_patched must exist at /tmp/www_patched

Usage:
  # Start Nova mock in background first:
  python3 tests/verified_targets/MikroTik_6.48.6/mock_supervisor.py &
  # Then run campaign:
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
BINARY     = '/tmp/www_patched'   # patched binary (bypasses integrity checks)
ROOTFS     = str(MIKRO_ROOT)
QEMU       = str(ROOT / '../../build/qemu-i386')

# HTTP seed trace: full Nova handshake + GET / response (77KB, 232 syscalls)
TRACE_FILE  = str(ROOT / 'tests/verified_targets/MikroTik_6.48.6/traces/http_seed.trace')
OUTPUT_DIR  = str(FUZZING / 'fuzz_output_mikrotik_http')


def check_prerequisites():
    errors = []
    if not Path(BINARY).exists():
        errors.append(f'www_patched not found: {BINARY} (copy patched binary here)')
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

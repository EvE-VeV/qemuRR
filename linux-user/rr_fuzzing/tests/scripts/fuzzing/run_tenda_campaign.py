#!/usr/bin/env python3
"""
Tenda AC15 RRFuzz campaign launcher.

Step 1 (auto): Record seed trace via run.sh + HTTP GET
Step 2 (auto): Start fuzzing with FuzzingCore

Known crash: POST /goform/setDeviceName with large name →
  stack overflow in R7WebsSecurityHandler (repro_tenda_crash.py)
Expected: RRFuzz finds this via syscall-level buffer mutations.

Usage:
  cd rr_fuzzing/fuzzing
  python3 ../tests/scripts/fuzzing/run_tenda_campaign.py [--record-only] [--fuzz-only]
"""
import os
import sys
import time
import signal
import subprocess
import requests
from pathlib import Path

ROOT    = Path(__file__).resolve().parents[3]
FUZZING = ROOT / 'fuzzing'
sys.path.insert(0, str(FUZZING))

ROOTFS     = str(ROOT / 'tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root')
BINARY     = f'{ROOTFS}/bin/httpd'
QEMU       = str(ROOT / '../../build/qemu-arm')
# Use existing verified trace (1019 syscalls, TRRR format, has .analyzer.pkl)
TRACE_FILE = str(ROOT / 'crashes/real_world_repro/TENDA_AC15/traces/tenda_test_v26.trace')
OUTPUT_DIR = str(FUZZING / 'fuzz_output_tenda_ac15')
PORT       = 8080


def patch_libraries():
    patch_script = ROOT / 'tests/scripts/tools/patch_tenda_libraries.py'
    if patch_script.exists():
        subprocess.run(['python3', str(patch_script), '--skip-libc'],
                       capture_output=True)


def record_trace():
    if Path(TRACE_FILE).exists():
        print(f'[Record] Trace already exists: {TRACE_FILE}')
        return True

    print('[Record] Starting Tenda AC15 in RR_MODE=record...')
    patch_libraries()

    env = {k: v for k, v in os.environ.items()
           if k in ('PATH', 'HOME', 'USER', 'LANG')}
    env.update({
        'RR_ENABLED': '1',
        'RR_MODE': 'record',
        'RR_TRACE_FILE': TRACE_FILE,
        'QEMU_LD_PREFIX': ROOTFS,
    })

    proc = subprocess.Popen(
        [QEMU, '-L', ROOTFS, BINARY],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    print(f'[Record] PID={proc.pid}, waiting for bind...')
    time.sleep(4)

    if proc.poll() is not None:
        print('[Record] ❌ httpd died early — check patch_tenda_libraries.py')
        return False

    # Send seed HTTP request
    try:
        r = requests.get(f'http://127.0.0.1:{PORT}/', timeout=5)
        print(f'[Record] HTTP GET → {r.status_code}')
    except Exception as e:
        print(f'[Record] HTTP request: {e}')

    time.sleep(1)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        proc.terminate()
    proc.wait(timeout=5)

    if Path(TRACE_FILE).exists():
        size = Path(TRACE_FILE).stat().st_size
        print(f'[Record] ✅ Trace saved: {TRACE_FILE} ({size} bytes)')
        return True
    else:
        print(f'[Record] ❌ No trace at {TRACE_FILE}')
        return False


def run_campaign():
    from conductor.fuzzing_core import FuzzingCore

    # Ensure libCfm.so / libcommon.so are patched before replay
    patch_libraries()

    print(f'[Fuzz] Starting Tenda AC15 campaign → {OUTPUT_DIR}')
    print(f'[Fuzz] binary : {BINARY}')
    print(f'[Fuzz] trace  : {TRACE_FILE}')
    print(f'[Fuzz] Target : POST /goform/setDeviceName stack overflow')

    env = {k: v for k, v in os.environ.items()
           if k in ('PATH', 'HOME', 'USER', 'LANG')}
    env['RR_ENABLED'] = '1'
    for k in list(os.environ.keys()):
        if k not in env and not k.startswith('RR_'):
            try:
                del os.environ[k]
            except Exception:
                pass
    os.environ.update(env)

    core = FuzzingCore(
        qemu_path=QEMU,
        target_binary=BINARY,
        initial_trace=TRACE_FILE,
        output_dir=OUTPUT_DIR,
        ld_prefix=ROOTFS,
    )
    core.run(max_iterations=50000)


def main():
    record_only = '--record-only' in sys.argv
    fuzz_only   = '--fuzz-only' in sys.argv

    if not fuzz_only:
        ok = record_trace()
        if not ok:
            print('[!] Record failed. Check httpd startup.')
            sys.exit(1)

    if not record_only:
        run_campaign()


if __name__ == '__main__':
    main()

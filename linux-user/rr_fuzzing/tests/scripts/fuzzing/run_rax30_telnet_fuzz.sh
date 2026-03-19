#!/bin/bash
# Fuzzing launcher for RAX30 Telnet service (CVE-2023-40478)

set -e

# Paths
QEMU_PATH="../../build/qemu-arm"
TARGET_BIN="tests/images/RAX30/sim_root/usr/sbin/utelnetd"
TRACE_FILE="crashes/real_world_repro/RAX30_TELNET/traces/rax30_telnet_passwd.trace"
CAMPAIGN_DIR="campaigns/rax30_telnet"
SIM_ROOT="tests/images/RAX30/sim_root"

# Fuzzing parameters
WORKERS=${WORKERS:-4}
TIMEOUT=${TIMEOUT:-5000}
DURATION=${DURATION:-3600}  # 1 hour

echo "[*] RAX30 Telnet Fuzzing Campaign"
echo "    Target: $TARGET_BIN"
echo "    Trace: $TRACE_FILE"
echo "    Workers: $WORKERS"
echo ""

# Check trace exists
if [ ! -f "$TRACE_FILE" ]; then
    echo "[-] Trace file not found: $TRACE_FILE"
    echo "[*] Run: python3 tools/record_rax30_telnet.py"
    exit 1
fi

# Create campaign directory
mkdir -p "$CAMPAIGN_DIR"

# Launch fuzzing
echo "[*] Starting fuzzing campaign..."
python3 $SIM_ROOT/fuzzing/fuzz_main.py \
    --qemu "$QEMU_PATH" \
    --target "$TARGET_BIN" \
    --sim-root "$SIM_ROOT" \
    --trace "$TRACE_FILE" \
    --campaign-dir "$CAMPAIGN_DIR" \
    --workers "$WORKERS" \
    --timeout "$TIMEOUT" \
    --duration "$DURATION" \
    --dict fuzzing/dictionaries/telnet_commands.dict \
    --strategy pathfinder \
    "$@"

echo "[+] Fuzzing campaign completed!"
echo "[*] Results in: $CAMPAIGN_DIR"

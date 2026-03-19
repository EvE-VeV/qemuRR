#!/bin/bash
# Final Comprehensive Launch Script for 15 Firmware Fuzzing Campaigns
# Scaling firmware fuzzing to 15 concurrent targets.

set -euo pipefail

RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PYTHON_BIN="python3"
QEMU_ARM="/home/webfuzz/Documents/qemu/build/qemu-arm"
QEMU_MIPS="/home/webfuzz/Documents/qemu/build/qemu-mips"
QEMU_MIPSEL="/home/webfuzz/Documents/qemu/build/qemu-mipsel"
VT="${RR_ROOT}/tests/verified_targets"

# Helper function
launch_fuzzer() {
    local name="$1"; shift
    local output_dir="${RR_ROOT}/fuzz_output_${name}"
    mkdir -p "$output_dir"
    echo "[*] Launching $name..."
    nohup env \
        "$PYTHON_BIN" "$RR_ROOT/fuzzing/fuzz_main.py" \
        --iterations 100000 \
        --infinite \
        --persistence \
        --output "$output_dir" \
        "$@" > "$output_dir/launch.log" 2>&1 &
    echo "    PID=$! log -> $output_dir/launch.log"
}

cd "$RR_ROOT"

# --- Current 11 Targets ---

# 1. Netgear RAX30 (ARM) - utelnetd
echo "[*] 1/15 RAX30"
launch_fuzzer "rax30" \
    --qemu "$QEMU_ARM" \
    --trace "${VT}/Netgear_RAX30/artifacts/upnp_full.txt" \
    --target "${VT}/Netgear_RAX30/rootfs/usr/sbin/utelnetd" \
    --ld-prefix "${VT}/Netgear_RAX30/rootfs"

# 2. Tenda AC15 (ARM) - httpd
echo "[*] 2/15 Tenda AC15"
launch_fuzzer "tenda" \
    --qemu "$QEMU_ARM" \
    --trace "${RR_ROOT}/crashes/real_world_repro/TENDA_AC15/traces/tenda_test_v28.trace" \
    --target "${VT}/Tenda_AC15/rootfs/bin/httpd" \
    --ld-prefix "${VT}/Tenda_AC15/rootfs"

# 3. TP-Link AXE75 (ARM) - uhttpd
echo "[*] 3/15 TP-Link AXE75"
launch_fuzzer "tplink" \
    --qemu "$QEMU_ARM" \
    --trace "tests/seeds/TPLink_AXE75.trace" \
    --target "${VT}/TPLink_AXE75/rootfs/usr/sbin/uhttpd" \
    --ld-prefix "${VT}/TPLink_AXE75/rootfs"

# 4. Asus RT-AC68U (ARM) - httpd
echo "[*] 4/15 Asus RTAC68U"
launch_fuzzer "rtac68u" \
    --qemu "$QEMU_ARM" \
    --trace "tests/seeds/Asus_RTAC68U.trace" \
    --target "${VT}/Asus_RTAC68U/rootfs/usr/sbin/httpd" \
    --ld-prefix "${VT}/Asus_RTAC68U/rootfs"

# 5. D-Link DIR-842 (MIPS) - jjhttpd
echo "[*] 5/15 D-Link DIR-842"
launch_fuzzer "dir842" \
    --qemu "$QEMU_MIPS" \
    --trace "tests/seeds/DLink_DIR842_RevA.trace" \
    --target "${VT}/DLink_DIR842_RevA/rootfs/sbin/jjhttpd" \
    --ld-prefix "${VT}/DLink_DIR842_RevA/rootfs" \
    --word-size 32

# 6. Trendnet TEW-827DRU (MIPSEL) - uhttpd
echo "[*] 6/15 Trendnet TEW827"
launch_fuzzer "tew827" \
    --qemu "$QEMU_MIPSEL" \
    --trace "tests/seeds/Trendnet_TEW827.trace" \
    --target "${VT}/Trendnet_TEW827DRU/rootfs/usr/sbin/uhttpd" \
    --ld-prefix "${VT}/Trendnet_TEW827DRU/rootfs" \
    --word-size 32

# 7. Totolink (MIPS) - BOA
echo "[*] 7/15 Totolink BOA"
launch_fuzzer "boa" \
    --qemu "$QEMU_MIPS" \
    --trace "tests/seeds/TOTOLINK/boa_totolink_v2.trace" \
    --target "${RR_ROOT}/tests/images/Totolink/extracted_firmware/sim_root/bin/boa" \
    --ld-prefix "${RR_ROOT}/tests/images/Totolink/extracted_firmware/sim_root" \
    --args="-c . -d" \
    --word-size 32

# 8. Netis WF2419 (MIPS) - BOA
echo "[*] 8/15 Netis WF2419"
launch_fuzzer "netis_be" \
    --qemu "$QEMU_MIPS" \
    --trace "tests/seeds/Netis_WF2419.trace" \
    --target "${RR_ROOT}/tests/images/Netis/rootfs/bin/boa" \
    --ld-prefix "${RR_ROOT}/tests/images/Netis/rootfs" \
    --word-size 32

# 9. Linksys E1200 (MIPSEL) - httpd
echo "[*] 9/15 Linksys E1200"
launch_fuzzer "linksys" \
    --qemu "$QEMU_MIPSEL" \
    --trace "tests/seeds/Linksys_E1200.trace" \
    --target "${VT}/Linksys_E1200/rootfs/usr/sbin/httpd" \
    --ld-prefix "${VT}/Linksys_E1200/rootfs" \
    --word-size 32

# 10. D-Link DIR-820L (MIPS) - jjhttpd
echo "[*] 10/15 D-Link DIR-820L (jjhttpd)"
launch_fuzzer "jjhttpd" \
    --qemu "$QEMU_MIPS" \
    --trace "${RR_ROOT}/tests/images/DLink/DIR820L/traces/jjhttpd_full.txt" \
    --target "${VT}/DLink_DIR820L/rootfs/sbin/jjhttpd" \
    --ld-prefix "${VT}/DLink_DIR820L/rootfs" \
    --word-size 32

# 11. Asus RT-AX56U (ARM) - httpd
echo "[*] 11/15 Asus RTAX56U"
launch_fuzzer "rtax56u" \
    --qemu "${VT}/Asus_RTAX56U/qemu_wrapper.sh" \
    --trace "${VT}/Asus_RTAX56U/traces/init.trace" \
    --target "${VT}/Asus_RTAX56U/rootfs/usr/sbin/httpd" \
    --ld-prefix "${VT}/Asus_RTAX56U/rootfs"

# --- New Phase 3 Targets ---

# 12. Asus RT-AX88U (ARM) - httpd
echo "[*] 12/15 Asus RTAX88U"
launch_fuzzer "rtax88u" \
    --qemu "${VT}/Asus_RTAX88U/qemu_wrapper.sh" \
    --trace "${VT}/Asus_RTAX88U/traces/ax88u_init.trace" \
    --target "${VT}/Asus_RTAX88U/sim_root/usr/sbin/httpd" \
    --ld-prefix "${VT}/Asus_RTAX88U/sim_root"

# 13. TOTOLINK A720R (MIPS-BE) - BOA
echo "[*] 13/15 TOTOLINK A720R"
launch_fuzzer "a720r" \
    --qemu "$QEMU_MIPS" \
    --trace "tests/seeds/TOTOLINK_A720R.trace" \
    --target "${VT}/TOTOLINK_A720R/rootfs/bin/boa" \
    --ld-prefix "${VT}/TOTOLINK_A720R/rootfs" \
    --args="-d" \
    --word-size 32

# 14. Netgear RAX30 v1.0.10.94 (ARM) - utelnetd
RAX30_V2_ROOT="${RR_ROOT}/tests/images/Netgear/RAX30-V1.0.10.94_3.img.extracted/_RAX30-V1.0.10.94_3.img.extracted/squashfs-root"
echo "[*] 14/15 Netgear RAX30 v2"
launch_fuzzer "rax30_v2" \
    --qemu "$QEMU_ARM" \
    --trace "tests/seeds/Netgear_RAX30_v2.trace" \
    --target "${RAX30_V2_ROOT}/usr/sbin/utelnetd" \
    --ld-prefix "${RAX30_V2_ROOT}"

# 15. MikroTik 6.48.6 (x86) - www
MIKRO_OUTPUT="${RR_ROOT}/fuzz_output_mikrotik"
MIKRO_MOCK="${VT}/MikroTik_6.48.6/mock_supervisor.py"
MIKRO_WRAPPER="${VT}/MikroTik_6.48.6/qemu_wrapper.sh"
MIKRO_TRACE="${VT}/MikroTik_6.48.6/traces/init.txt"
MIKRO_TARGET="${RR_ROOT}/tests/images/MikroTik/system_pkg/nova/bin/www"

echo "[*] 15/15 MikroTik 6.48.6"
mkdir -p "$MIKRO_OUTPUT"
echo "    [*] Launching mock supervisor..."
nohup python3 "$MIKRO_MOCK" > "$MIKRO_OUTPUT/mock_supervisor.log" 2>&1 &
sleep 2
echo "    [*] Launching fuzzer master..."
nohup env RR_MODE=REPLAY_ADVANCE \
    python3 -m fuzzing.multiprocess.fuzz_master \
    --target "$MIKRO_TARGET" \
    --trace "$MIKRO_TRACE" \
    --sync-dir "${VT}/MikroTik_6.48.6/sync" \
    --workers 2 \
    --qemu "$MIKRO_WRAPPER" \
    --architecture "i386" > "$MIKRO_OUTPUT/fuzz_master.log" 2>&1 &
echo "    PID=$! -> $MIKRO_OUTPUT/fuzz_master.log"

echo ""
echo "[*] All 15 campaigns initiated. Monitoring:"
echo "    for d in ${RR_ROOT}/fuzz_output_*; do echo \"--- \$(basename \$d) ---\"; tail -n2 \"\$d/launch.log\" 2>/dev/null; tail -n2 \"\$d/fuzz_master.log\" 2>/dev/null; done"

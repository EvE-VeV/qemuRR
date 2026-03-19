#!/bin/bash
# Launch all RR-Fuzz campaigns — fixed QEMU binary 2026-03-14 15:30
# Usage: bash launch_all_campaigns.sh

R="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
B="/home/webfuzz/Documents/qemu/build"
FUZZ="$R/fuzzing/fuzz_main.py"
SCRIPTS="$R/tests/scripts/fuzzing"

launch() {
    local name=$1; shift
    mkdir -p "$R/fuzz_output_${name}"
    PYTHONPATH="$R" nohup python3 "$FUZZ" "$@" \
        --infinite --persistence \
        --output "$R/fuzz_output_${name}" \
        > "$R/fuzz_output_${name}/launch.log" 2>&1 &
    echo "[+] $name  PID=$!"
    sleep 0.5
}

echo "=== Starting all campaigns ==="

# ── ARM ──────────────────────────────────────────────────────────────────────

# rtac68u: 11 unique SIGSEGV — highest priority
VT="$R/tests/verified_targets"
launch rtac68u \
    --qemu "$B/qemu-arm" \
    --target "$VT/Asus_RTAC68U/rootfs/usr/sbin/httpd" \
    --trace "$R/tests/seeds/Asus_RTAC68U.trace"

# rtax88u: 4 unique (SIGILL + SIGSEGV)
launch rtax88u \
    --qemu "$VT/Asus_RTAX88U/qemu_wrapper.sh" \
    --target "$VT/Asus_RTAX88U/sim_root/usr/sbin/httpd" \
    --trace "$VT/Asus_RTAX88U/traces/ax88u_init.trace"

# tplink AXE75: 5 unique (SIGBUS + SIGSEGV)
launch tplink \
    --qemu "$B/qemu-arm" \
    --target "$VT/TPLink_AXE75/rootfs/usr/sbin/uhttpd" \
    --trace "$R/tests/seeds/TPLink_AXE75.trace"

# rax30_v2: 2 unique
RAX30_FS="$R/tests/images/Netgear/RAX30-V1.0.10.94_3.img.extracted/_RAX30-V1.0.10.94_3.img.extracted/squashfs-root"
launch rax30_v2 \
    --qemu "$B/qemu-arm" \
    --target "$RAX30_FS/usr/sbin/utelnetd" \
    --trace "$R/tests/seeds/Netgear_RAX30_v2.trace"

# rax30_upnp
launch rax30_upnp \
    --qemu "$B/qemu-arm" \
    --target "$VT/Netgear_RAX30/rootfs/bin/upnp" \
    --trace "$VT/Netgear_RAX30/artifacts/upnp_full.txt"

# ── MIPS ─────────────────────────────────────────────────────────────────────

# dir842: 2 unique (SIGILL + SIGSEGV)
launch dir842 \
    --qemu "$B/qemu-mips" \
    --target "$VT/DLink_DIR842_RevA/rootfs/sbin/jjhttpd" \
    --trace "$R/tests/seeds/DLink_DIR842_RevA.trace"

# boa (TOTOLINK): 1 unique SIGSEGV, 41k crashes
launch boa \
    --qemu "$B/qemu-mips" \
    --target "$R/tests/images/Totolink/extracted_firmware/sim_root/bin/boa" \
    --trace "$R/tests/seeds/TOTOLINK/boa_totolink_v2.trace"

# netis_be: 1 unique SIGSEGV, 12k crashes
launch netis_be \
    --qemu "$B/qemu-mips" \
    --target "$R/tests/images/Netis/rootfs/bin/boa" \
    --trace "$R/tests/seeds/Netis_WF2419.trace"

# a720r: 2 unique
launch a720r \
    --qemu "$B/qemu-mips" \
    --target "$VT/TOTOLINK_A720R/rootfs/bin/boa" \
    --trace "$R/tests/seeds/TOTOLINK_A720R.trace"

# ── MIPS-L ───────────────────────────────────────────────────────────────────

# tew827: 0 crashes but 110k iterations — keep exploring
launch tew827 \
    --qemu "$B/qemu-mipsel" \
    --target "$VT/Trendnet_TEW827DRU/rootfs/usr/sbin/uhttpd" \
    --trace "$R/tests/seeds/Trendnet_TEW827.trace"

# linksys: 2 unique
launch linksys \
    --qemu "$B/qemu-mipsel" \
    --target "$VT/Linksys_E1200/rootfs/usr/sbin/httpd" \
    --trace "$R/tests/seeds/Linksys_E1200.trace"

# ── x86-64 ───────────────────────────────────────────────────────────────────

# jjhttpd: 0 crashes, 929k iterations — continue
launch jjhttpd \
    --qemu "$B/qemu-mips" \
    --target "$R/tests/images/DLink/DIR820L_sim_root/sbin/jjhttpd" \
    --trace "$R/tests/images/DLink/DIR820L/traces/jjhttpd_full.txt"

echo ""
echo "=== Done. Monitoring: ==="
echo "    watch -n5 'ps aux | grep fuzz_main | grep -v grep | wc -l'"
echo "    tail -f $R/fuzz_output_<name>/fuzzing.log"

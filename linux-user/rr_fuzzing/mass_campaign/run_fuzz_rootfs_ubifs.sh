#!/bin/bash
# Auto-generated fuzzing script for rootfs_ubifs
# Arch: arm
# Binary: httpd
# Config: -f /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Asus/_RT-AX56U_3.0.0.4_386_42808-g28fefb1_cferom_pureubi.w-0.extracted/ubifs-root/278916373/rootfs_ubifs/rom/etc/ld.so.conf

export QEMU_LD_PREFIX="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Asus/_RT-AX56U_3.0.0.4_386_42808-g28fefb1_cferom_pureubi.w-0.extracted/ubifs-root/278916373/rootfs_ubifs"
export RR_mmap_fixed_mapped_disallowed=1
# Mock wireless extensions and other ioctls using our preload
# export LD_PRELOAD="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/rr_mock_ioctls.so"
# Enable mock if needed (some need it, some don't. For mass scan, maybe safe to add?)

# Basic library path guess
export LD_LIBRARY_PATH="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Asus/_RT-AX56U_3.0.0.4_386_42808-g28fefb1_cferom_pureubi.w-0.extracted/ubifs-root/278916373/rootfs_ubifs/lib:/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Asus/_RT-AX56U_3.0.0.4_386_42808-g28fefb1_cferom_pureubi.w-0.extracted/ubifs-root/278916373/rootfs_ubifs/usr/lib"

# Workdir for output
mkdir -p /tmp/mass_fuzz/rootfs_ubifs

# Copy config to tmp if needed (some servers need write access to config dir)
# For now we use in-place or assume read-only is fine

echo "[*] Starting fuzzing for rootfs_ubifs..."

while true; do
    /home/webfuzz/Documents/qemu/build/qemu-arm \
        /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Asus/_RT-AX56U_3.0.0.4_386_42808-g28fefb1_cferom_pureubi.w-0.extracted/ubifs-root/278916373/rootfs_ubifs/usr/sbin/httpd \
        -f /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Asus/_RT-AX56U_3.0.0.4_386_42808-g28fefb1_cferom_pureubi.w-0.extracted/ubifs-root/278916373/rootfs_ubifs/rom/etc/ld.so.conf \
        > /tmp/mass_fuzz/rootfs_ubifs/stdout.log 2> /tmp/mass_fuzz/rootfs_ubifs/stderr.log
    
    RET=$?
    # If it exits too fast (less than 1s), sleep a bit to avoid CPU spin
    # But for fuzzing we want fast restart. 
    # Logic: If it segfaults (>128), log it.
    
    if [ $RET -gt 128 ]; then
        echo "[!] CRASH DETECTED with signal $((RET-128))!"
        cp /tmp/mass_fuzz/rootfs_ubifs/stderr.log /tmp/mass_fuzz/rootfs_ubifs/crash_$(date +%s).log
    fi
    sleep 0.5
done

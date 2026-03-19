#!/bin/bash
# Auto-generated fuzzing script for squashfs-root-0
# Arch: mips
# Binary: boa
# Config: -c /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/_TOTOLINK-IND-N200RE-Ad-V4.0.0-B20250429.1836-C9131R_04410_V26.web.extracted/squashfs-root-0/etc/boa.org

export QEMU_LD_PREFIX="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/_TOTOLINK-IND-N200RE-Ad-V4.0.0-B20250429.1836-C9131R_04410_V26.web.extracted/squashfs-root-0"
export RR_mmap_fixed_mapped_disallowed=1
# Mock wireless extensions and other ioctls using our preload
# export LD_PRELOAD="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/rr_mock_ioctls.so"
# Enable mock if needed (some need it, some don't. For mass scan, maybe safe to add?)

# Basic library path guess
export LD_LIBRARY_PATH="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/_TOTOLINK-IND-N200RE-Ad-V4.0.0-B20250429.1836-C9131R_04410_V26.web.extracted/squashfs-root-0/lib:/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/_TOTOLINK-IND-N200RE-Ad-V4.0.0-B20250429.1836-C9131R_04410_V26.web.extracted/squashfs-root-0/usr/lib"

# Workdir for output
mkdir -p /tmp/mass_fuzz/squashfs-root-0

# Copy config to tmp if needed (some servers need write access to config dir)
# For now we use in-place or assume read-only is fine

echo "[*] Starting fuzzing for squashfs-root-0..."

while true; do
    /home/webfuzz/Documents/qemu/build/qemu-mips \
        /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/_TOTOLINK-IND-N200RE-Ad-V4.0.0-B20250429.1836-C9131R_04410_V26.web.extracted/squashfs-root-0/bin/boa \
        -c /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/_TOTOLINK-IND-N200RE-Ad-V4.0.0-B20250429.1836-C9131R_04410_V26.web.extracted/squashfs-root-0/etc/boa.org \
        > /tmp/mass_fuzz/squashfs-root-0/stdout.log 2> /tmp/mass_fuzz/squashfs-root-0/stderr.log
    
    RET=$?
    # If it exits too fast (less than 1s), sleep a bit to avoid CPU spin
    # But for fuzzing we want fast restart. 
    # Logic: If it segfaults (>128), log it.
    
    if [ $RET -gt 128 ]; then
        echo "[!] CRASH DETECTED with signal $((RET-128))!"
        cp /tmp/mass_fuzz/squashfs-root-0/stderr.log /tmp/mass_fuzz/squashfs-root-0/crash_$(date +%s).log
    fi
    sleep 0.5
done

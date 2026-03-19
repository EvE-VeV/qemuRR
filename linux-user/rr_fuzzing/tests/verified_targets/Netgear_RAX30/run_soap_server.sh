#!/bin/bash
QEMU="/home/webfuzz/Documents/qemu/build/qemu-arm"
SYSROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Netgear/RAX30/sim_root/"
BINARY="$SYSROOT/bin/soap_serverd"

# Args from eid_netgearSoapServer.txt: "-d 0 -n 1 -l 1"
# -d debug level?
# -n instance number? (usually mapping to port 5000 + n?)
# -l ?
# -p port (for HTTPS instance)

# Let's try to force port 80 if possible, or 5000. 
# Usage help was: "usage: %s [-d num] [-p port_num] [-m shmid] [-v]"
# It didn't mention -n or -l in the usage string I saw earlier in `strings` output?
# Wait, let me check the strings output for usage again.
# "usage: %s [-d num] [-p port_num] [-m shmid] [-v]" was in strings.
# But eid file had -n and -l. Maybe specific version differences or hidden args.

# I will try to pass -p 80 explicitly to make PoC easier.
# Preload the mock library
MOCK_LIB="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/verified_targets/Netgear_RAX30/libmockcms.so"

echo "[*] Starting soap_serverd with HTTP args (-n 1)..."
$QEMU -L $SYSROOT -E LD_PRELOAD=$MOCK_LIB $BINARY -d 0 -n 1 -l 1 > /tmp/soap.log 2>&1 &

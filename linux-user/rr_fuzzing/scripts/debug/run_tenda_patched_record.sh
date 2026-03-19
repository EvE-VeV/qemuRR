#!/bin/bash
ROOTFS="linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root"
export RR_DEBUG_LEVEL=2
export RR_MODE=record
export RR_TRACE_FILE=/tenda_patched_v2.trace
sudo -E chroot $ROOTFS ../../../../../../../build/qemu-arm -L . bin/httpd &
sleep 5
sudo killall -9 qemu-arm httpd || true
cp $ROOTFS/tenda_patched_v2.trace ./
ls -la tenda_patched_v2.trace || true

#!/usr/bin/env python3
import sys

# libCfm.so:
# ConnectCfm: 36b0
# ConnectServer: 3468
# InitCfm: 540c
# InitServer: 32d8
LIB_PATH = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/lib/libCfm.so"

# mov r0, #0
# bx lr
RET0 = b"\x00\x00\xa0\xe3\x1e\xff\x2f\xe1"

with open(LIB_PATH, "rb") as f:
    data = bytearray(f.read())

OFFSETS = [0x36b0, 0x3468, 0x540c, 0x32d8]

for offset in OFFSETS:
    print(f"[*] Patching libCfm.so at {hex(offset)}...")
    data[offset:offset+len(RET0)] = RET0

with open(LIB_PATH, "wb") as f:
    f.write(data)

print("[+] Done.")

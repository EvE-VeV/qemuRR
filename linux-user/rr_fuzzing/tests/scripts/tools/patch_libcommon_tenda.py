#!/usr/bin/env python3
import sys

# libcommon.so: check_network VA 4d30 -> Offset 4d30
LIBC_PATH = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/lib/libcommon.so"

# mov r0, #1 (0x01,0x00,0xa0,0xe3)
# bx lr (0x1e,0xff,0x2f,0xe1)
RET1 = b"\x01\x00\xa0\xe3\x1e\xff\x2f\xe1"

with open(LIBC_PATH, "rb") as f:
    data = bytearray(f.read())

offset = 0x4d30
print(f"[*] Patching check_network in libcommon.so at {hex(offset)}...")
data[offset:offset+len(RET1)] = RET1

with open(LIBC_PATH, "wb") as f:
    f.write(data)

print("[+] Done.")

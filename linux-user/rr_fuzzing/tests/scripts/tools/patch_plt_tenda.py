#!/usr/bin/env python3
import sys

FILENAME = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/bin/httpd"

# PATCHES (Offset, NewBytes)
# mov r0, #0 (0x0000a0e3)
# mov pc, lr (0x1eff2fe1)
RET0 = b"\x00\x00\xa0\xe3\x1e\xff\x2f\xe1"

# ioctl@plt (eff0 VA -> 7ff0 Offset)
# bind@plt (f64c VA -> 864c Offset)
# socket@plt (f638 VA -> 8638 Offset)
PATCHES = [
    (0x7ff0, RET0), # ioctl
    (0x864c, RET0), # bind
    (0x8638, RET0), # socket
]

with open(FILENAME, "rb") as f:
    data = bytearray(f.read())

for offset, patch in PATCHES:
    print(f"[*] Patching at {hex(offset)}...")
    data[offset:offset+len(patch)] = patch

with open(FILENAME, "wb") as f:
    f.write(data)

print("[+] Done.")

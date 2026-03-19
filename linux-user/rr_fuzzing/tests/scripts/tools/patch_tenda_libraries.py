#!/usr/bin/env python3
import sys
import argparse

# Paths
ROOT = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root"
LIBC_PATH = f"{ROOT}/lib/libc.so.0"
CFM_PATH = f"{ROOT}/lib/libCfm.so"
COMMON_PATH = f"{ROOT}/lib/libcommon.so"

# Instructions
RET0 = b"\x00\x00\xa0\xe3\x1e\xff\x2f\xe1" # mov r0, #0 ; bx lr
RET1 = b"\x01\x00\xa0\xe3\x1e\xff\x2f\xe1" # mov r0, #1 ; bx lr
RET5 = b"\x05\x00\xa0\xe3\x1e\xff\x2f\xe1" # mov r0, #5 ; bx lr

def patch_file(path, patches):
    print(f"[*] Patching {path}...")
    try:
        with open(path, "rb") as f:
            data = bytearray(f.read())
        for offset, patch in patches:
            print(f"    - Offset {hex(offset)} -> {patch.hex()}")
            data[offset:offset+len(patch)] = patch
        with open(path, "wb") as f:
            f.write(data)
    except Exception as e:
        print(f" [!] Error: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-libc", action="store_true")
    args = parser.parse_args()

    if not args.skip_libc:
        libc_patches = [
            (0x162e8, RET0), # ioctl -> return 0
            (0x51fa8, RET5), # socket -> return 5
            (0x51cf0, RET0), # bind -> return 0
            (0x51de4, RET0), # listen -> return 0
            (0x51f44, RET0), # setsockopt -> return 0
        ]
        patch_file(LIBC_PATH, libc_patches)

    cfm_patches = [
        (0x36b0, RET1), # ConnectCfm
        (0x3468, RET1), # ConnectServer
        (0x540c, RET1), # InitCfm
        (0x32d8, RET1), # InitServer
    ]
    patch_file(CFM_PATH, cfm_patches)

    common_patches = [
        (0x4d30, RET1), # check_network
    ]
    patch_file(COMMON_PATH, common_patches)

    print("[+] Done.")

if __name__ == "__main__":
    main()

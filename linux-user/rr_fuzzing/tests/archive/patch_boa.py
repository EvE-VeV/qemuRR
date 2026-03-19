#!/usr/bin/env python3
import os
import sys

BOA_PATH = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root/bin/boa"
PATCH_OFFSET = 0x1fec0  # 0x41fec0 - 0x400000

# Expected bytes: 
# 0x41fec0: jal 0x402f90 -> 0c 10 0b e4
# 0x41fec4: sw v0, 0(s3) -> ae 62 00 00

EXPECTED_BYTES = b'\x0c\x10\x0b\xe4\xae\x62\x00\x00'
NOP_BYTES = b'\x00\x00\x00\x00\x00\x00\x00\x00'

def patch_binary():
    if not os.path.exists(BOA_PATH):
        print(f"Error: {BOA_PATH} not found.")
        sys.exit(1)

    with open(BOA_PATH, "r+b") as f:
        f.seek(PATCH_OFFSET)
        data = f.read(8)
        
        print(f"Read bytes at {hex(PATCH_OFFSET)}: {data.hex()}")
        
        if data == EXPECTED_BYTES:
            print("Bytes match expected instructions. Patching...")
            f.seek(PATCH_OFFSET)
            f.write(NOP_BYTES)
            print("Patch applied successfully.")
        elif data == NOP_BYTES:
            print("Binary already patched.")
        else:
            print("Error: Bytes do not match expected instructions. Aborting patch.")
            sys.exit(1)

if __name__ == "__main__":
    patch_binary()

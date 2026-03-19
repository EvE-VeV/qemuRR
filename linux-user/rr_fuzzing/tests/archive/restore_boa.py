#!/usr/bin/env python3
import os
import sys

BOA_PATH = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root/bin/boa"
PATCH_OFFSET = 0x1fec0

# Original bytes: 
# 0x41fec0: jal 0x402f90 -> 0c 10 0b e4
# 0x41fec4: sw v0, 0(s3) -> ae 62 00 00

ORIGINAL_BYTES = b'\x0c\x10\x0b\xe4\xae\x62\x00\x00'
NOP_BYTES = b'\x00\x00\x00\x00\x00\x00\x00\x00'

def restore_binary():
    if not os.path.exists(BOA_PATH):
        print(f"Error: {BOA_PATH} not found.")
        sys.exit(1)

    with open(BOA_PATH, "r+b") as f:
        f.seek(PATCH_OFFSET)
        data = f.read(8)
        
        print(f"Read bytes at {hex(PATCH_OFFSET)}: {data.hex()}")
        
        if data == NOP_BYTES:
            print("Bytes match NOPs. Restoring original instructions...")
            f.seek(PATCH_OFFSET)
            f.write(ORIGINAL_BYTES)
            print("Restore successful.")
        elif data == ORIGINAL_BYTES:
            print("Binary already original.")
        else:
            print("Error: Bytes verify failed. Unknown content.")
            sys.exit(1)

if __name__ == "__main__":
    restore_binary()

#!/usr/bin/env python3
import sys
import shutil

FILENAME = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/bin/httpd"
BACKUP = FILENAME + ".bak"
PATCHED = FILENAME + ".patched"

OFFSET = 0x29144
EXPECTED = b"\x03\x00\x00\xaa" # beq/bge ? disassembly showed aa000003
NEW = b"\x03\x00\x00\xea"      # b (unconditional)

try:
    # 1. Backup
    shutil.copy2(FILENAME, BACKUP)
    print(f"[*] Backed up to {BACKUP}")

    # 2. Read and Verify
    with open(FILENAME, "rb") as f:
        data = bytearray(f.read())
    
    current = data[OFFSET:OFFSET+4]
    print(f"[*] At offset {hex(OFFSET)}: {current.hex()}")
    
    if current != EXPECTED:
        print("[-] Mismatch! Aborting patch.")
        print(f"    Expected: {EXPECTED.hex()}")
        print(f"    Found:    {current.hex()}")
        sys.exit(1)
        
    # 3. Patch
    data[OFFSET:OFFSET+4] = NEW
    
    # 4. Write back (to original file for simplicity)
    with open(FILENAME, "wb") as f:
        f.write(data)
        
    print("[+] Successfully patched httpd (forced branch at 0x31144)")

except Exception as e:
    print(f"[-] Error: {e}")
    sys.exit(1)

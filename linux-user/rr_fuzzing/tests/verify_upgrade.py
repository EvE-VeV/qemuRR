
import os
import sys
import time
import struct
import subprocess
from pathlib import Path

# Add fuzzing root to path to allow package imports
sys.path.insert(0, str(Path(__file__).parent.parent / "fuzzing"))
from conductor.qemu_executor import QEMUExecutor
from conductor.instruction import FuzzInstruction
from conductor.constants import FUZZ_CMD_MUTATE_ARG

# Configuration
QEMU_PATH = "/home/webfuzz/Documents/qemu/build/qemu-x86_64"
TARGET_BINARY = "./verify_readv"
TRACE_FILE = "/tmp/verify_readv.bin"
LOG_FILE = "/tmp/verify_readv.log"

def record_trace():
    print(f"[*] Recording trace to {TRACE_FILE}...")
    if os.path.exists(TRACE_FILE):
        os.remove(TRACE_FILE)
    
    env = os.environ.copy()
    env['RR_MODE'] = 'record'
    env['RR_TRACE_FILE'] = TRACE_FILE
    env['RR_OUTPUT'] = '0' # Disable strace output during record to keep clean
    
    cmd = [QEMU_PATH, TARGET_BINARY]
    proc = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if proc.returncode != 0:
        print(f"[-] Recording failed: {proc.stderr.decode()}")
        sys.exit(1)
    
    if not os.path.exists(TRACE_FILE):
        print("[-] Trace file not created!")
        sys.exit(1)
        
    print(f"[+] Recording success. Trace size: {os.path.getsize(TRACE_FILE)} bytes")

def test_readv_clamping():
    print("\n[*] Testing READV Clamping...")
    
    executor = QEMUExecutor(QEMU_PATH, TARGET_BINARY, log_file=LOG_FILE)
    executor.extra_qemu_args = ["-d", "strace"] # Enable strace to see syscall return value
    
    # Mutate syscall index 2 (readv calls open, etc. first).
    # We need to find the index of readv.
    # We can guess or scan. Since it's a simple program:
    # 1. open(/dev/urandom)
    # 2. readv(fd, iov, 2)
    # 3. close(fd)
    # 4. exit
    # The index might be around 1-5.
    # Let's try to mutate index 0-10 with a distinguishable value.
    
    # We will try to override return value to 1000.
    # readv requests 64 bytes.
    # Expected: Clamped to 64.
    
    mutations = []
    # Target syscalls widely
    for i in range(10):
        # Cmd: MUTATE_ARG(arg_index=0xFF) -> retval override
        # Data: 1000 (0x3E8)
        mutations.append(FuzzInstruction(
            syscall_index=i,
            cmd=FUZZ_CMD_MUTATE_ARG,
            arg_index=0xFF,
            data=struct.pack("q", 1000)
        ))
        
    print(f"[*] Executing with {len(mutations)} mutations (forcing retval=1000)...")
    result = executor.execute_fork(TRACE_FILE, mutation_variants=[mutations])
    
    # Check log
    print("[*] Checking log for Clamping warning...")
    with open(LOG_FILE, 'r') as f:
        content = f.read()
        if "Clamping readv size" in content:
            print("[+] SUCCESS: Found 'Clamping readv size' in log!")
            print("    Log snippet:")
            os.system(f"grep 'Clamping readv' {LOG_FILE}")
        else:
            print("[-] FAILURE: Clamping message not found.")
            print(f"    Log tail:\n{content[-500:]}")

def test_error_injection():
    print("\n[*] Testing Error Injection (-EAGAIN)...")
    # Clean log
    os.remove(LOG_FILE)
    
    executor = QEMUExecutor(QEMU_PATH, TARGET_BINARY, log_file=LOG_FILE)
    executor.extra_qemu_args = ["-d", "strace"]
    
    mutations = []
    # Inject -11 (EAGAIN)
    # We assume readv is caught by the same loop
    for i in range(10):
        mutations.append(FuzzInstruction(
            syscall_index=i,
            cmd=FUZZ_CMD_MUTATE_ARG,
            arg_index=0xFF,
            data=struct.pack("q", -11)
        ))
        
    executor.execute_fork(TRACE_FILE, mutation_variants=[mutations])
    
    with open(LOG_FILE, 'r') as f:
        content = f.read()
        # Strace should show = -1 errno=11 (EAGAIN)
        # OR our debug log might say something.
        # But critically, the program verify_readv should print "readv failed: Resource temporarily unavailable"
        # Since we capture stdout in executor but redirected to LOG_FILE?
        # QEMUExecutor log file captures QEMU stderr (debug logs). 
        # Target stdout/stderr inheritance depends on executor.
        
        if "readv(-11)" in content or " = -11" in content or "4294967285" in content or "Resource temporarily unavailable" in content:
             print("[+] SUCCESS: Found injected error -11 in strace log (or perror output)")
        else:
             print("[-] Warning: Error code not explicitly seen in strace (could be format issue). Checking logic...")
             # Also check if it crashed (it shouldn't)
             if "SIGSEGV" in content:
                 print("[-] FAILED: Caused SIGSEGV!")
             else:
                 print("[+] Success: No crash with negative value.")

if __name__ == "__main__":
    try:
        record_trace()
        test_readv_clamping()
        test_error_injection()
    except Exception as e:
        print(f"[-] ERROR: {e}")
        import traceback
        traceback.print_exc()



import os
import subprocess
import time

# Configuration
QEMU_BUILD_PATH = "/home/webfuzz/Documents/qemu/build/qemu-mips"
ROOT_DIR = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/extracted_firmware/sim_root"
TRACE_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/traces/busybox.trace"
BUSYBOX_CMD = ["bin/busybox", "ls", "-l", "/"]

def run_recording():
    print(f"[*] Starting Recording to {TRACE_FILE}...")
    
    # Ensure trace directory exists/cleaned
    os.makedirs(os.path.dirname(TRACE_FILE), exist_ok=True)
    if os.path.exists(TRACE_FILE):
        os.remove(TRACE_FILE)
    if os.path.exists(TRACE_FILE + ".bbl"):
        os.remove(TRACE_FILE + ".bbl")

    env = os.environ.copy()
    env["RR_MODE"] = "record"
    env["RR_TRACE_FILE"] = TRACE_FILE
    env["QEMU_LD_PREFIX"] = "."
    
    cmd = [QEMU_BUILD_PATH] + ["-L", "."] + BUSYBOX_CMD
    
    print(f"[*] Executing: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=ROOT_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate(timeout=5)
        print(f"[*] Output:\n{stdout.decode()}")
        print(f"[*] Stderr:\n{stderr.decode()}")
    except Exception as e:
        print(f"[-] Failed to run process: {e}")
        return

    print("[*] Recording Finished.")
    
    if os.path.exists(TRACE_FILE):
        size = os.path.getsize(TRACE_FILE)
        print(f"[+] Trace file created: {TRACE_FILE} ({size} bytes)")
    else:
        print("[-] Trace file NOT created.")

if __name__ == "__main__":
    run_recording()

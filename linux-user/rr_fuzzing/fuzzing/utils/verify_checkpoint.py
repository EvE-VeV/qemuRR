
import os
import sys
import time
import subprocess
import struct

# Configuration
QEMU_PATH = "/home/webfuzz/Documents/qemu/build/qemu-x86_64"
TRACE_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/ls_trace.bin"
CMD_PIPE = "/tmp/rr_cmd_pipe_test"
STATUS_PIPE = "/tmp/rr_status_pipe_test"
SHM_NAME = "/dev/shm/rr_fuzzing_shm"

def setup_pipes():
    if not os.path.exists(CMD_PIPE):
        os.mkfifo(CMD_PIPE)
    if not os.path.exists(STATUS_PIPE):
        os.mkfifo(STATUS_PIPE)
        
def setup_shm():
    with open(SHM_NAME, "wb") as f:
        f.write(b'\x00' * 65536)

def cleanup_shm():
    if os.path.exists(SHM_NAME):
        os.remove(SHM_NAME)

def run_test():
    setup_pipes()
    setup_shm()
    
    # Environment
    env = os.environ.copy()
    env["RR_MODE"] = "fuzzing"
    env["RR_TRACE_FILE"] = TRACE_FILE
    env["RR_CMD_PIPE"] = CMD_PIPE
    env["RR_STATUS_PIPE"] = STATUS_PIPE
    env["RR_SHARED_MEMORY"] = "rr_fuzzing_shm" # Map to /dev/shm/rr_fuzzing_shm
    env["RR_FORK_SERVER"] = "1"
    env["RR_DEBUG_LEVEL"] = "3" # Verbose for checking flags
    
    # Open pipes (Order is critical to avoid deadlock/ENXIO)
    print("Opening pipes...")
    # Open STATUS as Reader first (Non-blocking to avoid waiting for Writer)
    # This ensures QEMU (Writer) succeeds in open(O_WRONLY|O_NONBLOCK)
    status_fd = os.open(STATUS_PIPE, os.O_RDONLY | os.O_NONBLOCK)
    
    # Launch QEMU with log capture
    log_file = open("qemu_debug.log", "w")
    print(f"Launching QEMU: {QEMU_PATH} /bin/ls (logging to qemu_debug.log)")
    qemu_proc = subprocess.Popen(
        [QEMU_PATH, "/bin/ls"],
        env=env,
        stderr=log_file,  # Capture logs to file
        stdout=subprocess.DEVNULL
    )
    
    # Open CMD as Writer (Blocking - waits for QEMU to open Reader)
    # QEMU opens CMD as Reader (O_RDONLY|O_NONBLOCK) - succeeds immediately?
    # No, open(O_WRONLY) blocks until Reader. QEMU is the Reader.
    cmd_fd = os.open(CMD_PIPE, os.O_WRONLY)
    
    # Make status_fd blocking again for easier reading
    import fcntl
    flags = fcntl.fcntl(status_fd, fcntl.F_GETFL)
    fcntl.fcntl(status_fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    
    # Wait for READY status
    print("Waiting for READY status...")
    start_time = time.time()
    while True:
        if time.time() - start_time > 10:  # Increased timeout
            print("Timeout waiting for READY")
            if qemu_proc.poll() is not None:
                print(f"QEMU exited with code: {qemu_proc.returncode}")
                # Close the write handle so we can read it
                log_file.flush()
                # Read the log file
                with open("qemu_debug.log", "r") as f:
                    print("--- QEMU STDERR (from file) ---")
                    print(f.read())
                    print("-------------------")
            log_file.close()
            return # Exit on timeout

        try:
            data = os.read(status_fd, 4)
            if len(data) == 4:
                status = struct.unpack("<i", data)[0]
                print(f"Received status: {status}")
                if status == 1 or status == 100: # READY
                    break
        except BlockingIOError:
            time.sleep(0.1)
            
    # Send Checkpoint Command 'C'
    target_index = 10
    print(f"Sending Checkpoint Command 'C' (target={target_index}) via SHM...")
    
    # Write to SHM:
    # 0: magic (0x46555A5A)
    # 8: num_variants (1)
    # 24: fork_point (10)
    with open(SHM_NAME, "r+b") as shm:
        # Magic
        shm.seek(0)
        shm.write(struct.pack("<I", 0x46555A5A))
        # Num Variants
        shm.seek(8)
        shm.write(struct.pack("<I", 1))
        # Fork Point
        shm.seek(24)
        shm.write(struct.pack("<I", target_index))
        shm.flush()

    # Write 'C' to Pipe
    os.write(cmd_fd, b'C')
    
    # Monitor logs for expected valid output (reading from file)
    print("Monitoring QEMU logs from file for 'ADVANCE'...")
    # Re-open in read mode while QEMU writes to it? 
    # Better to read line by line from the file path
    monitor_start = time.time()
    found_advance = False
    found_reentry = False
    
    # Wait a bit for logs to flush
    time.sleep(0.5) 
    
    with open("qemu_debug.log", "r") as f:
        # Seek to end? No, re-read from start to catch all
        while time.time() - monitor_start < 5:
            line = f.readline()
            if not line:
                if qemu_proc.poll() is not None:
                    break
                time.sleep(0.1)
                continue
                
            line_str = line.strip()
            print(f"[QEMU] {line_str}")
            
            if "Returning to ADVANCE" in line_str:
                print("✅ Verified: Parent received instruction to advance")
                found_advance = True
                
            if "Re-entering Fork Server" in line_str:
                print("✅ Verified: Parent re-entered fork server loop")
                found_reentry = True
                break # Success!

    log_file.close()

    if found_advance and found_reentry:
        print("\n🏆 SUCCESS: Checkpoint integration verified!")
    else:
        print("\n❌ FAILURE: Did not see expected logs.")

    qemu_proc.terminate()
    try:
        os.close(status_fd)
        os.close(cmd_fd)
    except:
        pass
    cleanup_shm()

if __name__ == "__main__":
    run_test()

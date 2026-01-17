import os
import subprocess
import time

# Configuration
QEMU_PATH = "/home/webfuzz/Documents/qemu/build/qemu-arm"
SIM_ROOT = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/RAX30/sim_root"
TARGET_BIN = "webs/cgi-bin/rex_cgi.real"
TRACE_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/traces/rax30_cgi.trace"

def record_trace():
    print("[*] Recording direct trace for rex_cgi...")
    
    # Ensure trace directory exists
    os.makedirs(os.path.dirname(TRACE_FILE), exist_ok=True)
    
    # Payload
    # Using 'wizWifi' as a potential valid function name
    payload = '{"function": "wizWifi", "serialNumber": "12345678", "test": "' + "A" * 100 + '"}'
    
    env = os.environ.copy()
    env["RR_MODE"] = "RECORD"
    env["RR_TRACE_FILE"] = TRACE_FILE
    env["LD_LIBRARY_PATH"] = f"{SIM_ROOT}/lib:{SIM_ROOT}/usr/lib:."
    
    # CGI Environment
    env["REQUEST_METHOD"] = "POST"
    env["CONTENT_TYPE"] = "application/json"
    env["CONTENT_LENGTH"] = str(len(payload))
    env["SCRIPT_NAME"] = "/cgi-bin/rex_cgi"
    env["REQUEST_URI"] = "/cgi-bin/rex_cgi"
    env["SERVER_NAME"] = "127.0.0.1"
    env["SERVER_PORT"] = "8080"
    env["HTTP_HOST"] = "127.0.0.1:8080"
    env["GATEWAY_INTERFACE"] = "CGI/1.1"
    env["REMOTE_ADDR"] = "127.0.0.1"
    
    cmd = [
        QEMU_PATH,
        "-L", SIM_ROOT,
        f"{SIM_ROOT}/{TARGET_BIN}"
    ]
    
    try:
        print(f"[*] Executing rex_cgi with payload: {payload}")
        # Run process and pass payload to stdin
        result = subprocess.run(
            cmd, 
            input=payload.encode(), 
            env=env, 
            cwd=SIM_ROOT,
            capture_output=True
        )
        
        print(f"[*] Exit code: {result.returncode}")
        print(f"[*] Stdout: {result.stdout.decode(errors='ignore')}")
        print(f"[*] Stderr: {result.stderr.decode(errors='ignore')}")
        
        print(f"[+] Trace recorded to {TRACE_FILE}")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    record_trace()

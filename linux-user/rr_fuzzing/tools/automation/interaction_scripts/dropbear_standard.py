import subprocess
import time
import sys
import os

def interact():
    # Wait for server to bind
    time.sleep(2)
    print("[*] Starting SSH interaction...")
    
    # SSH client command
    # We use -N (no remote command) just to do connection/auth
    # or just try to run 'id'
    cmd = [
        "ssh",
        "-p", "2222",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-o", "PreferredAuthentications=password",
        "-o", "NumberOfPasswordPrompts=1",
        "webfuzz@localhost",
        "id"
    ]
    
    env = os.environ.copy()
    env["SSH_ASKPASS"] = "/bin/false" # Prevent GUI prompt
    
    try:
        print(f"[*] Executing: {' '.join(cmd)}")
        # We provide a wrong password to trigger auth failure path
        proc = subprocess.Popen(
            cmd, 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            env=env
        )
        
        out, err = proc.communicate(input=b"wrongpass\n", timeout=10)
        
        print(f"[*] SSH finished with code {proc.returncode}")
        print(f"[*] Stdout: {out}")
        print(f"[*] Stderr (snippet): {err[:200]}")
        
    except subprocess.TimeoutExpired:
        print("[!] SSH timed out, killing...")
        proc.kill()
    except Exception as e:
        print(f"[!] SSH Error: {e}")

if __name__ == "__main__":
    interact()

#!/usr/bin/env python3
import subprocess
import time
import os

def run_ssh_attempt(port, user="webfuzz"):
    # Attempt SSH with a wrong password to exercise auth rejection logic
    # Use -o BatchMode=no -o PasswordAuthentication=yes to force password prompt interaction
    # But since it's automated, we expect it to fail or we use a tool like 'sshpass' if needed.
    # For recording, we just need the packet exchange.
    
    cmd = [
        "ssh", "-p", str(port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        f"{user}@127.0.0.1",
        "exit"
    ]
    
    print(f"[Dropbear-Auth] Starting SSH session (expecting auth failure)...")
    env = os.environ.copy()
    env["SSH_ASKPASS"] = "/bin/false"
    env["DISPLAY"] = ":0" # Fake display to avoid tty issues in some environments
    
    process = subprocess.Popen(cmd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2) # Wait for handshake and password prompt
    process.terminate()
    print("[Dropbear-Auth] Terminated SSH attempt.")

if __name__ == "__main__":
    port = 2222 # Dropbear port
    run_ssh_attempt(port)

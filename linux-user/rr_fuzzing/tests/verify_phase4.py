import os
import sys
import json
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.absolute()))

from fuzzing.conductor.fuzzing_core import FuzzingCore
from fuzzing.conductor.campaign_manager import CampaignManager

def verify_phase4():
    print("[*] Starting Phase 4 Verification (Stability & Monitoring)...")
    
    # 1. Setup paths and profile
    profile_path = "fuzzing/config/targets/rax30.json"
    qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-arm"
    seed_path = "tests/seeds/Netgear_RAX30/rax30_cgi_seed.bin"
    output_dir = "tests/fuzz_output_phase4_test"
    
    # Clean up old output
    import shutil
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    # 2. Initialize FuzzingCore
    print("[*] Initializing FuzzingCore...")
    core = FuzzingCore(
        qemu_path=qemu_path,
        target_binary="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netgear_RAX30/rootfs/usr/sbin/lighttpd",
        initial_trace=seed_path,
        output_dir=output_dir,
        ld_prefix="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netgear_RAX30/rootfs"
    )
    
    # 3. Initialize CampaignManager
    print("[*] Initializing CampaignManager...")
    manager = CampaignManager(core, iteration_limit=50) # Small run for verification
    
    # 4. Mock a Static CFG with a "Dangerous Sink"
    print("[*] Inducing mock Static CFG data for Watchdog...")
    mock_cfg = {
        'bb_to_func': {
            '0x400010': 'system',
            '0x400020': 'strcpy',
            '0x500010': 'normal_function'
        },
        'branches': []
    }
    core.security_watchdog._load_cfg(mock_cfg)
    
    # 5. Test Watchdog logic
    print("[*] Testing SecurityWatchdog heuristic...")
    sinks = core.security_watchdog.check_execution([0x400010, 0x500010])
    if 'system' in sinks:
        print("[+] SUCCESS: SecurityWatchdog correctly identified 'system' hit.")
    else:
        print("[-] FAILURE: SecurityWatchdog missed the 'system' hit.")
        return False

    # 6. Test Campaign Maintenance (Dry Run)
    print("[*] Testing Campaign Maintenance (Pruning & Stability)...")
    # Add many traces to trigger pruning
    for i in range(25):
        from fuzzing.conductor.trace_manager import Trace, TraceMetadata
        mock_trace = Trace(
            id=f"prune_test_{i}",
            file_path=seed_path,
            metadata=TraceMetadata(creation_time=time.time(), generation=i, exec_count=i)
        )
        core.trace_pool.add_trace(mock_trace, category='EVOLVED')
    
    print(f"[*] TracePool before pruning: {core.trace_pool.get_category_count()}")
    core.trace_pool.prune_redundant_traces(max_per_category=10)
    print(f"[*] TracePool after pruning: {core.trace_pool.get_category_count()}")
    
    if core.trace_pool.get_category_count()['EVOLVED'] <= 10:
        print("[+] SUCCESS: Trace pruning successfully limited pool size.")
    else:
        print("[-] FAILURE: Trace pruning failed.")
        return False

    # 7. Run small campaign session
    print("[*] Running short campaign session (5 iterations)...")
    manager.iteration_limit = 5
    manager.run()
    
    print("[+] SUCCESS: Phase 4 Infrastructure verified!")
    return True

if __name__ == "__main__":
    success = verify_phase4()
    if not success:
        sys.exit(1)

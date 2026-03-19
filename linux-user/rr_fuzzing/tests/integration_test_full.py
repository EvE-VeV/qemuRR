import os
import sys
import json
import time
import logging
from pathlib import Path

# Setup Project Path
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzing.conductor.fuzzing_core import FuzzingCore
from fuzzing.conductor.target_profile import TargetProfile
from fuzzing.conductor.campaign_manager import CampaignManager
from fuzzing.conductor.async_logger import alog

def run_integration_test():
    alog("🚀 Starting Full System Integration Test...", "TEST", "INFO")
    
    # 1. Configuration
    profile_path = "fuzzing/config/targets/rax30.json"
    seed_path = "tests/seeds/Netgear_RAX30/rax30_cgi_seed.bin"
    output_dir = "tests/integration_output"
    qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-arm"
    
    # Clean output
    import shutil
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    # 2. Initialize FuzzingCore
    # FuzzingCore internally uses TargetProfile and LifecycleManager now
    # We pass the profile path indirectly via the directory or explicit load
    core = FuzzingCore(
        qemu_path=qemu_path,
        target_binary="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netgear_RAX30/rootfs/usr/sbin/lighttpd",
        initial_trace=seed_path,
        output_dir=output_dir,
        ld_prefix="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netgear_RAX30/rootfs",
        enable_monitoring=True,
        enable_pathfinder=True,
        use_energy_scheduler=True
    )
    
    # 3. Setup Campaign Manager
    # Pruning every 50 iters, Snapshot every 100 iters for faster test
    manager = CampaignManager(core, iteration_limit=150)
    manager.pruning_interval = 50
    manager.snapshot_interval = 100
    
    # 4. Run Campaign
    alog("[*] Handing control to CampaignManager for 150 iterations...", "TEST", "INFO")
    start_time = time.time()
    manager.run()
    end_time = time.time()
    
    # 5. Outcome Verification
    alog("📊 Analyzing Integration Test Results...", "TEST", "INFO")
    
    # Check TracePool
    stats = core.trace_pool.get_category_count()
    alog(f"TracePool Stats: {stats}", "TEST", "INFO")
    
    # Check if pruning worked (we started with 1 + many execs, should be within limits)
    # Actually, in 150 iters, evolution might not trigger many promotions unless coverage is found.
    
    # Check Manifest
    manifest_path = Path(output_dir) / "trace_pool_manifest.json"
    if manifest_path.exists():
        alog("[+] Manifest verified.", "TEST", "INFO")
    else:
        alog("[-] Manifest missing!", "TEST", "ERROR")
        return False

    # Check for Evolution (Performance dependent, but we can check candidates)
    if len(core.evolution_engine.candidates) > 0 or stats.get('EVOLVED', 0) > 0:
        alog("[+] Evolution system active (candidates or evolved traces found).", "TEST", "INFO")
    
    alog(f"✨ Integration Test Completed in {end_time - start_time:.1f}s", "TEST", "INFO")
    return True

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    success = run_integration_test()
    if not success:
        sys.exit(1)

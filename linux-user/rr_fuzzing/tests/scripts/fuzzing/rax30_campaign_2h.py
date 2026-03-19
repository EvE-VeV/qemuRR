#!/usr/bin/env python3
import os
import sys
import json
import time
import logging
from pathlib import Path

# Setup paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from fuzzing.conductor.fuzzing_core import FuzzingCore
from fuzzing.conductor.mutator import SmartMutator
from fuzzing.conductor.campaign_manager import CampaignManager
from fuzzing.conductor.async_logger import alog

def run_rax30_campaign(profile_path: str, seed_path: str, iteration_limit: int = 10000):
    alog(f"🚀 Initializing RAX30 Campaign ({iteration_limit} iterations)...", "CAMPAIGN", "INFO")
    
    with open(profile_path, 'r') as f:
        profile = json.load(f)
    
    # 1. Environment and Config Setup
    rootfs_path = profile['rootfs_path']
    target_binary = str(Path(rootfs_path) / profile['binary_path'])
    target_args = " ".join(profile['start_command'][1:])
    output_dir = "tests/fuzz_output_rax30_campaign"
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # Apply environment from profile
    for k, v in profile.get('env', {}).items():
        os.environ[k] = v
    
    # Set campaign-specific optimizations
    os.environ['RR_FORK_POINT'] = str(profile.get('fork_point', 0))
    os.environ['RR_SHARED_MEMORY_SIZE'] = profile.get('shared_memory_size', '1M')
    os.environ['RR_DEBUG_LEVEL'] = '1' # Low verbosity for performance
    
    # 2. Initialize Mutator
    mutator = SmartMutator(trace_file=seed_path, target_binary=target_binary)
    
    # 3. Initialize FuzzingCore
    core = FuzzingCore(
        qemu_path="/home/webfuzz/Documents/qemu/build/qemu-arm",
        target_binary=target_binary,
        initial_trace=seed_path,
        output_dir=output_dir,
        mutator=mutator,
        target_args=target_args,
        ld_prefix=rootfs_path,
        enable_monitoring=True,
        enable_pathfinder=True,
        use_energy_scheduler=True,
        enable_persistence=True # Enable state auto-resume
    )
    
    # 4. Setup CampaignManager
    manager = CampaignManager(core, iteration_limit=iteration_limit)
    manager.pruning_interval = 200    # Prune every 200 iterations
    manager.snapshot_interval = 500  # Checkpoint every 500 iterations
    
    # 5. Launch
    alog("[*] Handing control to CampaignManager...", "CAMPAIGN", "INFO")
    try:
        manager.run()
    except Exception as e:
        alog(f"💥 Campaign failed: {e}", "CAMPAIGN", "ERROR")
        import traceback
        traceback.print_exc()
        
    alog("✅ Campaign finished or stopped.", "CAMPAIGN", "INFO")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    profile = "fuzzing/config/targets/rax30.json"
    seed = "tests/seeds/Netgear_RAX30/rax30_cgi_seed.bin"
    
    # 2-hour estimate: ~1-2 iterations per second -> 10,000 iterations is roughly 2 hours
    # Adjust limit if needed
    run_rax30_campaign(profile, seed, iteration_limit=10000)

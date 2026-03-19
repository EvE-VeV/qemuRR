#!/usr/bin/env python3
import os
import sys
import json
import time
from pathlib import Path
from typing import Optional

# Setup paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "fuzzing"))

from conductor.fuzzing_core import FuzzingCore
from conductor.mutator import SmartMutator

def verify_rax30_fuzz(profile_path: str, seed_path: str, iterations: int = 10):
    print(f"[*] Loading RAX30 profile from {profile_path}...")
    with open(profile_path, 'r') as f:
        profile = json.load(f)
    
    # 1. Prepare environment
    env = os.environ.copy()
    env.update(profile.get('env', {}))
    # Add project root to path for imports
    env['PYTHONPATH'] = str(PROJECT_ROOT / "fuzzing")
    # Set high debug level for C-side RR components    # 1. Environment variables
    env['RR_MODE'] = '3'
    env['RR_DEBUG_LEVEL'] = '4' 
    env['RR_LOG_LEVEL'] = '5'
    env['RR_MAX_VARIANTS'] = '5'
    env['RR_TRIGGER_PROB'] = '1.0'
    os.environ.update(env)

    
    # Apply patches (optional, record_target.py already did this, but just in case)
    # Actually, fuzzing_core won't apply patches. We assume /tmp/lighttpd.conf is ready.
    # But let's verify it's there.
    # 1.5 Apply config patches from profile
    for patch in profile.get('config_patches', []):
        source_path = Path(profile['rootfs_path']) / patch['source']
        target_path = Path(patch['target'])
        print(f"[*] Patching {target_path} using {source_path}...")
        
        if not source_path.exists():
            print(f"[!] Warning: source config {source_path} not found!")
            continue
            
        with open(source_path, 'r') as f:
            content = f.read()
            
        for search, replace in patch['replacements'].items():
            # Handle placeholder
            replace = replace.replace("{{ROOTFS}}", profile['rootfs_path'])
            content = content.replace(search, replace)
            
        with open(target_path, 'w') as f:
            f.write(content)
        print(f"[*] Patched {target_path} successfully.")
    
    # 2. Initialize Mutator
    print(f"[*] Initializing SmartMutator for trace: {seed_path}")
    mutator = SmartMutator(trace_file=seed_path, target_binary=str(Path(profile['rootfs_path']) / profile['binary_path']))
    
    # 3. Initialize FuzzingCore
    print(f"[*] Initializing FuzzingCore with seed: {seed_path}")
    qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-arm"
    target_binary = str(Path(profile['rootfs_path']) / profile['binary_path'])
    
    # Note: start_command[0] is the binary. start_command[1:] are the args.
    target_args = " ".join(profile['start_command'][1:])
    
    output_dir = "tests/fuzz_output_rax30"
    
    # We need to set the environment variables in os.environ before init if we want QEMUExecutor to inherit them
    for k, v in profile.get('env', {}).items():
        os.environ[k] = v
    
    # Also set the debug variables in current os.environ for inheritance
    os.environ['RR_DEBUG_LEVEL'] = '4'
    os.environ['RR_MAX_VARIANTS'] = '5'
    os.environ['RR_TRIGGER_PROB'] = '1.0'
        
    # Set optimizations in os.environ for inheritance
    os.environ['RR_FORK_POINT'] = str(profile.get('fork_point', 0))
    os.environ['RR_SHARED_MEMORY_SIZE'] = profile.get('shared_memory_size', '1M')
    os.environ['RR_DEBUG_LEVEL'] = '1' # Reduce verbosity for speed
    
    core = FuzzingCore(
        qemu_path=qemu_path,
        target_binary=target_binary,
        initial_trace=seed_path,
        output_dir=output_dir,
        mutator=mutator,
        target_args=target_args,
        ld_prefix=profile['rootfs_path']
    )
    
    print(f"[*] Starting fuzzing verification (Single Process)...")
    print(f"[*] Optimization: Fork Point set to {os.environ.get('RR_FORK_POINT')}")
    try:
        for i in range(iterations):
            print(f"\n--- Iteration {i+1}/{iterations} ---")
            # 4. Run one iteration
            # run_single_iteration manages seed selection, mutation, execution, and analysis
            core.run_single_iteration()
            
            # 5. Check progress
            core._display_progress(force=True)
            
            # Small delay to keep logs readable
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("[*] Interrupted by user.")
    finally:
        print("[*] Fuzzing session finished.")
        # Statistics summary
        stats = core.stats
        print(f"\n[+] Total Executions: {stats.total_execs}")
        print(f"[+] Paths Found: {stats.paths_found}")
        print(f"[+] Unique Crashes: {stats.unique_crashes}")
        
if __name__ == "__main__":
    profile = "fuzzing/config/targets/rax30.json"
    seed = "tests/seeds/Netgear_RAX30/rax30_cgi_seed.bin"
    
    if len(sys.argv) > 1:
        profile = sys.argv[1]
    if len(sys.argv) > 2:
        seed = sys.argv[2]
        
    verify_rax30_fuzz(profile, seed, iterations=20)

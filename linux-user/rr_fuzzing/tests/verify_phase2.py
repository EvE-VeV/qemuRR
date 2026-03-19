import os
import sys
import json
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.absolute()))

from fuzzing.conductor.fuzzing_core import FuzzingCore
from fuzzing.conductor.trace_manager import Trace, TraceMetadata

def verify_phase2():
    print("[*] Starting Phase 2 Verification (TracePool & Energy)...")
    
    # 1. Setup paths and profile
    profile_path = "fuzzing/config/targets/rax30.json"
    with open(profile_path, 'r') as f:
        profile = json.load(f)
        
    qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-arm"
    target_binary = str(Path(profile['rootfs_path']) / profile['binary_path'])
    seed_path = "tests/seeds/Netgear_RAX30/rax30_cgi_seed.bin"
    output_dir = "tests/fuzz_output_phase2_test"
    
    # Clean up old output
    import shutil
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)
    
    with open(os.path.join(output_dir, "profile.json"), "w") as f:
        json.dump(profile, f)

    # 2. Initialize FuzzingCore
    print("[*] Initializing FuzzingCore...")
    core = FuzzingCore(
        qemu_path=qemu_path,
        target_binary=target_binary,
        initial_trace=seed_path,
        output_dir=output_dir,
        ld_prefix=profile['rootfs_path']
    )
    
    # 3. Check TracePool status
    print(f"[*] TracePool stats: {core.trace_pool.get_category_count()}")
    if 'INITIAL' in core.trace_pool.categories and len(core.trace_pool.categories['INITIAL']) > 0:
        print("[+] INITIAL trace successfully registered in pool.")
    else:
        print("[-] FAILURE: INITIAL trace not found in pool.")
        return False

    # 4. Mock an evolved trace
    print("[*] Mocking trace evolution...")
    evolved_path = os.path.join(output_dir, "seeds", "evolved_mock.bin")
    os.makedirs(os.path.dirname(evolved_path), exist_ok=True)
    shutil.copy(seed_path, evolved_path)
    
    # Add to manager and pool
    new_trace = core.trace_manager.add_trace(
        trace_file=evolved_path,
        coverage_info={'has_new_edges': True, 'new_edge_count': 5},
        parent_id="trace_000"
    )
    if new_trace:
        core.trace_pool.add_trace(new_trace, category='EVOLVED')
        print(f"[+] Evolved trace added. Generation: {new_trace.metadata.generation}")
    
    # 5. Check manifest
    manifest_path = Path(output_dir) / "trace_pool_manifest.json"
    if manifest_path.exists():
        print("[+] Manifest file created.")
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
            print(f"[*] Manifest summary: {manifest['stats']}")
    else:
        print("[-] FAILURE: Manifest file not found.")
        return False

    # 6. Check Energy Scheduling (Visual Inspection of Weights)
    if hasattr(core.trace_manager, 'queue'):
        queue = core.trace_manager.queue
        if hasattr(queue, 'energy_scheduler'):
            scheduler = queue.energy_scheduler
            print(f"[*] Scheduler Weights: Depth={scheduler.depth_weight}, Coverage={scheduler.coverage_weight}")
            if scheduler.depth_weight == 0.3:
                print("[+] SUCCESS: Enhanced depth weighting confirmed.")
            else:
                print(f"[-] WARNING: Unexpected depth weight: {scheduler.depth_weight}")

    return True

if __name__ == "__main__":
    success = verify_phase2()
    if not success:
        sys.exit(1)

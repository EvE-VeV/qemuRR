import os
import sys
import json
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.absolute()))

from fuzzing.conductor.fuzzing_core import FuzzingCore
from fuzzing.conductor.evolution_engine import EvolutionCandidate
from fuzzing.conductor.instruction import FuzzInstruction

def verify_evolution():
    print("[*] Starting Evolution Engine Verification...")
    
    # 1. Setup paths and profile
    profile_path = "fuzzing/config/targets/rax30.json"
    with open(profile_path, 'r') as f:
        profile = json.load(f)
        
    qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-arm"
    target_binary = str(Path(profile['rootfs_path']) / profile['binary_path'])
    seed_path = "tests/seeds/Netgear_RAX30/rax30_cgi_seed.bin"
    output_dir = "tests/fuzz_output_evolution_test"
    
    # Clean up old output
    import shutil
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)
    
    # Copy profile to output_dir so FuzzingCore can find it
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
    
    # 3. Create a mock high-potential candidate
    # A mutation on syscall index 81 (read) with some data
    mock_instructions = [
        FuzzInstruction(syscall_index=81, cmd=2, arg_index=1, data=b"GET /cgi-bin/rex_cgi?test=1 HTTP/1.1\r\n\r\n")
    ]
    
    class MockResult:
        def __init__(self):
            self.new_coverage = 10
            self.trace_id = "trace_000"
            
    mock_result = MockResult()
    
    print("[*] Inducing mock discovery...")
    candidate = core.evolution_engine.evaluate_iteration(mock_result, mock_instructions)
    if candidate:
        print(f"[+] Candidate added to engine! Score: {candidate.score}")
    else:
        print("[-] Failed to add candidate.")
        return False

    # 4. Trigger evolution step
    print("[*] Triggering evolution step (Promotion)...")
    # We need to make sure re_recorder is initialized
    if not core.re_recorder:
        print("[-] Re-recorder not initialized. Check profile.json in output_dir.")
        return False
        
    core._perform_evolution_step()
    
    # 5. Verify results
    # Check if a new trace appeared in the seeds directory
    seeds_dir = Path(output_dir) / "seeds"
    evolved_traces = list(seeds_dir.glob("evolved_*.bin"))
    
    if evolved_traces:
        print(f"[+] SUCCESS: Evolution triggered! New trace: {evolved_traces[0].name}")
        # Check if it was added to TraceManager
        if hasattr(core.trace_manager, 'queue'):
            if hasattr(core.trace_manager.queue, 'seeds'):
                trace_count = len(core.trace_manager.queue.seeds)
            else:
                # AdvancedSeedQueue uses self.seeds
                trace_count = len(getattr(core.trace_manager.queue, 'seeds', []))
        else:
            trace_count = len(core.trace_manager.trace_pool)
            
        print(f"[+] TraceManager has {trace_count} seeds.")
        if trace_count > 1:
            print("[+] SUCCESS: New trace added to pool.")
            return True
    else:
        print("[-] FAILURE: No evolved trace found.")
        # Check log
        log_path = Path(output_dir) / "fuzzing.log"
        if log_path.exists():
            with open(log_path, "r") as f:
                print("\n--- Last 10 lines of Fuzzing Log ---")
                print("".join(f.readlines()[-10:]))
                
    return False

if __name__ == "__main__":
    success = verify_evolution()
    if not success:
        sys.exit(1)

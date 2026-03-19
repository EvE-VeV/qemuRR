#!/usr/bin/env python3
import os
import sys
import shutil
import time
import json
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(project_root))

from fuzzing.conductor.mutator import SmartMutator
from fuzzing.conductor.fuzzing_core import FuzzingCore
from fuzzing.multiprocess.crash_analyzer import CrashAnalyzer, CrashInfo

def test_dictionary_extraction():
    print("\n--- Testing Dictionary Extraction ---")
    # Use any binary that likely has strings, e.g., /bin/ls
    mutator = SmartMutator(trace_file=None, target_binary="/bin/ls")
    mutator._extract_dictionary_tokens("/bin/ls")
    
    print(f"Extracted {len(mutator.dictionary)} tokens")
    # Check for some common protocol keywords we added
    common_found = [t for t in mutator.dictionary if t in [b"HTTP/1.1", b"GET", b"admin", b"M-SEARCH"]]
    print(f"Protocol tokens found: {[t.decode() for t in common_found]}")
    
    assert len(mutator.dictionary) > 10, "Should extract at least some tokens"
    print("✅ Dictionary extraction test passed")

def test_mutation_injection():
    print("\n--- Testing Dictionary Token Injection ---")
    # Mock a target and trace
    mutator = SmartMutator(trace_file=None, target_binary="/bin/ls")
    mutator.dictionary = [b"SECRET_TOKEN_123", b"ANOTHER_TOKEN_ABC"]
    
    # We want to see if _generate_advanced_instruction uses these
    # Strategy 6 is REPLACE_BUFFER (small) which now has 60% chance to use dictionary
    from unittest.mock import MagicMock
    target_candidate = MagicMock()
    target_candidate.index = 0
    target_candidate.name = "read"
    
    found_token = False
    for _ in range(100):
        # We manually call _generate_advanced_instruction with strategy_type=6
        instr = mutator._generate_advanced_instruction(target_candidate, strategy_type=6, iteration=1)
        if any(token in instr.data for token in mutator.dictionary):
            print(f"Found injected token in instruction: {instr.data}")
            found_token = True
            break
            
    assert found_token, "Dictionary token should be injected into REPLACE_BUFFER"
    print("✅ Mutation injection test passed")

def test_seed_loopback():
    print("\n--- Testing Seed Loopback ---")
    test_dir = Path("./test_sync_dir")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir()
    (test_dir / "queue").mkdir()
    
    # Worker 1 creates a seed
    worker1_id = 1
    seed1_path = test_dir / "queue" / "seed_w1_iter10.bin"
    with open(seed1_path, "wb") as f:
        f.write(b"worker 1 discovery")
    # Create corresponding .bbl
    with open(str(seed1_path) + ".bbl", "wb") as f:
        f.write(b"worker 1 bb trace")
        
    # Worker 2 tries to import it
    worker2_id = 2
    worker2_out = Path("./worker2_out")
    if worker2_out.exists():
        shutil.rmtree(worker2_out)
    worker2_out.mkdir()
    
    # Initialize Worker 2's core
    core2 = FuzzingCore(
        qemu_path="/usr/bin/qemu-x86_64",
        target_binary="/bin/ls",
        initial_trace="/bin/ls", # dummy
        output_dir=str(worker2_out),
        sync_dir=str(test_dir),
        worker_id=worker2_id
    )
    
    # Run import
    core2.import_external_seeds()
    
    # Check if seed was imported to worker2_out/seeds_imported
    imported_path = worker2_out / "seeds_imported" / "seed_w1_iter10.bin"
    assert imported_path.exists(), "Worker 2 should have imported Worker 1's seed"
    print(f"Successfully imported seed: {imported_path.name}")
    
    # Check if it was added to trace_manager
    found_in_mgr = False
    if hasattr(core2.trace_manager, 'trace_to_seed_map'):
        for seed in core2.trace_manager.trace_to_seed_map.values():
            if "seed_w1_iter10.bin" in str(seed.trace_file):
                found_in_mgr = True
                break
    elif hasattr(core2.trace_manager, 'traces'):
        for t in core2.trace_manager.traces.values():
            if "seed_w1_iter10.bin" in str(t.file_path):
                found_in_mgr = True
                break
    assert found_in_mgr, "Imported seed should be in trace manager"
    
    print("✅ Seed loopback test passed")

def test_crash_deduplication():
    print("\n--- Testing Cross-Worker Crash Deduplication ---")
    sync_dir = Path("./test_crash_sync")
    if sync_dir.exists():
        shutil.rmtree(sync_dir)
    sync_dir.mkdir()
    (sync_dir / "crashes").mkdir()
    
    # Worker 1 finds a crash
    analyzer1 = CrashAnalyzer(sync_dir, worker_id=1)
    crash1 = CrashInfo(
        crash_id="crash1", signal=11, signal_name="SIGSEGV", pc=0x414141,
        fault_address=0, backtrace=["func1", "func2"], syscall_index=5,
        mutation_recipe={}, timestamp="2026-01-22T10:00:00",
        crash_hash="same_hash_123", priority="HIGH", exploitability="EXPLOITABLE"
    )
    analyzer1.save_crash(crash1)
    
    # Worker 2 finds the SAME crash (same hash)
    analyzer2 = CrashAnalyzer(sync_dir, worker_id=2)
    crash2 = CrashInfo(
        crash_id="crash2", signal=11, signal_name="SIGSEGV", pc=0x414141,
        fault_address=0, backtrace=["func1", "func2"], syscall_index=5,
        mutation_recipe={}, timestamp="2026-01-22T10:00:05",
        crash_hash="same_hash_123", priority="HIGH", exploitability="EXPLOITABLE"
    )
    analyzer2.save_crash(crash2)
    
    # Check the DB
    with open(sync_dir / "crashes" / "crash_db.json", "r") as f:
        db = json.load(f)
        
    assert "same_hash_123" in db
    assert db["same_hash_123"]["count"] == 2
    assert "crash_w1_000000_same_has" in str(db["same_hash_123"]["crash_ids"]) or "crash1" in str(db["same_hash_123"]["crash_ids"])
    # Note: CrashAnalyzer.save_crash uses crash_info.crash_id which we passed as "crash1" and "crash2" in this test
    # but in real usage it generates them.
    
    print(f"Crash DB deduplicated same_hash_123, count={db['same_hash_123']['count']}")
    assert len(db) == 1, "Should have only 1 unique crash in DB"
    
    print("✅ Crash deduplication test passed")

if __name__ == "__main__":
    try:
        test_dictionary_extraction()
        test_mutation_injection()
        test_seed_loopback()
        test_crash_deduplication()
        print("\n✨ ALL TESTS PASSED ✨")
    finally:
        # Cleanup
        for d in ["test_sync_dir", "worker2_out", "test_crash_sync"]:
            if os.path.exists(d):
                shutil.rmtree(d)

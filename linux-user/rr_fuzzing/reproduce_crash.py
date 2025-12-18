#!/usr/bin/env python3
import os
import sys
import time
import shutil
import json
from pathlib import Path

# Add the python module path
sys.path.append("/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing")

from conductor.qemu_executor import QEMUExecutor, STATUS_CRASH
from conductor.instruction import FuzzInstruction
from conductor import constants

def reproduce_crash():
    print("[-] Starting Crash Reproduction...")
    
    # Configuration
    qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-x86_64"
    target_binary = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/data/lava_corpus/LAVA-M/md5sum/coreutils-8.24-lava-safe/src/md5sum"
    original_trace = "/home/webfuzz/Documents/qemu/md5sum_trace.bin"
    crash_trace = "/home/webfuzz/Documents/qemu/fuzz_md5sum_production/crashes/crash_000000_7aab888f.bin"
    crash_meta = "/home/webfuzz/Documents/qemu/fuzz_md5sum_production/crashes/crash_000000_7aab888f.meta"
    
    # Verify files exist
    if not os.path.exists(qemu_path):
        print(f"Error: QEMU not found at {qemu_path}")
        return
    if not os.path.exists(target_binary):
        print(f"Error: Target binary not found at {target_binary}")
        return
    if not os.path.exists(crash_trace):
        print(f"Error: Crash trace not found at {crash_trace}")
        return
    if not os.path.exists(crash_meta):
        print(f"Error: Crash meta not found at {crash_meta}")
        return

    # Load metadata to get mutations
    with open(crash_meta, 'r') as f:
        meta = json.load(f)
        
    print(f"[-] Loaded metadata for crash {meta['crash_id']}")
    print(f"[-] Crash hash: {meta['crash_hash']}")
    
    mutations_data = meta.get('mutations', [])
    print(f"[-] Found {len(mutations_data)} mutations")
    
    # Reconstruct FuzzInstruction objects
    mutations = []
    
    for idx, m_data in enumerate(mutations_data):
        syscall_index = m_data.get('syscall_index')
        cmd = m_data.get('cmd')
        
        # Note: metadata might be missing explicit data/args if it wasn't saved.
        # However, for boundary value (cmd=4), we might just need defaults if data is missing.
        # Or maybe the data IS pivotal.
        # But look at FuzzInstruction __init__:
        # def __init__(self, syscall_index, cmd, arg_index, data, offset=0, size=None, mutation_type='unknown'):
        
        # If metadata lacks 'data', we might have incomplete records.
        # Let's check what fields we have.
        # Based on Step 33 view_file:
        # { "syscall_index": 5, "cmd": 4 }
        # It seems ONLY syscall_index and cmd are saved in JSON.
        # This implies either:
        # A) The command is self-sufficient (e.g. predefined boundary value).
        # B) The saving logic was lossy.
        
        # If it's lossy, exact reproduction is impossible.
        # But let's try to infer or use defaults.
        
        # For cmd=4 (BOUNDARY_VALUE), it usually tries a set of known bad integers.
        # Without knowing WHICH value, we can't be sure.
        # BUT, wait.
        # If the fuzzer is deterministic from seed, then we need the seed.
        # But here we are replaying a trace with explicit mutations.
        
        # Let's inspect FuzzInstruction constants or Mutator code.
        # If we can't reconstruct, we can try to run with "generic" data for that command.
        
        # Default fallback values
        arg_index = m_data.get('arg_index', 0) # Default to arg 0?
        data = m_data.get('data', b'\x00' * 8) 
        offset = m_data.get('offset', 0)
        size = m_data.get('size', 8)
        
        # Construct instruction
        instr = FuzzInstruction(
            syscall_index=syscall_index,
            cmd=cmd,
            arg_index=arg_index,
            data=data,
            offset=offset,
            size=size,
            mutation_type="reproduction"
        )
        mutations.append(instr)
        print(f"    Mutation {idx}: Syscall[{syscall_index}] Cmd[{cmd}]")

    # Create a temporary trace file for reproduction (copy of the CRASH BIN which is just the base trace)
    repro_trace = "/tmp/repro_trace_mutated.bin"
    shutil.copy(crash_trace, repro_trace)
    print(f"[-] Copied base trace to {repro_trace}")

    # Initialize Executor
    print("[-] Initializing QEMUExecutor...")
    executor = QEMUExecutor(
        qemu_path=qemu_path,
        target_binary=target_binary,
        timeout=5.0,
        persistent_mode=False 
    )

    try:
        print(f"[-] Executing trace with {len(mutations)} mutations...")
        
        # execute() expects List[FuzzInstruction]
        # In this codebase, 'mutations' argument to execute is List[FuzzInstruction].
        # But wait, execute_fork takes List[List[FuzzInstruction]] (variants).
        # execute() takes List[FuzzInstruction] (single execution).
        
        result = executor.execute(repro_trace, mutations)
        
        print("\n" + "="*40)
        print("REPRODUCTION RESULT")
        print("="*40)
        print(f"Status: {result.status} ({result.status_name})")
        print(f"QEMU Exit Code: {result.qemu_exit_code}")
        print(f"Signal: {result.signal_number}")
        
        if result.status == STATUS_CRASH:
            print("\n[SUCCESS] CRASH REPRODUCED!")
            print(f"The target crashed with signal {result.signal_number}")
        else:
            print("\n[FAILURE] CRASH NOT REPRODUCED.")
            print("The target did not crash as expected.")
            print("Possible reasons: Mutation data missing from metadata, or non-deterministic behavior.")

    except Exception as e:
        print(f"[-] Exception during reproduction: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        if hasattr(executor, 'stop_persistent_qemu'):
             executor.stop_persistent_qemu()
        executor.cleanup_shared_coverage() 

if __name__ == "__main__":
    reproduce_crash()

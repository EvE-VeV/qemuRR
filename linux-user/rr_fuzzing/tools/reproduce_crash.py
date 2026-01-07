#!/usr/bin/env python3
import os
import sys
import time
import shutil
import json
import argparse
from pathlib import Path

# Setup paths relative to script location
SCRIPT_DIR = Path(__file__).parent.absolute()
RR_FUZZING_ROOT = SCRIPT_DIR.parent
FUZZING_ROOT = RR_FUZZING_ROOT / "fuzzing"
PROJECT_ROOT = RR_FUZZING_ROOT.parent.parent

# Add the python module path
sys.path.insert(0, str(FUZZING_ROOT))

try:
    from conductor.qemu_executor import QEMUExecutor, STATUS_CRASH
    from conductor.instruction import FuzzInstruction
    from conductor import constants
except ImportError as e:
    print(f"Error: Could not import RR-Fuzz modules: {e}")
    print(f"FUZZING_ROOT: {FUZZING_ROOT}")
    sys.exit(1)

def reproduce_crash(qemu_path, target_binary, crash_meta_path, verbose=False):
    print(f"[-] Starting Crash Reproduction...")
    
    crash_meta_path = Path(crash_meta_path).absolute()
    crash_trace_path = crash_meta_path.with_suffix(".bin")
    
    # Verify files exist
    if not os.path.exists(qemu_path):
        print(f"Error: QEMU not found at {qemu_path}")
        return False
    if not os.path.exists(target_binary):
        print(f"Error: Target binary not found at {target_binary}")
        return False
    if not crash_meta_path.exists():
        print(f"Error: Crash meta not found at {crash_meta_path}")
        return False
    if not crash_trace_path.exists():
        print(f"Error: Crash trace not found at {crash_trace_path} (expected by .bin association)")
        return False

    # Load metadata to get mutations
    with open(crash_meta_path, 'r') as f:
        meta = json.load(f)
        
    print(f"[-] Loaded metadata for crash {meta.get('crash_id', 'unknown')}")
    print(f"[-] Crash hash: {meta.get('crash_hash', 'unknown')}")
    
    mutations_data = meta.get('mutations', [])
    print(f"[-] Found {len(mutations_data)} mutations")
    
    # Reconstruct FuzzInstruction objects
    mutations = []
    for idx, m_data in enumerate(mutations_data):
        instr = FuzzInstruction(
            syscall_index=m_data.get('syscall_index'),
            cmd=m_data.get('cmd'),
            arg_index=m_data.get('arg_index'),
            data=bytes.fromhex(m_data.get('data_hex', '')) if 'data_hex' in m_data else m_data.get('data'),
            offset=m_data.get('offset'),
            size=m_data.get('size'),
            mutation_type=m_data.get('mutation_type', 'repro')
        )
        mutations.append(instr)
        if verbose:
            print(f"    Mutation {idx}: Syscall[{instr.syscall_index}] Cmd[{instr.cmd}] Type[{instr.mutation_type}]")

    # Create a temporary trace file for reproduction
    repro_trace = "/tmp/repro_trace_mutated.bin"
    shutil.copy(str(crash_trace_path), repro_trace)
    
    # Initialize Executor
    if verbose:
        print("[-] Initializing QEMUExecutor...")
        
    executor = QEMUExecutor(
        qemu_path=str(qemu_path),
        target_binary=str(target_binary),
        timeout=10.0,
        persistent_mode=False 
    )

    try:
        print(f"[-] Executing trace with {len(mutations)} mutations...")
        result = executor.execute(repro_trace, mutations)
        
        print("\n" + "="*40)
        print("REPRODUCTION RESULT")
        print("="*40)
        print(f"Status: {result.status_name} (code: {result.status})")
        print(f"QEMU Exit Code: {result.qemu_exit_code}")
        print(f"Signal: {result.signal_number}")
        
        if result.status == STATUS_CRASH:
            print("\n[SUCCESS] CRASH REPRODUCED!")
            return True
        else:
            print("\n[FAILURE] CRASH NOT REPRODUCED.")
            return False

    except Exception as e:
        print(f"[-] Exception during reproduction: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if hasattr(executor, 'stop_persistent_qemu'):
             executor.stop_persistent_qemu()
        executor.cleanup_shared_coverage() 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reproduce RR-Fuzz crashes from metadata")
    parser.add_argument("meta", help="Path to the crash .meta file")
    parser.add_argument("--qemu", help="Path to QEMU executable (default: auto-detect)")
    parser.add_argument("--target", help="Path to target binary (default: auto-detect from meta if possible)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Simple auto-detect logic for QEMU
    qemu = args.qemu
    if not qemu:
        possible_qemu = PROJECT_ROOT / "build/qemu-x86_64"
        if possible_qemu.exists():
            qemu = str(possible_qemu)
        else:
            print("Error: QEMU path not provided and not found in build directory.")
            sys.exit(1)
            
    # Simple auto-detect logic for target
    target = args.target
    if not target:
        # Note: In real scenarios, metadata might contain the target path
        # For now, let's try to infer or ask the user
        print("Warning: Target binary path not provided. Add --target <path>")
        sys.exit(1)
        
    success = reproduce_crash(qemu, target, args.meta, args.verbose)
    sys.exit(0 if success else 1)

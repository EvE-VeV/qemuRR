#!/usr/bin/env python3
import sys
import os
import argparse
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from conductor.fuzzing_core import FuzzingCore
from conductor.mutator import SmartMutator

def main():
    parser = argparse.ArgumentParser(description="RR-Fuzz: Universal QEMU Fuzzer")
    parser.add_argument("--qemu", required=True, help="Path to QEMU binary")
    parser.add_argument("--target", required=True, help="Path to target binary")
    parser.add_argument("--trace", required=True, help="Path to initial trace file")
    parser.add_argument("--output", default="fuzzing_output", help="Output directory")
    parser.add_argument("--iterations", type=int, default=1000, help="Max iterations")
    parser.add_argument("--infinite", action="store_true", help="Run indefinitely")
    parser.add_argument("--no-progress-timeout", type=int, default=300, help="Timeout if no progress (seconds)")
    parser.add_argument("--args", default="", help="Target binary arguments")
    parser.add_argument("--tree", action="store_true", help="Enable Syscall Tree visualization (default: False)")
    parser.add_argument("--persistence", action="store_true", help="Enable unified session persistence (Auto Save/Resume)")
    parser.add_argument("--word-size", type=int, default=0, help="Word size (32 or 64, 0 for auto)")
    parser.add_argument("--endian", default="auto", choices=["auto", "little", "big"], help="Endianness")
    
    args = parser.parse_args()
    
    fuzzing_core = None
    try:
        # Initialize Core
        # Note: SmartMutator requires trace_file and target_binary
        mutator = SmartMutator(
            args.trace, 
            target_binary=args.target,
            word_size=args.word_size,
            endian=args.endian
        )
        
        fuzzing_core = FuzzingCore(
            qemu_path=args.qemu,
            target_binary=args.target,
            initial_trace=args.trace,
            output_dir=args.output,
            mutator=mutator,
            use_fork_server=True,  # Internal design: high-speed fork server
            enable_persistence=args.persistence,
            target_args=args.args,
            enable_tree_viz=args.tree
        )
        
        # Run Fuzzing
        stop_conditions = {
            'max_iterations': args.iterations,
            'no_progress_timeout': None if args.infinite else args.no_progress_timeout,
            'infinite': args.infinite
        }

        fuzzing_core.run_advanced(stop_conditions)
        
        print("\n✅ Fuzzing completed successfully!")
        return 0
    
    except KeyboardInterrupt:
        print("\n[Main] Interrupted by user")
        return 130
    
    except Exception as e:
        print(f"\n❌ Error during fuzzing: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    finally:
        if fuzzing_core:
            print("[Main] Cleaning up...")
            fuzzing_core.cleanup()

if __name__ == '__main__':
    sys.exit(main())

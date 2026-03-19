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
    parser.add_argument("-n", "--workers", type=int, default=1, help="Number of worker processes (default: 1)")
    parser.add_argument("--dictionary", help="Path to dictionary file")
    parser.add_argument("--ld-prefix", help="QEMU LD Prefix (RootFS)")
    parser.add_argument("--fork-point", type=int, help="Manual fork point index (overrides DFC logic)")
    
    # Ablation Study Flags
    parser.add_argument("--disable-smartdict", action="store_true", help="Disable SmartMutator (use BaseMutator instead)")
    parser.add_argument("--disable-pathfinder", action="store_true", help="Disable PathFinder guided execution")
    
    args = parser.parse_args()
    
    fuzzing_core = None
    try:
        # [NEW] Derive target architecture from QEMU path for consistent mapping
        arch = 'auto'
        qemu_name = os.path.basename(args.qemu).lower()
        if 'aarch64' in qemu_name:
            arch = 'arm64'
        elif 'arm' in qemu_name:
            arch = 'arm'
        elif 'mips' in qemu_name:
            arch = 'mips'
        elif 'x86_64' in qemu_name:
            arch = 'x86_64'
        elif 'i386' in qemu_name:
            arch = 'i386'
            
        # Initialize Core
        if args.disable_smartdict:
            from conductor.mutator import BaseMutator
            mutator = BaseMutator()
        else:
            mutator = SmartMutator(
                args.trace, 
                target_binary=args.target,
                word_size=args.word_size,
                endian=args.endian,
                dictionary_file=args.dictionary,
                arch=arch  # Pass derived arch
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
            enable_tree_viz=args.tree,
            ld_prefix=args.ld_prefix,
            manual_fork_point=args.fork_point
        )
        
        # Multi-Process Mode
        if args.workers > 1:
            from multiprocess.fuzz_master import FuzzMaster
            print(f"[*] Starting Multi-Process Master with {args.workers} workers")
            master = FuzzMaster(
                qemu_path=args.qemu,
                target_binary=args.target,
                initial_trace=args.trace,
                target_args=args.args,
                num_workers=args.workers,
                sync_dir=args.output,
                mutator_type="base" if args.disable_smartdict else "smart",
                enable_pathfinder=not args.disable_pathfinder,
                enable_persistence=args.persistence,
                dictionary_file=args.dictionary,
                ld_prefix=args.ld_prefix,
                manual_fork_point=args.fork_point
            )
            master.run()
            return 0

        # Run Fuzzing (Single-Process)
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

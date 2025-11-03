#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RR-Fuzz Main Entry Point - Reorganized Architecture

This is the main entry point for RR-Fuzz using the reorganized architecture
aligned with DETAILED_ARCHITECTURE.md.

Architecture:
  Layer 1: TraceManager - Manages trace pool and selection
  Layer 2: FuzzingCore - Coordinates fuzzing loop
           - QEMUExecutor: Executes traces with mutations
           - BaseMutator/SmartMutator: Generates mutations
           - CoverageTracker: Tracks code coverage
           - CrashDetector: Detects and saves crashes

Usage:
    # Basic fuzzing with random mutation
    python3 fuzz_main.py --qemu ./qemu --trace ./trace.bin --target ./program
    
    # With smart mutation (trace-aware)
    python3 fuzz_main.py --qemu ./qemu --trace ./trace.bin --target ./program --smart
    
    # With recipe-driven mutation
    python3 fuzz_main.py --qemu ./qemu --trace ./trace.bin --target ./program --smart --recipe recipes.json
    
    # Limited iterations
    python3 fuzz_main.py --qemu ./qemu --trace ./trace.bin --target ./program --iterations 1000
    
    # Time-limited fuzzing
    python3 fuzz_main.py --qemu ./qemu --trace ./trace.bin --target ./program --timeout 3600

Author: RR-Fuzz Team
Date: 2025-11-03
"""

import os
import sys
import signal
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from conductor import (
    FuzzingCore,
    BaseMutator,
    SmartMutator
)


# Global variables for signal handling
_fuzzing_core = None
_shutdown_requested = False


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global _shutdown_requested, _fuzzing_core
    
    print(f"\n[Main] Received signal {signum}, shutting down...")
    _shutdown_requested = True
    
    if _fuzzing_core:
        print("[Main] Saving final results...")
        _fuzzing_core.save_final_results()
    
    sys.exit(0)


def validate_args(args):
    """Validate command line arguments"""
    errors = []
    
    if not os.path.exists(args.qemu):
        errors.append(f"QEMU executable not found: {args.qemu}")
    
    if not os.path.exists(args.target):
        errors.append(f"Target binary not found: {args.target}")
    
    if not os.path.exists(args.trace):
        errors.append(f"Trace file not found: {args.trace}")
    
    if args.recipe and not os.path.exists(args.recipe):
        errors.append(f"Recipe file not found: {args.recipe}")
    
    if args.iterations and args.iterations < 1:
        errors.append(f"Iterations must be >= 1")
    
    if args.timeout and args.timeout < 1:
        errors.append(f"Timeout must be >= 1 second")
    
    return errors


def main():
    """Main entry point"""
    global _fuzzing_core
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='RR-Fuzz - Record-Replay Guided Fuzzing (Reorganized Architecture)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic fuzzing (random mutation)
  python3 fuzz_main.py --qemu ./qemu --trace trace.bin --target ./program
  
  # Smart fuzzing (trace-aware mutation)
  python3 fuzz_main.py --qemu ./qemu --trace trace.bin --target ./program --smart
  
  # Recipe-driven fuzzing
  python3 fuzz_main.py --qemu ./qemu --trace trace.bin --target ./program --smart --recipe recipes.json
  
  # Limited iterations
  python3 fuzz_main.py --qemu ./qemu --trace trace.bin --target ./program --iterations 1000
  
  # Time-limited fuzzing (1 hour)
  python3 fuzz_main.py --qemu ./qemu --trace trace.bin --target ./program --timeout 3600

For more information, see DETAILED_ARCHITECTURE.md
        """
    )
    
    # Required arguments
    parser.add_argument('--qemu', required=True,
                        help='Path to QEMU executable')
    parser.add_argument('--target', required=True,
                        help='Path to target binary')
    parser.add_argument('--trace', required=True,
                        help='Path to initial trace file (seed)')
    
    # Optional arguments
    parser.add_argument('--output', default='fuzzing_output',
                        help='Output directory (default: fuzzing_output)')
    parser.add_argument('--iterations', type=int, default=None,
                        help='Maximum iterations (default: unlimited)')
    parser.add_argument('--timeout', type=int, default=None,
                        help='Maximum time in seconds (default: unlimited)')
    parser.add_argument('--qemu-timeout', type=float, default=30.0,
                        help='QEMU execution timeout in seconds (default: 30)')
    
    # Mutation mode
    mutation_group = parser.add_mutually_exclusive_group()
    mutation_group.add_argument('--smart', action='store_true',
                                help='Use smart mutation (trace-aware)')
    mutation_group.add_argument('--random', action='store_true',
                                help='Use random mutation (default)')
    
    # Recipe support (only with smart mutation)
    parser.add_argument('--recipe', default=None,
                        help='Recipe file for guided mutation (requires --smart)')
    
    args = parser.parse_args()
    
    # Validate arguments
    errors = validate_args(args)
    if errors:
        print("❌ Validation errors:")
        for error in errors:
            print(f"  - {error}")
        return 1
    
    # Check recipe without smart
    if args.recipe and not args.smart:
        print("⚠️  Warning: --recipe requires --smart, enabling smart mutation")
        args.smart = True
    
    # Print configuration
    print(f"\n{'=' * 60}")
    print(f"RR-Fuzz - Record-Replay Guided Fuzzing")
    print(f"{'=' * 60}")
    print(f"QEMU:       {args.qemu}")
    print(f"Target:     {args.target}")
    print(f"Trace:      {args.trace}")
    print(f"Output:     {args.output}")
    print(f"Mode:       {'Smart' if args.smart else 'Random'} Mutation")
    if args.recipe:
        print(f"Recipe:     {args.recipe}")
    if args.iterations:
        print(f"Max Iters:  {args.iterations}")
    if args.timeout:
        print(f"Max Time:   {args.timeout}s")
    print(f"{'=' * 60}\n")
    
    # Create mutator
    if args.smart:
        print("[Main] Creating SmartMutator...")
        mutator = SmartMutator(
            trace_file=args.trace,
            recipe_file=args.recipe
        )
    else:
        print("[Main] Creating BaseMutator...")
        mutator = BaseMutator()
    
    # Create FuzzingCore
    print("[Main] Creating FuzzingCore...")
    fuzzing_core = FuzzingCore(
        qemu_path=args.qemu,
        target_binary=args.target,
        initial_trace=args.trace,
        output_dir=args.output,
        mutator=mutator
    )
    _fuzzing_core = fuzzing_core
    
    # Run fuzzing
    try:
        print("\n[Main] Starting fuzzing campaign...\n")
        fuzzing_core.run(
            max_iterations=args.iterations,
            max_time=args.timeout
        )
        
        # Save final results
        print("\n[Main] Saving final results...")
        fuzzing_core.save_final_results()
        
        print("\n✅ Fuzzing completed successfully!")
        return 0
    
    except KeyboardInterrupt:
        print("\n[Main] Interrupted by user")
        fuzzing_core.save_final_results()
        return 130
    
    except Exception as e:
        print(f"\n❌ Error during fuzzing: {e}")
        import traceback
        traceback.print_exc()
        
        if fuzzing_core:
            fuzzing_core.save_final_results()
        
        return 1


if __name__ == '__main__':
    sys.exit(main())


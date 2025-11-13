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
from conductor.afl_enhanced_mutator import AFLEnhancedMutator


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
        errors.append(f"Timeout must be >= 1 minute")

    if args.crashes and args.crashes < 1:
        errors.append(f"Crash target must be >= 1")

    if args.paths and args.paths < 1:
        errors.append(f"Path target must be >= 1")

    if args.coverage_target and (args.coverage_target < 0 or args.coverage_target > 100):
        errors.append(f"Coverage target must be between 0.0 and 100.0")

    if args.no_progress_timeout and args.no_progress_timeout < 1:
        errors.append(f"No progress timeout must be >= 1 second")

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
    # 停止条件选项
    stop_group = parser.add_argument_group('Stop Conditions',
                                          'Various ways to limit fuzzing duration')
    stop_group.add_argument('--iterations', type=int, default=None,
                           help='Maximum iterations (default: unlimited)')
    stop_group.add_argument('--timeout', type=int, default=None,
                           help='Maximum time in minutes (default: unlimited)')
    stop_group.add_argument('--crashes', type=int, default=None,
                           help='Stop after finding N crashes (default: unlimited)')
    stop_group.add_argument('--paths', type=int, default=None,
                           help='Stop after finding N new paths (default: unlimited)')
    stop_group.add_argument('--coverage-target', type=float, default=None,
                           help='Stop when coverage reaches X%% (0.0-100.0)')
    stop_group.add_argument('--no-progress-timeout', type=int, default=None,
                           help='Stop if no new paths found for N seconds')
    stop_group.add_argument('--infinite', action='store_true',
                           help='Run indefinitely (ignore all limits except Ctrl+C)')

    parser.add_argument('--qemu-timeout', type=float, default=30.0,
                        help='QEMU execution timeout in seconds (default: 30)')
    
    # Mutation mode
    mutation_group = parser.add_mutually_exclusive_group()    # 互斥参数组，只能选择一个
    mutation_group.add_argument('--smart', action='store_true',
                                help='Use smart mutation (trace-aware)')
    mutation_group.add_argument('--afl-enhanced', action='store_true',
                                help='Use AFL-enhanced mutation (systematic + smart)')
    mutation_group.add_argument('--random', action='store_true',
                                help='Use random mutation (default)')
    
    # Recipe support (only with smart mutation)
    parser.add_argument('--recipe', default=None,
                        help='Recipe file for guided mutation (requires --smart or --afl-enhanced)')
    
    args = parser.parse_args()
    
    # Validate arguments
    errors = validate_args(args)
    if errors:
        print("❌ Validation errors:")
        for error in errors:
            print(f"  - {error}")
        return 1
    
    # Check recipe without smart or afl-enhanced
    if args.recipe and not (args.smart or args.afl_enhanced):
        print("⚠️  Warning: --recipe requires --smart or --afl-enhanced, enabling AFL-enhanced mutation")
        args.afl_enhanced = True
    
    # Print configuration
    print(f"\n{'=' * 60}")
    print(f"RR-Fuzz - Record-Replay Guided Fuzzing")
    print(f"{'=' * 60}")
    print(f"QEMU:       {args.qemu}")
    print(f"Target:     {args.target}")
    print(f"Trace:      {args.trace}")
    print(f"Output:     {args.output}")
    if args.afl_enhanced:
        mode_str = 'AFL-Enhanced'
    elif args.smart:
        mode_str = 'Smart'
    else:
        mode_str = 'Random'
    print(f"Mode:       {mode_str} Mutation")
    if args.recipe:
        print(f"Recipe:     {args.recipe}")

    # 停止条件显示
    print(f"\n📏 Stop Conditions:")
    if args.infinite:
        print(f"  Mode:       Infinite (until Ctrl+C)")
    else:
        print(f"  Mode:       Limited")
        if args.iterations:
            print(f"  Max Iters:  {args.iterations}")
        if args.timeout:
            print(f"  Max Time:   {args.timeout}分钟")
        if args.crashes:
            print(f"  Max Crashes: {args.crashes}")
        if args.paths:
            print(f"  Max Paths:  {args.paths}")
        if args.coverage_target:
            print(f"  Coverage:   {args.coverage_target}%")
        if args.no_progress_timeout:
            print(f"  Progress:   {args.no_progress_timeout}s timeout")
        if not any([args.iterations, args.timeout, args.crashes,
                   args.paths, args.coverage_target, args.no_progress_timeout]):
            print(f"  Mode:       Unlimited (until Ctrl+C)")

    print(f"{'=' * 60}\n")
    
    # Create mutator
    if args.afl_enhanced:
        print("[Main] Creating AFLEnhancedMutator...")
        mutator = AFLEnhancedMutator(
            trace_file=args.trace,
            recipe_file=args.recipe,
            target_binary=args.target
        )

    elif args.smart:
        print("[Main] Creating SmartMutator...")
        mutator = SmartMutator(
            trace_file=args.trace,
            recipe_file=args.recipe,
            target_binary=args.target  # 🔥 传递目标二进制给PathFinder
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

        # 构建停止条件字典 (时间转换为秒)
        timeout_seconds = None if args.infinite or not args.timeout else (args.timeout * 60)

        stop_conditions = {
            'max_iterations': None if args.infinite else args.iterations,
            'max_time': timeout_seconds,  # 分钟转为秒
            'max_crashes': None if args.infinite else args.crashes,
            'max_paths': None if args.infinite else args.paths,
            'coverage_target': None if args.infinite else args.coverage_target,
            'no_progress_timeout': None if args.infinite else args.no_progress_timeout,
            'infinite': args.infinite
        }

        fuzzing_core.run_advanced(stop_conditions)
        
        # Save final results
        print("\n[Main] Saving final results...")
        fuzzing_core.save_final_results()
        
        print("\n✅ Fuzzing completed successfully!")
        
        # Cleanup resources
        fuzzing_core.cleanup()
        
        return 0
    
    except KeyboardInterrupt:
        print("\n[Main] Interrupted by user")
        if fuzzing_core:
            fuzzing_core.save_final_results()
            fuzzing_core.cleanup()
        return 130
    
    except Exception as e:
        print(f"\n❌ Error during fuzzing: {e}")
        import traceback
        traceback.print_exc()
        
        if fuzzing_core:
            fuzzing_core.save_final_results()
            fuzzing_core.cleanup()
        
        return 1


if __name__ == '__main__':
    sys.exit(main())


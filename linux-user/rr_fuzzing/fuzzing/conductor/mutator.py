#!/usr/bin/env python3
"""
Mutator - Mutation Engine (Layer 2)

Provides basic and smart mutation capabilities:
- BaseMutator: Simple random mutation
- SmartMutator: Smart mutation based on trace analysis and recipe support
"""

import os
import json
import struct
import random
import sys
import time
from pathlib import Path
from typing import List, Optional

# Add analysis directory to path to import trace_analyzer
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "analysis"))

from .constants import (
    FUZZ_CMD_FLIP_BITS, FUZZ_CMD_LIGHT_MUTATION, FUZZ_CMD_INTERESTING_VALUES,
    FUZZ_CMD_BOUNDARY_VALUE, FUZZ_CMD_TRUNCATE, FUZZ_CMD_EXTEND,
    FUZZ_CMD_REPLACE_BUFFER, FUZZ_CMD_MUTATE_AUX_BUFFER, FUZZ_CMD_MUTATE_FLAGS,
    FUZZ_CMD_MUTATE_ARG, FUZZ_CMD_OVERWRITE_AT_OFFSET,
    INIT_SYSCALLS, INIT_PHASE_THRESHOLD, IMPORTANT_SYSCALLS,
    PRIMARY_IO_SYSCALLS, SECONDARY_IO_SYSCALLS, FORBIDDEN_MUTATION_SYSCALLS,
    FUZZ_MAX_INSTRUCTIONS
)
from .instruction import FuzzInstruction
from .io_mutator import IOReturnValueMutator
from .async_logger import alog
from .types import MutationRecipe


class BaseMutator:
    """
    Base Mutation Engine (Simple random mutation)
    
    Provides basic random mutations without trace analysis.
    Used as backup or for standalone fuzzing.
    
    Architecture: DETAILED_ARCHITECTURE.md lines 87-106
    """
    
    def __init__(self, use_io_mutation: bool = True):
        """Initialize BaseMutator

        Args:
            use_io_mutation: Whether to enable IO return value mutation (default True)
        """
        self.iteration_count = 0
        self.use_io_mutation = use_io_mutation
        self.io_mutator = IOReturnValueMutator() if use_io_mutation else None
        self.last_mutation_type = 'unknown'

        mode_str = "Random Mutation + IO Retval Mutation" if use_io_mutation else "Random Mutation Mode"
        alog(f"Initialized ({mode_str})", "MUTATOR", "INFO")
    
    def mutate(self, trace, fork_point: int = None) -> List[FuzzInstruction]:
        """
        Generate random mutation

        Args:
            trace: Trace object (may be None for BaseMutator)
            fork_point: Syscall index of fork point (for compatibility with SmartMutator)

        Returns:
            List of FuzzInstructions
        """
        self.iteration_count += 1

        # Strategy: 70% probability for IO return value mutation if trace is available
        if self.use_io_mutation and self.io_mutator and trace and random.random() < 0.7:
            self.last_mutation_type = 'io_mutation'
            instrs = self._generate_io_mutations(trace, fork_point)
            
            # Limit number of instructions to avoid pipe overflow
            if len(instrs) > FUZZ_MAX_INSTRUCTIONS:
                alog(f"IO mutation exceeded limit, truncating to {FUZZ_MAX_INSTRUCTIONS}", "MUTATOR", "WARN")
                instrs = instrs[:FUZZ_MAX_INSTRUCTIONS]
            return instrs

        # Baseline random mutation
        self.last_mutation_type = 'random'
        # Generate 1-3 random mutations
        num_mutations = random.randint(1, 3)
        instructions = []
        
        for i in range(num_mutations):
            if i == 0 and fork_point is not None:
                syscall_index = fork_point
                alog(f"Mutation targeting fork_point={fork_point}", "MUTATOR")
            else:
                # Random syscall index, ensuring >= fork_point (if specified)
                if fork_point is not None:
                    syscall_index = random.randint(fork_point, max(fork_point + 20, 99))
                else:
                    syscall_index = random.randint(0, 99)
                alog(f"Mutation {i+1} targeting random syscall_index={syscall_index}", "MUTATOR")
            
            # Mutation command selection
            mutation_types = [
                FUZZ_CMD_FLIP_BITS,
                FUZZ_CMD_INTERESTING_VALUES,
                FUZZ_CMD_BOUNDARY_VALUE,
                FUZZ_CMD_REPLACE_BUFFER,
                FUZZ_CMD_MUTATE_FLAGS,
                FUZZ_CMD_MUTATE_AUX_BUFFER,  # Aux Data Mutation
                FUZZ_CMD_TRUNCATE,
                FUZZ_CMD_EXTEND,
                FUZZ_CMD_LIGHT_MUTATION
            ]
            cmd = random.choice(mutation_types)

            # Generate random data + set mutation_type
            if cmd == FUZZ_CMD_FLIP_BITS:
                data = struct.pack('I', random.randint(1, 8))
                mut_type = 'bitflip'
            elif cmd == FUZZ_CMD_INTERESTING_VALUES:
                value = random.choice([0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF])
                data = struct.pack('Q', value & 0xFFFFFFFFFFFFFFFF)
                mut_type = 'interesting_value'
            elif cmd == FUZZ_CMD_BOUNDARY_VALUE:
                value = random.choice([0, -1, 0x7FFFFFFF, 0xFFFFFFFF])
                data = struct.pack('q', value)
                mut_type = 'boundary_value'
            elif cmd == FUZZ_CMD_REPLACE_BUFFER:
                size = random.choice([4, 8, 16, 32])
                data = bytes([random.randint(0, 255) for _ in range(size)])
                mut_type = 'replace_buffer'
            elif cmd == FUZZ_CMD_MUTATE_AUX_BUFFER:
                # Aux Data mutation: Generate attack pattern data
                attack_patterns = [
                    b'%s%s%s%p',           # Format string attack
                    b'A' * 64,             # Buffer overflow
                    b'../../../etc/passwd', # Path traversal
                    b'; cat /etc/passwd',  # Command injection
                    b'\x00' * 8,           # NULL injection
                ]
                data = random.choice(attack_patterns)
                mut_type = 'aux_buffer'
            elif cmd == FUZZ_CMD_TRUNCATE:
                # Truncate attack: Reduce data size
                truncate_size = random.choice([0, 1, 2, 4, 8])
                data = struct.pack('I', truncate_size)
                mut_type = 'truncate'
            elif cmd == FUZZ_CMD_EXTEND:
                # Extend attack: Increase data size to trigger overflow
                extend_size = random.choice([64, 128, 256, 512, 1024])
                data = struct.pack('I', extend_size)
                mut_type = 'extend'
            elif cmd == FUZZ_CMD_LIGHT_MUTATION:
                # Light mutation: Flip only 1-2 bits
                data = struct.pack('I', random.randint(1, 2))
                mut_type = 'light_mutation'
            else:  # MUTATE_FLAGS
                data = struct.pack('q', random.randint(0, 0xFFFFFFFF))
                mut_type = 'flags'

            instruction = FuzzInstruction(
                syscall_index=syscall_index,
                cmd=cmd,
                arg_index=1,
                data=data,
                mutation_type=mut_type 
            )
            instructions.append(instruction)

        # Limit verification
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            alog(f"Truncating instructions to {FUZZ_MAX_INSTRUCTIONS}", "MUTATOR", "WARN")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions  # This is the content for QEMU, wrapped as FuzzInstruction

    def _generate_io_mutations(self, trace, fork_point: int = None) -> List[FuzzInstruction]:
        """Generate IO return value mutation instructions

        Args:
            trace: Trace object
            fork_point: Fork point syscall index (optional)

        Returns:
            List of FuzzInstructions
        """
        alog(f"Attempting IO mutation, trace={trace}, fork_point={fork_point}", "MUTATOR")

        # Identify IO syscalls
        io_syscalls = self.io_mutator.identify_io_syscalls(trace)
        alog(f"Found {len(io_syscalls)} IO syscalls", "MUTATOR")

        if not io_syscalls:
            # No IO syscalls, fall back to random mutation
            alog("No IO syscalls found, falling back to random mutation", "MUTATOR", "INFO")
            return self._generate_random_mutations(trace, fork_point)

        # Prioritize IO syscall at fork_point (if specified)
        target_io = None
        if fork_point is not None:
            for io in io_syscalls:
                if io['index'] == fork_point:
                    target_io = io
                    break

        # If no IO syscall found at fork_point, choose one randomly
        if target_io is None:
            target_io = random.choice(io_syscalls)

        # Generate mutation for this IO syscall
        mutations = self.io_mutator.generate_mutations_for_io(
            target_io,
            strategy='buffer_overflow' if target_io['is_input'] else 'boundary'
        )

        # Priority sorting
        mutations = self.io_mutator.prioritize_mutations(mutations)

        # Increase mutation density to test a wider range of values
        num_mutations = random.randint(3, 6)
        selected_mutations = mutations[:num_mutations]

        # Convert to FuzzInstruction
        instructions = []
        for m in selected_mutations:
            # 1. Return value mutation
            data = struct.pack('Q', m.new_return_value)  # New return value

            instruction = FuzzInstruction(
                syscall_index=m.syscall_index,
                cmd=FUZZ_CMD_MUTATE_ARG,  # Temporary use, can define specialized IO_RETURN command later
                arg_index=0xFF,  # Special marker: 0xFF indicates changing return value
                data=data,
                mutation_type='io_return_value'
            )
            instructions.append(instruction)

            alog(f"IO Mutation (retval): {m.description}", "MUTATOR")

            # 2. If buffer_content exists, also generate REPLACE_BUFFER instruction
            if m.buffer_content:
                # Get buffer argument index (read's second argument is buffer pointer)
                buf_arg_index = 1
                
                # Chance to use attack patterns instead of IOMutator content
                content_to_use = m.buffer_content
                if random.random() < 0.3:
                     patterns = [
                        b'%s%s%s%s', b'A' * 64, b'../../../etc/passwd', 
                        b'; cat /etc/passwd', b'\x00' * 8, 
                        b'CRASH_ME', b'CRASH_ME\n', 
                        b'CRASH_ME\x00', b'CRASH_ME\n\x00'
                     ]
                     content_to_use = random.choice(patterns)

                buffer_instruction = FuzzInstruction(
                    syscall_index=m.syscall_index,
                    cmd=FUZZ_CMD_REPLACE_BUFFER,
                    arg_index=buf_arg_index,
                    data=content_to_use[:min(len(content_to_use), 256)]
                )
                instructions.append(buffer_instruction)
                alog(f"IO Mutation (buffer): Fill {len(content_to_use)} bytes", "MUTATOR")



        # Verify instruction count does not exceed limit
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            alog(f"IO mutation generated {len(instructions)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}", "MUTATOR", "WARN")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions

    def _generate_random_mutations(self, trace, fork_point: int = None) -> List[FuzzInstruction]:
        """Generate traditional random mutations (helper method)"""
        # This is the original implementation of the mutate method, extracted as a standalone method
        num_mutations = random.randint(1, 3)
        instructions = []

        for i in range(num_mutations):
            if i == 0 and fork_point is not None:
                syscall_index = fork_point
            else:
                if fork_point is not None:
                    syscall_index = random.randint(fork_point, max(fork_point + 20, 99))
                else:
                    syscall_index = random.randint(0, 99)

            # Aux Data mutation commands (consistent with mutate method)
            mutation_types = [
                FUZZ_CMD_FLIP_BITS,
                FUZZ_CMD_INTERESTING_VALUES,
                FUZZ_CMD_BOUNDARY_VALUE,
                FUZZ_CMD_REPLACE_BUFFER,
                FUZZ_CMD_MUTATE_FLAGS,
                FUZZ_CMD_MUTATE_AUX_BUFFER,
                FUZZ_CMD_TRUNCATE,
                FUZZ_CMD_EXTEND,
                FUZZ_CMD_LIGHT_MUTATION
            ]
            cmd = random.choice(mutation_types)

            if cmd == FUZZ_CMD_FLIP_BITS:
                data = struct.pack('I', random.randint(1, 8))
                mut_type = 'bitflip'
            elif cmd == FUZZ_CMD_INTERESTING_VALUES:
                value = random.choice([0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF])
                data = struct.pack('Q', value & 0xFFFFFFFFFFFFFFFF)
                mut_type = 'interesting_value'
            elif cmd == FUZZ_CMD_BOUNDARY_VALUE:
                value = random.choice([0, -1, 0x7FFFFFFF, 0xFFFFFFFF])
                data = struct.pack('q', value)
                mut_type = 'boundary_value'
            elif cmd == FUZZ_CMD_REPLACE_BUFFER:
                # Use attack patterns for buffer replacement too, or random
                if random.random() < 0.5:
                     # Use attack patterns (defined below, we need to move definition up or duplicate)
                     patterns = [
                        b'%s%s%s%s', b'A' * 64, b'../../../etc/passwd', 
                        b'; cat /etc/passwd', b'\x00' * 8, 
                        b'CRASH_ME', b'CRASH_ME\n'
                     ]
                     data = random.choice(patterns)
                else:
                     size = random.choice([4, 8, 16, 32])
                     data = bytes([random.randint(0, 255) for _ in range(size)])
                mut_type = 'replace_buffer'
            elif cmd == FUZZ_CMD_MUTATE_AUX_BUFFER:
                # Aux Data mutation: Generate attack pattern data
                attack_patterns = [
                    b'%s%s%s%p',           # Format string attack
                    b'A' * 64,             # Buffer overflow
                    b'../../../etc/passwd', # Path traversal
                    b'; cat /etc/passwd',  # Command injection
                    b'\x00' * 8,           # NULL injection
                    b'CRASH_ME',           # Explicit target trigger
                    b'CRASH_ME\n',         # Explicit target trigger (newline)
                    b'CRASH_ME\x00',       # Explicit target trigger (null-terminated)
                    b'CRASH_ME\n\x00',     # Explicit target trigger (newline + null)
                ]
                data = random.choice(attack_patterns)
                mut_type = 'aux_buffer'
            elif cmd == FUZZ_CMD_TRUNCATE:
                truncate_size = random.choice([0, 1, 2, 4, 8])
                data = struct.pack('I', truncate_size)
                mut_type = 'truncate'
            elif cmd == FUZZ_CMD_EXTEND:
                extend_size = random.choice([64, 128, 256, 512, 1024])
                data = struct.pack('I', extend_size)
                mut_type = 'extend'
            elif cmd == FUZZ_CMD_LIGHT_MUTATION:
                data = struct.pack('I', random.randint(1, 2))
                mut_type = 'light_mutation'
            else:  # MUTATE_FLAGS
                data = struct.pack('q', random.randint(0, 0xFFFFFFFF))
                mut_type = 'flags'

            instruction = FuzzInstruction(
                syscall_index=syscall_index,
                cmd=cmd,
                arg_index=1,
                data=data,
                mutation_type=mut_type 
            )
            instructions.append(instruction)

        # Verify instruction count does not exceed limit
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            alog(f"Random mutation generated {len(instructions)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}", "MUTATOR", "WARN")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions


class SmartMutator:
    """
    Smart Mutator
    
    Analyzes trace files, filters mutable syscalls, and uses multiple strategies
    to generate smart mutation instructions.
    """
    
    # Class-level cache to avoid redundant parsing of same trace
    _trace_cache = {}  # {trace_file: TraceAnalyzer}
    
    def __init__(self, trace_file, recipe_file=None, target_binary=None, path_finder=None):
        """
        Initialize SmartMutator

        Args:
            trace_file: Path to trace file
            recipe_file: Path to recipe file (optional, Phase 2)
            target_binary: Path to target binary (for PathFinder CFG analysis)
            path_finder: Existing PathFinder instance (optional, avoids re-initialization)
        """
        # Use cached TraceAnalyzer if available
        if trace_file in SmartMutator._trace_cache:
            alog(f"Using cached analysis results: {trace_file}", "MUTATOR", "DEBUG")
            self.analyzer = SmartMutator._trace_cache[trace_file]
        else:
            # Analyze using repaired TraceAnalyzer
            alog(f"Analyzing trace file: {trace_file}", "MUTATOR", "INFO")
            
            # Import TraceAnalyzer
            from trace_analyzer import TraceAnalyzer
            
            # TraceAnalyzer calls analyze() automatically in __init__
            self.analyzer = TraceAnalyzer(trace_file)
            
            # Cache for future use
            SmartMutator._trace_cache[trace_file] = self.analyzer
        
        # Get all pure replay syscalls (those with aux_data)
        pure_syscalls = self.analyzer.get_pure_syscalls()
        
        # Save all syscalls for later use
        self.syscalls = self.analyzer.syscalls
        
        # Convert to Candidate objects (with full metadata)
        self.pure_candidates = [sc for sc in pure_syscalls]
        
        # Get hybrid replay syscalls (without aux_data)
        hybrid_syscalls = self.analyzer.get_hybrid_syscalls()
        self.hybrid_candidates = [sc for sc in hybrid_syscalls]
        
        # FD tracking and environment filtering
        self._perform_fd_tracking()
        
        # These can be removed later
        # These can be removed later
        alog(f"Found {len(self.pure_candidates)} pure replay syscalls:", "MUTATOR", "DEBUG")
        for cand in self.pure_candidates[:10]:  # Only print first 10
            alog(f"  index={cand.index}, name={cand.name}, nr={cand.syscall_nr}", "MUTATOR", "DEBUG")
        if len(self.pure_candidates) > 10:
            alog(f"  ... and {len(self.pure_candidates) - 10} more", "MUTATOR", "DEBUG")
        
        # Lazy filtering, wait for PathFinder ready
        self.mutable_candidates = []
        
        # PathFinder & Recipe drive mode
        self.recipes = []
        self.recipe_mode = False
        self.path_finder = None
        self.target_binary = target_binary

        # PathFinder integration (automatic recipe generation)
        if path_finder:
            self.path_finder = path_finder
            alog(f"Using external PathFinder instance", "MUTATOR", "INFO")
        elif target_binary:
            self._init_pathfinder(trace_file, target_binary)
        else:
            self.path_finder = None

        # Manual recipe file loading
        if recipe_file and os.path.exists(recipe_file):
            self._load_recipes(recipe_file)
            self.recipe_mode = True
            alog(f"Recipe-driven mode enabled (Manual: {len(self.recipes)} recipes)", "MUTATOR", "INFO")

        # Attempt to auto-generate recipes from PathFinder
        auto_recipes = self._generate_automatic_recipes()
        if auto_recipes:
            self.recipes.extend(auto_recipes)
        if auto_recipes:
            self.recipes.extend(auto_recipes)
            alog(f"Automatically generated {len(auto_recipes)} recipes (Total: {len(self.recipes)})", "MUTATOR", "INFO")

        if len(self.recipes) > 0:
            self.recipe_mode = True
        if len(self.recipes) > 0:
            self.recipe_mode = True
            alog(f"Recipe-driven mode enabled (Total: {len(self.recipes)} recipes)", "MUTATOR", "INFO")
        else:
            alog(f"Random mutation mode (No recipes provided or generated)", "MUTATOR", "WARN")
        
        # Now PathFinder initialized, perform candidate filtering
        self.mutable_candidates = self._filter_mutable_candidates()
        
        # Stagnation Detection parameters
        self.last_new_coverage_iter = 0
        self.stagnation_threshold = 1000 
        self.is_stagnant = False 
        self.total_iterations = 0 
        self.last_mutation_type = 'unknown'
        alog(f"Stagnation detection enabled (threshold={self.stagnation_threshold} iterations)", "MUTATOR", "INFO")
    
    def _perform_fd_tracking(self):
        """
        Track File Descriptor (FD) open and close.
        Identifies system-level FDs such as library files and marks corresponding syscall indexes as disabled.
        """
        active_forbidden_fds = set()
        self.syscall_forbidden_map = {} # index -> bool
        
        for sc in self.syscalls:
            # 1. Check if current syscall uses a marked forbidden FD
            is_forbidden = False
            if sc.uses_fd and sc.args:
                fd = sc.args[0]
                if fd in active_forbidden_fds:
                    is_forbidden = True
            
            self.syscall_forbidden_map[sc.index] = is_forbidden
            
            # 2. Track FD open and update status
            if sc.creates_fd and sc.created_fd > 2:
                filename = "unknown"
                if sc.name in ['open', 'openat']:
                    idx = 1 if sc.name == 'openat' else 0
                    if idx in sc.arg_data:
                        try:
                            filename = sc.arg_data[idx].split(b'\x00')[0].decode('utf-8', errors='ignore')
                        except:
                            filename = str(sc.arg_data[idx])
                
                # If it's a system library, or early unknown filename at init phase, add to forbidden set
                is_library = "/lib/" in filename or "/usr/lib/" in filename or "ld.so.cache" in filename
                is_early_unknown = (sc.index < 30 and filename == "unknown")
                
                if is_library or is_early_unknown:
                    active_forbidden_fds.add(sc.created_fd)
                    reason = "library" if is_library else "early_init"
                    alog(f"FD {sc.created_fd} (index={sc.index}) marked FORBIDDEN ({reason}): {filename}", "MUTATOR")
                else:
                    # If FD is reused for regular files, remove from forbidden set
                    if sc.created_fd in active_forbidden_fds:
                        active_forbidden_fds.discard(sc.created_fd)
                        alog(f"FD {sc.created_fd} (index={sc.index}) UNMARKED (reused): {filename}", "MUTATOR")
            
            # 3. Track FD close
            if sc.name == 'close' and sc.args:
                fd = sc.args[0]
                if fd in active_forbidden_fds:
                    active_forbidden_fds.discard(fd)
        
        forbidden_count = sum(1 for v in self.syscall_forbidden_map.values() if v)
        if forbidden_count > 0:
            alog(f"Environment Filtering: {forbidden_count} system library IO calls protected", "MUTATOR", "INFO")
    
    def _should_skip_mutation(self, syscall_info, index):
        """
        Determine if mutation for this syscall should be skipped
        
        Args:
            syscall_info: Syscall info object
            index: Index position in trace
        
        Returns:
            bool: True to skip, False to allow mutation
        """
        # Core protection
        # 1. General startup phase protection: First 40 syscalls usually ld.so and libc init
        # Remove hardcoded index < 40 check, use PathFinder smart filtering instead
        # if index < 40:
        #    alog(f"Startup Protection: Skip early init syscall (index={index})", "MUTATOR", "DEBUG")
        #    return True
            
        syscall_name = getattr(syscall_info, 'name', '').lower()
        
        # 2. Identified Forbidden FD protection
        if self.syscall_forbidden_map.get(index, False):
            alog(f"Skip Forbidden IO: {syscall_name} (index={index})", "MUTATOR", "DEBUG")
            return True
        
        # Important IO syscalls never skip (already FD/Startup filtered)
        if syscall_name in IMPORTANT_SYSCALLS:
            return False  # Never skip
        
        # Skip key syscalls during initialization phase (using dynamic threshold)
        # Note: dynamic_threshold will be set by Conductor during first fuzzing
        threshold = getattr(self, 'dynamic_threshold', INIT_PHASE_THRESHOLD)
        if index < threshold:
            if any(init_sc in syscall_name for init_sc in INIT_SYSCALLS):
                alog(f"Skip init syscall: {syscall_name} (index={index}, threshold={threshold})", "MUTATOR", "DEBUG")
                return True
        
        # 1. PathFinder enhanced filtering:
        # If PathFinder available, check if syscall is reachable by target code segment
        if self.path_finder and hasattr(self.path_finder, 'bb_to_syscall'):
            # Check if any target BB maps to this syscall
            is_target_reachable = False
            for bb_addr, sc_idx in self.path_finder.bb_to_syscall.items():
                if sc_idx == index:
                    is_target_reachable = True
                    break
            
            if not is_target_reachable:
                # If syscall is in trace but never called/covered by BB in target range,
                # it's likely called by early loader or libc init code.
                alog(f"PathFinder Filter: Skip non-target syscall (index={index}, {syscall_name})", "MUTATOR", "DEBUG")
                return True
        
        return False
    
    def _filter_mutable_candidates(self):
        """
        Filter mutable candidates with hierarchical prioritization.

        Principles:
        1. Exclude high-risk syscalls (FORBIDDEN_MUTATION_SYSCALLS)
        2. Retain safe syscalls beyond just IO
        3. Priority levels: Important > Primary IO > Secondary IO > Others

        Returns:
            list: List of safe mutable syscall candidates
        """
        important = []   # Important syscalls (must mutate)
        primary_io = []  # Primary IO syscalls
        secondary_io = [] # Secondary IO syscalls
        others = []      # Other safe syscalls

        all_candidates = list(self.pure_candidates) + list(self.hybrid_candidates)

        alog(f"Filtering {len(all_candidates)} candidates (Enhanced mode)...", "MUTATOR", "INFO")

        for candidate in all_candidates:
            syscall_name = candidate.name

            # 1. Skip forbidden syscalls (memory management, signals, process control)
            if syscall_name in FORBIDDEN_MUTATION_SYSCALLS:
                continue

            # 2. Skip key syscalls in initialization phase
            if self._should_skip_mutation(candidate, candidate.index):
                continue

            # 3. New Strategy: Sort by priority, but retain all safe syscalls
            if syscall_name in IMPORTANT_SYSCALLS:
                important.append(candidate)
            elif syscall_name in PRIMARY_IO_SYSCALLS:
                primary_io.append(candidate)
            elif syscall_name in SECONDARY_IO_SYSCALLS:
                secondary_io.append(candidate)
            else:
                # Key Improvement: Retain other syscalls (previously discarded)
                others.append(candidate)

        # Final consolidation of mutable candidates
        mutable = important + primary_io + secondary_io + others

        alog(f"Mutable syscall candidates: {len(mutable)}", "MUTATOR", "INFO")
        if not mutable:
            alog(f"WARNING: No candidates found for mutation!", "MUTATOR", "WARN")

        return mutable

    def _init_pathfinder(self, trace_file, target_binary):
        """
        Initialize PathFinder for CFG analysis
        """
        try:
            # Import PathFinder
            import sys
            from pathlib import Path

            # Add conductor directory to path
            conductor_dir = Path(__file__).parent
            if str(conductor_dir) not in sys.path:
                sys.path.insert(0, str(conductor_dir))

            # Import DualLevelPathFinder
            from .dual_level_path_finder import DualLevelPathFinder as PathFinder
            # Config is part of DB or params, maybe unnecessary or can use dummy
            # DualLevel uses different config, let's omit Config class import as it's not strictly needed if we pass dict or it handles it.
            # actually DualLevelPathFinder constructor signature might be different. 
            # Original: PathFinder(binary, config)
            # DualLevel: DualLevelPathFinder(binary, config_dict/obj)


            # Create config (conservative settings)
            config = {
                "verbose": False,
                "timeout": 30,  # 30s timeout
                "max_cfg_nodes": 5000,  # Limit nodes
                "graceful_disable": True,  # Disable on error instead of exception
                "enable_auto_fast_mode": True  # Auto simplify mode
            }

            # Initialize PathFinder
            self.path_finder = PathFinder(target_binary, config)
            alog(f"PathFinder initialized", "MUTATOR", "INFO")

            # Build dynamic CFG from trace
            if self.path_finder.build_from_trace(trace_file):
                alog(f"PathFinder dynamic CFG built", "MUTATOR", "INFO")
            else:
                alog(f"PathFinder dynamic CFG build failed", "MUTATOR", "WARN")

        except Exception as e:
            alog(f"PathFinder initialization failed: {e}", "MUTATOR", "ERROR")
            self.path_finder = None

    def _generate_automatic_recipes(self):
        """
        Auto-generate recipes from PathFinder
        """
        if not self.path_finder or not self.path_finder.is_available():
            return []

        try:
            # Analyze uncovered branches (simplified version, based on dynamic CFG)
            uncovered_branches = self._find_uncovered_branches()
            if not uncovered_branches:
                alog(f"PathFinder found no uncovered branches", "MUTATOR", "INFO")
                return []

            alog(f"PathFinder found {len(uncovered_branches)} uncovered branches", "MUTATOR", "INFO")

            # Generate recipes (now list of MutationRecipe objects)
            recipes = self.path_finder.generate_recipes(uncovered_branches, max_recipes=10)

            # Convert to compatible dictionary format (until we fully migrate RecipePool)
            auto_recipes = []
            for i, recipe in enumerate(recipes):
                if isinstance(recipe, MutationRecipe):
                    r_dict = recipe.to_dict()
                else:
                    r_dict = recipe

                # Ensure id field
                if 'id' not in r_dict or not r_dict['id']:
                    r_dict['id'] = f"pathfinder_auto_{i}_{int(time.time())}"
                
                auto_recipes.append(r_dict)

            return auto_recipes

        except Exception as e:
            alog(f"PathFinder recipe generation failed: {e}", "MUTATOR", "ERROR")
            return []

    def _find_uncovered_branches(self):
        """
        Find uncovered branches based on dynamic CFG (simplified implementation)
        """
        if not self.path_finder or not hasattr(self.path_finder, 'dynamic_edges'):
            # For DualLevelPathFinder, we generate branches based on coverage at runtime
            return []

        uncovered = []

        # Simplified logic: Iterate through all dynamic nodes, looking for nodes with single outgoing edge
        # These nodes might have unexplored branches
        for node_id, edges in self.path_finder.dynamic_edges.items():
            if len(edges) == 1:  # Only one outgoing edge, likely another branch unexplored
                edge = list(edges)[0]
                # Construct hypothetical uncovered branch
                uncovered_branch = {
                    'from': self.path_finder.dynamic_nodes.get(node_id, node_id),
                    'to': self.path_finder.dynamic_nodes.get(edge, edge),
                    'type': 'conditional',
                    'has_syscall': node_id in self.path_finder.dynamic_syscalls,
                    'distance': 1  # Simplified distance calculation
                }

                # If node has syscall info, add it to branch info
                if node_id in self.path_finder.dynamic_syscalls:
                    uncovered_branch['syscalls'] = self.path_finder.dynamic_syscalls[node_id]

                uncovered.append(uncovered_branch)

        # Limit quantity to avoid generating too many recipes
        return uncovered[:15]

    def _load_recipes(self, recipe_file):
        """
        Load recipe from JSON file
        
        Args:
            recipe_file: Path to recipe file (recipes.json)
        """
        try:
            with open(recipe_file, 'r') as f:
                data = json.load(f)
            
            self.recipes = data.get('recipes', [])
            alog(f"Loaded {len(self.recipes)} recipes from {recipe_file}", "MUTATOR", "INFO")
            
            # Print first few recipes (debug)
            for i, recipe in enumerate(self.recipes[:5]):
                alog(f"  Recipe {i}: {recipe['source_branch']} -> {recipe['target_branch']}, "
                      f"syscall_idx={recipe['syscall_index']}, type={recipe['mutation_type']}", "MUTATOR", "DEBUG")
            
        except Exception as e:
            alog(f"Failed to load recipes: {e}", "MUTATOR", "ERROR")
            self.recipes = []
    
    def _recipe_to_instruction(self, recipe):
        """
        Convert recipe to FuzzInstruction
        
        Args:
            recipe: Recipe dictionary (from recipes.json)
        
        Returns:
            FuzzInstruction or None
        """
        try:
            syscall_index = recipe['syscall_index']
            mutation_type = recipe['mutation_type']
            offset = recipe.get('offset', 0)
            size = recipe.get('size', 4)
            data_template = recipe.get('data_template', 'RANDOM')
            
            # Generate actual data based on data_template
            if data_template == 'RANDOM':
                mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            elif data_template == 'ZERO':
                mutation_data = b'\x00' * size
            elif data_template == 'FF':
                mutation_data = b'\xFF' * size
            elif data_template.startswith('ASCII:'):
                ascii_data = data_template.split(':', 1)[1]
                mutation_data = ascii_data.encode('utf-8')
                size = len(mutation_data)
            elif data_template.startswith('0x'):
                # Hex value
                val = int(data_template, 16)
                mutation_data = struct.pack('Q', val)[:size]
            else:
                # Default random
                mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            
            # Select command based on mutation_type
            if mutation_type == 'buffer_overwrite':
                # Exact buffer overwrite at specified offset
                instr = FuzzInstruction(
                    syscall_index, 
                    FUZZ_CMD_OVERWRITE_AT_OFFSET, 
                    recipe.get('arg_index', 1), 
                    mutation_data,
                    offset=offset,
                    size=size
                )
                return instr
            elif mutation_type == 'value_change':
                return FuzzInstruction(syscall_index, FUZZ_CMD_MUTATE_ARG, 0, mutation_data, 0, size)
            elif mutation_type == 'size_modify':
                return FuzzInstruction(syscall_index, FUZZ_CMD_BOUNDARY_VALUE, 0, mutation_data, 0, size)
            else:
                # Default to buffer replacement
                return FuzzInstruction(syscall_index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data, 0, size)
                
        except Exception as e:
            print(f"[Mutator] Failed to convert recipe to instruction: {e}")
            return None
    
    def _build_from_recipes(self, iteration):
        """
        Generate Fuzz instructions from recipe

        Args:
            iteration: Current iteration count

        Returns:
            list: List of FuzzInstructions
        """
        instrs = []
        
        # Select recipe (cyclic use)
        recipe_idx = iteration % len(self.recipes)
        recipe = self.recipes[recipe_idx]
        
        # Record recipe used (for feedback)
        self.last_recipe_used = recipe
        
        print(f"[Mutator] Using recipe {recipe_idx}/{len(self.recipes)}: "
              f"{recipe['source_branch']} -> {recipe['target_branch']}")
        
        # Convert to instruction
        instr = self._recipe_to_instruction(recipe)
        if instr:
            instrs.append(instr)
            print(f"[Mutator]   Generated instruction: syscall_idx={recipe['syscall_index']}, "
                  f"cmd={recipe['mutation_type']}")
        
        return instrs
    
    def update_stagnation_status(self, iteration: int, has_new_coverage: bool):
        """
        Update stagnation detection status

        Args:
            iteration: Current iteration count
            has_new_coverage: Whether new coverage was found in this iteration
        """
        self.total_iterations = iteration
        
        if has_new_coverage:
            # New coverage found, reset stagnation count
            self.last_new_coverage_iter = iteration
            was_stagnant = self.is_stagnant
            self.is_stagnant = False
            
            if was_stagnant:
                print(f"[Mutator] Recovered from stagnation at iteration {iteration}!")
        else:
            # Check for stagnation
            stagnation_duration = iteration - self.last_new_coverage_iter
            
            if stagnation_duration >= self.stagnation_threshold:
                if not self.is_stagnant:
                    self.is_stagnant = True
                    print(f"[Mutator] Stagnation detected at iteration {iteration}!")
                    print(f"[Mutator] Switching to aggressive mutation mode...")
    
    def _select_strategy(self):
        """
        Choose mutation strategy with balanced probability
        
        New design principles:
        1. Balance discovery capability for various vulnerability types
        2. Avoid excessive bias towards a single vulnerability type
        3. Support diversified mutation patterns
        
        Returns:
            int: Strategy type (0-10)
        """
        if self.is_stagnant:
            # Stagnation mode: Aggressive strategy distribution
            strategy_weights = [
                8,   # 0: FLIP_BITS
                15,  # 1: INTERESTING_VALUES
                12,  # 2: TRUNCATE
                20,  # 3: EXTEND
                5,   # 4: LIGHT_MUTATION
                10,  # 5: MUTATE_AUX_BUFFER
                8,   # 6: REPLACE_BUFFER (small)
                12,  # 7: REPLACE_BUFFER (large)
                12,  # 8: BOUNDARY_VALUE
                10,  # 9: MUTATE_FLAGS
                8,   # 10: OVERWRITE_AT_OFFSET
            ]
        else:
            # Regular mode: Balanced strategy distribution
            strategy_weights = [
                12,  # 0: FLIP_BITS
                12,  # 1: INTERESTING_VALUES
                10,  # 2: TRUNCATE
                14,  # 3: EXTEND
                8,   # 4: LIGHT_MUTATION
                9,   # 5: MUTATE_AUX_BUFFER
                9,   # 6: REPLACE_BUFFER (small)
                10,  # 7: REPLACE_BUFFER (large)
                10,  # 8: BOUNDARY_VALUE
                9,   # 9: MUTATE_FLAGS
                7,   # 10: OVERWRITE_AT_OFFSET
            ]

        return random.choices(range(11), weights=strategy_weights)[0]
    
    def _generate_advanced_instruction(self, target_candidate, strategy_type, iteration):
        """
        Generate advanced mutation instruction (fully utilize 11 C-side mutation commands)

        Args:
            target_candidate: Target syscall candidate
            strategy_type: Strategy type (0-10)
            iteration: Iteration count

        Returns:
            FuzzInstruction: Generated mutation instruction
        """
        index = target_candidate.index
        
        # Select mutation command based on strategy type
        if strategy_type == 0:
            # FLIP_BITS - Bit flip (lightweight, keep most data unchanged)
            num_flips = random.randint(1, 8)  # Flip 1-8 bits
            data = struct.pack('I', num_flips)
            print(f"[Mutator]   Target: index={index}, name={target_candidate.name}, cmd=FLIP_BITS({num_flips} bits)")
            return FuzzInstruction(index, FUZZ_CMD_FLIP_BITS, 1, data)
        
        elif strategy_type == 1:
            # INTERESTING_VALUES - Smart special value injection (chosen based on syscall type)
            syscall_name = target_candidate.name.lower()

            if 'read' in syscall_name or 'recv' in syscall_name:
                # Input syscall: Use various attack patterns
                pattern_type = random.randint(0, 7)  # 8 modes (matches C-side switch)
                data = struct.pack('B', pattern_type)
                print(f"[Mutator]   Target: index={index}, name={target_candidate.name}, cmd=INTERESTING_VALUES(vuln_pattern={pattern_type})")
            else:
                # Other syscalls: Use traditional boundary values
                boundary_values = [
                    0, 1, -1,                           # Basic boundaries
                    0x7F, 0x80, 0xFF,                   # 8-bit boundaries
                    0x7FFF, 0x8000, 0xFFFF,             # 16-bit boundaries
                    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, # 32-bit boundaries
                    0x100, 0x400, 0x1000,               # Page size related
                ]
                value = random.choice(boundary_values)
                data = struct.pack('Q', value & 0xFFFFFFFFFFFFFFFF)
                print(f"[Mutator]   Target: index={index}, name={target_candidate.name}, cmd=INTERESTING_VALUES(0x{value:x})")
            return FuzzInstruction(index, FUZZ_CMD_INTERESTING_VALUES, 1, data)
        
        elif strategy_type == 2:
            truncate_to = random.randint(0, 8)
            data = struct.pack('I', truncate_to)
            return FuzzInstruction(index, FUZZ_CMD_TRUNCATE, 1, data)
        
        elif strategy_type == 3:
            # EXTEND - Increase data size to trigger buffer overflows
            if self.is_stagnant or iteration % 10 == 0:
                extend_by = random.choice([64, 128, 256, 512, 1024])
            else:
                extend_by = random.choice([1, 4, 16, 32, 64, 128])
            mutation_data = struct.pack('I', extend_by)
            return FuzzInstruction(index, FUZZ_CMD_EXTEND, 1, mutation_data)
        
        elif strategy_type == 4:
            num_flips = random.randint(1, 2)
            data = struct.pack('I', num_flips)
            return FuzzInstruction(index, FUZZ_CMD_LIGHT_MUTATION, 1, data)
        
        elif strategy_type == 5:
            # MUTATE_AUX_BUFFER - Mutate auxiliary buffer
            # Randomly modify a few bytes in the buffer
            num_changes = random.randint(1, 4)
            data = struct.pack('I', num_changes)
            print(f"[Mutator]   Target: index={index}, name={target_candidate.name}, cmd=MUTATE_AUX_BUFFER({num_changes} bytes)")
            return FuzzInstruction(index, FUZZ_CMD_MUTATE_AUX_BUFFER, 1, data)
        
        elif strategy_type == 6:
            # REPLACE_BUFFER - Completely replace buffer (small data)
            size = random.choice([4, 8, 16, 32])
            data = bytes([random.randint(0, 255) for _ in range(size)])
            print(f"[Mutator]   Target: index={index}, name={target_candidate.name}, cmd=REPLACE_BUFFER({size} bytes)")
            return FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, data)
        
        elif strategy_type == 7:
            # REPLACE_BUFFER - Large buffer replacement for overflow testing
            if self.is_stagnant or iteration % 15 == 0:
                size = random.choice([128, 256, 512, 1024])
                pattern = random.choice([b'A', b'B', b'X', b'\x41'])
                mutation_data = pattern * size
            else:
                size = random.choice([64, 128, 256])
                mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            print(f"[Mutator]   Target: index={index}, name={target_candidate.name}, cmd=REPLACE_BUFFER({size} bytes, large)")
            return FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data)
        
        elif strategy_type == 9:
            # Vulnerability pattern injection
            vuln_patterns = {
                'format_string': [
                    b'%s%s%s%s%n',           
                    b'%x%x%x%x%x%x',         
                    b'%p%p%p%p',             
                    b'%08x.%08x.%08x',       
                ],
                'injection': [
                    b"'; DROP TABLE users;--",  
                    b"' OR '1'='1",            
                    b"$(id)",                  
                    b"`whoami`",               
                    b"|cat /etc/passwd",       
                ],
                'path_traversal': [
                    b'/../../../etc/passwd',    
                    b'..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',  
                    b'/proc/self/environ',      
                    b'/dev/urandom',            
                ],
                'overflow_patterns': [
                    b'A' * 256,                 
                    b'\x41' * 512 + b'\x42\x43\x44\x45',  
                    b'%n' * 100,                
                ],
                'special_chars': [
                    b'\x00' * 32,               
                    b'\xFF' * 32,               
                    b'\x0A\x0D' * 16,          
                    b'\x80\x81\x82\x83',       
                ],
                'unicode_attacks': [
                    b'\xC0\xAE\xC0\xAE\x2f',  
                    b'\xEF\xBB\xBF',          
                    b'\x00\x41\x00\x42',      
                ],
                'race_condition': [
                    b'AAAAAAAAAAAAAAAA',        
                    b'1234567890' * 10,        
                    b'test\x00test\x00',       
                ]
            }

            syscall_name = target_candidate.name.lower()
            if 'read' in syscall_name or 'recv' in syscall_name:
                pattern_type = random.choice(['format_string', 'injection', 'overflow_patterns', 'special_chars'])
            elif 'write' in syscall_name or 'send' in syscall_name:
                pattern_type = random.choice(['format_string', 'special_chars', 'unicode_attacks'])
            elif 'open' in syscall_name:
                pattern_type = random.choice(['path_traversal', 'special_chars'])
            else:
                pattern_type = random.choice(['overflow_patterns', 'special_chars', 'race_condition'])

            mutation_data = random.choice(vuln_patterns[pattern_type])
            return FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data)
        
        else:
            # MUTATE_FLAGS - Flag mutation
            if random.random() < 0.7:
                # Single bit flip
                data = struct.pack('B', 1)
                print(f"[Mutator]   Target: index={index}, name={target_candidate.name}, cmd=MUTATE_FLAGS(single bit)")
            else:
                # Multi bit flip
                data = struct.pack('B', 4)
                print(f"[Mutator]   Target: index={index}, name={target_candidate.name}, cmd=MUTATE_FLAGS(multi bits)")
            return FuzzInstruction(index, FUZZ_CMD_MUTATE_FLAGS, 0, data)
    
    def mutate(self, trace, fork_point: int = None) -> List['FuzzInstruction']:
        """
        Produce mutation for trace (interface compatibility)
        
        Args:
            trace: Trace object (uses metadata.exec_count as iteration count)
            fork_point: Syscall index of fork point (ensures mutation target >= fork_point)
        
        Returns:
            list: List of FuzzInstructions
        """
        iteration = getattr(trace.metadata, 'exec_count', 0) if hasattr(trace, 'metadata') else 0
        return self.build_fuzz_instructions(iteration, fork_point=fork_point)
    
    def build_fuzz_instructions(self, iteration: int, fork_point: int = None):
        """
        Construct Fuzz instructions
        
        Adaptive strategy based on stagnation and iteration count.
        Uses enhanced set of 11 mutation commands including:
        FLIP_BITS, INTERESTING_VALUES, TRUNCATE, EXTEND, LIGHT_MUTATION,
        MUTATE_AUX_BUFFER, REPLACE_BUFFER, BOUNDARY_VALUE, MUTATE_FLAGS,
        OVERWRITE_AT_OFFSET.
        
        Args:
            iteration: Current iteration count
            fork_point: Syscall index of fork point (optional)
        
        Returns:
            list: List of FuzzInstructions
        """
        instrs = []

        # Recipe-driven mode selection
        if self.recipe_mode and self.recipes:
            # import random  <-- REMOVED

            
            # Adjust recipe probability based on iteration count to balance directed vs systematic fuzzing

            # Adjust recipe probability based on iteration count
            if iteration < 1000:
                recipe_probability = 0.7  # 70% use recipe in early phase
            elif iteration < 5000:
                recipe_probability = 0.5  # 50% use recipe in mid phase
            else:
                recipe_probability = 0.3  # 30% use recipe in late phase
            
            # Further reduce recipe usage when stagnant (increase exploration)
            if self.is_stagnant:
                recipe_probability *= 0.6  # Reduce recipe usage when stagnant

            if random.random() < recipe_probability:
                self.last_mutation_type = 'recipe'
                return self._build_from_recipes(iteration)
            else:
                # Fall through to systematic exploration
                print(f"[Mutator] Skipping recipe, using systematic exploration (iteration={iteration}, prob={recipe_probability:.1%})")

        # ━━━━ If no recipe or recipe probability miss, use systematic exploration ━━━━

        # ━━━━ Enhanced: Random Mutation Mode ━━━━
        self.last_mutation_type = 'smart_random'

        if not self.mutable_candidates:
            print("[Mutator] WARNING: No mutable candidates found!")
            return []
        
        num_candidates = len(self.mutable_candidates)
        
        # Determine mutation intensity based on stagnation status
        if self.is_stagnant:
            # Aggressive mode: High mutation count
            if num_candidates < 5:
                num_mutations = min(4, max(3, num_candidates))
            elif num_candidates < 10:
                num_mutations = min(7, max(5, num_candidates))
            else:
                num_mutations = min(15, max(8, num_candidates // 2))
            
            stagnation_duration = iteration - self.last_new_coverage_iter
            print(f"[Mutator] Stagnant mode: Mutating {num_mutations} syscalls (duration={stagnation_duration})")
        else:
            # Regular mode: Moderate mutation count
            if num_candidates < 5:
                num_mutations = min(3, max(2, num_candidates))
            elif num_candidates < 10:
                num_mutations = min(5, max(3, num_candidates))
            else:
                num_mutations = min(8, max(5, num_candidates // 3))
        
        # P2: Filter candidates >= fork_point
        valid_candidates = self.mutable_candidates
        if fork_point is not None:
            valid_candidates = [c for c in self.mutable_candidates if c.index >= fork_point]
            print(f"[Mutator] Fork point={fork_point}, candidates >= fork_point: {len(valid_candidates)}")
            
            if len(valid_candidates) == 0:
                # 🔍 RELAXATION: If no candidates >= fork_point, check if fork_point itself is a valid IO
                # (it might have been filtered out due to FD tracking or other environment factors)
                all_syscalls = getattr(self.analyzer, 'syscalls', [])
                target_sc = next((sc for sc in all_syscalls if sc.index == fork_point), None)
                
                if target_sc and target_sc.name in IMPORTANT_SYSCALLS:
                    print(f"[Mutator] OK: Fork point {fork_point} ({target_sc.name}) is an IO syscall - Force including it")
                    valid_candidates = [target_sc]
                else:
                    print(f"[Mutator] WARNING: No candidates >= fork_point and {fork_point} is not a valid IO target")
                    valid_candidates = self.mutable_candidates
        
        num_candidates = len(valid_candidates)
        
        print(f"[Mutator] Iteration {iteration}: Mutating {num_mutations} from {num_candidates} IO candidates")
        
        # P3: Classify candidates (all candidates are already IO syscalls)
        primary_io = [c for c in valid_candidates if c.name in PRIMARY_IO_SYSCALLS]
        secondary_io = [c for c in valid_candidates if c.name in SECONDARY_IO_SYSCALLS]
        
        print(f"[Mutator]   Primary IO: {len(primary_io)}, Secondary IO: {len(secondary_io)}")
        
        # P4: If fork_point specified, guarantee at least one mutation target is it
        fork_point_candidate = None
        if fork_point is not None:
            for c in valid_candidates:
                if c.index == fork_point:
                    fork_point_candidate = c
                    break
            
            if fork_point_candidate:
                strategy_type = self._select_strategy()
                fork_instr = self._generate_advanced_instruction(fork_point_candidate, strategy_type, iteration)
                instrs.append(fork_instr)
                print(f"[Mutator] P4: Guaranteed mutation at fork_point={fork_point} ({fork_point_candidate.name})")
                num_mutations -= 1
            elif fork_point is not None:
                print(f"[Mutator] WARNING: fork_point={fork_point} not in valid candidates")

        # P5: Select remaining mutation targets
        if num_mutations > 0 and len(valid_candidates) > 0:
            targets = self._select_diverse_targets(valid_candidates, num_mutations, iteration)
            for target_sc in targets:
                # Avoid redundant mutation of fork_point
                if fork_point_candidate and target_sc.index == fork_point_candidate.index:
                    continue
                
                strategy_type = self._select_strategy()
                mutation_instr = self._generate_advanced_instruction(target_sc, strategy_type, iteration)
                if mutation_instr:
                    instrs.append(mutation_instr)
        


        # Record result and verify limit
        self.last_mutation_type = 'smart' if len(instrs) > 0 else 'none'
        
        if len(instrs) > FUZZ_MAX_INSTRUCTIONS:
            print(f"[SmartMutator] Truncating instructions to {FUZZ_MAX_INSTRUCTIONS}")
            instrs = instrs[:FUZZ_MAX_INSTRUCTIONS]
        
        print(f"[Mutator] Generated {len(instrs)} mutation instructions")
        return instrs

    def _select_diverse_targets(self, candidates: list, num_targets: int, iteration: int) -> list:
        """
        Strategy:
        1. Rotation: Cycle through candidates based on iteration ID.
        2. Dispersion: Ensure selected syscalls are spread across the trace.
        3. Jitter: Add occasional random selection for unpredictability.
        4. History avoidance: Prevent consecutive iterations from targeting identical sets.

        Args:
            candidates: List of optional candidates (sorted by index)
            num_targets: Number of targets to select
            iteration: Current iteration ID
        Returns:
            List of selected candidates
        """
        if not candidates:
            return []

        if len(candidates) <= num_targets:
            return candidates.copy()

        selected = []
        count = len(candidates)

        # Strategy 1: Iteration-based rotation start point
        start_idx = iteration % count

        # Strategy 2: Distributed selection - Try to select candidates far apart
        if num_targets == 1:
            # Single selection: based on iteration rotation
            selected.append(candidates[start_idx])
        else:
            # Multiple selections: use stepping algorithm to ensure distribution
            step = max(1, count // num_targets)
            for i in range(num_targets):
                idx = (start_idx + i * step) % count
                selected.append(candidates[idx])

        # Strategy 3: Random perturbation (25% probability)
        if random.random() < 0.25:
            # Replace one selected candidate with a random candidate
            if selected:
                replace_idx = random.randrange(len(selected))
                selected[replace_idx] = random.choice(candidates)

        # Deduplication (in case rotation produces duplicates)
        final_selected = []
        seen_indices = set()
        for cand in selected:
            if cand.index not in seen_indices:
                final_selected.append(cand)
                seen_indices.add(cand.index)

        # If count insufficient after deduplication, supplement selection
        if len(final_selected) < num_targets:
            for candidate in candidates:
                if candidate.index not in seen_indices:
                    final_selected.append(candidate)
                    seen_indices.add(candidate.index)
                if len(final_selected) >= num_targets:
                    break

        return final_selected[:num_targets]


#!/usr/bin/env python3
"""
SmartMutator - Intelligent Mutation Engine

This module provides smart mutation capabilities that:
1. Analyzes trace files to identify mutable syscalls
2. Filters out initialization-phase syscalls
3. Supports recipe-driven mutation (PathFinder integration)
4. Implements 11 different mutation strategies
5. Dynamically adjusts mutation intensity

Mutation Strategies:
- FLIP_BITS: Light bit flipping
- LIGHT_MUTATION: 1-2 bit flipping
- INTERESTING_VALUES: Special boundary values
- BOUNDARY_VALUE: Boundary value testing
- TRUNCATE: Data truncation
- EXTEND: Data extension
- REPLACE_BUFFER: Buffer replacement (small/large)
- MUTATE_AUX_BUFFER: Auxiliary data mutation
- MUTATE_FLAGS: Flag bit mutation
- Special patterns: Format strings, injections, etc.
"""

import os
import json
import struct
import random
import sys
from pathlib import Path

# Add analysis directory to path for trace_analyzer import
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "analysis"))

from .constants import (
    FUZZ_CMD_FLIP_BITS, FUZZ_CMD_LIGHT_MUTATION, FUZZ_CMD_INTERESTING_VALUES,
    FUZZ_CMD_BOUNDARY_VALUE, FUZZ_CMD_TRUNCATE, FUZZ_CMD_EXTEND,
    FUZZ_CMD_REPLACE_BUFFER, FUZZ_CMD_MUTATE_AUX_BUFFER, FUZZ_CMD_MUTATE_FLAGS,
    FUZZ_CMD_MUTATE_ARG, FUZZ_CMD_OVERWRITE_AT_OFFSET,
    INIT_SYSCALLS, INIT_PHASE_THRESHOLD, IMPORTANT_SYSCALLS
)
from .instruction import FuzzInstruction


class SmartMutator:
    """
    Smart Mutation Engine
    
    Analyzes trace files, filters mutable syscalls, and generates intelligent
    mutation instructions using multiple strategies.
    """
    
    def __init__(self, trace_file, recipe_file=None):
        """
        Initialize SmartMutator
        
        Args:
            trace_file: Trace file path
            recipe_file: Recipe file path (optional, Phase 2)
        """
        # ✅ Fix: Auto-parse using fixed TraceAnalyzer
        print(f"[Mutator] Analyzing trace file: {trace_file}")
        
        # Import and use fixed TraceAnalyzer
        from trace_analyzer import TraceAnalyzer
        
        self.analyzer = TraceAnalyzer(trace_file)
        if not self.analyzer.analyze():
            raise RuntimeError(f"Failed to analyze trace: {trace_file}")
        
        # Get all pure syscalls (syscalls with aux_data)
        pure_syscalls = self.analyzer.get_pure_syscalls()
        
        # Define Candidate class
        class Candidate:
            def __init__(self, index, name, nr):
                self.index = index
                self.name = name
                self.syscall_nr = nr
        
        # Convert to Candidate objects
        self.pure_candidates = [
            Candidate(sc.index, sc.name, sc.syscall_nr)
            for sc in pure_syscalls
        ]
        
        # Get hybrid syscalls (syscalls without aux_data)
        hybrid_syscalls = self.analyzer.get_hybrid_syscalls()
        self.hybrid_candidates = [
            Candidate(sc.index, sc.name, sc.syscall_nr)
            for sc in hybrid_syscalls
        ]
        
        # Save all syscalls for later use
        self.syscalls = self.analyzer.syscalls
        
        print(f"[Mutator] ✅ Found {len(self.pure_candidates)} pure replay syscalls:")
        for cand in self.pure_candidates[:10]:  # Only print first 10
            print(f"[Mutator]   index={cand.index}, name={cand.name}, nr={cand.syscall_nr}")
        if len(self.pure_candidates) > 10:
            print(f"[Mutator]   ... and {len(self.pure_candidates) - 10} more")
        
        # Phase 1: Filter non-mutable syscalls
        self.mutable_candidates = self._filter_mutable_candidates()
        
        # ━━━━ Phase 2: Recipe-driven mode ━━━━
        self.recipes = []
        self.recipe_mode = False
        if recipe_file and os.path.exists(recipe_file):
            self._load_recipes(recipe_file)
            self.recipe_mode = True
            print(f"[Mutator] 🧪 Recipe-driven mode enabled ({len(self.recipes)} recipes loaded)")
        else:
            print(f"[Mutator] 🎲 Random mutation mode (no recipe file provided)")
    
    def _should_skip_mutation(self, syscall_info, index):
        """
        Determine whether to skip this syscall's mutation
        
        Args:
            syscall_info: System call information object
            index: Index position in trace
        
        Returns:
            bool: True means skip, False means can mutate
        """
        syscall_name = getattr(syscall_info, 'name', '').lower()
        
        # 🔥 Critical fix: Important IO syscalls never skip
        if syscall_name in IMPORTANT_SYSCALLS:
            print(f"[Mutator] ✅ Keeping important IO syscall: {syscall_name} (index={index})")
            return False  # Never skip
        
        # 1. Skip critical syscalls in initialization phase (use dynamic threshold)
        # Note: dynamic_threshold will be set by Conductor during first fuzzing
        threshold = getattr(self, 'dynamic_threshold', INIT_PHASE_THRESHOLD)
        if index < threshold:
            if any(init_sc in syscall_name for init_sc in INIT_SYSCALLS):
                print(f"[Mutator] ⏭️  Skipping init syscall: {syscall_name} (index={index}, threshold={threshold})")
                return True
        
        # 2. Skip syscalls without mutable data (can be extended later)
        # Currently TraceAnalyzer has filtered out pure/hybrid candidates
        
        return False
    
    def _filter_mutable_candidates(self):
        """
        Filter out truly mutable candidates
        
        Returns:
            list: List of safely mutable syscall candidates
        """
        mutable = []
        
        # Merge pure and hybrid candidates
        all_candidates = list(self.pure_candidates) + list(self.hybrid_candidates)
        
        print(f"[Mutator] 📋 Filtering {len(all_candidates)} candidates...")
        
        for candidate in all_candidates:
            if not self._should_skip_mutation(candidate, candidate.index):
                mutable.append(candidate)
        
        print(f"[Mutator] ✅ Filtered result: {len(mutable)} mutable candidates")
        print(f"[Mutator] 📝 Mutable candidates:")
        for i, cand in enumerate(mutable):
            print(f"[Mutator]   [{i}] index={cand.index}, name={cand.name}")
        
        return mutable
    
    def _load_recipes(self, recipe_file):
        """
        Load recipes from JSON file
        
        Args:
            recipe_file: Recipe file path (recipes.json)
        """
        try:
            with open(recipe_file, 'r') as f:
                data = json.load(f)
            
            self.recipes = data.get('recipes', [])
            print(f"[Mutator] Loaded {len(self.recipes)} recipes from {recipe_file}")
            
            # Print first few recipes
            for i, recipe in enumerate(self.recipes[:5]):
                print(f"[Mutator]   Recipe {i}: {recipe['source_branch']} -> {recipe['target_branch']}, "
                      f"syscall_idx={recipe['syscall_index']}, type={recipe['mutation_type']}")
            
        except Exception as e:
            print(f"[Mutator] ⚠️  Failed to load recipes: {e}")
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
                # Hexadecimal value
                val = int(data_template, 16)
                mutation_data = struct.pack('Q', val)[:size]
            else:
                # Default random
                mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            
            # Select command based on mutation_type
            if mutation_type == 'buffer_overwrite':
                # Phase 2 new: Use FUZZ_CMD_OVERWRITE_AT_OFFSET
                # Use offset and size from recipe to create precise overwrite instruction
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
                # Default use buffer replacement
                return FuzzInstruction(syscall_index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data, 0, size)
                
        except Exception as e:
            print(f"[Mutator] ⚠️  Failed to convert recipe to instruction: {e}")
            return None
    
    def _build_from_recipes(self, iteration):
        """
        Generate Fuzz instructions from recipes
        
        Args:
            iteration: Current iteration number
        
        Returns:
            list: FuzzInstruction list
        """
        instrs = []
        
        # Select recipe (cycle through)
        recipe_idx = iteration % len(self.recipes)
        recipe = self.recipes[recipe_idx]
        
        print(f"[Mutator] 🧪 Using recipe {recipe_idx}/{len(self.recipes)}: "
              f"{recipe['source_branch']} -> {recipe['target_branch']}")
        
        # Convert to instruction
        instr = self._recipe_to_instruction(recipe)
        if instr:
            instrs.append(instr)
            print(f"[Mutator]   Generated instruction: syscall_idx={recipe['syscall_index']}, "
                  f"cmd={recipe['mutation_type']}")
        
        return instrs
    
    def _generate_advanced_mutation(self, target_candidate, strategy_type, iteration):
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
            # FLIP_BITS - Bit flipping (lightweight, keep most data unchanged)
            num_flips = random.randint(1, 8)  # Flip 1-8 bits
            mutation_data = struct.pack('I', num_flips)
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=FLIP_BITS({num_flips} bits)")
            return FuzzInstruction(index, FUZZ_CMD_FLIP_BITS, 1, mutation_data)
        
        elif strategy_type == 1:
            # INTERESTING_VALUES - Special value injection (boundary values, magic numbers, etc.)
            interesting_values = [
                0, 1, -1,                           # Basic boundaries
                0x7F, 0x80, 0xFF,                   # 8-bit boundaries
                0x7FFF, 0x8000, 0xFFFF,             # 16-bit boundaries
                0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, # 32-bit boundaries
                0x100, 0x400, 0x1000,               # Page size related
            ]
            value = random.choice(interesting_values)
            mutation_data = struct.pack('Q', value & 0xFFFFFFFFFFFFFFFF)
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=INTERESTING_VALUES(0x{value:x})")
            return FuzzInstruction(index, FUZZ_CMD_INTERESTING_VALUES, 1, mutation_data)
        
        elif strategy_type == 2:
            # TRUNCATE - Truncate data (reduce size)
            truncate_to = random.choice([0, 1, 2, 4, 8, 16])
            mutation_data = struct.pack('I', truncate_to)
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=TRUNCATE(to {truncate_to})")
            return FuzzInstruction(index, FUZZ_CMD_TRUNCATE, 1, mutation_data)
        
        elif strategy_type == 3:
            # EXTEND - Extend data (increase size)
            extend_by = random.choice([1, 4, 16, 64, 256])
            mutation_data = struct.pack('I', extend_by)
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=EXTEND(by {extend_by})")
            return FuzzInstruction(index, FUZZ_CMD_EXTEND, 1, mutation_data)
        
        elif strategy_type == 4:
            # LIGHT_MUTATION - Lightweight mutation (only flip 1-2 bits)
            num_flips = random.randint(1, 2)
            mutation_data = struct.pack('I', num_flips)
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=LIGHT_MUTATION({num_flips} bits)")
            return FuzzInstruction(index, FUZZ_CMD_LIGHT_MUTATION, 1, mutation_data)
        
        elif strategy_type == 5:
            # MUTATE_AUX_BUFFER - Mutate aux_data buffer
            # Randomly change a few bytes in the buffer
            num_changes = random.randint(1, 8)
            mutation_data = struct.pack('I', num_changes) + bytes([random.randint(0, 255) for _ in range(num_changes)])
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=MUTATE_AUX_BUFFER({num_changes} bytes)")
            return FuzzInstruction(index, FUZZ_CMD_MUTATE_AUX_BUFFER, 1, mutation_data)
        
        elif strategy_type == 6:
            # REPLACE_BUFFER - Completely replace buffer (small data)
            size = random.choice([4, 8, 16, 32])
            mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=REPLACE_BUFFER({size} bytes)")
            return FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data)
        
        elif strategy_type == 7:
            # REPLACE_BUFFER - Large data replacement (test overflow)
            size = random.choice([64, 128, 256])
            mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=REPLACE_BUFFER({size} bytes, large)")
            return FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data)
        
        elif strategy_type == 8:
            # BOUNDARY_VALUE - Boundary value testing
            boundary_vals = [0, -1, 0x7FFFFFFF, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF]
            value = random.choice(boundary_vals)
            mutation_data = struct.pack('q', value)
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=BOUNDARY_VALUE(0x{value:x})")
            return FuzzInstruction(index, FUZZ_CMD_BOUNDARY_VALUE, 1, mutation_data)
        
        elif strategy_type == 9:
            # Special character sequences (format strings, SQL injection, etc.)
            special_patterns = [
                b'%s%s%s%s%n',        # Format string
                b"'; DROP TABLE --",   # SQL injection
                b'<script>alert(1)</script>',  # XSS
                b'/../../../etc/passwd',  # Path traversal
                b'\x00' * 16,          # NULL bytes
                b'\xFF' * 16,          # 0xFF bytes
            ]
            mutation_data = random.choice(special_patterns)
            print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=REPLACE_BUFFER(special pattern)")
            return FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data)
        
        else:
            # MUTATE_FLAGS - Flag bit mutation
            if iteration % 3 == 0:
                # Single bit flip
                flag_mutation = struct.pack('q', (1 << (iteration % 32)))
                print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=MUTATE_FLAGS(single bit)")
            else:
                # Multi-bit flip
                flag_mutation = struct.pack('q', random.randint(0, 0xFFFFFFFF))
                print(f"[Mutator]   🎯 Target: index={index}, name={target_candidate.name}, cmd=MUTATE_FLAGS(multi bits)")
            return FuzzInstruction(index, FUZZ_CMD_MUTATE_FLAGS, 0, flag_mutation)
    
    def build_instructions(self, iteration):
        """
        Build Fuzz instructions
        
        ━━━━ Phase 2.1 Enhancement: Fully utilize 11 mutation commands ━━━━
        - If has recipes: Use recipes to generate precise mutation instructions
        - If no recipes: Use enhanced random mutation mode
        
        🔥 Enhancement Strategy (Random Mode):
        - Mutate 1-3 syscalls per round (dynamically adjust based on candidate count)
        - Use all 11 mutation strategies:
          * FLIP_BITS, LIGHT_MUTATION - Lightweight mutation
          * INTERESTING_VALUES, BOUNDARY_VALUE - Boundary value testing
          * TRUNCATE, EXTEND - Size mutation
          * REPLACE_BUFFER, MUTATE_AUX_BUFFER - Buffer mutation
          * MUTATE_FLAGS, MUTATE_ARG - Parameter mutation
          * Special patterns - Format strings, injection attacks, etc.
        
        Args:
            iteration: Current iteration number
        
        Returns:
            list: FuzzInstruction list
        """
        instrs = []
        
        # ━━━━ Phase 2: Recipe-driven mode ━━━━
        if self.recipe_mode and self.recipes:
            return self._build_from_recipes(iteration)
        
        # ━━━━ Enhancement: Random mutation mode ━━━━
        if not self.mutable_candidates:
            print("[Mutator] ⚠️  No mutable candidates found!")
            return instrs
        
        num_candidates = len(self.mutable_candidates)
        
        # Mutate 1-3 syscalls per round (dynamically adjust based on candidate count)
        num_mutations = min(3, max(1, num_candidates // 10))
        
        print(f"[Mutator] 🎯 Round {iteration}: Mutating {num_mutations} syscalls (Enhanced Mode)")
        
        for i in range(num_mutations):
            # Select different candidate syscalls (avoid duplicates)
            offset = (iteration * num_mutations + i) % num_candidates
            target_candidate = self.mutable_candidates[offset]
            
            # Select mutation strategy (0-10, 11 strategies total)
            strategy_type = random.randint(0, 10)
            
            # Generate advanced mutation instruction
            instr = self._generate_advanced_mutation(target_candidate, strategy_type, iteration)
            if instr:
                instrs.append(instr)
        
        return instrs


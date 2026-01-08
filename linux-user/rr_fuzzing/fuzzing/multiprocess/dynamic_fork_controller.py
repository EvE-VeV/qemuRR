#!/usr/bin/env python3
"""
DynamicForkController - Dynamic Fork Exploration Controller

Functionality:
1. Identify uncovered branches based on PathFinder
2. Generate multiple mutation variants
3. Coordinate batch fork execution
4. Collect and analyze results
5. Update RecipePool feedback

Author: RR-Fuzz Team
Date: 2025-11-06
"""

import random
import time
from typing import List, Dict, Optional, Tuple, TYPE_CHECKING
from pathlib import Path
from dataclasses import dataclass

# Import existing components (100% reuse)
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# Use TYPE_CHECKING to avoid circular imports
if TYPE_CHECKING:
    from conductor.qemu_executor import QEMUExecutor
else:
    # Lazy import at runtime
    QEMUExecutor = None

from conductor.mutator import SmartMutator
from conductor.coverage import CoverageTracker
from conductor.trace_manager import TraceManager, Trace
try:
    from conductor.dual_level_path_finder import DualLevelPathFinder as PathFinder
except ImportError:
    from .dual_level_path_finder import DualLevelPathFinder as PathFinder
from .recipe_pool import RecipePool
from conductor.async_logger import alog
from conductor.constants import PRIMARY_IO_SYSCALLS

@dataclass
class FuzzCheckpoint:
    """
    Depth-First Exploration Checkpoint Data Structure

    Each checkpoint represents a state point that can continue to be explored.
    """
    trace_file: str  # Path to trace file
    syscall_index: int  # Syscall position of the checkpoint
    depth: int  # Current exploration depth
    coverage_state: bytes  # Coverage state (for restoration)
    unexplored_mutations: List  # Unexplored mutation variants
    parent_checkpoint_id: str  # Parent checkpoint ID (for backtracking)
    checkpoint_id: str  # Unique identifier
    discovery_iteration: int  # Iteration count when this checkpoint was found
    mutation_node_ids: List[str] = None  # Mutation node IDs for tracking in dependency graph

    def __str__(self):
        return f"Checkpoint[{self.checkpoint_id}] @syscall[{self.syscall_index}] depth={self.depth} mutations={len(self.unexplored_mutations)}"


class DynamicForkController:
    """
    Dynamic Fork Exploration Controller
    
    Reused components:
    - PathFinder: Identify uncovered branches ✅
    - RecipePool: Manage branch recipes ✅  
    - SmartMutator: Generate mutations ✅
    - QEMUExecutor: Execute batch forks ✅
    - CoverageTracker: Analyze results ✅
    
    New logic:
    - Intelligent fork point selection
    - Batch fork coordination
    - Branch value evaluation
    """
    
    def __init__(self,
                 executor: 'QEMUExecutor',
                 path_finder: Optional[PathFinder],
                 mutator: SmartMutator,
                 recipe_pool: Optional[RecipePool],
                 coverage_tracker: CoverageTracker,
                 trace_manager: TraceManager = None,
                 fuzzing_stats=None,
                 mutation_graph=None,
                 crash_detector=None,
                 analyzer=None):  # ✅ Task #8: Add crash detector
        """Initialize dynamic fork controller
        
        Args:
            executor: QEMU executor
            path_finder: PathFinder instance (optional, None uses simple strategy)
            mutator: SmartMutator instance
            recipe_pool: RecipePool instance (optional)
            coverage_tracker: CoverageTracker instance
            trace_manager: TraceManager instance (for saving interesting seeds)
            fuzzing_stats: FuzzingStatistics instance (for unified tracking)
            mutation_graph: MutationDependencyGraph instance (for mutation tracking)
            crash_detector: CrashDetector instance (for saving crashes)
            analyzer: TraceAnalyzer instance (optional)
        """
        self.executor = executor
        self.path_finder = path_finder
        self.mutator = mutator
        self.recipe_pool = recipe_pool
        self.coverage_tracker = coverage_tracker
        self.trace_manager = trace_manager
        self.fuzzing_stats = fuzzing_stats
        self.mutation_graph = mutation_graph
        self.crash_detector = crash_detector
        self.analyzer = analyzer
        self.last_batch_execs = 0  # ✅ Track executions in last batch
        
        # Depth-first exploration mode configuration
        self.depth_first_mode = True 
        
        # ✅ Configurable parameters via Environment Variables
        import os
        self.max_depth = int(os.environ.get('RR_MAX_DEPTH', 2))
        alog(f"Config: max_depth = {self.max_depth}", "DFC", "INFO")
        
        self.max_variants_per_checkpoint = int(os.environ.get('RR_MAX_VARIANTS', 10))
        alog(f"Config: max_variants_per_checkpoint = {self.max_variants_per_checkpoint}", "DFC", "INFO")
        
        self.checkpoint_queue = []  # Queue of checkpoints to explore (Depth-First)

        # Traditional configuration (adjusted to support depth mode)
        self.max_variants_per_fork = self.max_variants_per_checkpoint
        self.fork_budget_per_1000 = 200  # Increase budget to support deep exploration

        # Adaptive trigger probability configuration
        # Default probability increased to handle low trigger frequency issues
        self.trigger_probability = float(os.environ.get('RR_TRIGGER_PROB', 0.2)) 
        alog(f"Config: trigger_probability = {self.trigger_probability}", "DFC", "INFO")
        
        self.adaptive_trigger = True  # Enable adaptive adjustment
        self.min_trigger_probability = 0.15  # 最小触发概率从0.05提升到0.15
        self.max_trigger_probability = 0.4  # 最大触发概率从0.3提升到0.4

        # Adaptive statistics window
        self.recent_forks = []  # [(success, timestamp), ...] Recent fork results
        self.recent_window_size = 20  # Window size
        self.last_new_coverage_time = time.time()  # Time when new coverage was last discovered

        # Current trace object used for IO mutations
        self.current_trace = None
        
        # Cache for IO syscalls analysis
        self._io_syscall_cache = {}

        # Statistics including depth-related metrics
        self.stats = {
            'total_multi_forks': 0,
            'total_variants_tested': 0,
            'new_paths_discovered': 0,
            'forks_this_period': 0,
            'total_checkpoints': 0,
            'max_depth_reached': 0,
            'snapshot_saves': 0,
            'snapshot_restores': 0
        }

        alog(f"Initialized (Depth-First Checkpoint Mode)", "DFC", "INFO")
        alog(f"  Max exploration depth: {self.max_depth}", "DFC", "INFO")
        alog(f"  Max variants per checkpoint: {self.max_variants_per_checkpoint}", "DFC", "INFO")
        alog(f"  Fork budget: {self.fork_budget_per_1000}/1000 iterations", "DFC", "INFO")
        if self.adaptive_trigger:
            alog(f"  Adaptive Trigger: Enabled (Initial={self.trigger_probability}, Range=[{self.min_trigger_probability}, {self.max_trigger_probability}])", "DFC", "INFO")

    def _calculate_adaptive_probability(self) -> float:
        """
        Calculate adaptive trigger_probability

        Adjustment strategies:
        1. High success rate (>30%) → Increase trigger probability (more valuable forks)
        2. Low success rate (<10%) → Decrease trigger probability (reduce waste)
        3. Coverage stagnation (>5 mins no new coverage) → Increase trigger probability (explore new paths)
        4. Rapid coverage growth → Maintain current probability

        Returns:
            Adjusted trigger_probability
        """
        if not self.adaptive_trigger:
            return self.trigger_probability

        current_prob = self.trigger_probability

        # 1. Adjust based on success rate
        if len(self.recent_forks) >= 10:
            # Calculate recent success rate
            recent_success_count = sum(1 for success, _ in self.recent_forks if success)
            success_rate = recent_success_count / len(self.recent_forks)

            if success_rate > 0.3:
                # High success rate, increase trigger probability
                current_prob = min(current_prob * 1.2, self.max_trigger_probability)
            elif success_rate < 0.1:
                # Low success rate, decrease trigger probability
                current_prob = max(current_prob * 0.8, self.min_trigger_probability)

        # 2. Adjust based on coverage stagnation
        time_since_last_coverage = time.time() - self.last_new_coverage_time
        if time_since_last_coverage > 300:  # 5 minutes without new coverage
            # Coverage stagnation, increase Dynamic Fork exploration
            current_prob = min(current_prob * 1.5, self.max_trigger_probability)

        # 3. Constrain within range
        current_prob = max(self.min_trigger_probability, min(current_prob, self.max_trigger_probability))

        return current_prob

    def _record_fork_result(self, success: bool):
        """
        Record fork success/failure result (for adaptive adjustment)

        Args:
            success: True if new coverage or crash was found, False otherwise
        """
        if not self.adaptive_trigger:
            return

        current_time = time.time()
        self.recent_forks.append((success, current_time))

        # Maintain window size
        if len(self.recent_forks) > self.recent_window_size:
            self.recent_forks.pop(0)

    def should_trigger_multi_fork(self, iteration: int) -> bool:
        """
        Decide whether to trigger multi-fork (adaptive version)

        Args:
            iteration: Current iteration count

        Returns:
            True if should trigger
        """
        # Budget check
        period = iteration // 1000
        if self.stats['forks_this_period'] >= self.fork_budget_per_1000:
            return False

        # Reset on new period
        if iteration % 1000 == 0:
            self.stats['forks_this_period'] = 0

        # Adaptive probability trigger logic
        if self.adaptive_trigger:
            adaptive_prob = self._calculate_adaptive_probability()
            # Update trigger_probability periodically
            if iteration % 100 == 0:
                old_prob = self.trigger_probability
                self.trigger_probability = adaptive_prob
                if abs(old_prob - adaptive_prob) > 0.01:
                    alog(f"Adaptive trigger_probability: {old_prob:.3f} → {adaptive_prob:.3f}", "DFC", "DEBUG")
            return random.random() < adaptive_prob
        else:
            return random.random() < self.trigger_probability
    
    def explore_multi_path(self, trace: Trace, iteration_id: int = 0) -> bool:
        """
        Depth-First Checkpoint/Snapshot Exploration

        Strategy:
        1. Start from root trace or restore deepest checkpoint.
        2. Create checkpoint at each IO syscall.
        3. Execute first mutation to continue deeper exploration.
        4. If max depth is reached or no new coverage is found, backtrack.
        5. Continue exploring other mutations for the checkpoint.

        Args:
            trace: Trace to explore
            iteration_id: Current iteration number

        Returns:
            True if discovered new paths
        """
        # Save current trace for mutation use
        self.current_trace = trace
        if not self.depth_first_mode:
            # Compatibility: Use breadth-first mode if depth mode is not enabled
            return self._explore_breadth_first(trace, iteration_id)

        alog(f"🌊 Iteration {iteration_id}: Dynamic Multi-Fork on {trace.id}", "DFC", "INFO")

        # Execute multiple mutations from root trace once
        alog("Starting multi-fork exploration from root trace", "DFC", "DEBUG")
        return self._start_depth_exploration(trace, iteration_id)

    def _start_depth_exploration(self, trace: Trace, iteration_id: int) -> bool:
        """
        Start depth exploration from root trace

        ✅ OPTIMIZATION: Cache baseline execution results to avoid repeated QEMU forks
        """
        # Reset batch counter for this exploration
        self.last_batch_execs = 0

        cache_key = trace.id
        if cache_key in self._io_syscall_cache:
            # Use cached IO syscalls to avoid repeated analysis
            io_syscalls = self._io_syscall_cache[cache_key]
            alog(f"Using cached IO syscalls for {trace.id}", "DFC", "DEBUG")
        else:
            # Use static analysis to discover IO syscalls (avoids expensive QEMU baseline execution)
            alog("Static analysis to discover IO syscalls...", "DFC", "DEBUG")
            io_syscalls = self._find_io_syscalls(trace, max_fork_points=2)
            self._io_syscall_cache[cache_key] = io_syscalls

        if not io_syscalls:
            alog("No IO syscalls found", "DFC", "WARN")
            return False

        alog(f"Found {len(io_syscalls)} IO syscalls: {io_syscalls}", "DFC", "DEBUG")

        # ✅ Store as instance variable for nested fork use
        self.current_io_syscalls = io_syscalls

        # Start depth exploration from first IO syscall
        first_io_syscall = io_syscalls[0]
        alog(f"🎯 Starting deep exploration at first IO syscall[{first_io_syscall}]", "DFC", "INFO")

        return self._explore_at_checkpoint(trace.file_path, first_io_syscall, 0, iteration_id, "root")

    def _explore_at_checkpoint(self, trace_file: str, syscall_index: int, depth: int, iteration_id: int, parent_id: str) -> bool:
        """
        Create checkpoint at specified syscall position and explore
        """
        if depth > self.max_depth:
            alog(f"🔚 Reached max depth ({self.max_depth}), stopping exploration", "DFC", "DEBUG")
            return False

        checkpoint_id = f"cp_{iteration_id}_{syscall_index}_{depth}"
        alog(f"📍 Creating checkpoint[{checkpoint_id}] @syscall[{syscall_index}] depth={depth}", "DFC", "DEBUG")

        mutations = []
        mutation_node_ids = []  # Track mutation node IDs in graph
        for i in range(self.max_variants_per_checkpoint):
            # 🔥 Pass current trace object for IO mutation use
            mutation = self.mutator.mutate(self.current_trace, fork_point=syscall_index, analyzer=self.analyzer)
            mutations.append(mutation)

            # Track mutation in graph and extract type from instructions
            if isinstance(mutation, list) and len(mutation) > 0:
                mut_type = getattr(mutation[0], 'mutation_type', 'unknown')
            else:
                mut_type = 'unknown'

            if self.mutation_graph:
                node_id = self.mutation_graph.add_mutation(
                    iteration=iteration_id,
                    mutation_index=i,
                    mutation_type=mut_type,
                    parent_trace_id=f"checkpoint_{checkpoint_id}",
                    syscall_index=syscall_index,
                    field_name="dynamic_fork"
                )
                mutation_node_ids.append(node_id)

        alog(f"Generated {len(mutations)} mutations for checkpoint", "DFC", "DEBUG")

        # Save current coverage state as checkpoint
        coverage_snapshot = self._save_coverage_state()

        # 🔥 FIX: Direct execution of all mutations without checkpoint queue
        checkpoint = FuzzCheckpoint(
            trace_file=trace_file,
            syscall_index=syscall_index,
            depth=depth,
            coverage_state=coverage_snapshot,
            unexplored_mutations=[],  
            parent_checkpoint_id=parent_id,
            checkpoint_id=checkpoint_id,
            discovery_iteration=iteration_id,
            mutation_node_ids=mutation_node_ids if mutation_node_ids else []
        )

        # Execute all mutations in parallel (dynamic multi-fork)
        if mutations:
            alog(f"Executing {len(mutations)} variants in parallel...", "DFC", "DEBUG")

            try:
                results = self.executor.execute_fork(
                    trace_file=trace_file,
                    fork_point=syscall_index,
                    mutation_variants=mutations,  # Pass all mutations
                    depth=depth,
                    iteration_id=iteration_id
                )

                # ✅ Update unified stats counter (1 execution per variant)
                if self.fuzzing_stats and results:
                    batch_count = len(results)
                    self.fuzzing_stats.total_execs += batch_count
                    self.last_batch_execs += batch_count

                any_new_path = False
                if results and len(results) > 0:
                    for i, result in enumerate(results):
                        # Use corresponding mutation node ID if available
                        node_id = mutation_node_ids[i] if i < len(mutation_node_ids) else None
                        
                        has_new_coverage = self.coverage_tracker.has_new_coverage(result.coverage_bitmap)

                        # ✅ Update mutation result in graph
                        if self.mutation_graph and node_id:
                            coverage_stats = self.coverage_tracker.get_stats()
                            self.mutation_graph.update_mutation_result(
                                node_id=node_id,
                                has_new_coverage=has_new_coverage,
                                new_edges=coverage_stats.get('new_edges_this_run', 0),
                                total_edges=coverage_stats.get('total_edges', 0),
                                crashed=result.crashed,
                                timed_out=False,
                                exec_time=getattr(result, 'exec_time', 0.0)
                            )

                        if result.crashed:
                            alog(f"💥 CRASH detected for variant {i} at depth={depth}!", "DFC", "WARN")
                            alog(f"🎯 Crash info: {result.crash_info if hasattr(result, 'crash_info') else 'Unknown crash'}", "DFC", "WARN")
                            # self.stats['new_paths_discovered'] += 1
                            any_new_path = True
                            
                            # ✅ Update global counter for UI
                            if self.fuzzing_stats:
                                self.fuzzing_stats.crashes_found += 1
                            
                            if self.crash_detector:
                                alog(f"Saving crash report...", "DFC", "INFO")
                                trace_obj = self.current_trace
                                # Ensure trace object has file_path
                                if trace_obj and not hasattr(trace_obj, 'file_path'):
                                    trace_obj = None 
                                
                                # Log crash details to detector
                                self.crash_detector.save_crash(
                                    result=result,
                                    trace=trace_obj,
                                    mutations=mutations[i] if i < len(mutations) else mutations[0]
                                )

                            # ✅ Record successful fork
                            self._record_fork_result(success=True)

                        elif has_new_coverage:
                            alog(f"🎉 New coverage discovered for variant {i} at depth={depth}!", "DFC", "INFO")
                            self.stats['new_paths_discovered'] += 1
                            any_new_path = True

                            # Update success metrics for adaptive trigger
                            self._record_fork_result(success=True)
                            self.last_new_coverage_time = time.time()

                            # Save new seed to corpus if coverage improved
                            if self.trace_manager:
                                coverage_stats = self.coverage_tracker.get_stats()
                                new_edges = coverage_stats.get('new_edges', set())

                                coverage_info = {
                                    'has_new_edges': True,
                                    'new_edge_count': len(new_edges) if new_edges else 1,
                                    'total_unique_edges': coverage_stats.get('total_edges', 0),
                                    'edges': new_edges if new_edges else set()
                                }

                                mutation_dicts = []
                                current_mutation = mutations[i] if i < len(mutations) else []
                                if isinstance(current_mutation, list):
                                    for instr in current_mutation:
                                        if hasattr(instr, 'syscall_index') and hasattr(instr, 'cmd'):
                                            mutation_dicts.append({
                                                'syscall_index': instr.syscall_index,
                                                'cmd': instr.cmd
                                            })

                                parent_trace_id = getattr(self, 'current_trace_id', None)
                                self.trace_manager.add_trace(
                                    trace_file=trace_file,
                                    coverage_info=coverage_info,
                                    parent_id=parent_trace_id,
                                    mutations=mutation_dicts
                                )
                                alog(f"Saved new seed for variant {i} to corpus (new_edges={len(new_edges)})", "DFC", "INFO")

                        else:
                            alog(f"📊 No new coverage for variant {i} at depth={depth}", "DFC", "DEBUG")
                            # ✅ Record failed fork
                            self._record_fork_result(success=False)

                    # 🔥 Backtrack check: Decide if we should go deeper after processing ALL variants at this level
                    if any_new_path:
                        # Nested Fork: Explore deeper levels using preselected IO syscalls
                        if depth < self.max_depth:
                            next_syscall = None
                            if hasattr(self, 'current_io_syscalls') and self.current_io_syscalls:
                                # Find next preselected IO syscall after current index
                                next_io_syscalls = [io for io in self.current_io_syscalls if io > syscall_index]
                                if next_io_syscalls:
                                    next_syscall = next_io_syscalls[0]
                                    
                            if next_syscall is not None:
                                # 🌊 Recursive exploration of next level
                                alog(f"Continuing deeper exploration to syscall[{next_syscall}]", "DFC", "DEBUG")
                                deeper_success = self._explore_at_checkpoint(
                                    trace_file=trace_file,
                                    syscall_index=next_syscall,
                                    depth=depth + 1,
                                    iteration_id=iteration_id,
                                    parent_id=checkpoint_id
                                )
                                if deeper_success:
                                    alog(f"⬆️  Coming back from depth {depth+1} (found interesting path)", "DFC", "DEBUG")
                                    self.stats['max_depth_reached'] = max(self.stats.get('max_depth_reached', 0), depth + 1)
                                else:
                                    alog(f"⬆️  Coming back from depth {depth+1} (no new findings)", "DFC", "DEBUG")
                        
                        return True
                    else:
                        alog(f"⬅️  Depth {depth} finished (no new findings), backtracking to checkpoint...", "DFC", "DEBUG")
                        return False
                else:
                    alog(f"❌ Fork execution failed (no results)", "DFC", "ERROR")
                    # ✅ Record failed fork
                    self._record_fork_result(success=False)
                    return False

            except Exception as e:
                alog(f"Error during deep exploration: {e}", "DFC", "ERROR")
                return False

        return False

    def _resume_checkpoint_exploration(self, checkpoint: FuzzCheckpoint, iteration_id: int) -> bool:
        """
        Restore from checkpoint and continue exploration
        """
        alog(f"🔄 Restoring checkpoint {checkpoint.checkpoint_id}", "DFC", "DEBUG")

        # Restore coverage state
        self._restore_coverage_state(checkpoint.coverage_state)
        self.stats['snapshot_restores'] += 1

        # Take next unexplored mutation
        if not checkpoint.unexplored_mutations:
            alog(f"📋 No more mutations in checkpoint {checkpoint.checkpoint_id}", "DFC", "DEBUG")
            return False

        next_mutation = checkpoint.unexplored_mutations.pop(0)

        # ✅ Task #6补充: Get corresponding mutation node ID
        next_mutation_node_id = None
        if checkpoint.mutation_node_ids:
            next_mutation_node_id = checkpoint.mutation_node_ids.pop(0)

        # If more mutations remain, re-add to queue
        if checkpoint.unexplored_mutations:
            self.checkpoint_queue.append(checkpoint)

        alog(f"🧪 Testing next mutation from checkpoint...", "DFC", "DEBUG")

        # 执行mutation
        try:
            results = self.executor.execute_fork(
                trace_file=checkpoint.trace_file,
                fork_point=checkpoint.syscall_index,
                mutation_variants=[next_mutation],
                depth=checkpoint.depth,
                iteration_id=iteration_id
            )

            # ✅ Update unified stats counter (1 execution per variant)
            if self.fuzzing_stats and results:
                self.fuzzing_stats.total_execs += len(results)

            if results and len(results) > 0:
                result = results[0]
                has_new_coverage = self.coverage_tracker.has_new_coverage(result.coverage_bitmap)

                # ✅ Task #6补充: Update mutation result in graph
                if self.mutation_graph and next_mutation_node_id:
                    coverage_stats = self.coverage_tracker.get_stats()
                    self.mutation_graph.update_mutation_result(
                        node_id=next_mutation_node_id,
                        has_new_coverage=has_new_coverage,
                        new_edges=coverage_stats.get('new_edges_this_run', 0),
                        total_edges=coverage_stats.get('total_edges', 0),
                        crashed=result.crashed,
                        timed_out=False,
                        exec_time=getattr(result, 'exec_time', 0.0)
                    )

                # 🔥 FIX: Correct handling after checkpoint restoration
                if result.crashed:
                    alog(f"💥 CRASH detected from checkpoint restoration!", "DFC", "WARN")
                    alog(f"🎯 Crash at checkpoint {checkpoint.checkpoint_id}, depth={checkpoint.depth}", "DFC", "WARN")
                    self.stats['new_paths_discovered'] += 1
                    
                    # ✅ Update global counter for UI
                    if self.fuzzing_stats:
                        self.fuzzing_stats.crashes_found += 1
                    
                    return True  # crash是成功结果，继续处理其他checkpoints

                elif has_new_coverage:
                    alog(f"🎉 New coverage from checkpoint restoration!", "DFC", "INFO")
                    self.stats['new_paths_discovered'] += 1
                    alog(f"⬅️  Program finished (normal exit with new coverage), backtracking...", "DFC", "DEBUG")
                    return True  # 有新coverage，成功的探索

                else:
                    alog(f"📊 No new coverage from restored checkpoint", "DFC", "DEBUG")
                    alog(f"⬅️  Program finished (normal exit, no new coverage), backtracking...", "DFC", "DEBUG")
                    return False  # 无新发现，回退

        except Exception as e:
            alog(f"Error during checkpoint restoration: {e}", "DFC", "ERROR")
            return False

        return False

    def _save_coverage_state(self) -> bytes:
        """Save current coverage state"""
        self.stats['snapshot_saves'] += 1
        # Should save actual coverage bitmap state here
        # For simplicity, currently returns empty bytes; actual implementation should save coverage_tracker state
        return b""

    def _restore_coverage_state(self, state: bytes):
        """Restore coverage state"""
        # Should restore coverage bitmap state here
        # For simplicity, currently only resets coverage
        self.executor.reset_coverage()

    def _find_next_io_syscalls(self, trace_file: str, current_index: int) -> List[int]:
        """
        Find IO syscalls after the specified index
        """
        # Should analyze trace file to find subsequent IO syscalls
        # For simplicity, returning some hypothetical subsequent IO syscalls for now
        try:
            from ..trace_analyzer import TraceAnalyzer
        except ImportError:
            # Fix relative import error
            import sys
            from pathlib import Path
            parent_dir = Path(__file__).parent.parent
            sys.path.insert(0, str(parent_dir))
            from trace_analyzer import TraceAnalyzer

        try:
            analyzer = TraceAnalyzer(trace_file)
            all_io_syscalls = []
            for record in analyzer.syscalls:
                if hasattr(record, 'name') and record.name.lower() in ['read', 'write', 'open', 'close', 'openat']:
                    all_io_syscalls.append(record.index)

            # Return IO syscalls greater than current_index
            next_ios = [idx for idx in all_io_syscalls if idx > current_index]
            return next_ios[:3]  # Return at most 3 subsequent IO syscalls
        except:
            # If analysis fails, return empty list
            return []

    def _explore_breadth_first(self, trace: Trace, iteration_id: int) -> bool:
        """
        Traditional breadth-first exploration (compatibility)
        """
        # This is a simplified version of the original explore_multi_path logic
        # Maintaining backward compatibility
        alog(f"Using legacy breadth-first mode", "DFC", "INFO")
        return False
    
    def _get_covered_blocks(self) -> set:
        """
        Get set of covered basic blocks
        
        Returns:
            Set of covered block addresses
        """
        covered = set()
        
        # Extract covered edges from coverage bitmap
        for i, val in enumerate(self.coverage_tracker.global_bitmap):
            if val > 0:
                # Simplification: Use bitmap index as block ID
                covered.add(i & 0xFFFF)
        
        return covered
    
    def _select_top_branches(self, branches: List[Dict], max_n: int) -> List[Dict]:
        """
        Select the most valuable N branches
        
        Args:
            branches: All uncovered branches
            max_n: Maximum selection count
        
        Returns:
            Top-N branch list
        """
        scored = []
        
        for branch in branches:
            score = self._evaluate_branch_value(branch)
            scored.append((score, branch))
        
        # ✅ FIX: Sort by score only (first element is float)
        scored.sort(key=lambda x: x[0], reverse=True)
        return [b for _, b in scored[:max_n]]
    
    def _evaluate_branch_value(self, branch: Dict) -> float:
        """
        Evaluate branch value
        
        Scoring criteria:
        - Proximity (ease of reach)
        - Contains syscalls (targets for mutation)
        - Type is conditional branch (not switch)
        """
        score = 0.0
        
        # 1. Distance score
        distance = branch.get('distance', 999)
        score += 10.0 / (1 + distance)
        
        # 2. Syscall score
        if branch.get('has_syscall', False):
            score += 5.0
        
        # 3. Type score
        if branch.get('type') in ['true_branch', 'false_branch']:
            score += 3.0
        
        return score
    
    def _find_recipe_for_branch(self, branch: Dict) -> Optional[Dict]:
        """
        Find the recipe corresponding to a branch
        
        Args:
            branch: Branch information
        
        Returns:
            Recipe dict or None
        """
        if not self.recipe_pool:
            return None
        
        target_addr = branch['to']
        
        # Traverse active recipes
        for recipe in self.recipe_pool.active_recipes:
            if recipe.get('target_branch') == f"0x{target_addr:x}":
                return recipe
        
        return None
    
    def _find_io_syscalls(self, trace: Trace, max_fork_points: int = 2) -> list:
        """
        Intelligently select IO syscalls as fork points

        ✅ 2025-11-18: Optimization - Limit fork point count to avoid excessive execution

        Strategy:
        1. Priority sorting: read > write > getrandom
        2. Return value size: Large return values are more likely to affect program behavior
        3. Limit count: Select only top N most important IO syscalls

        Args:
            trace: Trace object
            max_fork_points: Maximum number of fork points (default 2)

        Returns:
            List of IO syscall indices (sorted, at most max_fork_points)
        """
        # Import TraceAnalyzer
        import sys
        from pathlib import Path
        import trace_analyzer
        if self.analyzer and getattr(self.analyzer, 'trace_file', None) == trace.file_path:
             analyzer = self.analyzer
        else:
             analyzer = trace_analyzer.TraceAnalyzer(trace.file_path)
             if not hasattr(analyzer, 'trace_file'):
                 analyzer.trace_file = trace.file_path
             self.analyzer = analyzer  # ✅ FIX: Save for reuse

        # ✅ Collect IO syscalls and their metadata
        io_candidates = []

        for sc in analyzer.syscalls:
            # Only consider IO syscalls
            if sc.name in PRIMARY_IO_SYSCALLS:
                # Skip first 10% of syscalls (initialization phase)
                if sc.index < len(analyzer.syscalls) * 0.1:
                    continue

                # ✅ Calculate priority score
                priority_score = 0

                # 1. Syscall type priority
                if sc.name in ['read', 'recv', 'recvfrom']:
                    priority_score += 100  # Highest priority
                elif sc.name in ['getrandom']:
                    priority_score += 50   # Medium priority
                elif sc.name in ['write', 'send']:
                    priority_score += 30   # Lower priority

                # 2. Return value size (indicates data volume)
                try:
                    retval = int(sc.retval) if hasattr(sc, 'retval') else 0
                    if retval > 0:
                        priority_score += min(retval, 100)  # Max +100 points
                except:
                    pass

                # 3. Position bonus (intermediate syscalls are more important)
                total_syscalls = len(analyzer.syscalls)
                position_ratio = sc.index / total_syscalls
                if 0.2 < position_ratio < 0.8:  # Middle 60%
                    priority_score += 20

                io_candidates.append({
                    'index': sc.index,
                    'name': sc.name,
                    'retval': int(sc.retval) if hasattr(sc, 'retval') else 0,
                    'priority': priority_score
                })

        # ✅ Sort by priority and limit count
        io_candidates.sort(key=lambda x: x['priority'], reverse=True)
        selected = io_candidates[:max_fork_points]

        # Return list of indices
        result = [item['index'] for item in selected]

        if result:
            print(f"[DynamicForkController] ✅ Selected {len(result)}/{len(io_candidates)} IO syscalls as fork points:")
            for item in selected:
                print(f"  - syscall[{item['index']}] {item['name']}: retval={item['retval']}, priority={item['priority']:.0f}")

        return result

    def _select_diverse_fork_point(self, io_syscalls: list, iteration_id: int) -> int:
        """
        Select diverse fork points to avoid getting stuck in restricted local optima.

        Strategy:
        1. Rotation: Cycle through available IO syscalls.
        2. Tiered exploration: Target early/mid/late phases based on iteration.
        3. Random perturbation: Add jitter to selection.
        4. (Future) PathFinder integration: Prioritize CFG-guided hotspots.

        Args:
            io_syscalls: List of available IO syscall indices
            iteration_id: Current iteration ID

        Returns:
            Selected fork point index
        """
        if not io_syscalls:
            return 10  # Default fallback

        # Strategy 1: Iteration ID based rotation algorithm
        base_index = iteration_id % len(io_syscalls)

        # Strategy 2: Tiered exploration - Select different regions based on iteration phase
        if iteration_id < 10:
            # Early phase: Explore early IO syscalls
            region_start = 0
            region_end = min(3, len(io_syscalls))
        elif iteration_id < 30:
            # Mid phase: Explore middle part
            region_start = len(io_syscalls) // 3
            region_end = min(len(io_syscalls) * 2 // 3 + 1, len(io_syscalls))
        else:
            # Late phase: Explore all syscalls, focusing on the latter part
            region_start = max(0, len(io_syscalls) - 5)
            region_end = len(io_syscalls)

        # Selection within the chosen region
        if region_end > region_start:
            region_syscalls = io_syscalls[region_start:region_end]
            target_index = base_index % len(region_syscalls)
            fork_point = region_syscalls[target_index]
        else:
            fork_point = io_syscalls[base_index]

        # Strategy 3: Random perturbation (20% probability)
        if random.random() < 0.2:
            fork_point = random.choice(io_syscalls)

        # Strategy 4: PathFinder integration (if available)
        # TODO: Integrate PathFinder hotspot analysis in the future

        # Ensure minimum value
        return max(10, fork_point)

    def _mutation_from_recipe(self, recipe: Dict) -> List:
        """
        Generate mutation from recipe
        
        Args:
            recipe: Recipe dict
        
        Returns:
            Mutation instruction list
        """
        # ✅ Reuse SmartMutator recipe support
        # TODO: Implement recipe to instruction conversion
        # Currently simplified: use mutator to generate
        return self.mutator.mutate(None)
    
    def get_statistics(self) -> Dict:
        """Get statistics"""
        return self.stats.copy()
    
    def print_summary(self):
        """Print exploration summary"""
        print(f"\n{'='*60}")
        print(f"Dynamic Fork Exploration Summary")
        print(f"{'='*60}")
        print(f"  Total multi-forks:     {self.stats['total_multi_forks']}")
        print(f"  Total variants tested: {self.stats['total_variants_tested']}")
        print(f"  New paths discovered:  {self.stats['new_paths_discovered']}")
        
        if self.stats['total_variants_tested'] > 0:
            success_rate = self.stats['new_paths_discovered'] / self.stats['total_variants_tested'] * 100
            print(f"  Success rate:          {success_rate:.1f}%")
        
        print(f"{'='*60}\n")


# Test code
if __name__ == '__main__':
    print("DynamicForkController module loaded successfully")


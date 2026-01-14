#!/usr/bin/env python3
"""
DualLevelPathFinder - Dual-level CFG Architecture Implementation

Implements dual-layer control flow graph analysis for BB-level and Syscall-level,
resolving inaccuracies in syscall index mapping.
"""

import os
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple, Any, Optional
from collections import defaultdict
import logging

# Add parent directory to path if needed (though usually conductor/ is in path)
# Add parent directory to path if needed (though usually conductor/ is in path)
try:
    from .syscall_block import SyscallBlock
    from .async_logger import alog
    from .conductor_types import MutationRecipe
except ImportError:
    # Standalone/Script usage fallback
    from syscall_block import SyscallBlock
    from async_logger import alog
    from conductor_types import MutationRecipe


class DualLevelPathFinder:
    """PathFinder implementation with dual-level CFG"""

    def __init__(self, target_binary: str, config=None):
        """
        Args:
            target_binary: Path to target binary
            config: PathFinder configuration (optional)
        """
        self.target_binary = target_binary
        self.config = config
        # self.logger = self._setup_logger() # Replaced by alog

        # Layer 2: Syscall-level CFG
        self.syscall_blocks: Dict[int, SyscallBlock] = {}  # syscall_idx → block
        self.syscall_edges: Set[Tuple[int, int]] = set()  # (from_idx, to_idx)

        # Mapping: BB → Syscall Block
        self.bb_to_syscall: Dict[int, int] = {}  # bb_addr → syscall_idx

        # Exploration targets (for when graph is saturated)
        self.exploration_targets: List[Dict] = []

        # Statistics
        self.stats = {
            'total_blocks': 0,
            'total_edges': 0,
            'total_bbs': 0,
        }

        # Cache for tree files: path -> (mtime, size, nodes_data, blocks, map)
        self._tree_cache = {}

        # Layer 3: Static CFG (from angr)
        self.static_branches: List[Dict] = []
        self.bb_to_func: Dict[int, str] = {}
        
        self.available = True

    # def _setup_logger(self) -> logging.Logger:
    #     """Setup logger"""
    #     # Replaced by alog
    #     pass

    def load_syscall_tree(self, tree_file: str = "/tmp/syscall_tree.json") -> bool:
        """
        Load precise BB->Syscall mapping from syscall tree JSON exported from C-side.
        """
        if not os.path.exists(tree_file):
            alog(f"Syscall tree file not found: {tree_file}", "PathFinder", "WARN")
            alog(f"Hint: Ensure C-side code has exported syscall tree", "PathFinder", "WARN")
            return False

        import json
        import re
        
        try:
            # 1. Check cache (Check mtime/size to avoid redundant parsing)
            stat = os.stat(tree_file)
            mtime = stat.st_mtime
            size = stat.st_size
            
            if tree_file in self._tree_cache:
                c_mtime, c_size, c_data = self._tree_cache[tree_file]
                if c_mtime == mtime and c_size == size:
                    # ✅ Cache Hit: Skip parsing, but still need to restore state if needed
                    # However, if we are in the same process, self.syscall_blocks might already be populated.
                    if self.syscall_blocks:
                         # alog(f"♻️ PathFinder state already active for {tree_file}", "PathFinder", "DEBUG")
                         return True
                    
                    # If state was lost but cache data exists, rebuild from cached data
                    tree_data = c_data
                    alog(f"♻️ Using cached tree data for {tree_file}", "PathFinder", "DEBUG")
                else:
                    tree_data = None
            else:
                tree_data = None

            if tree_data is None:
                # 2. Parse tree_file (Handle HTML bundle or pure JSON)
                with open(tree_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # HTML bundle parsing
                if 'treeData =' in content:
                    match_start = re.search(r'(?:const|var)\s+treeData\s*=\s*', content)
                    if match_start:
                        start_idx = match_start.end()
                        end_idx = content.find(';\n', start_idx)
                        if end_idx == -1: end_idx = content.find('};', start_idx) + 1
                        
                        json_str = content[start_idx:end_idx].strip()
                        try:
                            tree_data = json.loads(json_str)
                        except:
                            # Robust recovery for complex HTML
                            brace_count = 0
                            for i, char in enumerate(content[start_idx:], start=start_idx):
                                if char == '{': brace_count += 1
                                elif char == '}': 
                                    brace_count -= 1
                                    if brace_count == 0:
                                        tree_data = json.loads(content[start_idx:i+1])
                                        break
                else:
                    tree_data = json.loads(content)

                if not tree_data:
                    alog(f"Could not parse valid JSON from {tree_file}", "PathFinder", "WARN")
                    return False
                
                # Save to cache
                self._tree_cache[tree_file] = (mtime, size, tree_data)

            # 3. Process nodes and build graph
            nodes = tree_data.get('nodes', [])
            if not nodes:
                alog(f"Syscall tree is empty: {tree_file}", "PathFinder", "WARN")
                return False
            
            self.syscall_blocks.clear()
            self.bb_to_syscall.clear()
            self.syscall_edges.clear()
            
            # Map node_id -> block for edge creation
            id_to_block = {}
            for node in nodes:
                idx = node.get('syscall_index', -1)
                if idx < 0: continue
                
                block = SyscallBlock(idx, node.get('syscall_name', 'unknown'))
                block.bb_addrs = node.get('bb_addresses', [])
                # ✅ Mark covered if in the tree (the tree represents an ACTUAL execution)
                block.is_covered = True 
                
                self.syscall_blocks[idx] = block
                id_to_block[node.get('id', -1)] = block
                
                # Build BB map
                for addr in block.bb_addrs:
                    if isinstance(addr, str):
                        try: addr = int(addr, 16)
                        except: continue
                    self.bb_to_syscall[addr] = idx

            # Build edges
            for node in nodes:
                nid = node.get('id', -1)
                pid = node.get('parent_id', -1)
                if nid in id_to_block and pid in id_to_block:
                    child = id_to_block[nid]
                    parent = id_to_block[pid]
                    parent.add_successor(child)
                    child.add_predecessor(parent)
                    self.syscall_edges.add((parent.syscall_index, child.syscall_index))

            # Statistics
            self.stats['total_blocks'] = len(self.syscall_blocks)
            self.stats['total_edges'] = len(self.syscall_edges)
            self.stats['total_bbs'] = len(self.bb_to_syscall)
            
            alog(f"✅ Syscall tree loaded and initialized:", "PathFinder", "INFO")
            alog(f"  - Nodes: {len(nodes)}", "PathFinder", "INFO")
            alog(f"  - Initialized Blocks: {len(self.syscall_blocks)}", "PathFinder", "INFO")
            alog(f"  - Edges: {len(self.syscall_edges)}", "PathFinder", "INFO")
            alog(f"  - BB Mappings: {len(self.bb_to_syscall)}", "PathFinder", "INFO")
            
            return True

        except Exception as e:
            alog(f"Failed to load syscall tree: {e}", "PathFinder", "ERROR")
            return False

    def load_static_cfg(self, cfg_file: str) -> bool:
        """Load whole-program static CFG data exported from StaticAnalyzer."""
        if not os.path.exists(cfg_file):
            return False
        
        import json
        try:
            with open(cfg_file, 'r') as f:
                data = json.load(f)
            
            self.static_branches = data.get('branches', [])
            self.bb_to_func = data.get('bb_to_func', {})
            
            # Convert keys to int (json keys are strings)
            self.bb_to_func = {int(k): v for k, v in self.bb_to_func.items()}
            
            alog(f"✅ Static CFG loaded: {len(self.static_branches)} branches", "PathFinder", "INFO")
            return True
        except Exception as e:
            alog(f"Failed to load static CFG: {e}", "PathFinder", "ERROR")
            return False

    def mark_nodes_covered(self, tree_file: str) -> int:
        """
        Redundant with new load_syscall_tree which marks all nodes in tree as covered.
        Keeping for compatibility but making it a no-op if already loaded.
        """
        return 0

    def build_dual_cfg(self, trace_file: str, analyzer: Optional[Any] = None) -> bool:
        """
        Build dual-level CFG from trace file

        Args:
            trace_file: Path to trace file
            analyzer: Existing TraceAnalyzer instance (optional)

        Returns:
            True if successfully built, False otherwise
        """
        alog("Starting dual-level CFG build...", "PathFinder", "INFO")

        try:
            # Import TraceAnalyzer
            from trace_analyzer import TraceAnalyzer

            # Parse trace
            if not analyzer:
                from trace_analyzer import TraceAnalyzer
                analyzer = TraceAnalyzer(trace_file)
                if not analyzer.analyze():
                    alog("TraceAnalyzer parsing failed", "PathFinder", "ERROR")
                    return False
            
            # Check BB trace
            if not analyzer.has_bb_trace() or not analyzer.bb_trace_parser:
                alog("Missing BB trace, using simplified mode", "PathFinder", "WARN")
                return self._build_syscall_only_cfg(analyzer)
            
            # Build Syscall-level CFG
            self._build_syscall_cfg(analyzer)
            
            alog(f"✅ Dual-level CFG build complete:", "PathFinder", "INFO")
            alog(f"  - Syscall blocks: {len(self.syscall_blocks)}", "PathFinder", "INFO")
            alog(f"  - Syscall edges: {len(self.syscall_edges)}", "PathFinder", "INFO")
            alog(f"  - BB mappings: {len(self.bb_to_syscall)}", "PathFinder", "INFO")

            return True

        except Exception as e:
            alog(f"Dual-level CFG build failed: {e}", "PathFinder", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def _build_syscall_cfg(self, analyzer):
        """
        Build Syscall-level CFG from TraceAnalyzer

        Args:
            analyzer: TraceAnalyzer instance
        """
        syscalls = analyzer.syscalls
        bb_entries = analyzer.bb_trace_parser.entries

        # Step 1: Create all SyscallBlocks
        for syscall in syscalls:
            idx = syscall.index
            block = SyscallBlock(
                syscall_index=idx,
                syscall_name=syscall.name,
            )
            block.syscall_args = getattr(syscall, 'args', [])
            block.syscall_retval = getattr(syscall, 'retval', 0)
            self.syscall_blocks[idx] = block

        # Step 2: Assign BBs to corresponding SyscallBlocks
        for bb_entry in bb_entries:
            bb_addr = bb_entry.pc
            syscall_idx = bb_entry.syscall_idx

            if syscall_idx >= 0 and syscall_idx in self.syscall_blocks:
                self.syscall_blocks[syscall_idx].add_bb(bb_addr)
                self.bb_to_syscall[bb_addr] = syscall_idx

        # Step 3: Build Syscall-level control flow edges
        self._build_syscall_edges(bb_entries)

        # Update statistics
        self.stats['total_blocks'] = len(self.syscall_blocks)
        self.stats['total_edges'] = len(self.syscall_edges)
        self.stats['total_bbs'] = len(self.bb_to_syscall)

    def _build_syscall_edges(self, bb_entries: List):
        """
        Analyze control flow edges between syscalls

        Strategy: Create edges when syscall_idx changes in BB trace
        """
        prev_syscall_idx = None

        for bb_entry in bb_entries:
            curr_syscall_idx = bb_entry.syscall_idx

            if curr_syscall_idx < 0:
                continue

            # Detect syscall boundary crossing
            if prev_syscall_idx is not None and prev_syscall_idx != curr_syscall_idx:
                if prev_syscall_idx in self.syscall_blocks and curr_syscall_idx in self.syscall_blocks:
                    # Create edge
                    edge = (prev_syscall_idx, curr_syscall_idx)
                    if edge not in self.syscall_edges:
                        self.syscall_edges.add(edge)

                        # Update successors/predecessors of SyscallBlock
                        prev_block = self.syscall_blocks[prev_syscall_idx]
                        curr_block = self.syscall_blocks[curr_syscall_idx]
                        prev_block.add_successor(curr_block)
                        curr_block.add_predecessor(prev_block)

            prev_syscall_idx = curr_syscall_idx

    def _build_syscall_only_cfg(self, analyzer) -> bool:
        """
        Build syscall-only CFG (Fallback plan when BB trace is missing)

        Args:
            analyzer: TraceAnalyzer instance
        """
        syscalls = analyzer.syscalls

        # Create SyscallBlocks
        for syscall in syscalls:
            idx = syscall.index
            block = SyscallBlock(
                syscall_index=idx,
                syscall_name=syscall.name,
            )
            block.syscall_args = getattr(syscall, 'args', [])
            block.syscall_retval = getattr(syscall, 'retval', 0)
            self.syscall_blocks[idx] = block

        # Build linear edges (syscalls execute in order)
        for i in range(len(syscalls) - 1):
            curr_idx = syscalls[i].index
            next_idx = syscalls[i + 1].index

            if curr_idx in self.syscall_blocks and next_idx in self.syscall_blocks:
                edge = (curr_idx, next_idx)
                self.syscall_edges.add(edge)

                curr_block = self.syscall_blocks[curr_idx]
                next_block = self.syscall_blocks[next_idx]
                curr_block.add_successor(next_block)
                next_block.add_predecessor(curr_block)

        self.stats['total_blocks'] = len(self.syscall_blocks)
        self.stats['total_edges'] = len(self.syscall_edges)

        alog(f"✅ Syscall-only CFG build complete: {len(self.syscall_blocks)} blocks", "PathFinder", "INFO")
        return True


    def validate_transition(self, current_syscall_idx: int, next_syscall_idx: int) -> int:
        """
        [Validator] Check if a transition is valid according to the Static CFG.
        
        Args:
            current_syscall_idx: The current syscall node index
            next_syscall_idx: The proposed next syscall node index
            
        Returns:
            int: A score representing the validity (see VALIDATION_SCORE constants).
        """
        try:
            from .constants import VALIDATION_SCORE_KNOWN, VALIDATION_SCORE_UNKNOWN, VALIDATION_SCORE_INVALID
        except ImportError:
            from constants import VALIDATION_SCORE_KNOWN, VALIDATION_SCORE_UNKNOWN, VALIDATION_SCORE_INVALID

        # 1. Check if current node is known
        if current_syscall_idx not in self.syscall_blocks:
            # Unknown state - return UNKNOWN instead of FALSE to allow exploration
            return VALIDATION_SCORE_UNKNOWN
            
        block = self.syscall_blocks[current_syscall_idx]
        
        # 2. Check cached edge set for O(1) lookup
        if (current_syscall_idx, next_syscall_idx) in self.syscall_edges:
            return VALIDATION_SCORE_KNOWN
            
        # 3. Double check successors list
        for succ in block.successors:
            if succ.syscall_index == next_syscall_idx:
                return VALIDATION_SCORE_KNOWN
                
        # 4. If not known, it's an "Unknown Transition" (Exploration opportunity)
        return VALIDATION_SCORE_UNKNOWN

    def find_uncovered_syscall_branches(self, covered_bbs: Set[int]) -> List[Dict[str, Any]]:
        """
        Find uncovered syscall-level branches

        Args:
            covered_bbs: Set of covered BB addresses

        Returns:
            List of uncovered syscall branches
        """
        if not self.syscall_blocks:
            return []

        # Step 1: Map BB coverage to Syscall coverage
        covered_syscalls = set()
        matched_bb_count = 0
        for bb_addr in covered_bbs:
            if bb_addr in self.bb_to_syscall:
                syscall_idx = self.bb_to_syscall[bb_addr]
                covered_syscalls.add(syscall_idx)
                matched_bb_count += 1
        
        alog(f"Coverage Mapping Analysis: BBs={len(covered_bbs)}, Matched BBs={matched_bb_count}, Mapped Syscalls={len(covered_syscalls)}", "PathFinder", "DEBUG")

        # Newly covered blocks count
        newly_covered_blocks = 0
        for idx in covered_syscalls:
            if idx in self.syscall_blocks:
                if not self.syscall_blocks[idx].is_covered:
                    self.syscall_blocks[idx].is_covered = True
                    newly_covered_blocks += 1

        uncovered_branches = []

        # Step 2: Find uncovered static branches (BB-level)
        static_uncovered = 0
        for branch in self.static_branches:
            src = branch['src_addr']
            if src in covered_bbs:
                # Source is covered, check targets
                for target in branch['targets']:
                    if target not in covered_bbs:
                        # Found an uncovered static branch!
                        # Map back to nearest syscall if possible
                        syscall_idx = self.bb_to_syscall.get(src, -1)
                        if syscall_idx != -1:
                            uncovered_branches.append({
                                'from_addr': hex(src),
                                'to_addr': hex(target),
                                'type': 'static_branch',
                                'from_syscall_idx': syscall_idx,
                                'target_syscall_idx': syscall_idx,
                                'description': f"Static branch in {self.bb_to_func.get(src, 'unknown')}",
                                'has_syscall': True
                            })
                            static_uncovered += 1
                        break
        
        if static_uncovered > 0:
            alog(f"Added {static_uncovered} static-only branches to exploration set", "PathFinder", "INFO")

        # Step 3: Find uncovered syscall branches (Syscall-level)
        # (Append to existing list)

        # Iterate through all covered syscall blocks
        total_successors = 0
        for syscall_idx in self.syscall_blocks:
            block = self.syscall_blocks[syscall_idx]
            
            # Only check successors of covered blocks
            if not block.is_covered:
                continue
            
            # Check each successor
            for succ_block in block.successors:
                total_successors += 1
                if not succ_block.is_covered:
                    # Uncovered branch
                    branch = {
                        'from_syscall_idx': block.syscall_index,
                        'to_syscall_idx': succ_block.syscall_index,
                        'from_syscall_name': block.syscall_name,
                        'to_syscall_name': succ_block.syscall_name,
                        'type': 'syscall_edge',
                        'target_syscall_idx': block.syscall_index,  # Use source syscall for mutation
                        'has_syscall': True,
                    }
                    uncovered_branches.append(branch)

        alog(f"Found {len(uncovered_branches)} uncovered branches (Analyzed {total_successors} edges)", "PathFinder", "INFO")
        alog(f"  Covered syscalls: {sum(1 for b in self.syscall_blocks.values() if b.is_covered)}/{len(self.syscall_blocks)}", "PathFinder", "INFO")
        return uncovered_branches

    def generate_syscall_recipes(self, uncovered_branches: List[Dict[str, Any]]) -> List[MutationRecipe]:
        """
        Generate recipes for uncovered syscall branches

        Args:
            uncovered_branches: List of uncovered branches

        Returns:
            List of MutationRecipe objects
        """
        recipes = []

        for i, branch in enumerate(uncovered_branches):
            from_idx = branch['from_syscall_idx']

            # Get detailed info of source syscall block
            if from_idx not in self.syscall_blocks:
                continue
            
            from_block = self.syscall_blocks[from_idx]
            
            # Build MutationRecipe
            recipe = MutationRecipe(
                source_branch=from_idx,
                target_branch=branch.get('to_syscall_idx', -1),
                syscall_index=from_idx,
                mutation_type=self._infer_mutation_type(from_block.syscall_name),
                description=branch.get('description', f"Trigger path from {from_block.syscall_name}"),
                priority=10
            )

            recipes.append(recipe)

        alog(f"Generated {len(recipes)} precise syscall recipes (MutationRecipe)", "PathFinder", "INFO")
        return recipes

    def _infer_mutation_type(self, syscall_name: str) -> str:
        """Infer mutation strategy based on syscall type"""
        if syscall_name in ['read', 'write', 'recv', 'send']:
            return 'FUZZ_CMD_EXTEND'
        elif syscall_name in ['open', 'openat']:
            return 'FUZZ_CMD_MUTATE_FLAGS'
        elif syscall_name in ['mmap', 'mprotect']:
            return 'FUZZ_CMD_MUTATE_ARG'
        else:
            return 'FUZZ_CMD_INTERESTING_VALUES'

    def _infer_arg_index(self, syscall_name: str) -> int:
        """Infer which argument to mutate"""
        if syscall_name in ['read', 'write', 'recv', 'send']:
            return 2  # count parameter
        elif syscall_name in ['open', 'openat']:
            return 1  # flags parameter
        return 0  # Default to first parameter

    def is_available(self) -> bool:
        """
        Check if PathFinder is available
        Dual-level CFG uses lazy building, available after initialization
        """
        return self.available

    def ensure_cfg_ready(self) -> bool:
        """
        Ensure CFG is ready (compatibility method)
        Dual-level CFG uses lazy building, always available after initialization
        """
        return True

    def build_from_trace(self, trace_file: str, analyzer: Optional[Any] = None) -> bool:
        """
        Build CFG from trace (compatibility method)
        Compatible with original PathFinder interface, calls build_dual_cfg internally
        """
        return self.build_dual_cfg(trace_file, analyzer=analyzer)

    def enhance_from_trace_files(
        self,
        syscall_trace_file: str,
        bb_trace_file: str,
        covered_set: Optional[Set[int]] = None
    ) -> int:
        """
        Enhance CFG: Update syscall-level coverage and edges using BB trace
        
        Args:
            syscall_trace_file: Syscall trace path (unused, compatibility parameter)
            bb_trace_file: BB trace file path (.bbl)
            covered_set: Covered BB set (optional optimization)
            
        Returns:
            int: Number of new syscall nodes mapped
        """
        import struct
        from .bb_trace_parser import BBTraceParser
        
        if not os.path.exists(bb_trace_file):
            return 0
            
        mapped_count = 0
        last_syscall_idx = -1
        
        try:
            # Use shared parser to handle correct struct size (16 bytes)
            parser = BBTraceParser(bb_trace_file)
            if not parser.parse():
                alog(f"Failed to parse BB trace: {bb_trace_file}", "PathFinder", "ERROR")
                return 0
                
            for entry in parser.entries:
                syscall_idx = entry.syscall_idx
                
                # Dynamic Learning: Update BB -> Syscall mapping from trace
                # This is crucial if static analysis didn't provide BB addresses
                self.bb_to_syscall[entry.pc] = syscall_idx
                
                # Try mapping BB -> Syscall (Dynamic)
                if syscall_idx >= 0 and syscall_idx in self.syscall_blocks:
                    block = self.syscall_blocks[syscall_idx]
                    
                    # 1. Mark covered
                    if not block.is_covered:
                        block.is_covered = True
                        mapped_count += 1
                    
                    # 2. Build syscall-level edge (CFG Edge)
                    if last_syscall_idx >= 0 and last_syscall_idx != syscall_idx:
                        # Add predecessor/successor relationship
                        if last_syscall_idx in self.syscall_blocks:
                            last_block = self.syscall_blocks[last_syscall_idx]
                            
                            # Avoid duplicate addition
                            exists = False
                            for succ in last_block.successors:
                                if succ.syscall_index == syscall_idx:
                                    exists = True
                                    break
                            
                            if not exists:
                                last_block.add_successor(block)
                                block.add_predecessor(last_block)
                                self.syscall_edges.add((last_syscall_idx, syscall_idx))
                                
                    last_syscall_idx = syscall_idx
            
            # Also update bb_to_syscall map from trace if needed
            # (Optional: might not be needed if we trust the trace's syscall_idx)
                        
            return mapped_count
            
        except Exception as e:
            alog(f"CFG enhancement failed: {e}", "PathFinder", "ERROR")
            import traceback
            traceback.print_exc()
            return 0

    def find_uncovered_branches(self, covered_bbs: Set[int]) -> List[Dict[str, Any]]:
        """
        Find uncovered branches (compatibility method)
        Internal call to find_uncovered_syscall_branches
        """
        return self.find_uncovered_syscall_branches(covered_bbs)

    def generate_recipes(
        self,
        uncovered_branches: List[Dict[str, Any]],
        max_recipes: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate recipes (compatibility method)
        Internal call to generate_syscall_recipes
        """
        if max_recipes and len(uncovered_branches) > max_recipes:
            uncovered_branches = uncovered_branches[:max_recipes]
        return self.generate_syscall_recipes(uncovered_branches)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics"""
        return self.stats.copy()

    def export_cfg(self, output_file: str):
        """
        Export CFG to JSON format

        Args:
            output_file: Path to output file
        """
        import json

        cfg_data = {
            'syscall_blocks': {
                idx: block.to_dict()
                for idx, block in self.syscall_blocks.items()
            },
            'syscall_edges': list(self.syscall_edges),
            'stats': self.stats,
        }

        with open(output_file, 'w') as f:
            json.dump(cfg_data, f, indent=2)

        alog(f"CFG exported to: {output_file}", "PathFinder", "INFO")

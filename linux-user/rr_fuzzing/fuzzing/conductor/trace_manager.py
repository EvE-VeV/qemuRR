#!/usr/bin/env python3
"""
TraceManager - Layer 1: Trace Storage Management

Manages the trace pool and provides trace selection strategies.
Implements the architecture described in DETAILED_ARCHITECTURE.md Layer 1.
"""

import os
import json
import time
import random
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class TraceMetadata:
    """Metadata for a single trace"""
    creation_time: float
    parent_trace_id: Optional[str] = None
    mutation_applied: List[Dict] = field(default_factory=list)
    energy: float = 1.0
    exec_count: int = 0
    new_coverage_count: int = 0


@dataclass
class Trace:
    """
    Single Trace Object
    
    Represents a recorded execution trace that can be replayed
    and mutated during fuzzing.
    """
    id: str
    file_path: str
    metadata: TraceMetadata
    
    def __post_init__(self):
        """Validate trace file exists"""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Trace file not found: {self.file_path}")


class TraceManager:
    """
    Layer 1: Trace Storage Manager
    
    Responsibilities:
    1. Manage trace pool (add, remove, select traces)
    2. Track coverage information per trace
    3. Implement AFL-style energy-based selection
    4. Maintain active traces (high-energy subset)
    5. 新增：收集syscall级别的执行统计
    
    Architecture: DETAILED_ARCHITECTURE.md Line 18-51
    """
    
    def __init__(self, initial_trace: Optional[str] = None):
        """
        Initialize TraceManager
        
        Args:
            initial_trace: Path to initial trace file (seed)
        """
        self.trace_pool: List[Trace] = []
        self.active_traces: List[Trace] = []  # High-energy traces
        self.coverage_map: Dict[str, Dict] = {}  # trace_id -> coverage_info
        
        # Statistics
        self.total_traces = 0
        self.traces_saved = 0
        
        # Selection parameters
        self.exploit_probability = 0.8  # 80% exploit, 20% explore
        
        # ✅ 新增：Syscall级别的执行统计
        # 格式: {trace_id: {syscall_index: {exec_count, fork_count, mutations, ...}}}
        self.syscall_stats: Dict[str, Dict[int, Dict]] = {}
        
        # ✅ P0 FIX: 多样性追踪 - 记住上次选择的trace
        self._last_selected_id: Optional[str] = None
        
        # Add initial trace if provided
        if initial_trace:
            self.add_initial_trace(initial_trace)
    
    def add_initial_trace(self, trace_file: str):
        """Add the initial seed trace"""
        trace_id = "trace_000"
        metadata = TraceMetadata(
            creation_time=time.time(),
            parent_trace_id=None,
            energy=3.0  # ✅ P0 FIX: 降低initial trace energy (10.0→3.0) 提高多样性
        )
        
        trace = Trace(
            id=trace_id,
            file_path=trace_file,
            metadata=metadata
        )
        
        self.trace_pool.append(trace)
        self.active_traces.append(trace)
        self.total_traces += 1
        
        print(f"[TraceManager] Added initial trace: {trace_id}")
    
    def add_trace(self, trace_file: str, coverage_info: Dict, 
                  parent_id: Optional[str] = None, 
                  mutations: Optional[List] = None) -> Trace:
        """
        Add a new trace to the pool
        
        Args:
            trace_file: Path to trace file
            coverage_info: Coverage information from execution
            parent_id: Parent trace ID (if mutated from another trace)
            mutations: List of mutations applied
        
        Returns:
            Trace: The created trace object
        """
        trace_id = f"trace_{self.total_traces:06d}"
        
        metadata = TraceMetadata(
            creation_time=time.time(),
            parent_trace_id=parent_id,
            mutation_applied=mutations or [],
            energy=1.0,
            new_coverage_count=coverage_info.get('new_edge_count', 0)
        )
        
        trace = Trace(
            id=trace_id,
            file_path=trace_file,
            metadata=metadata
        )
        
        self.trace_pool.append(trace)
        self.coverage_map[trace_id] = coverage_info
        self.total_traces += 1
        self.traces_saved += 1
        
        # Add to active traces if it found new coverage
        if coverage_info.get('has_new_edges', False):
            self.active_traces.append(trace)
            self._prune_active_traces()
        
        print(f"[TraceManager] Added trace: {trace_id} "
              f"(new_coverage={coverage_info.get('has_new_edges', False)})")
        
        return trace
    
    def select_trace(self) -> Optional[Trace]:
        """
        ✅ 改进的trace选择策略 - 增加diversity，减少重复
        
        Strategy:
        - 60% probability: Select from active_traces (exploitation) - 降低从80%
        - 40% probability: Select from entire trace_pool (exploration) - 提高从20%
        - 使用更激进的权重衰减 (1.5→2.0)
        - 添加多样性惩罚 (避免连续选择同一trace)
        - 对新发现的trace给予更高权重
        
        Returns:
            Trace: Selected trace or None if pool is empty
        """
        if not self.trace_pool:
            return None
        
        # ✅ 改进1: 降低exploitation比例，提高exploration
        exploit_prob = 0.60  # 从0.8降低到0.6
        
        # Decide: Exploit or Explore
        if random.random() < exploit_prob and self.active_traces:
            # Exploit: Select from high-energy traces
            pool = self.active_traces
            source = "active"
        else:
            # Explore: Select from all traces
            pool = self.trace_pool
            source = "all"
        
        # ✅ 改进2: 更激进的权重衰减 + 多样性惩罚
        weights = []
        for trace in pool:
            # 基础energy
            base_energy = trace.metadata.energy
            
            # ✅ 对新trace给予3倍权重boost
            if trace.metadata.new_coverage_count > 0:
                base_energy *= 3.0
            
            # ✅ P0 FIX: 更激进的衰减：1.5 → 2.0
            # 这样高exec_count的trace权重会快速下降
            exec_penalty = (1 + trace.metadata.exec_count) ** 2.0
            
            # ✅ P0 FIX: 多样性惩罚 - 避免连续选择同一个trace
            diversity_penalty = 1.0
            if trace.id == self._last_selected_id:
                diversity_penalty = 0.1  # ✅ 加强惩罚: 0.3→0.1 (权重降到10%)
            
            energy = (base_energy / exec_penalty) * diversity_penalty
            weights.append(max(energy, 0.01))  # 确保最小权重
        
        # Select trace
        if sum(weights) == 0:
            # Fallback to uniform selection
            selected = random.choice(pool)
        else:
            selected = random.choices(pool, weights=weights)[0]
        
        # Update exec count
        selected.metadata.exec_count += 1
        
        # ✅ P0 FIX: 记住这次选择，用于下次的多样性惩罚
        self._last_selected_id = selected.id
        
        print(f"[TraceManager] Selected trace: {selected.id} from {source} pool "
              f"(exec_count={selected.metadata.exec_count}, energy={selected.metadata.energy:.2f})")
        
        return selected
    
    def get_trace_by_id(self, trace_id: str) -> Optional[Trace]:
        """Get trace by ID"""
        for trace in self.trace_pool:
            if trace.id == trace_id:
                return trace
        return None
    
    def remove_trace(self, trace_id: str):
        """Remove trace from pool (rarely used)"""
        self.trace_pool = [t for t in self.trace_pool if t.id != trace_id]
        self.active_traces = [t for t in self.active_traces if t.id != trace_id]
        
        if trace_id in self.coverage_map:
            del self.coverage_map[trace_id]
    
    def _prune_active_traces(self, max_active: int = 100):
        """Prune active traces to limit size (keep most energetic)"""
        if len(self.active_traces) <= max_active:
            return
        
        # Sort by energy and new_coverage_count
        self.active_traces.sort(
            key=lambda t: (t.metadata.new_coverage_count, t.metadata.energy),
            reverse=True
        )
        
        # Keep top N
        self.active_traces = self.active_traces[:max_active]
    
    def get_statistics(self) -> Dict:
        """Get TraceManager statistics"""
        return {
            'total_traces': self.total_traces,
            'trace_pool_size': len(self.trace_pool),
            'active_traces': len(self.active_traces),
            'traces_saved': self.traces_saved
        }
    
    def record_execution(self, trace_id: str, trace_file: str, mutations: list, 
                         has_new_coverage: bool = False):
        """
        ✅ P0 FIX: 记录一次trace执行（包括所有syscall的统计，不仅仅是被mutate的）
        
        Args:
            trace_id: Trace ID
            trace_file: Trace文件路径（用于解析所有syscalls）
            mutations: List of FuzzInstructions applied
            has_new_coverage: Whether new coverage was found
        """
        # 初始化trace的syscall_stats（如果不存在）
        if trace_id not in self.syscall_stats:
            self.syscall_stats[trace_id] = {}
        
        # ✅ NEW: 解析trace文件，获取所有syscalls
        # 这样可以记录所有执行的syscalls，不仅仅是被mutate的
        try:
            import sys
            from pathlib import Path
            analysis_path = Path(__file__).parent.parent / 'analysis'
            if str(analysis_path) not in sys.path:
                sys.path.insert(0, str(analysis_path))
            
            from trace_analyzer import TraceAnalyzer
            analyzer = TraceAnalyzer(trace_file)
            
            # ✅ 记录所有syscalls的基础执行统计
            for i, sc in enumerate(analyzer.syscalls):
                if i not in self.syscall_stats[trace_id]:
                    self.syscall_stats[trace_id][i] = {
                        'exec_count': 0,
                        'fork_count': 0,
                        'mutation_applied': False,
                        'mutation_types': [],
                        'arg_modifications': {},
                        'new_coverage': 0,
                        'syscall_name': sc.name,
                        'syscall_nr': sc.syscall_nr  # ✅ FIX: 使用syscall_nr而不是nr
                    }
                
                # 增加执行计数（每个syscall都被记录）
                self.syscall_stats[trace_id][i]['exec_count'] += 1
        
        except Exception as e:
            # 如果解析失败，回退到只记录mutations
            print(f"[TraceManager] ⚠️  Failed to parse trace for full stats: {e}")
        
        # ✅ 更新受mutation影响的syscall统计（额外的mutation信息）
        for mutation in mutations:
            syscall_idx = mutation.syscall_index
            
            # 确保该syscall存在于stats中
            if syscall_idx not in self.syscall_stats[trace_id]:
                self.syscall_stats[trace_id][syscall_idx] = {
                    'exec_count': 1,
                    'fork_count': 0,
                    'mutation_applied': False,
                    'mutation_types': [],
                    'arg_modifications': {},
                    'new_coverage': 0
                }
            
            stat = self.syscall_stats[trace_id][syscall_idx]
            
            # 标记mutation相关信息
            stat['fork_count'] += 1  # 每次mutation都会fork
            stat['mutation_applied'] = True
            
            # 记录mutation类型
            cmd_name = self._get_mutation_name(mutation.cmd)
            if cmd_name not in stat['mutation_types']:
                stat['mutation_types'].append(cmd_name)
            
            # 记录参数修改
            arg_key = f"arg[{mutation.arg_index}]"
            if arg_key not in stat['arg_modifications']:
                stat['arg_modifications'][arg_key] = {
                    'modification_count': 0,
                    'mutation_commands': []
                }
            stat['arg_modifications'][arg_key]['modification_count'] += 1
            if cmd_name not in stat['arg_modifications'][arg_key]['mutation_commands']:
                stat['arg_modifications'][arg_key]['mutation_commands'].append(cmd_name)
            
            # 如果发现新coverage，记录
            if has_new_coverage:
                stat['new_coverage'] += 1
    
    def _get_mutation_name(self, cmd: int) -> str:
        """将mutation命令转换为名称"""
        from .constants import (
            FUZZ_CMD_FLIP_BITS, FUZZ_CMD_LIGHT_MUTATION, FUZZ_CMD_INTERESTING_VALUES,
            FUZZ_CMD_BOUNDARY_VALUE, FUZZ_CMD_TRUNCATE, FUZZ_CMD_EXTEND,
            FUZZ_CMD_REPLACE_BUFFER, FUZZ_CMD_MUTATE_AUX_BUFFER, FUZZ_CMD_MUTATE_FLAGS,
            FUZZ_CMD_MUTATE_ARG, FUZZ_CMD_OVERWRITE_AT_OFFSET
        )
        
        cmd_names = {
            FUZZ_CMD_FLIP_BITS: "FLIP_BITS",
            FUZZ_CMD_LIGHT_MUTATION: "LIGHT_MUTATION",
            FUZZ_CMD_INTERESTING_VALUES: "INTERESTING_VALUES",
            FUZZ_CMD_BOUNDARY_VALUE: "BOUNDARY_VALUE",
            FUZZ_CMD_TRUNCATE: "TRUNCATE",
            FUZZ_CMD_EXTEND: "EXTEND",
            FUZZ_CMD_REPLACE_BUFFER: "REPLACE_BUFFER",
            FUZZ_CMD_MUTATE_AUX_BUFFER: "MUTATE_AUX_BUFFER",
            FUZZ_CMD_MUTATE_FLAGS: "MUTATE_FLAGS",
            FUZZ_CMD_MUTATE_ARG: "MUTATE_ARG",
            FUZZ_CMD_OVERWRITE_AT_OFFSET: "OVERWRITE_AT_OFFSET"
        }
        return cmd_names.get(cmd, f"UNKNOWN({cmd})")
    
    def get_syscall_stats(self, trace_id: str) -> Dict[int, Dict]:
        """
        获取指定trace的syscall统计信息
        
        Args:
            trace_id: Trace ID
        
        Returns:
            Dict mapping syscall_index to stats dict
        """
        return self.syscall_stats.get(trace_id, {})
    
    def save_corpus(self, output_dir: str):
        """Save all traces and metadata to corpus directory"""
        corpus_dir = Path(output_dir) / "corpus"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        
        # Save each trace
        for trace in self.trace_pool:
            # Copy trace file
            dest = corpus_dir / f"{trace.id}.bin"
            if os.path.exists(trace.file_path):
                import shutil
                shutil.copy(trace.file_path, dest)
            
            # Save metadata
            meta_file = corpus_dir / f"{trace.id}.meta"
            with open(meta_file, 'w') as f:
                json.dump({
                    'id': trace.id,
                    'creation_time': trace.metadata.creation_time,
                    'parent_trace_id': trace.metadata.parent_trace_id,
                    'mutation_applied': trace.metadata.mutation_applied,
                    'energy': trace.metadata.energy,
                    'exec_count': trace.metadata.exec_count,
                    'new_coverage_count': trace.metadata.new_coverage_count,
                    'coverage_info': self.coverage_map.get(trace.id, {}),
                    # ✅ 保存syscall统计信息
                    'syscall_stats': self.syscall_stats.get(trace.id, {})
                }, f, indent=2)
        
        print(f"[TraceManager] Saved {len(self.trace_pool)} traces to {corpus_dir}")


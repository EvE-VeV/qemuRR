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
        
        # Add initial trace if provided
        if initial_trace:
            self.add_initial_trace(initial_trace)
    
    def add_initial_trace(self, trace_file: str):
        """Add the initial seed trace"""
        trace_id = "trace_000"
        metadata = TraceMetadata(
            creation_time=time.time(),
            parent_trace_id=None,
            energy=10.0  # Initial trace gets high energy
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
        Select a trace for fuzzing using AFL-style energy-based selection
        
        Strategy:
        - 80% probability: Select from active_traces (exploitation)
        - 20% probability: Select from entire trace_pool (exploration)
        
        Returns:
            Trace: Selected trace or None if pool is empty
        """
        if not self.trace_pool:
            return None
        
        # Decide: Exploit or Explore
        if random.random() < self.exploit_probability and self.active_traces:
            # Exploit: Select from high-energy traces
            pool = self.active_traces
            source = "active"
        else:
            # Explore: Select from all traces
            pool = self.trace_pool
            source = "all"
        
        # Weight selection by energy (inverse of exec_count)
        weights = []
        for trace in pool:
            # Energy decreases with exec count (AFL-style)
            energy = trace.metadata.energy / (1 + trace.metadata.exec_count)
            weights.append(energy)
        
        # Select trace
        if sum(weights) == 0:
            # Fallback to uniform selection
            selected = random.choice(pool)
        else:
            selected = random.choices(pool, weights=weights)[0]
        
        # Update exec count
        selected.metadata.exec_count += 1
        
        print(f"[TraceManager] Selected trace: {selected.id} from {source} pool "
              f"(exec_count={selected.metadata.exec_count})")
        
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
                    'coverage_info': self.coverage_map.get(trace.id, {})
                }, f, indent=2)
        
        print(f"[TraceManager] Saved {len(self.trace_pool)} traces to {corpus_dir}")


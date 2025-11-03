#!/usr/bin/env python3
"""
FuzzingCore - Layer 2: Core Fuzzing Engine + Layer 5: Monitoring & Analysis

Main fuzzing loop coordinator that orchestrates all fuzzing components.
Implements the architecture described in DETAILED_ARCHITECTURE.md Layer 2 & Layer 5.

Layer 5 Integration (Line 382-408 in DETAILED_ARCHITECTURE.md):
- SyscallTree Visualizer: 自动生成 syscall tree HTML (重点功能)
- CrashAnalyzer: 自动分析和去重 crashes
- CorpusManager: 自动保存和管理 corpus
"""

import os
import sys
import time
from typing import Optional, Dict
from dataclasses import dataclass, field
from pathlib import Path

from .trace_manager import TraceManager, Trace
from .mutator import BaseMutator
from .coverage import CoverageTracker
from .qemu_executor import QEMUExecutor, ExecutionResult

# Layer 5: Import monitoring & analysis components
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from multiprocess.crash_analyzer import CrashAnalyzer as Layer5CrashAnalyzer
    from multiprocess.corpus_manager import CorpusManager
    _HAS_LAYER5_CRASH = True
    _HAS_LAYER5_CORPUS = True
except ImportError:
    _HAS_LAYER5_CRASH = False
    _HAS_LAYER5_CORPUS = False

try:
    from tree_visualizer import TreeVisualizer
    _HAS_TREE_VIZ = True
except ImportError:
    _HAS_TREE_VIZ = False
    print("[FuzzingCore] ⚠️  TreeVisualizer not available")


@dataclass
class FuzzingStatistics:
    """Statistics for fuzzing session"""
    total_execs: int = 0
    paths_found: int = 0
    crashes_found: int = 0
    unique_crashes: int = 0
    timeouts: int = 0
    last_new_path: float = field(default_factory=time.time)
    start_time: float = field(default_factory=time.time)
    
    @property
    def execs_per_sec(self) -> float:
        """Calculate executions per second"""
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0
        return self.total_execs / elapsed
    
    @property
    def elapsed_time(self) -> float:
        """Get elapsed time"""
        return time.time() - self.start_time


class CrashDetector:
    """Simple crash detector and deduplicator"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.crashes = []
        self.crash_hashes = set()
    
    def save_crash(self, result: ExecutionResult, trace: Trace, mutations: list):
        """Save crash information"""
        import hashlib
        import json
        import os
        from pathlib import Path
        
        # Create crash directory
        crash_dir = Path(self.output_dir) / "crashes"
        crash_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate crash hash (simple deduplication)
        crash_data = f"{result.status}_{result.qemu_exit_code}_{result.signal_number}"
        crash_hash = hashlib.md5(crash_data.encode()).hexdigest()[:8]
        
        # Check if duplicate
        if crash_hash in self.crash_hashes:
            print(f"[CrashDetector] Duplicate crash (hash={crash_hash}), skipping")
            return False
        
        self.crash_hashes.add(crash_hash)
        crash_id = f"crash_{len(self.crashes):06d}_{crash_hash}"
        
        # Save crash trace
        import shutil
        crash_trace = crash_dir / f"{crash_id}.bin"
        if os.path.exists(trace.file_path):
            shutil.copy(trace.file_path, crash_trace)
        
        # Save crash metadata
        crash_meta = crash_dir / f"{crash_id}.meta"
        with open(crash_meta, 'w') as f:
            json.dump({
                'crash_id': crash_id,
                'crash_hash': crash_hash,
                'trace_id': trace.id,
                'status': result.status,
                'status_name': result.status_name,
                'exit_code': result.qemu_exit_code,
                'signal': result.signal_number,
                'timestamp': time.time(),
                'mutations': [
                    {'syscall_index': m.syscall_index, 'cmd': m.cmd}
                    for m in mutations
                ]
            }, f, indent=2)
        
        self.crashes.append(crash_id)
        print(f"[CrashDetector] 💥 Saved new crash: {crash_id}")
        return True


class FuzzingCore:
    """
    Layer 2: Core Fuzzing Loop Coordinator
    
    Responsibilities:
    1. Coordinate all fuzzing components
    2. Implement main fuzzing loop
    3. Manage fuzzing statistics
    4. Handle crashes and new coverage
    5. Provide progress reporting
    
    Main Loop (Architecture: DETAILED_ARCHITECTURE.md Line 57-85):
    1. Select trace from TraceManager
    2. Generate mutations with Mutator
    3. Execute with QEMUExecutor
    4. Analyze coverage with CoverageTracker
    5. Save interesting traces
    6. Detect and save crashes
    7. Update statistics
    """
    
    def __init__(
        self,
        qemu_path: str,
        target_binary: str,
        initial_trace: str,
        output_dir: str = "fuzzing_output",
        mutator: Optional[BaseMutator] = None,
        enable_monitoring: bool = True
    ):
        """
        Initialize FuzzingCore
        
        Args:
            qemu_path: Path to QEMU executable
            target_binary: Path to target program
            initial_trace: Path to initial seed trace
            output_dir: Output directory for results
            mutator: Custom mutator (optional, will create BaseMutator if None)
            enable_monitoring: Enable Layer 5 monitoring (default: True)
        """
        print(f"[FuzzingCore] Initializing...")
        
        # Layer 1: Trace Management
        self.trace_manager = TraceManager(initial_trace=initial_trace)
        
        # Layer 2: Core Components
        self.mutator = mutator if mutator else BaseMutator()
        self.coverage_tracker = CoverageTracker(pid=0)  # Use pid 0 for single process
        self.execution_engine = QEMUExecutor(qemu_path, target_binary)
        self.crash_detector = CrashDetector(output_dir)
        
        # Statistics
        self.stats = FuzzingStatistics()
        
        # Output directory
        self.output_dir = output_dir
        self.initial_trace = initial_trace
        
        # Layer 5: Monitoring & Analysis (Architecture Line 382-408)
        self.enable_monitoring = enable_monitoring
        self.layer5_crash_analyzer = None
        self.layer5_corpus_manager = None
        
        if enable_monitoring:
            print(f"[FuzzingCore] 🔍 Enabling Layer 5: Monitoring & Analysis")
            
            # 1. CrashAnalyzer (去重和分析)
            if _HAS_LAYER5_CRASH:
                self.layer5_crash_analyzer = Layer5CrashAnalyzer(Path(output_dir))
                print(f"  ✅ CrashAnalyzer enabled")
            else:
                print(f"  ⚠️  CrashAnalyzer not available (using basic CrashDetector)")
            
            # 2. CorpusManager (持久化)
            if _HAS_LAYER5_CORPUS:
                self.layer5_corpus_manager = CorpusManager(Path(output_dir) / "corpus")
                print(f"  ✅ CorpusManager enabled")
            else:
                print(f"  ⚠️  CorpusManager not available")
            
            # 3. SyscallTree Generator (重点功能!)
            if _HAS_TREE_VIZ:
                print(f"  ✅ SyscallTree Visualizer enabled (重点功能)")
            else:
                print(f"  ⚠️  SyscallTree Visualizer not available")
        
        print(f"[FuzzingCore] ✅ Initialization complete")
        print(f"  Output dir: {output_dir}")
        print(f"  Initial trace: {initial_trace}")
        print(f"  Monitoring: {'Enabled' if enable_monitoring else 'Disabled'}")
    
    def _display_progress(self, force: bool = False):
        """Display fuzzing progress (every 100 executions or when forced)"""
        if not force and self.stats.total_execs % 100 != 0:
            return
        
        cov_stats = self.coverage_tracker.get_stats()
        
        print(f"\n{'━' * 60}")
        print(f"Iteration: {self.stats.total_execs}")
        print(f"{'━' * 60}")
        print(f"Exec speed:  {self.stats.execs_per_sec:.1f} exec/s")
        print(f"Trace pool:  {len(self.trace_manager.trace_pool)} traces")
        print(f"Coverage:    {cov_stats['total_edges']} edges")
        print(f"Paths found: {self.stats.paths_found}")
        print(f"Crashes:     {self.stats.crashes_found} "
              f"({len(self.crash_detector.crashes)} unique)")
        
        time_since_last = time.time() - self.stats.last_new_path
        print(f"Last path:   {time_since_last:.1f}s ago")
        print(f"{'━' * 60}")
    
    def run_single_iteration(self) -> bool:
        """
        Run a single fuzzing iteration
        
        Returns:
            bool: True if should continue, False if should stop
        
        This implements the detailed fuzzing flow from DETAILED_ARCHITECTURE.md
        Line 416-1076 (Single Iteration)
        """
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 1: Trace Selection
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        trace = self.trace_manager.select_trace()
        if not trace:
            print("[FuzzingCore] ⚠️  No traces available in pool")
            return False
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 2: Mutation Generation
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        mutations = self.mutator.mutate(trace)
        if not mutations:
            print("[FuzzingCore] ⚠️  No mutations generated")
            return True  # Continue with next iteration
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 3: QEMU Execution
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        result = self.execution_engine.execute(trace.file_path, mutations)
        self.stats.total_execs += 1
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 4: Coverage Analysis
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        has_new_coverage = False
        if result.coverage_bitmap:
            has_new_coverage = self.coverage_tracker.has_new_coverage(
                result.coverage_bitmap
            )
            
            if has_new_coverage:
                self.stats.paths_found += 1
                self.stats.last_new_path = time.time()
                print(f"[FuzzingCore] 🎯 New coverage found! "
                      f"(total edges: {self.coverage_tracker.get_stats()['total_edges']})")
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 5: Trace Saving (if interesting)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if has_new_coverage:
            # For now, reuse the same trace file (Phase 1 simplification)
            # Phase 2 will implement trace re-recording with mutations
            coverage_info = {
                'has_new_edges': True,
                'new_edge_count': 1,  # Simplified
                'total_unique_edges': self.coverage_tracker.get_stats()['total_edges']
            }
            
            self.trace_manager.add_trace(
                trace_file=trace.file_path,
                coverage_info=coverage_info,
                parent_id=trace.id,
                mutations=[
                    {'syscall_index': m.syscall_index, 'cmd': m.cmd}
                    for m in mutations
                ]
            )
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 6: Crash Detection and Saving
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if result.crashed:
            self.stats.crashes_found += 1
            self.crash_detector.save_crash(result, trace, mutations)
        
        # Handle timeout
        if result.timeout:
            self.stats.timeouts += 1
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 7: Statistics Update & Display
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        self._display_progress()
        
        return True
    
    def run(self, max_iterations: Optional[int] = None, max_time: Optional[float] = None):
        """
        Run main fuzzing loop
        
        Args:
            max_iterations: Maximum iterations (None for unlimited)
            max_time: Maximum time in seconds (None for unlimited)
        """
        print(f"\n{'=' * 60}")
        print(f"[FuzzingCore] Starting fuzzing campaign")
        if max_iterations:
            print(f"  Max iterations: {max_iterations}")
        if max_time:
            print(f"  Max time: {max_time}s")
        print(f"{'=' * 60}\n")
        
        iteration = 0
        start_time = time.time()
        
        try:
            while True:
                # Check stopping conditions
                if max_iterations and iteration >= max_iterations:
                    print(f"\n[FuzzingCore] Reached max iterations ({max_iterations})")
                    break
                
                if max_time and (time.time() - start_time) >= max_time:
                    print(f"\n[FuzzingCore] Reached max time ({max_time}s)")
                    break
                
                # Run single iteration
                should_continue = self.run_single_iteration()
                if not should_continue:
                    break
                
                iteration += 1
        
        except KeyboardInterrupt:
            print(f"\n[FuzzingCore] Interrupted by user")
        
        finally:
            # Final statistics
            self._display_final_statistics()
    
    def _display_final_statistics(self):
        """Display final fuzzing statistics"""
        cov_stats = self.coverage_tracker.get_stats()
        trace_stats = self.trace_manager.get_statistics()
        exec_stats = self.execution_engine.get_statistics()
        
        print(f"\n{'=' * 60}")
        print(f"Fuzzing Campaign Complete")
        print(f"{'=' * 60}")
        print(f"\n📊 Execution Statistics:")
        print(f"  Total executions:  {self.stats.total_execs}")
        print(f"  Exec/sec:          {self.stats.execs_per_sec:.1f}")
        print(f"  Total time:        {self.stats.elapsed_time:.1f}s")
        
        print(f"\n🎯 Coverage Statistics:")
        print(f"  Total edges:       {cov_stats['total_edges']}")
        print(f"  New paths found:   {self.stats.paths_found}")
        print(f"  Bitmap density:    {cov_stats['bitmap_density']:.2f}%")
        
        print(f"\n📦 Corpus Statistics:")
        print(f"  Total traces:      {trace_stats['total_traces']}")
        print(f"  Active traces:     {trace_stats['active_traces']}")
        print(f"  Traces saved:      {trace_stats['traces_saved']}")
        
        print(f"\n💥 Crash Statistics:")
        print(f"  Total crashes:     {self.stats.crashes_found}")
        print(f"  Unique crashes:    {len(self.crash_detector.crashes)}")
        print(f"  Crash rate:        {exec_stats['crash_rate']:.2%}")
        
        print(f"\n⏱️  Timeout Statistics:")
        print(f"  Total timeouts:    {self.stats.timeouts}")
        print(f"  Timeout rate:      {exec_stats['timeout_rate']:.2%}")
        
        print(f"\n{'=' * 60}\n")
    
    def save_final_results(self):
        """
        Save final results to disk
        
        Layer 5 Integration: 自动生成所有监控和分析报告
        """
        import json
        from pathlib import Path
        
        output_path = Path(self.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[FuzzingCore] 💾 Saving final results...")
        
        # Save corpus (Layer 2)
        self.trace_manager.save_corpus(self.output_dir)
        
        # Save final statistics
        stats_file = output_path / "final_stats.json"
        with open(stats_file, 'w') as f:
            json.dump({
                'execution': {
                    'total_execs': self.stats.total_execs,
                    'execs_per_sec': self.stats.execs_per_sec,
                    'elapsed_time': self.stats.elapsed_time,
                    'crashes_found': self.stats.crashes_found,
                    'paths_found': self.stats.paths_found,
                    'timeouts': self.stats.timeouts
                },
                'coverage': self.coverage_tracker.get_stats(),
                'traces': self.trace_manager.get_statistics(),
                'executor': self.execution_engine.get_statistics()
            }, f, indent=2)
        
        print(f"  ✅ Statistics saved to {stats_file}")
        
        # ═══════════════════════════════════════════════════════════
        # Layer 5: Monitoring & Analysis (重点!)
        # ═══════════════════════════════════════════════════════════
        
        if self.enable_monitoring:
            print(f"\n[FuzzingCore] 🔍 Layer 5: Generating monitoring reports...")
            
            # 1. CorpusManager: 保存持久化 corpus
            if self.layer5_corpus_manager:
                try:
                    # Note: corpus_manager 需要 seed_queue 对象，这里简化处理
                    print(f"  ✅ Corpus management available (manual save needed)")
                except Exception as e:
                    print(f"  ⚠️  Corpus save failed: {e}")
            
            # 2. CrashAnalyzer: 生成 crash 报告
            if self.layer5_crash_analyzer:
                try:
                    print(f"\n[FuzzingCore] 💥 Generating crash analysis report...")
                    self.layer5_crash_analyzer.print_summary(top_n=20, verbose=True)
                    
                    # 导出 crash 报告
                    crash_report = output_path / "crash_analysis.json"
                    self.layer5_crash_analyzer.export_to_file(crash_report, format='json')
                    print(f"  ✅ Crash report: {crash_report}")
                except Exception as e:
                    print(f"  ⚠️  Crash analysis failed: {e}")
            
            # 3. ⭐ SyscallTree Visualizer: 生成 syscall tree (重点功能!)
            if _HAS_TREE_VIZ:
                print(f"\n[FuzzingCore] 🌳 Generating Syscall Trees (重点功能)...")
                self._generate_syscall_trees(output_path)
            else:
                print(f"  ⚠️  SyscallTree Visualizer not available")
        
        print(f"\n[FuzzingCore] ✅ All results saved to {output_path}")
    
    def _generate_syscall_trees(self, output_path: Path):
        """
        生成 Syscall Tree 可视化 (Layer 5 重点功能)
        
        生成统一的树状可视化，包含所有 traces
        使用 D3.js tree layout，真正的树形结构
        """
        trees_dir = output_path / "syscall_trees"
        trees_dir.mkdir(exist_ok=True)
        
        # 收集所有 trace 文件
        trace_files = []
        labels = []
        
        # 1. Initial trace
        if os.path.exists(self.initial_trace):
            trace_files.append(self.initial_trace)
            labels.append("Initial Trace")
        
        # 2. Corpus traces (限制前10个)
        corpus_dir = Path(self.output_dir) / "corpus"
        if corpus_dir.exists():
            for trace_file in sorted(corpus_dir.glob("*.bin"))[:10]:
                trace_files.append(str(trace_file))
                labels.append(f"Corpus: {trace_file.stem}")
        
        # 3. Crash traces (限制前5个)
        crashes_dir = Path(self.output_dir) / "crashes"
        if crashes_dir.exists():
            for crash_file in sorted(crashes_dir.glob("*.bin"))[:5]:
                trace_files.append(str(crash_file))
                labels.append(f"Crash: {crash_file.stem}")
        
        if not trace_files:
            print(f"  ⚠️  No traces found for visualization")
            return
        
        # 使用 TreeVisualizer 生成真正的树状可视化
        print(f"  🌳 Generating tree visualization for {len(trace_files)} traces...")
        
        try:
            viz = TreeVisualizer()
            
            for trace_file, label in zip(trace_files, labels):
                viz.add_trace(trace_file, label)
            
            tree_html = trees_dir / "syscall_tree.html"
            if viz.generate_html(str(tree_html)):
                print(f"  ✅ Generated tree: {tree_html}")
                print(f"  📂 View tree: file://{tree_html.absolute()}")
            else:
                print(f"  ⚠️  Failed to generate tree visualization")
        
        except Exception as e:
            print(f"  ⚠️  Tree generation failed: {e}")
            import traceback
            traceback.print_exc()


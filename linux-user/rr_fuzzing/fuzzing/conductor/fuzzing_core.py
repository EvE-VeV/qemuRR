#!/usr/bin/env python3
"""
FuzzingCore - Layer 2: Core Fuzzing Engine + Layer 5: Monitoring & Analysis

Main fuzzing loop coordinator, orchestrating all fuzzing components.
Implements Layer 2 and Layer 5 architectures described in DETAILED_ARCHITECTURE.md.

Layer 5 Integration (DETAILED_ARCHITECTURE.md lines 382-408):
- SyscallTree Visualizer: Automatically generate syscall tree HTML (Key feature)
- CrashAnalyzer: Automatically analyze and deduplicate crashes
- CorpusManager: Automatically save and manage corpus
"""

import os
import sys
import time
import subprocess
import threading
import glob
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from pathlib import Path

from .trace_manager import TraceManager, Trace
from .mutator import BaseMutator, SmartMutator
from .coverage import CoverageTracker
from .qemu_executor import QEMUExecutor, ExecutionResult
from .fuzzing_metrics import FuzzingMetrics, FailureReason
from .iteration_result import (
    IterationResult, IterationStatus,
    create_success_result, create_failure_result
)
from .mutation_dependency_graph import MutationDependencyGraph
from .async_logger import AsyncLogger, alog
from .watchdog import FuzzingWatchdog
from .checkpoint import CheckpointManager
from .static_analyzer import StaticAnalyzer

# Ensure parent directory is in sys.path for internal imports
_fuzzing_dir = Path(__file__).parent.parent.resolve()
if str(_fuzzing_dir) not in sys.path:
    sys.path.insert(0, str(_fuzzing_dir))

# Attempt to import PathFinder (Prioritize the dual-level CFG version)
_HAS_PATH_FINDER = False
PathFinder = None
PathFinderConfig = None

# Prioritize DualLevelPathFinder for CFG-guided fuzzing
try:
    from .dual_level_path_finder import DualLevelPathFinder
    PathFinder = DualLevelPathFinder
    _HAS_PATH_FINDER = True
    print("[FuzzingCore] Loaded DualLevelPathFinder")
except ImportError as e:
    print(f"[FuzzingCore] ⚠️ DualLevelPathFinder import failed: {e}. PathFinder unavailable.")
    _HAS_PATH_FINDER = False

# Attempt to import RecipePool
_HAS_RECIPE_POOL = False
RecipePool = None
try:
    from multiprocess import recipe_pool as _rp_module
    RecipePool = _rp_module.RecipePool
    _HAS_RECIPE_POOL = True
except ImportError:
    pass

# Attempt to import DynamicForkController
_HAS_DYNAMIC_FORK = False
DynamicForkController = None
try:
    from multiprocess import dynamic_fork_controller as _dfc_module
    DynamicForkController = _dfc_module.DynamicForkController
    _HAS_DYNAMIC_FORK = True
except ImportError:
    pass

# Layer 5: Import monitoring and analysis components
try:
    from multiprocess.crash_analyzer import CrashAnalyzer as Layer5CrashAnalyzer
    from multiprocess.corpus_manager import CorpusManager
    _HAS_LAYER5_CRASH = True
    _HAS_LAYER5_CORPUS = True
except ImportError:
    _HAS_LAYER5_CRASH = False
    _HAS_LAYER5_CORPUS = False

# ✅ Option A: Use Realtime Tree Visualizer (from QEMU dynamic messages)
# ❌ Deprecated: tree_visualizer (from static trace file, inaccurate data)
# try:
#     from tree_visualizer import TreeVisualizer
#     _HAS_TREE_VIZ = True
# except ImportError:
#     _HAS_TREE_VIZ = False
#     print("[FuzzingCore] ⚠️  TreeVisualizer不可用")

# ✅ BB Trace support
try:
    from bb_trace_parser import BBTraceParser, BBEntry
    BB_TRACE_AVAILABLE = True
except ImportError:
    BB_TRACE_AVAILABLE = False

# ✅ Realtime tree visualizer does not need to be imported; it will run as a separate process
_HAS_REALTIME_VIZ = False  # ⚠️ DISABLED: Visualizer O(N) search causing 10-100x slowdown


@dataclass
class FuzzingStatistics:
    """Fuzzing session statistics"""
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
        """Save crash info"""
        import hashlib
        import json
        import os
        from pathlib import Path
        
        # Create crash directory
        crash_dir = Path(self.output_dir) / "crashes"
        crash_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate crash hash
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
        
        # Get syscall name mapping (load trace using TraceAnalyzer)
        from .constants import get_mutation_type_name
        from ..trace_analyzer import TraceAnalyzer
        
        syscall_names = {}
        try:
            # Load trace file using TraceAnalyzer to get syscall information
            analyzer = TraceAnalyzer(trace.file_path)
            if analyzer.syscalls:
                for sc in analyzer.syscalls:
                    syscall_names[sc.index] = sc.name
        except Exception as e:
            print(f"[CrashDetector] ⚠️  Unable to extract syscall names from trace: {e}")
        
        with open(crash_meta, 'w') as f:
            json.dump({
                'crash_id': crash_id,
                'crash_hash': crash_hash,
                'trace_id': trace.id,
                'trace_file': trace.file_path,
                'status': result.status,
                'status_name': result.status_name,
                'exit_code': result.qemu_exit_code,
                'signal': result.signal_number,
                'timestamp': time.time(),
                'mutations': [
                    {
                        'syscall_index': m.syscall_index,
                        'syscall_name': syscall_names.get(m.syscall_index, 'unknown'),  # ✅ From TraceAnalyzer
                        'cmd': m.cmd,
                        'mutation_type': get_mutation_type_name(m.cmd),  # ✅ Use mapping
                        'arg_index': m.arg_index,
                        'data': m.data.hex() if isinstance(m.data, bytes) else str(m.data),
                        'offset': m.offset,
                        'size': m.size,
                    }
                    for m in mutations
                ]
            }, f, indent=2)
        
        self.crashes.append(crash_id)
        print(f"[CrashDetector] 💥 New crash saved: {crash_id}")
        return True


class FuzzingCore:
    """
    Layer 2: Core Fuzzing Loop Coordinator
    
    Responsibilities:
    1. Coordinate all fuzzing components
    2. Implement the main fuzzing loop
    3. Manage fuzzing statistics
    4. Handle crashes and new coverage
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
        enable_monitoring: bool = True,
        enable_pathfinder: bool = True,  # PathFinder enabled by default
        enable_tree_viz: bool = False,   # Visualizer disabled by default (performance)
        use_fork_server: bool = True,    # AFL-style persistent mode (Process Persistence)
        enable_persistence: bool = False,# Unified session persistence (Save/Auto-Resume)
        use_energy_scheduler: bool = True,  # Energy Scheduler enabled by default (+40% coverage)
        initial_stats: Optional[Dict] = None,
        shared_coverage: Optional[Any] = None,  # SharedCoverage for multi-process mode
        target_args: str = ""   # Target program arguments
    ):
        # """
        alog(f"[FuzzingCore] __init__ called. _HAS_PATH_FINDER={_HAS_PATH_FINDER}, PathFinder class={(PathFinder.__name__ if PathFinder else 'None')}", "CORE")
        self.qemu_path = qemu_path
        self.recipe_pool = None

        # ✅ Performance: Start AsyncLogger
        self.logger = AsyncLogger(log_file=os.path.join(output_dir, "fuzzing.log"), console=True)
        self.logger.start()
        alog(f"Initializing...", "CORE", "INFO")


        # Core Component: Seed & Trace Management
        if use_energy_scheduler:
            from .seed_manager_adapter import SeedManagerAdapter
            self.trace_manager = SeedManagerAdapter(
                initial_trace=initial_trace,
                use_advanced=True
            )
            alog("Energy Scheduler / AdvancedSeedQueue enabled", "CORE", "INFO")
        else:
            self.trace_manager = TraceManager(initial_trace=initial_trace)
            alog("📝 Using legacy TraceManager", "CORE", "INFO")
        alog("TraceManager initialized", "CORE", "DEBUG")

        
        # Layer 2: Core Components
        self.mutator = mutator if mutator else BaseMutator()
        # ✅ Multi-process: Pass shared_coverage to CoverageTracker
        self.coverage_tracker = CoverageTracker(shared_coverage=shared_coverage)
        alog("CoverageTracker initialized", "CORE", "DEBUG")


        # ✅ Layer 2: Core Components - Execution Engine
        self.use_fork_server = use_fork_server
        if use_fork_server:
            alog("🚀 Using Process Persistence (Fork Server Mode)", "CORE", "INFO")
        else:
            alog("🚀 Using Fresh Execution Mode (One process per task)", "CORE", "INFO")
        self.execution_engine = QEMUExecutor(
            qemu_path, 
            target_binary, 
            target_args=target_args,
            persistent_mode=use_fork_server,
            log_file=os.path.join(output_dir, "qemu_debug.log")
        )
        alog(f"Execution engine initialized. SHM_ENV={self.execution_engine._coverage_env_value}", "CORE", "INFO")


        self.crash_detector = CrashDetector(output_dir)
        alog("CrashDetector initialized", "CORE", "DEBUG")


        # Fuzzing Session Tracking
        self.stats = FuzzingStatistics()
        if initial_stats:
            for k, v in initial_stats.items():
                if hasattr(self.stats, k):
                    setattr(self.stats, k, v)
            alog(f"Restored stats: execs={self.stats.total_execs}, paths={self.stats.paths_found}", "CORE", "INFO")
            
        self.metrics = FuzzingMetrics()
        self.mutation_graph = MutationDependencyGraph()
        
        # ✅ Restore persistence state if provided
        self.start_time = initial_stats.get('start_time', time.time()) if initial_stats else time.time()
        self.total_executions = initial_stats.get('total_execs', 0) if initial_stats else 0
        self.total_iterations = 0 # Iterations are always relative to current run

        # Output directory and paths
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.target_binary = target_binary  # P0-1: Save for PathFinder
        self.target_args = target_args       # ✅ Fix: Store target_args for restart

        
        # PathFinder support (multi-level static analysis + dynamic trace mapping)
        self.enable_pathfinder = enable_pathfinder and _HAS_PATH_FINDER
        self.path_finder = None
        
        # Dynamic Fork Controller (intelligent multi-path exploration)
        self.enable_dynamic_fork = _HAS_DYNAMIC_FORK
        self.dynamic_fork = None
        
        if enable_pathfinder and _HAS_PATH_FINDER:
            # Initialize PathFinder
            self._init_pathfinder()
        
        # ✅ Enable Syscall Tree Visualizer
        self.enable_tree_viz = enable_tree_viz
        
        # ✅ Start Visualizer in __init__
        if enable_tree_viz:
            try:
                self._start_realtime_visualizer()
            except Exception as e:
                alog(f"⚠️ Tree Visualizer failed to start: {e}", "CORE", "WARN")
        
        # ✅ Avoid duplicate RecipePool creation
        if not self.recipe_pool and _HAS_RECIPE_POOL and isinstance(mutator, SmartMutator) and mutator.recipe_mode:
            self.recipe_pool = RecipePool(max_active=50, retirement_threshold=100)
            # Load initial recipes from mutator
            if mutator.recipes:
                self.recipe_pool.add_recipes(mutator.recipes)
                alog(f"✅ RecipePool enabled ({len(mutator.recipes)} recipes)", "CORE", "INFO")
        
        self.last_cfg_analysis_iter = 0
        self.last_cfg_analysis_time = 0
        self.cfg_analysis_interval_iters = 100
        self.cfg_analysis_interval_time = 60
        self.min_cfg_analysis_interval = 5.0 # Minimum seconds between analyses even if new coverage
        
        self.trace_analyzer_cache = {} # {trace_file: TraceAnalyzer}
    
        self.last_cfg_analysis_time = time.time()
        self.last_cfg_analysis_iter = 0
        
        # Layer 5: Monitoring and Analysis Components
        self.enable_monitoring = enable_monitoring  # ✅ Ensure defined
        self.layer5_crash_analyzer = None
        self.layer5_corpus_manager = None
        
        if enable_monitoring:
            alog(f"🔍 Layer 5 enabled: Monitoring & Analysis", "CORE", "INFO")
            
            # 1. CrashAnalyzer (deduplication and analysis)
            if _HAS_LAYER5_CRASH:
                self.layer5_crash_analyzer = Layer5CrashAnalyzer(Path(output_dir))
                alog(f"  ✅ CrashAnalyzer enabled", "CORE", "INFO")
            else:
                alog(f"  ⚠️  CrashAnalyzer unavailable (using basic CrashDetector)", "CORE", "WARN")
            
            # 2. CorpusManager (persistence)
            if _HAS_LAYER5_CORPUS:
                self.layer5_corpus_manager = CorpusManager(Path(output_dir) / "corpus")
                alog(f"  ✅ CorpusManager enabled", "CORE", "INFO")
            else:
                alog(f"  ⚠️  CorpusManager unavailable", "CORE", "WARN")
            
            # ✅ 3. Realtime Tree Visualizer (Option A: Integrated version)
            # if _HAS_REALTIME_VIZ:
            #     print(f"  ✅ Realtime Tree Visualizer enabled (accurate execution paths)")
            # else:
            #     print(f"  ⚠️  Realtime Tree Visualizer unavailable")
        
        # ═══════════════════════════════════════════════════════════════
        # Option A: Realtime Visualizer Management
        # ═══════════════════════════════════════════════════════════════
        self.realtime_viz_process = None
        self.realtime_viz_pipe = None
        self.realtime_viz_thread = None  # For reading visualizer output
        
        self.dynamic_fork_controller = None
        if _HAS_DYNAMIC_FORK and DynamicForkController is not None:
            try:
                # Pre-load analyzer for initial trace to share among components
                initial_analyzer = self._get_analyzer(initial_trace)
                
                # If mutator is SmartMutator, ensure it uses this analyzer
                if isinstance(self.mutator, SmartMutator):
                     self.mutator.analyzer = initial_analyzer
                
                self.dynamic_fork_controller = DynamicForkController(
                    executor=self.execution_engine,
                    path_finder=self.path_finder,
                    mutator=self.mutator,
                    recipe_pool=self.recipe_pool,
                    coverage_tracker=self.coverage_tracker,
                    trace_manager=self.trace_manager,
                    fuzzing_stats=self.stats,
                    mutation_graph=self.mutation_graph,
                    crash_detector=self.crash_detector,
                    crash_analyzer=self.layer5_crash_analyzer, # ✅ Pass Layer 5 Analyzer
                    analyzer=initial_analyzer
                )
                alog(f"DynamicForkController enabled (Depth-First mode)", "CORE", "INFO")
            except Exception as e:
                alog(f"⚠️ DynamicForkController initialization failed: {e}", "CORE", "WARN")
                import traceback
                traceback.print_exc()
                self.dynamic_fork_controller = None
        else:
            alog(f"⚠️ DynamicForkController unavailable", "CORE", "WARN")

        # ✅ Initialize Watchdog (Phase 1 Fix: Tighten timeout for performance)
        self.watchdog = FuzzingWatchdog(
            executor_check_func=self._check_executor_alive,
            restart_func=self._restart_execution_engine,
            timeout_seconds=45,  # Optimized: (2s exec + 0.5s overhead) * 8 Havoc stacked * 2 safety factor
            check_interval=2     # Increased frequency to 2s
        )
        alog(f"  Watchdog: Enabled (Timeout=30s)", "CORE", "INFO")
        
        # ✅ State Persistence (Checkpoint System)
        self.enable_persistence = enable_persistence
        self.checkpoint_manager = CheckpointManager(output_dir) if enable_persistence else None
        self.checkpoint_interval = 300  # Save every 5 minutes
        self.last_checkpoint_time = time.time()
        
        alog(f"  Output directory: {output_dir}", "CORE", "INFO")
        alog(f"  Initial trace: {initial_trace}", "CORE", "INFO")
        alog(f"  Monitoring: {'Enabled' if enable_monitoring else 'Disabled'}", "CORE", "INFO")
        alog(f"  PathFinder: {'Enabled' if self.path_finder else 'Disabled'}", "CORE", "INFO")
        alog(f"  Syscall Tree Export: {'Enabled' if enable_tree_viz else 'Disabled'}", "CORE", "INFO")
        # print(f"  Dynamic Fork: {'Enabled' if self.dynamic_fork_controller else 'Disabled'}")

        if self.checkpoint_manager:
            if self.checkpoint_manager.exists():
                alog(f"📂 Found existing checkpoint in {output_dir}. Auto-resuming...", "CORE", "INFO")
                self.checkpoint_manager.load(self)
            else:
                alog(f"💾 Persistence enabled. Periodic saving every {self.checkpoint_interval}s", "CORE", "INFO")
        
        alog(f"✅ Initialization complete", "CORE", "INFO")

    def _init_pathfinder(self):
        """P1: Initialize PathFinder with lazy build support"""
        if not self.enable_pathfinder or not PathFinder:
            return
        
        try:
            alog(f"🧭 Initializing PathFinder...", "CORE", "INFO")
            # 1. Selection logic for PathFinder
            if isinstance(self.mutator, SmartMutator) and getattr(self.mutator, 'path_finder', None):
                 alog(f"♻️ Reusing PathFinder from Mutator", "CORE", "INFO")
                 self.path_finder = self.mutator.path_finder
            else:
                 # DualLevelPathFinder uses simplified initialization
                 self.path_finder = PathFinder(self.target_binary, config=None)
            
                 alog(f"💉 Injecting PathFinder into Mutator", "CORE", "INFO")
                 self.mutator.path_finder = self.path_finder

            # 3. Static Analysis Augmentation (Phase C)
            if self.target_binary:
                cfg_cache = os.path.join("/tmp", f"static_cfg_{os.path.basename(self.target_binary)}.json")
                if not os.path.exists(cfg_cache):
                    alog(f"🔍 Running Static Analysis on {self.target_binary}...", "CORE", "INFO")
                    analyzer = StaticAnalyzer(self.target_binary)
                    if analyzer.analyze():
                        analyzer.save_results(cfg_cache)
                
                if os.path.exists(cfg_cache):
                    self.path_finder.load_static_cfg(cfg_cache)

            # 4. Component enablement
            if _HAS_RECIPE_POOL and RecipePool is not None:
                self.recipe_pool = RecipePool(max_active=50, retirement_threshold=100)
            
            alog(f"✅ PathFinder initialized (Lazy CFG mode enabled)", "CORE", "INFO")
        except Exception as e:
            alog(f"❌ PathFinder initialization failed: {e}", "CORE", "ERROR")
            self.path_finder = None
            self.recipe_pool = None
            import traceback
            traceback.print_exc()
        
        # If PathFinder is available, log its status
        if self.path_finder and self.path_finder.is_available():
            alog(f"✅ PathFinder enabled (Lazy CFG build mode)", "CORE", "INFO")
            if self.recipe_pool:
                alog(f"✅ RecipePool enabled (max_active=50)", "CORE", "INFO")
        elif self.path_finder and not self.path_finder.is_available():
            reason = getattr(self.path_finder, 'disabled_reason', 'unknown reason')
            alog(f"⚠️ PathFinder automatically disabled: {reason}", "CORE", "WARN")
            self.path_finder = None
            self.recipe_pool = None
        elif self.enable_pathfinder and not _HAS_PATH_FINDER:
            alog(f"⚠️ PathFinder unavailable (requires angr)", "CORE", "WARN")
            alog(f"  _HAS_PATH_FINDER={_HAS_PATH_FINDER}", "CORE", "WARN")

    def _check_executor_alive(self) -> bool:
        """Watchdog callback: Check if QEMU process is alive"""
        if self.execution_engine and self.execution_engine.process:
            return self.execution_engine.process.poll() is None
        return False

    def _restart_execution_engine(self):
        """Watchdog callback: Force restart QEMU"""
        alog("Watchdog triggering QEMU restart...", "CORE", "WARN")
        if self.execution_engine:
            try:
                self.execution_engine.stop_persistent_mode()
            except:
                pass 
        # Re-initialize engine
        self.execution_engine = QEMUExecutor(
            self.qemu_path, 
            self.target_binary, 
            target_args=self.target_args, # ✅ SAVE original args
            persistent_mode=True,
            log_file=os.path.join(self.output_dir, "qemu_debug.log")
        )
        
        # 🔥 CRITICAL FIX: Update DynamicForkController with the NEW executor
        if self.dynamic_fork_controller:
            self.dynamic_fork_controller.executor = self.execution_engine
            
        alog("QEMU Engine restarted by Watchdog", "CORE", "INFO")
    
    # ✅ Remove duplicate _start_realtime_visualizer definition
    # Use the version on line 655, it is more complete and sets the correct variable names
    
    def _extract_covered_blocks(self) -> set:
        """
        Extracts covered basic blocks from the coverage bitmap
        
        Returns:
            A set of covered block addresses
        """
        covered = set()
        
        # Strategy A: Use PathFinder's precise mapping (High Accuracy)
        if self.path_finder and hasattr(self.path_finder, 'get_covered_bb_addresses'):
            covered = self.path_finder.get_covered_bb_addresses()
            if covered:
                alog(f"[FuzzingCore] _extract_covered_blocks: Using PathFinder ({len(covered)} BBs)", "DEBUG")
                return covered

        # Strategy B: Fallback to bitmap bits (Low Accuracy, Legacy)
        bits_set = 0
        for i, val in enumerate(self.coverage_tracker.global_bitmap):
            if val > 0:
                bits_set += 1
                # Heuristic: use bitmap index as block ID (very inaccurate)
                covered.add(i & 0xFFFF)
        
        if bits_set > 0:
            alog(f"[FuzzingCore] _extract_covered_blocks: Fallback mode, bits={bits_set}", "DEBUG")
        
        return covered

    def _select_coverage_driven_fork_points(self, trace: Trace, count: int) -> List[int]:
        """
        Selects coverage-driven fork points

        Strategy:
        1. If PathFinder is available, use syscalls near uncovered branches as fork points
        2. Otherwise, use an IO syscall rotation strategy as a fallback

        Parameters:
            trace: The current trace
            count: The number of fork points needed

        Returns:
            A list of fork point indices
        """
        fork_points = []

        # Strategy 1: Use PathFinder's uncovered branches
        if self.path_finder and hasattr(self.path_finder, 'uncovered_branches'):
            uncovered = self.path_finder.uncovered_branches
            if uncovered and len(uncovered) > 0:
                # PathFinder-guided fork point selection
                top_branches = uncovered[:count * 2] 
                for branch in top_branches:
                    if 'target_syscall_idx' in branch:
                        fork_points.append(branch['target_syscall_idx'])
                    elif 'from_syscall_idx' in branch:
                       fork_points.append(branch['from_syscall_idx'])

                    if len(fork_points) >= count:
                        break

        if fork_points:
                    alog(f"🎯 Using PathFinder-guided fork points: {fork_points[:count]}", "CORE", "INFO")
                    return fork_points[:count]

        # Strategy 2: Exploration Mode (Fallback for saturated graph)
        if self.path_finder and hasattr(self.path_finder, 'exploration_targets') and self.path_finder.exploration_targets:
            targets = self.path_finder.exploration_targets
            import random
            # Pick targets
            selected = random.sample(targets, min(len(targets), count))
            fork_points = [t['target_syscall_idx'] for t in selected]
            alog(f"🚀 Using Exploration Mode fork points: {fork_points}", "CORE", "INFO")
            return fork_points

        # Strategy 3: Blind Random Fallback (Last resort)
        # Use random Syscall Index as Fork point to explore possible hidden states
        alog(f"⚠️ PathFinder has no suggestions, enabling Random Exploration", "CORE", "WARN")
        
        # Assume trace has syscall_count attribute, or get it via trace.metadata
        # For simplicity, randomly select from 0 to 30 (assumption)
        import random
        # Try to get the actual syscall count
        limit = 20
        if hasattr(trace, 'metadata') and hasattr(trace.metadata, 'syscall_count'):
             limit = trace.metadata.syscall_count
        
        # Randomly select 'count' points
        random_points = sorted(random.sample(range(max(1, limit)), min(count, limit)))
        return random_points

    def _get_analyzer(self, trace_file: str):
        """Get or create TraceAnalyzer for a trace file (per-process cache)"""
        if trace_file in self.trace_analyzer_cache:
            return self.trace_analyzer_cache[trace_file]
        
        # ✅ Check SmartMutator cache (global to process)
        from .mutator import SmartMutator
        if trace_file in SmartMutator._trace_cache:
            analyzer = SmartMutator._trace_cache[trace_file]
            self.trace_analyzer_cache[trace_file] = analyzer
            return analyzer
        
        import trace_analyzer
        analyzer = trace_analyzer.TraceAnalyzer(trace_file)
        self.trace_analyzer_cache[trace_file] = analyzer
        return analyzer

    def _display_progress(self, force: bool = False):
        """Display fuzzing progress (every 100 executions or forced)"""
        if not force and self.stats.total_execs % 100 != 0:
            return
        
        cov_stats = self.coverage_tracker.get_stats()
        
        # Calculate speed
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            # execs_per_sec and elapsed_time are properties, no need to set them
            pass
        
        alog(f"\n{'━' * 60}", "STATS", "INFO")
        alog(f"Iteration: {self.stats.total_execs}", "STATS", "INFO")
        alog(f"{'━' * 60}", "STATS", "INFO")
        alog(f"Exec speed:  {self.stats.execs_per_sec:.1f} exec/s", "STATS", "INFO")

        # ✅ Compatible with SeedManagerAdapter and TraceManager
        if hasattr(self.trace_manager, 'trace_pool'):
            trace_count = len(self.trace_manager.trace_pool)
        elif hasattr(self.trace_manager, 'trace_to_seed_map'):
            trace_count = len(self.trace_manager.trace_to_seed_map)
        else:
            trace_count = 0
        alog(f"Trace pool:  {trace_count} traces", "STATS", "INFO")

        alog(f"Coverage:    {cov_stats['total_edges']} edges", "STATS", "INFO")
        alog(f"Paths found: {self.stats.paths_found}", "STATS", "INFO")
        alog(f"Crashes:     {self.stats.crashes_found} "
              f"({len(self.crash_detector.crashes)} unique)", "STATS", "INFO")
        
        time_since_last = time.time() - self.stats.last_new_path
        alog(f"Last path:   {time_since_last:.1f}s ago", "STATS", "INFO")
        alog(f"{'━' * 60}", "STATS", "INFO")
    
    def _perform_cfg_analysis(self, trace: Trace, has_new_coverage: bool, trigger_reason: str, iteration_id: int):
        """Performs unified CFG/PathFinder analysis"""
        if not self.path_finder:
            return

        # 1. Iteration interval check
        interval = self.cfg_analysis_interval_iters
        elapsed = self.stats.total_execs - self.last_cfg_analysis_iter
        
        # 2. Time interval check
        elapsed_since_cfg = time.time() - self.last_cfg_analysis_time
        
        should_run_cfg = False
        if elapsed >= interval:
            should_run_cfg = True
        
        # Force run on new coverage (with a minimum safety interval to avoid thrashing)
        if has_new_coverage:
            if elapsed_since_cfg >= self.min_cfg_analysis_interval:
                should_run_cfg = True
            elif self.stats.total_execs < 10: # Allow frequent runs at the very beginning
                should_run_cfg = True

        # Check explicit time interval (e.g. 60s)
        if elapsed_since_cfg >= self.cfg_analysis_interval_time:
            should_run_cfg = True

        # 🔥 P1 Fix: Force runs on first iteration to ensure PathFinder is ready
        if self.stats.total_execs == 0:
            should_run_cfg = True

        if not should_run_cfg:
            return

        alog(f"[FuzzingCore] 🧭 Running CFG Analysis (Trigger: {trigger_reason})", "CORE")
        self.last_cfg_analysis_iter = self.stats.total_execs
        self.last_cfg_analysis_time = time.time()

        try:
            # Load syscall tree mapping (Auto-detect from HTML bundle)
            import glob
            import os
            from pathlib import Path
            
            # Search order: 1. Output Dir (Latest), 2. /tmp (Legacy/Default)
            search_paths = [
                os.path.join(self.output_dir, "latest_syscall_tree.html"),
                "/tmp/syscall_tree_*.html",
                "/tmp/syscall_tree.json"
            ]
            
            tree_file = None
            for pattern in search_paths:
                files = glob.glob(pattern) if '*' in pattern else ([pattern] if os.path.exists(pattern) else [])
                if files:
                    tree_file = max(files, key=os.path.getctime)
                    break
            
            if tree_file:
                tree_loaded = self.path_finder.load_syscall_tree(tree_file)
                if tree_loaded:
                    alog(f"[FuzzingCore] Loaded precise syscall tree mapping from {tree_file}", "CORE")
                    
                    # ✅ P3 Fix 2: If new coverage was found in the current round, directly mark nodes as covered based on the tree
                    # This eliminates reliance on inaccurate bitmap->PC mapping
                    if has_new_coverage:
                        marked = self.path_finder.mark_nodes_covered(tree_file)
                        if marked:
                            alog(f"[FuzzingCore] 🎯 PathFinder marked {marked} new nodes as covered based on tree", "CORE")
                else:
                    alog(f"[FuzzingCore] ⚠️ Failed to load syscall tree from {tree_file}", "WARN")
            else:
                alog(f"[FuzzingCore] ⚠️ Syscall tree file not found in search paths", "WARN")
            
            # Ensure CFG is ready
            if not self.path_finder.ensure_cfg_ready():
                alog(f"[FuzzingCore] Building PathFinder CFG from {trace.file_path}...", "CORE")
                analyzer = self._get_analyzer(trace.file_path)
                build_ok = self.path_finder.build_from_trace(trace.file_path, analyzer=analyzer)
            else:
                build_ok = True

            if build_ok:
                # Get covered blocks
                covered_blocks = self._extract_covered_blocks()
                if covered_blocks:
                    # Enhance with trace file
                    # ✅ Optimization: Prioritize searching for the most recently generated temporary trace file
                    # If the latest tree_file is found, its corresponding .bin and .bbl files are usually nearby
                    current_bb_trace = None
                    if tree_file and "syscall_tree_" in tree_file:
                        # Attempt to infer trace path from tree_file path
                        # E.g., /tmp/syscall_tree_123_4.html -> /tmp/trace_123_4.bin.bbl
                        base = tree_file.replace("syscall_tree_", "trace_").replace(".html", "")
                        potential_bbl = base + ".bin.bbl"
                        if os.path.exists(potential_bbl):
                            current_bb_trace = potential_bbl
                    
                    # Fallback to seed trace
                    if not current_bb_trace:
                        current_bb_trace = trace.file_path + ".bbl"
                    
                    if os.path.exists(current_bb_trace):
                        mapped = self.path_finder.enhance_from_trace_files(
                            syscall_trace_file="", # Unused
                            bb_trace_file=current_bb_trace,
                            covered_set=covered_blocks
                        )
                        if mapped:
                            alog(f"[FuzzingCore] 🔗 PathFinder enhanced {mapped} CFG nodes via {os.path.basename(current_bb_trace)}", "CORE")
                    
                    # Find uncovered branches
                    uncovered = self.path_finder.find_uncovered_branches(covered_blocks)
                    alog(f"[PathFinder] Debug: Found {len(uncovered)} uncovered branches", "DEBUG")
                    if uncovered:
                        new_recipes = self.path_finder.generate_recipes(uncovered, max_recipes=20)
                        alog(f"[FuzzingCore] PathFinder produced {len(new_recipes) if new_recipes else 0} recipes", "DEBUG")
                        if new_recipes:
                            if self.recipe_pool:
                                self.recipe_pool.add_recipes(new_recipes)
                                alog(f"[FuzzingCore] Added {len(new_recipes)} recipes to pool", "CORE")
                            
                            if isinstance(self.mutator, SmartMutator):
                                self.mutator.recipes.extend(new_recipes)
                                alog(f"[FuzzingCore] ✅ Injected {len(new_recipes)} recipes into SmartMutator", "CORE")
                    else:
                        # Fallback: Exploration Mode (Task #710)
                        # If graph is fully covered (no logical uncovered branches), force mutate covered syscalls
                        alog(f"[FuzzingCore] ⚠️ No uncovered branches (Graph saturated). activating Exploration Mode.", "CORE")
                        
                        # Generate "Self-Loop" targets for all covered syscalls to force state headers
                        exploration_targets = []
                        for idx, block in self.path_finder.syscall_blocks.items():
                            if block.is_covered:
                                # Create a dummy 'uncovered' entry that points to itself/generic
                                exploration_targets.append({
                                    'from_syscall_idx': idx,
                                    'to_syscall_idx': idx, # Self
                                    'from_syscall_name': block.syscall_name,
                                    'to_syscall_name': block.syscall_name,
                                    'type': 'exploration',
                                    'target_syscall_idx': idx,
                                    'has_syscall': True
                                })
                        
                        # ✅ Store in PathFinder for Fork Point Selection
                        self.path_finder.exploration_targets = exploration_targets

                        if exploration_targets:
                            # Pick random subset to avoid overwhelming
                            import random
                            subset = random.sample(exploration_targets, min(len(exploration_targets), 10))
                            ex_recipes = self.path_finder.generate_recipes(subset, max_recipes=10)
                            if ex_recipes:
                                if isinstance(self.mutator, SmartMutator):
                                    self.mutator.recipes.extend(ex_recipes)
                                    alog(f"[FuzzingCore] 🚀 Injected {len(ex_recipes)} EXPLORATION recipes", "CORE")
        except Exception as e:
            alog(f"[FuzzingCore] ⚠️ PathFinder Analysis failed: {e}", "ERROR")

    def run_single_iteration(self, iteration_id: int = 0) -> IterationResult:
        """Runs a single fuzzing iteration"""
        import os
        import glob
        
        # ✅ Task #7: Record iteration start
        self.metrics.success_counts['total_iterations'] += 1
        
        import os
        import glob

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 1: Trace Selection
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        trace = self.trace_manager.select_trace()
        if not trace:
            # ✅ Task #7: Record failure
            self.metrics.record_failure(
                reason=FailureReason.CONFIG_INVALID_TRACE,
                component="TraceManager",
                details="No available traces in pool",
                iteration=iteration_id
            )
            alog("⚠️  No available traces in pool", "CORE", "WARN")
            # ✅ Task #8: Return failure result
            return create_failure_result(
                iteration_id=iteration_id,
                status=IterationStatus.NO_TRACE,
                error_message="No available traces in pool",
                error_component="TraceManager"
            )
        
        # ✅ FIX: Update SmartMutator if the trace file has changed
        # This ensures that mutations are targeted based on the correct syscall sequence
        if isinstance(self.mutator, SmartMutator):
            current_mutator_trace = getattr(self.mutator, 'trace_file', None)
            if current_mutator_trace != trace.file_path:
                # alog(f"🔄 Updating Mutator for new trace: {trace.id} ({trace.file_path})", "CORE", "DEBUG")
                # Creating a new SmartMutator is efficient because it uses shared analyzer
                analyzer = self._get_analyzer(trace.file_path)
                self.mutator = SmartMutator(
                    trace_file=trace.file_path,
                    target_binary=self.target_binary,
                    path_finder=self.path_finder,
                    analyzer=analyzer
                )
                if self.dynamic_fork_controller:
                    self.dynamic_fork_controller.analyzer = analyzer
        # Step 2: Depth-First Exploration - Intelligent Fork Point Selection (Dynamic Fork Integration)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        
        # Dynamic Fork Integration: Delegate to controller if available
        if self.dynamic_fork_controller:
            # Multi-path exploration handles mutation, execution, and coverage analysis
            success = self.dynamic_fork_controller.explore_multi_path(trace, iteration_id)
            
            if success:
                # Update total executions count in core as well
                if hasattr(self.dynamic_fork_controller, 'last_batch_execs'):
                    self.total_executions += self.dynamic_fork_controller.last_batch_execs
                
                self.metrics.record_success('dynamic_fork_batch')
            
                # Unified CFG Analysis
                self._perform_cfg_analysis(trace, success, f"DynamicFork: {'NewCov' if success else 'Interval'}", iteration_id)
            
            # ✅ FIX: Display progress even in dynamic fork mode
            self._display_progress()
            
            return create_success_result(
                iteration_id=iteration_id,
                status=IterationStatus.SUCCESS,
                new_coverage=success
            )
            # crashes_found=0 # Crashes are handled by DynamicForkController via CrashDetector

        batch_size = int(os.environ.get('RR_BATCH_SIZE', 5))  # 🔥 Configurable batch_size

        # 🔥 Fix: Coverage-driven fork point selection
        fork_points = self._select_coverage_driven_fork_points(trace, batch_size)

        # Iteration result tracking
        has_any_success = False
        total_execs = 0
        total_mutations = 0
        new_coverage_found = False
        has_new_coverage = False  
        new_paths_found = 0
        crashes_found_count = 0
        result = None

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 3: Batch Execution - Group mutations by fork point
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        from collections import defaultdict
        fork_to_mutations = defaultdict(list)
        
        # Perform multiple mutations per fork point for efficiency (batching reduces QEMU restarts)
        mutations_per_fork = int(os.environ.get('RR_MUTATIONS_PER_FORK', 4))
        
        analyzer = self._get_analyzer(trace.file_path)
        for fork_point in fork_points:
            for _ in range(mutations_per_fork):
                m = self.mutator.mutate(trace, fork_point=fork_point, analyzer=analyzer)
                
                # 🔥 OPTION A: VALIDATOR HOOK (Dual-Level Mapping)
                # Intercepts and drops mutations that violate the Static CFG
                if m and self.enable_pathfinder and self.path_finder and hasattr(self.mutator, 'last_recipe_used'):
                    recipe = getattr(self.mutator, 'last_recipe_used', None)
                    # Only validate if the recipe explicitly targets a control flow transition (has known source/target)
                    if recipe and hasattr(recipe, 'source_branch') and hasattr(recipe, 'target_branch'):
                         # Validator Check (Phase A: Relax & Rank)
                         validation_score = self.path_finder.validate_transition(recipe.source_branch, recipe.target_branch)
                         
                         from .constants import VALIDATION_SCORE_INVALID, VALIDATION_SCORE_UNKNOWN
                         
                         if validation_score == VALIDATION_SCORE_INVALID:
                             # Absolute resource failure (Phase B) - Block it
                             alog(f"🛑 Validator BLOCKED invalid resource: {recipe.source_branch} -> {recipe.target_branch}", "CORE", "DEBUG")
                             continue
                         
                         elif validation_score == VALIDATION_SCORE_UNKNOWN:
                             # Unknown path (Exploration) - Allow but give lower priority/energy
                             # We can handle energy adjustment here or later in the executor
                             recipe.priority = max(1, recipe.priority // 2)
                             alog(f"🔍 Validator DETECTED unknown path (Exploring): {recipe.source_branch} -> {recipe.target_branch}", "CORE", "DEBUG")
                         
                         # If it's VALIDATION_SCORE_KNOWN (10), we proceed normally with high priority

                if m:
                    fork_to_mutations[fork_point].append(m)
        
        for fork_point, mutations_list in fork_to_mutations.items():
            if not mutations_list:
                continue
                
            total_mutations += len(mutations_list)
            
            # Record mutations in graph
            node_ids = []
            for i, muts in enumerate(mutations_list):
                 node_id = self.mutation_graph.add_mutation(
                    iteration=iteration_id,
                    mutation_index=i,
                    mutation_type='batch',
                    parent_trace_id=trace.id,
                )
                 node_ids.append(node_id)

            # Execute batch at this fork point
            results = self.execution_engine.execute_fork(trace.file_path, fork_point, mutations_list, 0, iteration_id)

            # ✅ Record successful fork operations (fix statistics bug)
            if results and len(results) > 0:
                self.metrics.success_counts['successful_forks'] += 1

            # Process results
            for result_idx, result in enumerate(results):
                if result is None:
                    continue

                # ✅ FIX: Map result back to its corresponding mutation
                mutations = mutations_list[result_idx] if result_idx < len(mutations_list) else None
                node_id = node_ids[result_idx] if result_idx < len(node_ids) else None

                self.stats.total_execs += 1
                trace.metadata.exec_count += 1  # 🔥 Fix: Update trace execution count
                total_execs += 1
                has_any_success = True

                # ✅ Task #7: Record successful mutation execution
                self.metrics.record_success('successful_mutations')

                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                # Step 4: Coverage Analysis
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                if result.coverage_bitmap:
                    found_new = self.coverage_tracker.has_new_coverage(
                        result.coverage_bitmap
                    )

                    if found_new:
                        has_new_coverage = True
                        new_coverage_found = True
                        new_paths_found += 1
                        self.stats.paths_found += 1
                        self.stats.last_new_path = time.time()
                        alog(f"🎯 New coverage found! (Total edges: {self.coverage_tracker.get_stats()['total_edges']})", "CORE", "INFO")

                # Step 4.5: Record execution statistics
                analyzer = self._get_analyzer(trace.file_path)
                self.trace_manager.record_execution(
                    trace_id=trace.id,
                    trace_file=trace.file_path,
                    mutations=mutations,
                    has_new_coverage=has_new_coverage,
                    analyzer=analyzer
                )

                # Update stagnation detection status
                # 🔥 Fix: Use total_execs as global iteration counter (different from trace.exec_count)
                if isinstance(self.mutator, SmartMutator) and hasattr(self.mutator, 'update_stagnation_status'):
                    self.mutator.update_stagnation_status(
                        iteration=self.stats.total_execs,
                        has_new_coverage=has_new_coverage
                    )

                # Execution result notification
                coverage_stats = self.coverage_tracker.get_stats()
                self.mutation_graph.update_mutation_result(
                    node_id=node_id,
                    has_new_coverage=has_new_coverage,
                    new_edges=coverage_stats.get('new_edges_this_run', 0),
                    total_edges=coverage_stats.get('total_edges', 0),
                    crashed=getattr(result, 'crashed', False),
                    timed_out=getattr(result, 'timed_out', False),
                    exec_time=getattr(result, 'exec_time', 0.0)
                )
                
                # ❌ REMOVED: Duplicate crash detection (already handled in step 6 around line 917)
                # Original code was redundant and caused double-counting
        
        # ═════════════════════════════════════════════════════════════════
        # CFG-guided Fuzzing (Critical Fix!)
        # 🔥 Fix: Remove has_new_coverage dependency, allow proactive CFG analysis
        # ═════════════════════════════════════════════════════════════════
        # ═════════════════════════════════════════════════════════════════
        # CFG-guided Fuzzing (Critical Fix!)
        # 🔥 Fix: Remove has_new_coverage dependency, allow proactive CFG analysis
        # ═════════════════════════════════════════════════════════════════
        if self.path_finder:
            should_run_cfg = False

            trigger_reason = None

            # 🔥 Debug: Print current status
            if self.stats.total_execs % 10 == 0:  # Print every 10 iterations
                alog(f"[FuzzingCore] 🔍 CFG Check: exec={self.stats.total_execs}, last={self.last_cfg_analysis_iter}, interval={self.cfg_analysis_interval_iters}", "DEBUG")

            # ✅ P1: Mixed trigger conditions
            # ✅ P1: Mixed trigger conditions
            # Condition 1: Iteration threshold reached
            interval = self.cfg_analysis_interval_iters
            elapsed = self.stats.total_execs - self.last_cfg_analysis_iter
            
            # 🔥 Debug: Log CFG status
            alog(f"[PathFinder] Status Check: elapsed={elapsed}, interval={interval}, has_new_cov={has_new_coverage}", "DEBUG")

            if elapsed >= interval:
                should_run_cfg = True
                trigger_reason = f"{elapsed} iterations"
            
            # 🔥 Force run on new coverage for verification
            if has_new_coverage:
                 should_run_cfg = True
                 trigger_reason = "New Coverage Found"

            # Condition 2: Time threshold reached
            elapsed_since_cfg = time.time() - self.last_cfg_analysis_time
            if elapsed_since_cfg >= self.cfg_analysis_interval_time:
                should_run_cfg = True
                trigger_reason = f"{elapsed_since_cfg:.0f} seconds"
            
            # Unified CFG Analysis (Regular Path)
            if should_run_cfg:
                self._perform_cfg_analysis(trace, has_new_coverage, trigger_reason, iteration_id)
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 5: Trace Saving (if interesting)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if has_new_coverage:
            # Currently reusing the same trace file (Stage 1 simplification)
            # Stage 2 will implement re-recording traces with mutations
            coverage_stats = self.coverage_tracker.get_stats()
            new_edges = coverage_stats.get('new_edges', set())

            coverage_info = {
                'has_new_edges': True,
                'new_edge_count': len(new_edges) if new_edges else 1,
                'total_unique_edges': coverage_stats['total_edges'],
                'edges': new_edges if new_edges else set()
            }

            self.trace_manager.add_trace(
                trace_file=trace.file_path,
                coverage_info=coverage_info,
                parent_id=trace.id,
                mutations=[
                    {
                        'syscall_index': m.syscall_index,
                        'cmd': m.cmd,
                        'arg_index': m.arg_index,
                        'data': m.data.hex() if isinstance(m.data, bytes) else m.data,
                        'offset': m.offset,
                        'size': m.size,
                        'mutation_type': getattr(m, 'mutation_type', 'unknown')
                    }
                    for m in mutations
                ]
            )

            # Update context for scheduling
            if hasattr(self.trace_manager, 'update_context'):
                self.trace_manager.update_context(
                    new_coverage=new_edges if new_edges else set(),
                    no_progress=False
                )
        else:
            if hasattr(self.trace_manager, 'update_context'):
                self.trace_manager.update_context(
                    new_coverage=set(),
                    no_progress=True
                )

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 5.5: Recipe Feedback (if recipe mode)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if self.recipe_pool and hasattr(self.mutator, 'last_recipe_used'):
            recipe_used = getattr(self.mutator, 'last_recipe_used', None)
            
            if recipe_used and result:
                # Check if recipe was successful
                if has_new_coverage:
                    # TODO: Check if the target branch was actually covered
                    # For now, any new coverage is considered partial success
                    self.recipe_pool.update_recipe_result(
                        recipe_used,
                        success=True,
                        new_coverage=1
                    )
                    
                    # Get recipe statistics
                    recipe_id = recipe_used.get('id', -1)
                    if recipe_id in self.recipe_pool.stats:
                        stats = self.recipe_pool.stats[recipe_id]
                        print(f"[FuzzingCore] ✅ Recipe {recipe_id} successful! "
                              f"(Success rate: {stats.success_rate*100:.1f}%)")
                else:
                    # Recipe failed to generate new coverage
                    self.recipe_pool.update_recipe_result(
                        recipe_used,
                        success=False,
                        new_coverage=0
                    )
        
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                # Step 6: Crash Detection and Saving
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                if result.crashed:
                    # ✅ Corrected counting logic: only increment if unique
                    is_unique = self.crash_detector.save_crash(result, trace, mutations)
                    
                    if is_unique:
                        self.stats.crashes_found += 1
                        crashes_found_count += 1
                        print(f"[FuzzingCore] 💥 NEW UNIQUE CRASH FOUND! exit_code={result.qemu_exit_code}, signal={result.signal_number}")
                    else:
                        print(f"[FuzzingCore] 💥 Duplicate crash ignored (Stats consistency)")

                    # ✅ Always notify Layer 5
                    if self.layer5_crash_analyzer:
                        qemu_status = {
                            'signal': result.signal_number,
                            'exit_code': result.qemu_exit_code,
                            'pc': getattr(result, 'pc', 0),
                            'fault_address': getattr(result, 'fault_address', None),
                            'backtrace': getattr(result, 'backtrace', [])
                        }
                        
                        m_inst = mutations
                        mutation_recipe = {
                            'syscall_index': getattr(m_inst, 'syscall_index', -1),
                            'mutations': [str(m_inst)]
                        }
                        
                        try:
                            crash_info = self.layer5_crash_analyzer.analyze_crash(
                                qemu_status=qemu_status,
                                mutation_recipe=mutation_recipe,
                                iteration=self.stats.total_execs
                            )
                            self.layer5_crash_analyzer.save_crash(crash_info) # ✅ Persist to DB
                        except Exception as e:
                            alog(f"⚠️ Layer5 Analysis failed (Core): {e}", "CORE", "ERROR")

                # Handle timeouts
                if result.timeout:
                    self.stats.timeouts += 1

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # Step 7: Statistics Update and Display
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        self._display_progress()

        # ✅ Task #7: Record successful iteration
        self.metrics.record_success('successful_iterations')

        # ✅ Task #8: Return IterationResult
        if not has_any_success:
            # Complete failure: no successful executions
            return create_failure_result(
                iteration_id=iteration_id,
                status=IterationStatus.NO_MUTATIONS,
                error_message="No successful executions",
                error_component="Executor",
                trace_id=trace.id
            )
        else:
            # Success: at least one successful execution
            return create_success_result(
                iteration_id=iteration_id,
                new_coverage=new_coverage_found,
                new_paths=new_paths_found,
                crashes_found=crashes_found_count,
                execs_performed=total_execs,
                mutations_applied=total_mutations,
                trace_id=trace.id
            )
    
    def _read_visualizer_output(self):
        """Reads Realtime Visualizer output in a separate thread (refer to fuzz_conductor.py)"""
        if not self.realtime_viz_process or not self.realtime_viz_process.stdout:
            return
        
        try:
            while True:
                line = self.realtime_viz_process.stdout.readline()
                if not line:
                    break
                # Only print important visualizer messages (reduce noise)
                line_str = line.rstrip()
                if any(keyword in line_str for keyword in ['✅', '❌', '⚠️', 'FORK', 'ERROR', 'Tree', 'MSG', 'ITER', 'DEBUG', 'SimpleVisualizer', 'Connected', 'Initialized']):
                    alog(f"[Visualizer] {line_str}", "CORE", "INFO")
        except Exception as e:
            alog(f"Visualizer output read error: {e}", "CORE", "ERROR")
    
    def _start_realtime_visualizer(self):
        """
        Configures C-Side Syscall Tree Export
        (No longer starts Python Visualizer, instead QEMU C backend directly exports JSON)
        """
        try:
            # Set output path
            if self.enable_pathfinder:
                # Force enable syscall tree export for PathFinder mapping accuracy
                from pathlib import Path
                tree_output_path = Path(self.output_dir) / "latest_syscall_tree.html"
                os.environ["RR_TREE_OUTPUT"] = str(tree_output_path.absolute())
                alog(f"[FuzzingCore] 🌲 PathFinder Syscall Tree Configured: output={tree_output_path}", "CORE")

            if self.enable_tree_viz:
                # Clear old pipe vars if any
                if "RR_TRACE_PIPE" in os.environ:
                    del os.environ["RR_TRACE_PIPE"]
                alog(f"[FuzzingCore] 🎨 Visualizer enabled", "CORE")
            
        except Exception as e:
            alog(f"❌ Failed to configure syscall tree: {e}", "CORE", "ERROR")

    def _stop_realtime_visualizer(self):
        """Stub"""
        pass


    def _get_coverage_percentage(self):
        """Gets current coverage percentage"""
        try:
            stats = self.coverage_tracker.get_stats()
            return stats.get('bitmap_density', 0.0)
        except Exception:
            return 0.0

    def run_advanced(self, stop_conditions: dict):
        """
        Runs the main fuzzing loop (advanced stop conditions version)

        Parameters:
            stop_conditions: Dictionary of stop conditions, including:
                - max_iterations: Maximum number of iterations
                - max_time: Maximum time (seconds)
                - max_crashes: Maximum number of crashes
                - max_paths: Maximum number of new paths
                - coverage_target: Coverage target (%)
                - no_progress_timeout: No progress timeout (seconds)
                - infinite: Whether to run indefinitely
        """
        # Compatible with old interface
        max_iterations = stop_conditions.get('max_iterations')
        max_time = stop_conditions.get('max_time')

        # New advanced stop conditions
        max_crashes = stop_conditions.get('max_crashes')
        max_paths = stop_conditions.get('max_paths')
        coverage_target = stop_conditions.get('coverage_target')
        no_progress_timeout = stop_conditions.get('no_progress_timeout')
        infinite_mode = stop_conditions.get('infinite', False)

        return self._run_with_conditions(
            max_iterations, max_time, max_crashes, max_paths,
            coverage_target, no_progress_timeout, infinite_mode
        )

    def run(self, max_iterations: Optional[int] = None, max_time: Optional[float] = None):
        """
        Runs the main fuzzing loop (backward compatible version)

        Parameters:
            max_iterations: Maximum number of iterations (None for unlimited)
            max_time: Maximum time (seconds) (None for unlimited)
        """
        return self._run_with_conditions(max_iterations, max_time)

    def _run_with_conditions(self, max_iterations=None, max_time=None, max_crashes=None,
                           max_paths=None, coverage_target=None, no_progress_timeout=None,
                           infinite_mode=False):
        """
        Execute actual fuzzing loop, supporting various stop conditions
        """
        # ═══════════════════════════════════════════════════════════════
        # ✅ Note: Visualizer already started in __init__, do not restart
        # ═══════════════════════════════════════════════════════════════
        # Start now if not already started
        if self.enable_tree_viz and not self.realtime_viz_process:
            self._start_realtime_visualizer()

        # ✅ Check and Start Watchdog
        if self.watchdog and not self.watchdog.running:
             self.watchdog.start()

        # Display startup info
        alog(f"\n{'=' * 60}", "CORE", "INFO")
        alog(f"Starting fuzzing campaign", "CORE", "INFO")
        if infinite_mode:
            alog(f"  Mode: Infinite Run (until Ctrl+C)", "CORE", "INFO")
        else:
            if max_iterations:
                alog(f"  Max Iterations: {max_iterations}", "CORE", "INFO")
            if max_time:
                alog(f"  Max Time: {max_time}s", "CORE", "INFO")
            if max_crashes:
                alog(f"  Max Crashes: {max_crashes}", "CORE", "INFO")
            if max_paths:
                alog(f"  Max New Paths: {max_paths}", "CORE", "INFO")
            if coverage_target:
                alog(f"  Coverage Target: {coverage_target}%", "CORE", "INFO")
            if no_progress_timeout:
                alog(f"  No Progress Timeout: {no_progress_timeout}s", "CORE", "INFO")
        alog(f"{'=' * 60}\n", "CORE", "INFO")

        # Initialize variables
        iteration = self.total_iterations
        start_time = self.start_time
        last_progress_time = time.time()
        initial_paths = self.stats.paths_found
        initial_coverage = self._get_coverage_percentage()

        try:
            while True:
                # 🐶 Watchdog Kick
                if self.watchdog:
                     self.watchdog.kick()

                current_time = time.time()
                
                # 💾 Periodic Checkpoint Save
                if self.checkpoint_manager:
                    if current_time - self.last_checkpoint_time >= self.checkpoint_interval:
                        self.checkpoint_manager.save(self)
                        self.last_checkpoint_time = current_time

                # 🔥 Advanced stop condition check
                if not infinite_mode:
                    # Basic conditions
                    if max_iterations and iteration >= max_iterations:
                        alog(f"✅ Maximum iterations reached ({max_iterations})", "CORE", "INFO")
                        break

                    if max_time and (current_time - start_time) >= max_time:
                        alog(f"⏰ Maximum time reached ({max_time}s)", "CORE", "INFO")
                        break

                    # New advanced stop conditions
                    if max_crashes and self.stats.crashes_found >= max_crashes:
                        alog(f"🎯 Found enough crashes ({self.stats.crashes_found}/{max_crashes})", "CORE", "INFO")
                        break

                    if max_paths and (self.stats.paths_found - initial_paths) >= max_paths:
                        alog(f"Tracked enough new paths ({self.stats.paths_found - initial_paths}/{max_paths})", "CORE", "INFO")
                        break

                    if coverage_target:
                        current_coverage = self._get_coverage_percentage()
                        if current_coverage >= coverage_target:
                            alog(f"📊 Coverage target reached ({current_coverage:.1f}%/{coverage_target}%)", "STATS", "INFO")
                            break

                    if no_progress_timeout:
                        # Check for new progress
                        if self.stats.paths_found > initial_paths:
                            last_progress_time = current_time
                            initial_paths = self.stats.paths_found
                        elif (current_time - last_progress_time) >= no_progress_timeout:
                            alog(f"📉 No progress for {no_progress_timeout}s, stopping...", "CORE", "WARN")
                            break
                
                # Unified iteration entry point (handles both normal and dynamic fork)
                result = self.run_single_iteration(iteration_id=iteration)
                
                if result and result.is_failure():
                    alog(f"⚠️  Iteration {iteration} failed: {result}", "CORE", "WARN")
                
                iteration += 1
                self.total_iterations = iteration
        
        except BaseException as e:
            if isinstance(e, KeyboardInterrupt):
                alog(f"User interrupted", "CORE", "WARN")
            else:
                alog(f"🛑 Fuzzer terminated by exception: {type(e).__name__}: {e}", "CORE", "ERROR")
                raise
        
        finally:
            # 🛑 Stop Watchdog
            if self.watchdog:
                 self.watchdog.stop()
            
            # 💾 Final Checkpoint Save
            if self.checkpoint_manager:
                alog(f"💾 Saving final checkpoint...", "CORE", "INFO")
                self.checkpoint_manager.save(self)

            # ═══════════════════════════════════════════════════════════════
            # Option A: Stop Realtime Visualizer and generate final tree
            # ═══════════════════════════════════════════════════════════════
            alog(f"⏳ Waiting for components to finalize...", "CORE", "INFO")
            alog(f"⏳ Waiting for components to finalize...", "CORE", "INFO")
            time.sleep(5)  # ✅ Wait for all messages to be processed
            alog(f"⏳ Stopping Visualizer...", "CORE", "INFO")
            self._stop_realtime_visualizer()
            
            # Final statistics
            self._display_final_statistics()
    
    def _display_final_statistics(self):
        """Display final fuzzing statistics"""
        cov_stats = self.coverage_tracker.get_stats()
        trace_stats = self.trace_manager.get_statistics()
        exec_stats = self.execution_engine.get_statistics()
        
        alog(f"✅ Fuzzing loop completed. Preparing final report...", "CORE", "INFO")
        
        # Save final results (corpus, stats, etc.)
        self.save_final_results()
    
    def save_final_results(self):
        """
        Save final results to disk
        
        Layer 5 Integration: Auto-generate all monitoring and analysis reports
        """
        import json
        from pathlib import Path
        
        output_path = Path(self.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Display final statistics before saving
        self._display_progress(force=True)
        
        # 🔥 DEBUG: Check stats object identity and values
        alog(f"DEBUG: stats.total_execs={self.stats.total_execs}, type={type(self.stats)}", "CORE", "DEBUG")
        alog(f"DEBUG: cov_tracker.total_edges={self.coverage_tracker.total_edges_cached}", "CORE", "DEBUG")
        
        alog(f"💾 Saving final results...", "CORE", "INFO")
        
        # Save corpus (Layer 2)
        self.trace_manager.save_corpus(self.output_dir)
        
        # Save final statistics
        stats_file = output_path / "final_stats.json"
        with open(stats_file, 'w') as f:
            # Use default=list to convert any remaining sets to lists
            json.dump({
                'execution': {
                    'total_execs': self.stats.total_execs,
                    'execs_per_sec': self.stats.execs_per_sec,
                    'elapsed_time': self.stats.elapsed_time,
                    'crashes_found': self.stats.crashes_found,
                    'paths_found': self.stats.paths_found,
                    'timeouts': self.stats.timeouts
                },
                'start_time': self.start_time,
                'coverage': self.coverage_tracker.get_stats(),
                'traces': self.trace_manager.get_statistics(),
                'executor': self.execution_engine.get_statistics(),
                'metrics': self.metrics.to_dict(),
                'mutation_graph': self.mutation_graph.to_dict()
            }, f, indent=2, default=lambda o: list(o) if isinstance(o, set) else str(o))

        alog(f"  ✅ Statistics saved to {stats_file}", "CORE", "INFO")

        # ✅ Task #7: Save FuzzingMetrics detailed report
        metrics_report_file = output_path / "metrics_report.txt"
        with open(metrics_report_file, 'w') as f:
            f.write(self.metrics.generate_report())
        alog(f"  ✅ Metrics report saved to {metrics_report_file}", "CORE", "INFO")

        # ✅ Task #6: Save MutationDependencyGraph detailed report
        mutation_report_file = output_path / "mutation_analysis.txt"
        with open(mutation_report_file, 'w') as f:
            f.write(self.mutation_graph.generate_report())
        alog(f"  ✅ Mutation analysis report saved to {mutation_report_file}", "CORE", "INFO")

        # ✅ Task #6: Export complete mutation graph structure (for in-depth analysis)
        if self.mutation_graph.nodes:
            mutation_graph_file = output_path / "mutation_graph.json"
            self.mutation_graph.export_to_json(mutation_graph_file)
            alog(f"  ✅ Mutation graph structure saved to {mutation_graph_file}", "CORE", "INFO")
        
        # ═══════════════════════════════════════════════════════════
        # Layer 5: Monitoring & Analysis (Important!)
        # ═══════════════════════════════════════════════════════════
        
        if self.enable_monitoring:
            
            # Gather stats for final display
            cov_stats = self.coverage_tracker.get_stats()
            trace_stats = self.trace_manager.get_statistics()
            exec_stats = self.execution_engine.get_statistics()
            
            alog("\n" + "═"*70, "SUMMARY", "INFO")
            alog(f"{'🏁 Fuzzing Campaign Summary':^70}", "SUMMARY", "INFO")
            alog("═"*70, "SUMMARY", "INFO")
            
            # Row 1: Execution & Coverage
            # ✅ Fix: Use authoritative source for exec count
            final_total_execs = self.stats.total_execs
            if final_total_execs == 0:
                final_total_execs = exec_stats.get('total_executions', 0)
                if final_total_execs == 0:
                    final_total_execs = self.total_executions
            
            final_speed = self.stats.execs_per_sec
            if final_speed == 0 and final_total_execs > 0 and self.stats.elapsed_time > 0:
                final_speed = final_total_execs / self.stats.elapsed_time
            
            # If aggregated stats exist (e.g. from DynamicForkController updation)
            if hasattr(self.stats, 'aggregated_total_execs') and self.stats.aggregated_total_execs > 0:
                 final_total_execs = self.stats.aggregated_total_execs
                 if self.stats.elapsed_time > 0:
                     final_speed = final_total_execs / self.stats.elapsed_time

            alog(f" │ {'📊 Execution Metrics':<32} │ {'🎯 Coverage Metrics':<32} │", "SUMMARY", "INFO")
            alog(f" │ {'─'*32} │ {'─'*32} │", "SUMMARY", "INFO")
            alog(f" │ Total Execs : {final_total_execs:<18} │ Total Edges : {cov_stats['total_edges']:<18} │", "SUMMARY", "INFO")
            alog(f" │ Speed       : {final_speed:>.1f} exec/s       │ New Paths   : {self.stats.paths_found:<18} │", "SUMMARY", "INFO")
            alog(f" │ Duration    : {self.stats.elapsed_time:>.1f}s            │ Density     : {cov_stats['bitmap_density']:>.2f}%            │", "SUMMARY", "INFO")
            alog(" " + "─"*70, "SUMMARY", "INFO")
            
            # Row 2: Corpus & Reliability
            alog(f" │ {'📦 Corpus Health':<32} │ {'💥 Reliability Metrics':<32} │", "SUMMARY", "INFO")
            alog(f" │ {'─'*32} │ {'─'*32} │", "SUMMARY", "INFO")
            alog(f" │ Total Traces: {trace_stats['total_traces']:<18} │ Total Crashes: {self.stats.crashes_found:<17} │", "SUMMARY", "INFO")
            alog(f" │ Active      : {trace_stats['active_traces']:<18} │ Unique       : {len(self.crash_detector.crashes):<17} │", "SUMMARY", "INFO")
            alog(f" │ Saved       : {trace_stats['traces_saved']:<18} │ Crash Rate   : {exec_stats['crash_rate']:>.2%}            │", "SUMMARY", "INFO")
            alog("═"*70 + "\n", "SUMMARY", "INFO")
            
            # 1. CorpusManager: Persistent corpus
            if self.layer5_corpus_manager:
                try:
                    # Note: corpus_manager requires seed_queue object, simplified here
                    alog(f"  ✅ [Corpus] Manager Active (Manual save required)", "CORE", "INFO")
                except Exception as e:
                    alog(f"  ❌ [Corpus] Save Failed: {e}", "CORE", "ERROR")
            
            # 2. CrashAnalyzer: Generate crash report
            if self.layer5_crash_analyzer:
                try:
                    alog(f"  📊 [Analysis] Generating crash report...", "CORE", "INFO")
                    alog("  " + "─"*50, "CORE", "INFO")
                    
                    # Hack: Capture sys.stdout to redirect print_summary to alog
                    import io
                    from contextlib import redirect_stdout
                    f = io.StringIO()
                    with redirect_stdout(f):
                        self.layer5_crash_analyzer.print_summary(top_n=20, verbose=True)
                    
                    for line in f.getvalue().splitlines():
                        alog(f"  {line}", "CORE", "INFO")
                    
                    alog("  " + "─"*50, "CORE", "INFO")
                    
                    # Export crash report
                    crash_report = output_path / "crash_analysis.json"
                    self.layer5_crash_analyzer.export_to_file(crash_report, format='json')
                    alog(f"  ✅ [Report] Saved to: {crash_report}", "CORE", "INFO")
                except Exception as e:
                    alog(f"  ❌ [Analysis] Failed: {e}", "CORE", "ERROR")
            
            # 3. ⭐ C-Side Syscall Tree Export (HTML Bundle)
            tree_path = output_path / "latest_syscall_tree.html"
            if tree_path.exists():
                alog(f"  🌳 [Syscall Tree] HTML Bundle Exported", "CORE", "INFO")
                alog(f"     => file://{tree_path.absolute()}", "CORE", "INFO")
            else:
                # alog(f"  ⚠️  [Syscall Tree] Export Failed (File not found)", "CORE", "WARN")
                pass
            
            alog("\n" + "═"*60, "CORE", "INFO")
            alog(f"  📂 All artifacts saved to: {output_path}", "CORE", "INFO")
            alog("═"*60 + "\n", "CORE", "INFO")
            
            # ✅ Final Resource Cleanup
            if self.execution_engine:
                self.execution_engine.stop_persistent_qemu()
            
            # ✅ STOP LOGGER LAST
            if self.logger:
                alog("✅ Project cleanup complete. Goodbye!", "CORE", "INFO")
                self.logger.stop()
    
    def _generate_syscall_trees(self, output_path: Path):
        """
        Generate Syscall Tree Visualization (Layer 5 key feature)
        
        Generates a unified horizontal tree visualization for all traces.
        Uses D3.js tree layout for a true hierarchical structure.
        """
        trees_dir = output_path / "syscall_trees"
        trees_dir.mkdir(exist_ok=True)
        
        # Collect all trace files
        trace_files = []
        labels = []
        
        # 1. Initial trace
        if os.path.exists(self.initial_trace):
            trace_files.append(self.initial_trace)
            labels.append("Initial Trace")
        
        # 2. Corpus traces (limit to top 10)
        corpus_dir = Path(self.output_dir) / "corpus"
        if corpus_dir.exists():
            for trace_file in sorted(corpus_dir.glob("*.bin"))[:10]:
                trace_files.append(str(trace_file))
                labels.append(f"Corpus: {trace_file.stem}")
        
        # 3. Crash traces (limit to top 5)
        crashes_dir = Path(self.output_dir) / "crashes"
        if crashes_dir.exists():
            for crash_file in sorted(crashes_dir.glob("*.bin"))[:5]:
                trace_files.append(str(crash_file))
                labels.append(f"Crash: {crash_file.stem}")
        
        if not trace_files:

            return
        
        # Use TreeVisualizer to generate horizontal tree (with stats)
        alog(f"  🌳 Generating tree visualization for {len(trace_files)} traces...", "CORE", "INFO")
        
        try:
            viz = TreeVisualizer()
            
            for trace_file, label in zip(trace_files, labels):
                # ✅ Get statistics for this trace
                # Extract trace_id from filename (if it's a corpus file)
                trace_id = None
                if 'corpus' in str(trace_file):
                    trace_id = Path(trace_file).stem
                # ✅ Fix: Initial trace should be independent, not using corpus stats
                # Because initial trace has no mutations, it shouldn't share stats with mutated traces
                
                # Build stats dict
                stats_dict = None
                if trace_id:
                    syscall_stats = self.trace_manager.get_syscall_stats(trace_id)
                    if syscall_stats:
                        stats_dict = {
                            'syscall_stats': syscall_stats,
                            'trace_id': trace_id
                        }
                    alog(f"  📊 Found stats for {trace_id}: {len(syscall_stats)} syscalls have data", "CORE", "DEBUG")
                else:
                    # Initial trace has no stats (all mutation_applied=False)
                    alog(f"  📊 {label} has no stats (initial trace, no mutations)", "CORE", "DEBUG")
                
                # Add trace (with stats)
                viz.add_trace(trace_file, label, stats=stats_dict)
            
            tree_html = trees_dir / "syscall_tree.html"
            if viz.generate_html(str(tree_html)):
                alog(f"  ✅ Tree generated: {tree_html}", "CORE", "INFO")
                alog(f"  📂 View tree: file://{tree_html.absolute()}", "CORE", "INFO")
            else:
                alog(f"  ⚠️  Failed to generate tree visualization", "CORE", "WARN")
        
        except Exception as e:
            alog(f"  ⚠️  Tree generation failed: {e}", "CORE", "ERROR")
            import traceback
            traceback.print_exc()
    
    def cleanup(self):
        """Clean up resources (called on exit)"""
        alog("Cleaning up resources...", "CORE", "INFO")
        
        # Display final statistics if not already shown recently
        self._display_progress(force=True)
        
        # ═══════════════════════════════════════════════════════════════
        # Option A: Ensure Realtime Visualizer is stopped
        # ═══════════════════════════════════════════════════════════════
        self._stop_realtime_visualizer()
        
        # ✅ Fix: Gracefully stop persistent QEMU executor
        if hasattr(self, 'execution_engine') and self.execution_engine:
            if hasattr(self.execution_engine, 'stop_persistent_mode'):
                # New persistent executor
                self.execution_engine.stop_persistent_mode()
            elif hasattr(self.execution_engine, 'stop_persistent_qemu'):
                # Legacy executor
                self.execution_engine.stop_persistent_qemu()
        
        # Clean up shared coverage bitmap
        from .qemu_executor import QEMUExecutor
        QEMUExecutor.cleanup_shared_coverage()
        
        # Clean up CoverageTracker (release multiprocessing resources)
        if hasattr(self, 'coverage_tracker') and self.coverage_tracker:
            if hasattr(self.coverage_tracker, 'cleanup'):
                self.coverage_tracker.cleanup()
        
        alog("✅ Cleanup complete", "CORE", "INFO")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.cleanup()
        except:
            pass

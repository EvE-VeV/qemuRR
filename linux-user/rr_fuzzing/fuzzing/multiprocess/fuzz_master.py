#!/usr/bin/env python3
"""
FuzzMaster - Layer 4: Multi-Process Fuzzing Coordinator

Manages multiple worker processes for parallel fuzzing.
Implements the architecture described in DETAILED_ARCHITECTURE.md Layer 4 (Line 318-380).

Architecture:
  - Master process coordinates N workers
  - Each worker runs independent FuzzingCore
  - Shared sync directory for corpus/crashes/coverage
  - Periodic synchronization and statistics collection
"""

import os
import sys
import time
import json
import signal
import shutil
import multiprocessing as mp
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict, field

# Add parent directory to path for conductor imports
_current_dir = Path(__file__).parent
_fuzzing_dir = _current_dir.parent
if str(_fuzzing_dir) not in sys.path:
    sys.path.insert(0, str(_fuzzing_dir))

from conductor.fuzzing_core import FuzzingCore
from conductor.trace_manager import TraceManager
from conductor.mutator import BaseMutator, SmartMutator
from conductor.coverage import CoverageTracker


@dataclass
class WorkerConfig:
    """Configuration for a single worker"""
    worker_id: int
    qemu_path: str
    target_binary: str
    initial_trace: str
    sync_dir: Path
    worker_dir: Path
    mutator_type: str = "smart"  # "base" or "smart"
    recipe_file: Optional[str] = None


@dataclass
class WorkerStats:
    """Statistics for a single worker"""
    worker_id: int
    execs: int = 0
    paths_found: int = 0
    crashes_found: int = 0
    timeouts: int = 0
    total_edges: int = 0
    exec_speed: float = 0.0
    last_update: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class FuzzMaster:
    """
    Layer 4: Multi-Process Fuzzing Master
    
    Responsibilities:
    1. Spawn and manage N worker processes
    2. Distribute initial traces to workers
    3. Synchronize coverage and corpus between workers
    4. Collect and aggregate statistics
    5. Monitor worker health and restart if needed
    
    Architecture: DETAILED_ARCHITECTURE.md Line 318-380
    """
    
    def __init__(
        self,
        qemu_path: str,
        target_binary: str,
        initial_trace: str,
        num_workers: Optional[int] = None,
        sync_dir: str = "sync_dir",
        mutator_type: str = "smart",
        recipe_file: Optional[str] = None,
        master_timeout: Optional[int] = None
    ):
        """
        Initialize FuzzMaster
        
        Args:
            qemu_path: Path to QEMU executable
            target_binary: Path to target binary
            initial_trace: Path to initial seed trace
            num_workers: Number of worker processes (default: CPU count)
            sync_dir: Synchronization directory
            mutator_type: "base" or "smart"
            recipe_file: Recipe file for smart mutation
            master_timeout: Master timeout in seconds (None for unlimited)
        """
        self.qemu_path = qemu_path
        self.target_binary = target_binary
        self.initial_trace = initial_trace
        self.num_workers = num_workers or mp.cpu_count()
        self.sync_dir = Path(sync_dir).resolve()
        self.mutator_type = mutator_type
        self.recipe_file = recipe_file
        self.master_timeout = master_timeout
        
        # Worker management
        self.workers: List[mp.Process] = []
        self.worker_configs: List[WorkerConfig] = []
        self.worker_stats: Dict[int, WorkerStats] = {}
        
        # Shared resources
        self.global_coverage: Optional[bytearray] = None
        self.global_trace_count = 0
        self.global_crash_count = 0
        
        # Control
        self.shutdown_requested = False
        self.start_time = None
        
        print(f"[FuzzMaster] Initializing multi-process fuzzing")
        print(f"  Workers: {self.num_workers}")
        print(f"  Sync dir: {self.sync_dir}")
        print(f"  Mutator: {self.mutator_type}")
        
        # Setup sync directory structure
        self._setup_sync_directory()
    
    def _setup_sync_directory(self):
        """
        Setup synchronization directory structure
        
        Structure (Architecture Line 361-379):
        sync_dir/
        ├── queue/          # All test traces
        ├── crashes/        # Discovered crashes
        │   ├── worker0/
        │   └── worker1/
        ├── coverage/       # Coverage data
        ├── corpus/         # Persistent corpus
        └── stats/          # Statistics
        """
        # Create main directories
        self.sync_dir.mkdir(parents=True, exist_ok=True)
        
        dirs = ['queue', 'crashes', 'coverage', 'corpus', 'stats']
        for d in dirs:
            (self.sync_dir / d).mkdir(exist_ok=True)
        
        # Create worker-specific crash directories
        for i in range(self.num_workers):
            (self.sync_dir / 'crashes' / f'worker{i}').mkdir(exist_ok=True)
        
        # Copy initial trace to queue
        initial_queue_trace = self.sync_dir / 'queue' / 'trace_000.bin'
        if not initial_queue_trace.exists():
            shutil.copy(self.initial_trace, initial_queue_trace)
        
        # Initialize global coverage bitmap
        coverage_file = self.sync_dir / 'coverage' / 'global_bitmap.bin'
        if not coverage_file.exists():
            with open(coverage_file, 'wb') as f:
                f.write(bytes(64 * 1024))  # 64KB zero bitmap
        
        print(f"[FuzzMaster] Sync directory structure created")
    
    def _create_worker_config(self, worker_id: int) -> WorkerConfig:
        """Create configuration for a worker"""
        worker_dir = self.sync_dir / f'worker{worker_id}'
        worker_dir.mkdir(exist_ok=True)
        
        return WorkerConfig(
            worker_id=worker_id,
            qemu_path=self.qemu_path,
            target_binary=self.target_binary,
            initial_trace=self.initial_trace,
            sync_dir=self.sync_dir,
            worker_dir=worker_dir,
            mutator_type=self.mutator_type,
            recipe_file=self.recipe_file
        )
    
    @staticmethod
    def _worker_main(config: WorkerConfig, iterations_per_sync: int = 100):
        """
        Worker main function (runs in separate process)
        
        Each worker:
        1. Creates its own FuzzingCore
        2. Runs fuzzing iterations
        3. Periodically syncs to shared directory
        4. Updates worker statistics
        
        Args:
            config: Worker configuration
            iterations_per_sync: Iterations between syncs
        """
        worker_id = config.worker_id
        
        print(f"[Worker{worker_id}] Starting...")
        
        try:
            # Create mutator
            if config.mutator_type == "smart":
                mutator = SmartMutator(
                    trace_file=config.initial_trace,
                    recipe_file=config.recipe_file
                )
            else:
                mutator = BaseMutator()
            
            # Create FuzzingCore for this worker
            fuzzing_core = FuzzingCore(
                qemu_path=config.qemu_path,
                target_binary=config.target_binary,
                initial_trace=config.initial_trace,
                output_dir=str(config.worker_dir),
                mutator=mutator
            )
            
            print(f"[Worker{worker_id}] FuzzingCore initialized")
            
            # Worker fuzzing loop
            iteration = 0
            while True:
                # Run single iteration
                should_continue = fuzzing_core.run_single_iteration()
                if not should_continue:
                    break
                
                iteration += 1
                
                # Periodic sync
                if iteration % iterations_per_sync == 0:
                    FuzzMaster._worker_sync(config, fuzzing_core)
                    FuzzMaster._worker_update_stats(config, fuzzing_core)
        
        except KeyboardInterrupt:
            print(f"[Worker{worker_id}] Interrupted")
        except Exception as e:
            print(f"[Worker{worker_id}] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Layer 5: Save final results (including syscall trees!)
            try:
                if 'fuzzing_core' in locals():
                    print(f"[Worker{worker_id}] Saving final results (Layer 5)...")
                    fuzzing_core.save_final_results()
            except Exception as e:
                print(f"[Worker{worker_id}] Failed to save results: {e}")
            
            print(f"[Worker{worker_id}] Exiting")
    
    @staticmethod
    def _worker_sync(config: WorkerConfig, fuzzing_core: FuzzingCore):
        """
        Synchronize worker data to shared directory
        
        Syncs:
        1. New traces to queue/
        2. Crashes to crashes/workerN/
        3. Coverage to coverage/
        """
        worker_id = config.worker_id
        
        # Sync new traces from trace manager
        for trace in fuzzing_core.trace_manager.trace_pool:
            if trace.metadata.new_coverage_count > 0:
                # Copy to shared queue
                dest = config.sync_dir / 'queue' / f'{trace.id}_w{worker_id}.bin'
                if not dest.exists() and os.path.exists(trace.file_path):
                    try:
                        shutil.copy(trace.file_path, dest)
                    except:
                        pass
        
        # Sync crashes
        crash_dir = config.worker_dir / 'crashes'
        if crash_dir.exists():
            shared_crash_dir = config.sync_dir / 'crashes' / f'worker{worker_id}'
            for crash_file in crash_dir.glob('crash_*.bin'):
                dest = shared_crash_dir / crash_file.name
                if not dest.exists():
                    try:
                        shutil.copy(crash_file, dest)
                        # Also copy metadata
                        meta_file = crash_file.with_suffix('.meta')
                        if meta_file.exists():
                            shutil.copy(meta_file, dest.with_suffix('.meta'))
                    except:
                        pass
        
        # Sync coverage (merge into global)
        coverage_file = config.sync_dir / 'coverage' / 'global_bitmap.bin'
        try:
            # Read global coverage
            with open(coverage_file, 'rb') as f:
                global_cov = bytearray(f.read())
            
            # Read worker's coverage
            worker_cov = fuzzing_core.coverage_tracker.global_bitmap
            
            # Merge (bitwise OR)
            for i in range(len(global_cov)):
                global_cov[i] |= worker_cov[i]
            
            # Write back
            with open(coverage_file, 'wb') as f:
                f.write(global_cov)
        except Exception as e:
            print(f"[Worker{worker_id}] Coverage sync failed: {e}")
    
    @staticmethod
    def _worker_update_stats(config: WorkerConfig, fuzzing_core: FuzzingCore):
        """Update worker statistics in shared directory"""
        worker_id = config.worker_id
        
        stats = WorkerStats(
            worker_id=worker_id,
            execs=fuzzing_core.stats.total_execs,
            paths_found=fuzzing_core.stats.paths_found,
            crashes_found=fuzzing_core.stats.crashes_found,
            timeouts=fuzzing_core.stats.timeouts,
            total_edges=fuzzing_core.coverage_tracker.get_stats()['total_edges'],
            exec_speed=fuzzing_core.stats.execs_per_sec,
            last_update=time.time()
        )
        
        stats_file = config.sync_dir / 'stats' / f'worker{worker_id}_stats.json'
        try:
            with open(stats_file, 'w') as f:
                json.dump(stats.to_dict(), f, indent=2)
        except:
            pass
    
    def start_workers(self):
        """Start all worker processes"""
        print(f"\n[FuzzMaster] Starting {self.num_workers} workers...")
        
        for i in range(self.num_workers):
            config = self._create_worker_config(i)
            self.worker_configs.append(config)
            
            # Create and start worker process
            worker = mp.Process(
                target=FuzzMaster._worker_main,
                args=(config, 10),  # Sync every 10 iterations
                name=f"Worker{i}"
            )
            worker.daemon = False
            worker.start()
            
            self.workers.append(worker)
            self.worker_stats[i] = WorkerStats(worker_id=i)
            
            print(f"[FuzzMaster] Started Worker{i} (PID={worker.pid})")
            
            # Small delay between worker starts
            time.sleep(0.5)
        
        print(f"[FuzzMaster] All workers started")
    
    def _collect_statistics(self):
        """Collect statistics from all workers"""
        for i in range(self.num_workers):
            stats_file = self.sync_dir / 'stats' / f'worker{i}_stats.json'
            try:
                if stats_file.exists():
                    with open(stats_file, 'r') as f:
                        data = json.load(f)
                        self.worker_stats[i] = WorkerStats(**data)
            except:
                pass
    
    def _display_progress(self):
        """Display aggregated fuzzing progress"""
        # Collect latest stats
        self._collect_statistics()
        
        # Aggregate
        total_execs = sum(w.execs for w in self.worker_stats.values())
        total_paths = sum(w.paths_found for w in self.worker_stats.values())
        total_crashes = sum(w.crashes_found for w in self.worker_stats.values())
        total_timeouts = sum(w.timeouts for w in self.worker_stats.values())
        avg_speed = sum(w.exec_speed for w in self.worker_stats.values())
        
        # Read global coverage
        coverage_file = self.sync_dir / 'coverage' / 'global_bitmap.bin'
        try:
            with open(coverage_file, 'rb') as f:
                global_cov = f.read()
                total_edges = sum(1 for b in global_cov if b > 0)
        except:
            total_edges = 0
        
        # Count traces and crashes
        trace_count = len(list((self.sync_dir / 'queue').glob('*.bin')))
        crash_count = sum(len(list((self.sync_dir / 'crashes' / f'worker{i}').glob('*.bin')))
                         for i in range(self.num_workers))
        
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n{'=' * 70}")
        print(f"Multi-Process Fuzzing Progress")
        print(f"{'=' * 70}")
        print(f"Workers:       {self.num_workers} active")
        print(f"Total execs:   {total_execs}")
        print(f"Exec speed:    {avg_speed:.1f} exec/s")
        print(f"Elapsed:       {elapsed:.0f}s")
        print(f"")
        print(f"Corpus size:   {trace_count} traces")
        print(f"Coverage:      {total_edges} edges")
        print(f"Paths found:   {total_paths}")
        print(f"Crashes:       {crash_count} (unique)")
        print(f"Timeouts:      {total_timeouts}")
        print(f"")
        print(f"Per-Worker Stats:")
        for i in range(self.num_workers):
            w = self.worker_stats[i]
            alive = "✓" if self.workers[i].is_alive() else "✗"
            print(f"  Worker{i} [{alive}]: {w.execs:6d} execs, "
                  f"{w.paths_found:3d} paths, {w.crashes_found:3d} crashes, "
                  f"{w.exec_speed:5.1f} exec/s")
        print(f"{'=' * 70}")
    
    def _check_workers_alive(self):
        """Check worker health and restart if needed"""
        for i, worker in enumerate(self.workers):
            if not worker.is_alive():
                print(f"\n[FuzzMaster] ⚠️  Worker{i} died, restarting...")
                
                # Create new worker
                config = self.worker_configs[i]
                new_worker = mp.Process(
                    target=FuzzMaster._worker_main,
                    args=(config,),
                    name=f"Worker{i}"
                )
                new_worker.daemon = False
                new_worker.start()
                
                self.workers[i] = new_worker
                print(f"[FuzzMaster] Worker{i} restarted (PID={new_worker.pid})")
    
    def monitor_loop(self, display_interval: int = 5):
        """
        Master monitoring loop
        
        Tasks (Architecture Line 346-357):
        1. Every 5s: Check workers, collect stats, display progress
        2. Every 60s: Periodic maintenance tasks
        
        Args:
            display_interval: Display interval in seconds
        """
        print(f"\n[FuzzMaster] Entering monitoring loop...")
        
        self.start_time = time.time()
        last_display = time.time()
        last_maintenance = time.time()
        
        try:
            while not self.shutdown_requested:
                current_time = time.time()
                
                # Check timeout
                if self.master_timeout:
                    elapsed = current_time - self.start_time
                    if elapsed >= self.master_timeout:
                        print(f"\n[FuzzMaster] Timeout reached ({self.master_timeout}s)")
                        break
                
                # Check worker health
                self._check_workers_alive()
                
                # Display progress
                if current_time - last_display >= display_interval:
                    self._display_progress()
                    last_display = current_time
                
                # Periodic maintenance (every 60s)
                if current_time - last_maintenance >= 60:
                    self._periodic_maintenance()
                    last_maintenance = current_time
                
                # Sleep
                time.sleep(1)
        
        except KeyboardInterrupt:
            print(f"\n[FuzzMaster] Interrupted by user")
            self.shutdown_requested = True
    
    def _periodic_maintenance(self):
        """Periodic maintenance tasks (every 60s)"""
        # Save aggregated corpus
        corpus_dir = self.sync_dir / 'corpus'
        queue_dir = self.sync_dir / 'queue'
        
        # Copy interesting traces to corpus
        for trace_file in queue_dir.glob('*.bin'):
            dest = corpus_dir / trace_file.name
            if not dest.exists():
                try:
                    shutil.copy(trace_file, dest)
                except:
                    pass
    
    def shutdown(self):
        """Shutdown all workers gracefully"""
        print(f"\n[FuzzMaster] Shutting down workers...")
        
        # Terminate all workers
        for i, worker in enumerate(self.workers):
            if worker.is_alive():
                print(f"[FuzzMaster] Terminating Worker{i}...")
                worker.terminate()
                worker.join(timeout=5)
                
                if worker.is_alive():
                    print(f"[FuzzMaster] Killing Worker{i}...")
                    worker.kill()
                    worker.join()
        
        # Final statistics
        print(f"\n[FuzzMaster] Final Statistics:")
        self._display_progress()
        
        print(f"\n[FuzzMaster] Shutdown complete")
    
    def run(self):
        """
        Main entry point to run multi-process fuzzing
        
        Flow:
        1. Setup sync directory
        2. Start all workers
        3. Monitor loop
        4. Shutdown gracefully
        """
        try:
            # Start workers
            self.start_workers()
            
            # Monitor loop
            self.monitor_loop()
        
        except Exception as e:
            print(f"\n[FuzzMaster] Error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            # Shutdown
            self.shutdown()


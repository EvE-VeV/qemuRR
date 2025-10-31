#!/usr/bin/env python3
"""
Multi-Process Extensions for FuzzConductor

This module provides extensions to FuzzConductor to support multi-process fuzzing.
It acts as a wrapper/mixin to add multi-process capabilities without modifying
the core FuzzConductor heavily.
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import Optional
import multiprocessing as mp

# Import shared resources
from .shared_resources import SharedCoverage, WorkerSeedQueue


class MultiProcessFuzzConductor:
    """
    Multi-process wrapper for FuzzConductor
    
    为FuzzConductor添加多进程支持，包括：
    1. Worker ID和进程间同步
    2. 共享Coverage和Seed队列
    3. 定期统计信息更新
    """
    
    def __init__(
        self,
        base_conductor,
        worker_id: int = 0,
        num_workers: int = 1,
        sync_dir: Optional[str] = None,
    ):
        """
        初始化多进程扩展
        
        Args:
            base_conductor: 底层的FuzzConductor实例
            worker_id: Worker ID
            num_workers: 总worker数量
            sync_dir: 同步目录
        """
        self.base_conductor = base_conductor
        self.worker_id = worker_id
        self.num_workers = num_workers
        self.sync_dir = Path(sync_dir) if sync_dir else None
        
        # 是否启用多进程模式
        self.multiprocess_enabled = (sync_dir is not None and num_workers > 1)
        
        if self.multiprocess_enabled:
            print(f"[Worker {worker_id}] Multi-process mode enabled ({num_workers} workers)")
            
            # 初始化共享资源
            self.shared_coverage = SharedCoverage(self.sync_dir, worker_id)
            self.shared_seeds = WorkerSeedQueue(worker_id, self.sync_dir, num_workers)
            
            # 同步计数器
            self.iterations = 0
            self.SYNC_INTERVAL = 100  # 每100次迭代同步一次
            
            # 统计信息
            self.stats = {
                'execs': 0,
                'crashes': 0,
                'hangs': 0,
                'queue_size': 0,
                'coverage': 0,
            }
        else:
            print(f"[Conductor] Single-process mode")
            self.shared_coverage = None
            self.shared_seeds = None
    
    def run_fuzzing(self, rounds: int, shutdown_event: Optional[mp.Event] = None):
        """
        运行fuzzing循环（多进程版本）
        
        Args:
            rounds: Fuzzing迭代次数
            shutdown_event: 关闭事件（用于优雅退出）
        """
        print(f"[Worker {self.worker_id}] Starting fuzzing for {rounds} rounds")
        
        for i in range(rounds):
            # 检查shutdown信号
            if shutdown_event and shutdown_event.is_set():
                print(f"[Worker {self.worker_id}] Shutdown requested, exiting...")
                break
            
            # 执行一次fuzzing迭代
            self._fuzz_iteration(i)
            
            # 定期同步
            if self.multiprocess_enabled and self.should_sync():
                self._sync_with_master()
        
        print(f"[Worker {self.worker_id}] Fuzzing completed")
    
    def _fuzz_iteration(self, iteration: int):
        """
        单次fuzzing迭代
        
        Args:
            iteration: 迭代编号
        """
        # 1. 从底层conductor生成mutations
        instructions = self.base_conductor.smart_mutator.build_instructions(iteration)
        if not instructions:
            return
        
        # 2. 执行fuzzing
        status = self.base_conductor.send_fuzz_command(instructions)
        if status is None:
            return
        
        # 3. 读取coverage
        current_coverage = self.base_conductor.basic_coverage_tracker.read_coverage()
        
        # 4. 更新本地coverage
        new_edges = 0
        if current_coverage:
            if self.base_conductor.basic_coverage_tracker.has_new_coverage(current_coverage):
                # 保存新seed
                seed_info = {
                    'round': iteration + 1,
                    'instructions': instructions,
                    'status': status
                }
                self.base_conductor.new_seeds.append(seed_info)
                
                # 多进程模式：同步到全局
                if self.multiprocess_enabled:
                    new_edges = self.shared_coverage.update_coverage(current_coverage)
                    
                    # 保存到共享seed队列
                    if new_edges > 0:
                        self.shared_seeds.save_seed(
                            seed_info,
                            new_edges=new_edges,
                            depth=iteration  # 简化：使用iteration作为depth
                        )
        
        # 5. Coverage-guided fuzzing（如果启用）
        if self.base_conductor.enable_coverage_feedback and current_coverage:
            bb_sequence = [i for i, val in enumerate(current_coverage) if val > 0]
            new_seed = self.base_conductor.coverage_guided_fuzzer.add_seed(
                trace_file=f"trace_w{self.worker_id}_r{iteration}.dat",
                bb_sequence=bb_sequence,
                parent_id=None,
                crash=(status == "Crash Found")
            )
        
        # 6. 处理crash
        if status == "Crash Found":
            self.stats['crashes'] += 1
            
            # 使用crash analyzer（如果可用）
            if hasattr(self.base_conductor, 'crash_analyzer') and self.base_conductor.crash_analyzer:
                # 这里需要更详细的crash信息
                pass
        
        # 7. 更新统计
        self.stats['execs'] += 1
        self.iterations += 1
        
        if self.base_conductor.enable_coverage_feedback:
            self.stats['queue_size'] = len(self.base_conductor.coverage_guided_fuzzer.seed_queue.seeds)
            self.stats['coverage'] = len(self.base_conductor.coverage_guided_fuzzer.coverage_tracker.global_coverage)
    
    def should_sync(self) -> bool:
        """判断是否应该同步"""
        return self.iterations % self.SYNC_INTERVAL == 0
    
    def _sync_with_master(self):
        """定期同步"""
        if not self.multiprocess_enabled:
            return
        
        try:
            # 1. 从其他worker导入seeds
            imported_seeds = self.shared_seeds.sync_with_others()
            if imported_seeds and self.base_conductor.enable_coverage_feedback:
                for seed in imported_seeds:
                    # 将导入的seeds添加到本地队列
                    # 注意：这里需要将seed转换为合适的格式
                    pass
            
            # 2. 同步全局coverage
            new_edges = self.shared_coverage.sync_coverage()
            if new_edges > 0 and self.base_conductor.enable_coverage_feedback:
                # 更新本地coverage tracker
                # 将共享的bitmap合并到本地
                pass
            
            # 3. 更新统计文件
            self._update_stats_file()
            
            if imported_seeds:
                print(f"[Worker {self.worker_id}] Synced: imported {len(imported_seeds)} seeds, "
                      f"{new_edges} new coverage edges")
        
        except Exception as e:
            print(f"[Worker {self.worker_id}] Warning: sync failed: {e}")
    
    def _update_stats_file(self):
        """更新worker统计文件"""
        if not self.multiprocess_enabled:
            return
        
        stats_file = self.sync_dir / "stats" / f"worker{self.worker_id}_stats.json"
        try:
            with open(stats_file, 'w') as f:
                stats_dict = {
                    'worker_id': self.worker_id,
                    'timestamp': time.time(),
                    **self.stats
                }
                json.dump(stats_dict, f, indent=2)
        except Exception as e:
            print(f"[Worker {self.worker_id}] Warning: failed to update stats: {e}")


def create_multiprocess_conductor(
    program_path: str,
    qemu_path: str,
    trace_dir: str,
    worker_id: int = 0,
    num_workers: int = 1,
    sync_dir: Optional[str] = None,
    output_dir: Optional[str] = None,
    timeout: int = 1000,
    **conductor_kwargs
):
    """
    创建多进程模式的FuzzConductor
    
    这是一个工厂函数，用于创建配置好的多进程FuzzConductor实例。
    
    Args:
        program_path: 目标程序路径
        qemu_path: QEMU路径
        trace_dir: Trace目录
        worker_id: Worker ID
        num_workers: Worker数量
        sync_dir: 同步目录
        output_dir: 输出目录
        timeout: 超时时间
        **conductor_kwargs: 其他传递给FuzzConductor的参数
    
    Returns:
        配置好的MultiProcessFuzzConductor实例
    """
    from fuzz_conductor import FuzzConductor
    
    # 创建trace文件路径（简化：使用第一个trace）
    trace_files = list(Path(trace_dir).glob("*.strace"))
    if not trace_files:
        raise ValueError(f"No trace files found in {trace_dir}")
    trace_file = str(trace_files[0])
    
    # 创建底层FuzzConductor
    base_conductor = FuzzConductor(
        qemu_path=qemu_path,
        target_binary=program_path,
        trace_file=trace_file,
        output_dir=output_dir,
        **conductor_kwargs
    )
    
    # 包装为多进程版本
    mp_conductor = MultiProcessFuzzConductor(
        base_conductor=base_conductor,
        worker_id=worker_id,
        num_workers=num_workers,
        sync_dir=sync_dir,
    )
    
    return mp_conductor


def test_multiprocess_extensions():
    """测试多进程扩展"""
    print("Testing MultiProcess Extensions...")
    
    # 这里需要实际的FuzzConductor实例来测试
    # 暂时跳过
    print("⚠️  Test requires actual FuzzConductor instance, skipping")


if __name__ == '__main__':
    test_multiprocess_extensions()


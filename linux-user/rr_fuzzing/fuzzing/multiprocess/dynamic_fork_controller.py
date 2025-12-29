#!/usr/bin/env python3
"""
DynamicForkController - 动态Fork探索控制器

功能:
1. 基于PathFinder识别的未覆盖分支
2. 生成多个mutation variants
3. 协调批量fork执行
4. 收集和分析结果
5. 更新RecipePool反馈

作者: RR-Fuzz Team
日期: 2025-11-06
"""

import random
import time
from typing import List, Dict, Optional, Tuple, TYPE_CHECKING
from pathlib import Path
from dataclasses import dataclass

# 导入现有组件（100%复用）
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# 使用 TYPE_CHECKING 避免循环导入
if TYPE_CHECKING:
    from conductor.qemu_executor import QEMUExecutor
else:
    # 运行时延迟导入
    QEMUExecutor = None

from conductor.mutator import SmartMutator
from conductor.coverage import CoverageTracker
from conductor.trace_manager import TraceManager, Trace
from .dual_level_path_finder import DualLevelPathFinder as PathFinder
from .recipe_pool import RecipePool


@dataclass
class FuzzCheckpoint:
    """
    深度优先探索的Checkpoint数据结构

    每个checkpoint代表一个可以继续探索的状态点
    """
    trace_file: str  # trace文件路径
    syscall_index: int  # checkpoint的syscall位置
    depth: int  # 当前探索深度
    coverage_state: bytes  # 覆盖率状态（用于恢复）
    unexplored_mutations: List  # 未探索的mutation变种
    parent_checkpoint_id: str  # 父checkpoint ID（用于追溯）
    checkpoint_id: str  # 唯一标识
    discovery_iteration: int  # 发现此checkpoint的迭代次数
    mutation_node_ids: List[str] = None  # ✅ Task #6补充: Mutation node IDs for tracking

    def __str__(self):
        return f"Checkpoint[{self.checkpoint_id}] @syscall[{self.syscall_index}] depth={self.depth} mutations={len(self.unexplored_mutations)}"


class DynamicForkController:
    """
    动态Fork探索控制器
    
    复用的组件:
    - PathFinder: 识别未覆盖分支 ✅
    - RecipePool: 管理分支recipes ✅  
    - SmartMutator: 生成mutations ✅
    - QEMUExecutor: 执行批量fork ✅
    - CoverageTracker: 分析结果 ✅
    
    新增的逻辑:
    - 智能fork点选择
    - 批量fork协调
    - 分支价值评估
    """
    
    def __init__(self,
                 executor: 'QEMUExecutor',
                 path_finder: Optional[PathFinder],
                 mutator: SmartMutator,
                 recipe_pool: Optional[RecipePool],
                 coverage_tracker: CoverageTracker,
                 trace_manager: TraceManager = None,
                 fuzzing_stats=None,
                 mutation_graph=None):
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
        """
        self.executor = executor
        self.path_finder = path_finder
        self.mutator = mutator
        self.recipe_pool = recipe_pool
        self.coverage_tracker = coverage_tracker
        self.trace_manager = trace_manager  # ✅ 修复2: 添加trace_manager用于保存新种子
        self.fuzzing_stats = fuzzing_stats  # ✅ Single source of truth
        self.mutation_graph = mutation_graph  # ✅ Task #6补充: Mutation tracking

        # 🔥 新增：深度优先checkpoint/snapshot模式配置
        self.depth_first_mode = True  # 启用深度优先探索
        self.max_depth = 2  # ✅ P0 Fix 1.3: 降低深度从5到2 (执行数从243降到9, 节省96%)
        self.max_variants_per_checkpoint = 2  # 每个checkpoint最多2个变种
        self.checkpoint_queue = []  # 待探索的checkpoint队列（深度优先）

        # 传统配置（调整为支持深度模式）
        self.max_variants_per_fork = 2  # 降低并发数，支持深度探索
        self.fork_budget_per_1000 = 200  # 增加预算，支持深度探索

        # ✅ 自适应trigger_probability配置
        # 🔥 P3 Fix 3.2: 从10%提升到20%，解决触发频率过低问题 (6.7% → 20%+)
        self.trigger_probability = 0.2  # 基础概率（初始值）从0.1提升到0.2
        self.adaptive_trigger = True  # 启用自适应调整
        self.min_trigger_probability = 0.15  # 最小触发概率从0.05提升到0.15
        self.max_trigger_probability = 0.4  # 最大触发概率从0.3提升到0.4

        # 自适应统计窗口
        self.recent_forks = []  # [(success, timestamp), ...] 最近的fork结果
        self.recent_window_size = 20  # 窗口大小
        self.last_new_coverage_time = time.time()  # 最后发现新coverage的时间

        # 🔥 新增：当前trace对象（用于IO mutation）
        self.current_trace = None

        # 统计（增加深度相关统计）
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

        print(f"[DynamicForkController] Initialized (🌊 深度优先checkpoint/snapshot模式)")
        print(f"  Deep-First Mode: ✅ 启用")
        print(f"  Max exploration depth: {self.max_depth}")
        print(f"  Max variants per checkpoint: {self.max_variants_per_checkpoint}")
        print(f"  Fork budget: {self.fork_budget_per_1000}/1000 iterations")
        if self.adaptive_trigger:
            print(f"  Adaptive Trigger: ✅ 启用 (初始={self.trigger_probability}, 范围=[{self.min_trigger_probability}, {self.max_trigger_probability}])")

    def _calculate_adaptive_probability(self) -> float:
        """
        计算自适应trigger_probability

        调整策略：
        1. 成功率高（>30%）→ 增加触发概率（更多fork有价值）
        2. 成功率低（<10%）→ 降低触发概率（减少浪费）
        3. Coverage停滞（>5分钟无新coverage）→ 增加触发概率（探索新路径）
        4. Coverage快速增长 → 保持当前概率

        Returns:
            调整后的trigger_probability
        """
        if not self.adaptive_trigger:
            return self.trigger_probability

        current_prob = self.trigger_probability

        # 1. 基于成功率调整
        if len(self.recent_forks) >= 10:
            # 计算最近的成功率
            recent_success_count = sum(1 for success, _ in self.recent_forks if success)
            success_rate = recent_success_count / len(self.recent_forks)

            if success_rate > 0.3:
                # 成功率高，增加触发概率
                current_prob = min(current_prob * 1.2, self.max_trigger_probability)
            elif success_rate < 0.1:
                # 成功率低，降低触发概率
                current_prob = max(current_prob * 0.8, self.min_trigger_probability)

        # 2. 基于Coverage停滞调整
        time_since_last_coverage = time.time() - self.last_new_coverage_time
        if time_since_last_coverage > 300:  # 5分钟无新coverage
            # Coverage停滞，增加Dynamic Fork探索
            current_prob = min(current_prob * 1.5, self.max_trigger_probability)

        # 3. 限制在范围内
        current_prob = max(self.min_trigger_probability, min(current_prob, self.max_trigger_probability))

        return current_prob

    def _record_fork_result(self, success: bool):
        """
        记录fork的成功/失败结果（用于自适应调整）

        Args:
            success: True表示发现新coverage或crash，False表示无新发现
        """
        if not self.adaptive_trigger:
            return

        current_time = time.time()
        self.recent_forks.append((success, current_time))

        # 保持窗口大小
        if len(self.recent_forks) > self.recent_window_size:
            self.recent_forks.pop(0)

    def should_trigger_multi_fork(self, iteration: int) -> bool:
        """
        判断是否触发multi-fork（自适应版本）

        Args:
            iteration: 当前迭代次数

        Returns:
            True if should trigger
        """
        # 预算检查
        period = iteration // 1000
        if self.stats['forks_this_period'] >= self.fork_budget_per_1000:
            return False

        # 新周期重置
        if iteration % 1000 == 0:
            self.stats['forks_this_period'] = 0

        # ✅ 自适应概率触发
        if self.adaptive_trigger:
            adaptive_prob = self._calculate_adaptive_probability()
            # 每100次迭代更新一次trigger_probability
            if iteration % 100 == 0:
                old_prob = self.trigger_probability
                self.trigger_probability = adaptive_prob
                if abs(old_prob - adaptive_prob) > 0.01:  # 只在变化明显时输出
                    print(f"[DynamicForkController] Adaptive trigger_probability: {old_prob:.3f} → {adaptive_prob:.3f}")
            return random.random() < adaptive_prob
        else:
            return random.random() < self.trigger_probability
    
    def explore_multi_path(self, trace: Trace, iteration_id: int = 0) -> bool:
        """
        🌊 深度优先checkpoint/snapshot探索

        实现策略：
        1. 从根trace开始或恢复最深的checkpoint
        2. 在每个IO syscall处创建checkpoint
        3. 执行第一个mutation，继续深度探索
        4. 如果到达最大深度或无新覆盖率，回溯到前一个checkpoint
        5. 继续探索该checkpoint的其他mutations

        Args:
            trace: 要探索的trace
            iteration_id: 当前iteration编号

        Returns:
            True if discovered new paths
        """
        # 🔥 保存当前trace供mutation使用
        self.current_trace = trace
        if not self.depth_first_mode:
            # 兼容性：如果未启用深度模式，使用传统模式
            return self._explore_breadth_first(trace, iteration_id)

        print(f"\n[DynamicForkController] 🌊 Iteration {iteration_id}: Dynamic Multi-Fork on {trace.id}")

        # 🔥 修复：每次都从根trace开始，一次性测试多个mutations
        print(f"[DynamicForkController] 🌱 Starting multi-fork from root trace")
        return self._start_depth_exploration(trace, iteration_id)

    def _start_depth_exploration(self, trace: Trace, iteration_id: int) -> bool:
        """
        从根trace开始深度探索

        ✅ OPTIMIZATION: 缓存baseline执行结果，避免重复fork QEMU
        """
        # ✅ 检查是否已经缓存了这个trace的IO syscalls
        cache_key = trace.file_path
        if not hasattr(self, '_io_syscalls_cache'):
            self._io_syscalls_cache = {}

        if cache_key in self._io_syscalls_cache:
            # ✅ 使用缓存，避免重复分析
            io_syscalls = self._io_syscalls_cache[cache_key]
            print(f"[DynamicForkController] ⚡ Using cached IO syscalls for {trace.id} (0ms)")
        else:
            # ✅ P0 Fix 1.2: 使用静态分析替代baseline执行 (节省120ms)
            print(f"[DynamicForkController] 📊 Static analysis to discover IO syscalls (no QEMU execution)...")

            # ❌ 移除: baseline_result = self.executor.execute_baseline(...)
            # ✅ 改为: 直接使用TraceAnalyzer静态分析

            # ✅ 智能IO syscall选择（_find_io_syscalls内部使用TraceAnalyzer静态分析）
            io_syscalls = self._find_io_syscalls(trace, max_fork_points=2)

            # ✅ 缓存结果
            self._io_syscalls_cache[cache_key] = io_syscalls
            print(f"[DynamicForkController] 💾 Cached {len(io_syscalls)} IO syscalls for future use (saved 120ms baseline execution)")

        if not io_syscalls:
            print(f"[DynamicForkController] No IO syscalls found")
            return False

        print(f"[DynamicForkController] Found {len(io_syscalls)} IO syscalls: {io_syscalls}")

        # ✅ 存储为实例变量，供nested fork使用
        self.current_io_syscalls = io_syscalls

        # 从第一个IO syscall开始深度探索
        first_io_syscall = io_syscalls[0]
        print(f"[DynamicForkController] 🎯 Starting deep exploration at first IO syscall[{first_io_syscall}]")

        return self._explore_at_checkpoint(trace.file_path, first_io_syscall, 0, iteration_id, "root")

    def _explore_at_checkpoint(self, trace_file: str, syscall_index: int, depth: int, iteration_id: int, parent_id: str) -> bool:
        """
        在指定的syscall位置创建checkpoint并探索
        """
        if depth > self.max_depth:
            print(f"[DynamicForkController] 🔚 Reached max depth ({self.max_depth}), stopping exploration")
            return False

        checkpoint_id = f"cp_{iteration_id}_{syscall_index}_{depth}"
        print(f"[DynamicForkController] 📍 Creating checkpoint[{checkpoint_id}] @syscall[{syscall_index}] depth={depth}")

        # 生成mutations for this checkpoint
        mutations = []
        mutation_node_ids = []  # ✅ Task #6补充: Track mutation node IDs
        for i in range(self.max_variants_per_checkpoint):
            # 🔥 传递当前trace对象供IO mutation使用
            mutation = self.mutator.mutate(self.current_trace, fork_point=syscall_index)
            mutations.append(mutation)

            # ✅ Task #6补充: Track mutation in graph
            # ✅ 2025-11-18: 从FuzzInstruction中读取mutation_type
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

        print(f"[DynamicForkController] Generated {len(mutations)} mutations for checkpoint")

        # 保存当前覆盖率状态作为checkpoint
        coverage_snapshot = self._save_coverage_state()

        # 🔥 修复：不需要checkpoint队列，直接执行所有mutations
        # 创建checkpoint对象（用于记录，但不队列）
        checkpoint = FuzzCheckpoint(
            trace_file=trace_file,
            syscall_index=syscall_index,
            depth=depth,
            coverage_state=coverage_snapshot,
            unexplored_mutations=[],  # 所有mutations都会被执行
            parent_checkpoint_id=parent_id,
            checkpoint_id=checkpoint_id,
            discovery_iteration=iteration_id,
            mutation_node_ids=mutation_node_ids if mutation_node_ids else []
        )

        # 🔥 修复：一次性执行所有mutations（真正的dynamic fork）
        if mutations:
            print(f"[DynamicForkController] 🚀 Executing {len(mutations)} mutations in parallel (dynamic multi-fork)...")

            try:
                results = self.executor.execute_fork(
                    trace_file=trace_file,
                    fork_point=syscall_index,
                    mutation_variants=mutations,  # 传递所有mutations
                    depth=depth,
                    iteration_id=iteration_id
                )

                # ✅ Update unified stats counter (1 execution per variant)
                if self.fuzzing_stats and results:
                    self.fuzzing_stats.total_execs += len(results)

                if results and len(results) > 0:
                    result = results[0]
                    has_new_coverage = self.coverage_tracker.has_new_coverage(result.coverage_bitmap)

                    # ✅ Task #6补充: Update mutation result in graph
                    if self.mutation_graph and mutation_node_ids:
                        coverage_stats = self.coverage_tracker.get_stats()
                        self.mutation_graph.update_mutation_result(
                            node_id=mutation_node_ids[0],  # First mutation
                            has_new_coverage=has_new_coverage,
                            new_edges=coverage_stats.get('new_edges_this_run', 0),
                            total_edges=coverage_stats.get('total_edges', 0),
                            crashed=result.crashed,
                            timed_out=False,
                            exec_time=getattr(result, 'exec_time', 0.0)
                        )

                    # 🔥 修复：让程序运行到结束（正常退出或崩溃）再回退到checkpoint
                    if result.crashed:
                        print(f"[DynamicForkController] 💥 CRASH detected at depth={depth}!")
                        print(f"[DynamicForkController] 🎯 Crash info: {result.crash_info if hasattr(result, 'crash_info') else 'Unknown crash'}")
                        self.stats['new_paths_discovered'] += 1

                        # ✅ 记录成功的fork
                        self._record_fork_result(success=True)

                        print(f"[DynamicForkController] ⬅️  Program finished (crashed), backtracking to checkpoint...")
                        return True  # crash是成功的探索结果

                    elif has_new_coverage:
                        print(f"[DynamicForkController] 🎉 New coverage discovered at depth={depth}!")
                        self.stats['new_paths_discovered'] += 1

                        # ✅ 记录成功的fork并更新last_new_coverage_time
                        self._record_fork_result(success=True)
                        self.last_new_coverage_time = time.time()

                        # ✅ 修复2: 保存新种子到corpus
                        if self.trace_manager:
                            coverage_stats = self.coverage_tracker.get_stats()
                            new_edges = coverage_stats.get('new_edges', set())

                            coverage_info = {
                                'has_new_edges': True,
                                'new_edge_count': len(new_edges) if new_edges else 1,
                                'total_unique_edges': coverage_stats.get('total_edges', 0),
                                'edges': new_edges if new_edges else set()
                            }

                            # Flatten mutations list (mutations is List[List[FuzzInstruction]])
                            mutation_dicts = []
                            for mutation_list in mutations:
                                if isinstance(mutation_list, list):
                                    for instr in mutation_list:
                                        if hasattr(instr, 'syscall_index') and hasattr(instr, 'cmd'):
                                            mutation_dicts.append({
                                                'syscall_index': instr.syscall_index,
                                                'cmd': instr.cmd
                                            })

                            # 保存新种子（使用当前trace文件和mutations）
                            parent_trace_id = getattr(self, 'current_trace_id', None)
                            self.trace_manager.add_trace(
                                trace_file=trace_file,
                                coverage_info=coverage_info,
                                parent_id=parent_trace_id,
                                mutations=mutation_dicts
                            )
                            print(f"[DynamicForkController] 💾 Saved new seed to corpus (new_edges={len(new_edges) if new_edges else 1})")

                        # ✅ 2025-11-18: Nested Fork - 继续探索更深层次（使用预选IO syscalls）
                        if depth < self.max_depth:
                            # ✅ 2025-11-18: 智能选择 - 使用预选的IO syscall列表，避免过多fork点
                            next_syscall = None
                            if hasattr(self, 'current_io_syscalls') and self.current_io_syscalls:
                                # 找到当前syscall之后的下一个预选IO syscall
                                next_io_syscalls = [io for io in self.current_io_syscalls if io > syscall_index]
                                if next_io_syscalls:
                                    next_syscall = next_io_syscalls[0]
                                    print(f"[DynamicForkController] ⬇️  Going deeper: depth {depth} → {depth+1}, next IO fork @syscall[{next_syscall}]")
                                else:
                                    print(f"[DynamicForkController] 🔚 No more preselected IO syscalls available for deeper exploration at depth={depth}")
                            else:
                                # 回退到原有逻辑（如果没有预选IO syscalls）
                                next_syscall = syscall_index + 10
                                print(f"[DynamicForkController] ⬇️  Going deeper: depth {depth} → {depth+1}, next fork @syscall[{next_syscall}] (fallback)")

                            # ✅ 只在找到有效的下一个syscall时才递归探索
                            if next_syscall is not None:
                                deeper_success = self._explore_at_checkpoint(
                                    trace_file=trace_file,
                                    syscall_index=next_syscall,
                                    depth=depth + 1,
                                    iteration_id=iteration_id,
                                    parent_id=checkpoint_id
                                )

                                if deeper_success:
                                    print(f"[DynamicForkController] ⬆️  Coming back from depth {depth+1} (found interesting path)")
                                    self.stats['max_depth_reached'] = max(self.stats.get('max_depth_reached', 0), depth + 1)
                                else:
                                    print(f"[DynamicForkController] ⬆️  Coming back from depth {depth+1} (no new findings)")

                        print(f"[DynamicForkController] ⬅️  Program finished (normal exit with new coverage), backtracking to checkpoint...")
                        return True  # 有新coverage，这是成功的探索

                    else:
                        print(f"[DynamicForkController] 📊 No new coverage at depth={depth}")

                        # ✅ 记录失败的fork
                        self._record_fork_result(success=False)

                        print(f"[DynamicForkController] ⬅️  Program finished (normal exit, no new coverage), backtracking to checkpoint...")
                        return False  # 无新发现，回退
                else:
                    print(f"[DynamicForkController] ❌ Fork execution failed")

                    # ✅ 记录失败的fork
                    self._record_fork_result(success=False)

                    return False

            except Exception as e:
                print(f"[DynamicForkController] Error during deep exploration: {e}")
                return False

        return False

    def _resume_checkpoint_exploration(self, checkpoint: FuzzCheckpoint, iteration_id: int) -> bool:
        """
        从checkpoint恢复并继续探索
        """
        print(f"[DynamicForkController] 🔄 Restoring checkpoint {checkpoint.checkpoint_id}")

        # 恢复覆盖率状态
        self._restore_coverage_state(checkpoint.coverage_state)
        self.stats['snapshot_restores'] += 1

        # 取出下一个未探索的mutation
        if not checkpoint.unexplored_mutations:
            print(f"[DynamicForkController] 📋 No more mutations in checkpoint {checkpoint.checkpoint_id}")
            return False

        next_mutation = checkpoint.unexplored_mutations.pop(0)

        # ✅ Task #6补充: Get corresponding mutation node ID
        next_mutation_node_id = None
        if checkpoint.mutation_node_ids:
            next_mutation_node_id = checkpoint.mutation_node_ids.pop(0)

        # 如果还有更多mutations，重新加入队列
        if checkpoint.unexplored_mutations:
            self.checkpoint_queue.append(checkpoint)

        print(f"[DynamicForkController] 🧪 Testing next mutation from checkpoint...")

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

                # 🔥 修复：checkpoint恢复后的正确处理
                if result.crashed:
                    print(f"[DynamicForkController] 💥 CRASH detected from checkpoint restoration!")
                    print(f"[DynamicForkController] 🎯 Crash at checkpoint {checkpoint.checkpoint_id}, depth={checkpoint.depth}")
                    self.stats['new_paths_discovered'] += 1
                    return True  # crash是成功结果，继续处理其他checkpoints

                elif has_new_coverage:
                    print(f"[DynamicForkController] 🎉 New coverage from checkpoint restoration!")
                    self.stats['new_paths_discovered'] += 1
                    print(f"[DynamicForkController] ⬅️  Program finished (normal exit with new coverage), backtracking...")
                    return True  # 有新coverage，成功的探索

                else:
                    print(f"[DynamicForkController] 📊 No new coverage from restored checkpoint")
                    print(f"[DynamicForkController] ⬅️  Program finished (normal exit, no new coverage), backtracking...")
                    return False  # 无新发现，回退

        except Exception as e:
            print(f"[DynamicForkController] Error during checkpoint restoration: {e}")
            return False

        return False

    def _save_coverage_state(self) -> bytes:
        """保存当前覆盖率状态"""
        self.stats['snapshot_saves'] += 1
        # 这里应该保存实际的coverage bitmap状态
        # 为简化起见，目前返回空bytes，实际实现应该保存coverage_tracker的状态
        return b""

    def _restore_coverage_state(self, state: bytes):
        """恢复覆盖率状态"""
        # 这里应该恢复coverage bitmap状态
        # 为简化起见，目前仅重置coverage
        self.executor.reset_coverage()

    def _find_next_io_syscalls(self, trace_file: str, current_index: int) -> List[int]:
        """
        找到指定index之后的IO syscalls
        """
        # 这里应该分析trace文件找到后续的IO syscalls
        # 为简化起见，返回一些假设的后续IO syscalls
        try:
            from ..trace_analyzer import TraceAnalyzer
        except ImportError:
            # 修复相对import错误
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

            # 返回大于current_index的IO syscalls
            next_ios = [idx for idx in all_io_syscalls if idx > current_index]
            return next_ios[:3]  # 最多返回3个后续IO syscalls
        except:
            # 如果分析失败，返回空列表
            return []

    def _explore_breadth_first(self, trace: Trace, iteration_id: int) -> bool:
        """
        传统的广度优先探索（兼容性）
        """
        # 这里是原来的explore_multi_path逻辑的简化版本
        # 保持向后兼容性
        print(f"[DynamicForkController] Using legacy breadth-first mode")
        return False
    
    def _get_covered_blocks(self) -> set:
        """
        获取已覆盖的基本块集合
        
        Returns:
            已覆盖blocks的地址集合
        """
        covered = set()
        
        # 从coverage bitmap提取covered edges
        for i, val in enumerate(self.coverage_tracker.global_bitmap):
            if val > 0:
                # 简化：使用bitmap index作为block ID
                covered.add(i & 0xFFFF)
        
        return covered
    
    def _select_top_branches(self, branches: List[Dict], max_n: int) -> List[Dict]:
        """
        选择最有价值的N个分支
        
        Args:
            branches: 所有未覆盖分支
            max_n: 最多选择数量
        
        Returns:
            Top-N分支列表
        """
        scored = []
        
        for branch in branches:
            score = self._evaluate_branch_value(branch)
            scored.append((score, branch))
        
        # ✅ 修复：只按score排序（第一个元素是float）
        scored.sort(key=lambda x: x[0], reverse=True)
        return [b for _, b in scored[:max_n]]
    
    def _evaluate_branch_value(self, branch: Dict) -> float:
        """
        评估分支价值
        
        评分标准:
        - 距离近（容易到达）
        - 有syscall（可以mutation）
        - 类型是条件分支（不是switch）
        """
        score = 0.0
        
        # 1. 距离分数
        distance = branch.get('distance', 999)
        score += 10.0 / (1 + distance)
        
        # 2. Syscall分数
        if branch.get('has_syscall', False):
            score += 5.0
        
        # 3. 类型分数
        if branch.get('type') in ['true_branch', 'false_branch']:
            score += 3.0
        
        return score
    
    def _find_recipe_for_branch(self, branch: Dict) -> Optional[Dict]:
        """
        查找分支对应的recipe
        
        Args:
            branch: 分支信息
        
        Returns:
            Recipe dict或None
        """
        if not self.recipe_pool:
            return None
        
        target_addr = branch['to']
        
        # 遍历active recipes
        for recipe in self.recipe_pool.active_recipes:
            if recipe.get('target_branch') == f"0x{target_addr:x}":
                return recipe
        
        return None
    
    def _find_io_syscalls(self, trace: Trace, max_fork_points: int = 2) -> list:
        """
        智能选择IO syscalls作为fork点

        ✅ 2025-11-18: 优化 - 限制fork点数量，避免过多执行

        策略:
        1. 优先级排序: read > write > getrandom
        2. 返回值大小: 大返回值更可能影响程序行为
        3. 限制数量: 只选择top N个最重要的IO syscalls

        Args:
            trace: Trace对象
            max_fork_points: 最大fork点数量（默认2）

        Returns:
            IO syscall索引列表（已排序，最多max_fork_points个）
        """
        # 导入TraceAnalyzer
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'analysis'))
        from trace_analyzer import TraceAnalyzer

        analyzer = TraceAnalyzer(trace.file_path)

        # ✅ 收集IO syscalls及其元信息
        io_candidates = []

        for sc in analyzer.syscalls:
            # 只考虑IO syscalls
            if sc.name in ['read', 'recv', 'recvfrom', 'getrandom', 'write', 'send']:
                # 跳过前10%的syscalls（初始化阶段）
                if sc.index < len(analyzer.syscalls) * 0.1:
                    continue

                # ✅ 计算优先级分数
                priority_score = 0

                # 1. Syscall类型优先级
                if sc.name in ['read', 'recv', 'recvfrom']:
                    priority_score += 100  # 最高优先级
                elif sc.name in ['getrandom']:
                    priority_score += 50   # 中等优先级
                elif sc.name in ['write', 'send']:
                    priority_score += 30   # 较低优先级

                # 2. 返回值大小（表示数据量）
                try:
                    retval = int(sc.retval) if hasattr(sc, 'retval') else 0
                    if retval > 0:
                        priority_score += min(retval, 100)  # 最多加100分
                except:
                    pass

                # 3. 位置加成（中间位置的syscalls更重要）
                total_syscalls = len(analyzer.syscalls)
                position_ratio = sc.index / total_syscalls
                if 0.2 < position_ratio < 0.8:  # 中间60%
                    priority_score += 20

                io_candidates.append({
                    'index': sc.index,
                    'name': sc.name,
                    'retval': int(sc.retval) if hasattr(sc, 'retval') else 0,
                    'priority': priority_score
                })

        # ✅ 按优先级排序并限制数量
        io_candidates.sort(key=lambda x: x['priority'], reverse=True)
        selected = io_candidates[:max_fork_points]

        # 返回索引列表
        result = [item['index'] for item in selected]

        if result:
            print(f"[DynamicForkController] ✅ Selected {len(result)}/{len(io_candidates)} IO syscalls as fork points:")
            for item in selected:
                print(f"  - syscall[{item['index']}] {item['name']}: retval={item['retval']}, priority={item['priority']:.0f}")

        return result

    def _select_diverse_fork_point(self, io_syscalls: list, iteration_id: int) -> int:
        """
        🔥 修复：选择多样化的fork点，避免单点固定

        策略:
        1. 轮换算法：在IO syscalls之间循环选择
        2. 分层探索：早期/中期/后期syscalls
        3. 随机扰动：避免完全预测性
        4. PathFinder集成：优先选择CFG引导的热点

        Args:
            io_syscalls: 可用的IO syscall索引列表
            iteration_id: 当前迭代ID

        Returns:
            选择的fork点索引
        """
        if not io_syscalls:
            return 10  # 默认fallback

        # 策略1: 基于迭代ID的轮换算法
        base_index = iteration_id % len(io_syscalls)

        # 策略2: 分层探索 - 根据迭代阶段选择不同区域
        if iteration_id < 10:
            # 早期：探索较早的IO syscalls
            region_start = 0
            region_end = min(3, len(io_syscalls))
        elif iteration_id < 30:
            # 中期：探索中间部分
            region_start = len(io_syscalls) // 3
            region_end = min(len(io_syscalls) * 2 // 3 + 1, len(io_syscalls))
        else:
            # 后期：探索所有syscalls，重点关注后部
            region_start = max(0, len(io_syscalls) - 5)
            region_end = len(io_syscalls)

        # 在选定区域内选择
        if region_end > region_start:
            region_syscalls = io_syscalls[region_start:region_end]
            target_index = base_index % len(region_syscalls)
            fork_point = region_syscalls[target_index]
        else:
            fork_point = io_syscalls[base_index]

        # 策略3: 随机扰动（20%概率）
        if random.random() < 0.2:
            fork_point = random.choice(io_syscalls)

        # 策略4: PathFinder集成 (如果可用)
        # TODO: 将来集成PathFinder的热点分析

        # 确保最小值
        return max(10, fork_point)

    def _mutation_from_recipe(self, recipe: Dict) -> List:
        """
        从recipe生成mutation
        
        Args:
            recipe: Recipe dict
        
        Returns:
            Mutation instruction list
        """
        # ✅ 复用SmartMutator的recipe支持
        # TODO: 实现recipe到instruction的转换
        # 目前简化：使用mutator生成
        return self.mutator.mutate(None)
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        return self.stats.copy()
    
    def print_summary(self):
        """打印探索摘要"""
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


# 测试代码
if __name__ == '__main__':
    print("DynamicForkController module loaded successfully")


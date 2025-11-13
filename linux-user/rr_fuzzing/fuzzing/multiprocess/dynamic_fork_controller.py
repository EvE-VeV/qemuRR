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
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass

# 导入现有组件（100%复用）
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from conductor.qemu_executor import QEMUExecutor
from conductor.mutator import SmartMutator
from conductor.coverage import CoverageTracker
from conductor.trace_manager import TraceManager, Trace
from .path_finder import PathFinder
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
                 executor: QEMUExecutor,
                 path_finder: Optional[PathFinder],
                 mutator: SmartMutator,
                 recipe_pool: Optional[RecipePool],
                 coverage_tracker: CoverageTracker):
        """Initialize dynamic fork controller
        
        Args:
            executor: QEMU executor
            path_finder: PathFinder instance (optional, None uses simple strategy)
            mutator: SmartMutator instance
            recipe_pool: RecipePool instance (optional)
            coverage_tracker: CoverageTracker instance
        """
        self.executor = executor
        self.path_finder = path_finder
        self.mutator = mutator
        self.recipe_pool = recipe_pool
        self.coverage_tracker = coverage_tracker

        # 🔥 新增：深度优先checkpoint/snapshot模式配置
        self.depth_first_mode = True  # 启用深度优先探索
        self.max_depth = 5  # 最大探索深度
        self.max_variants_per_checkpoint = 2  # 每个checkpoint最多2个变种
        self.checkpoint_queue = []  # 待探索的checkpoint队列（深度优先）

        # 传统配置（调整为支持深度模式）
        self.max_variants_per_fork = 2  # 降低并发数，支持深度探索
        self.fork_budget_per_1000 = 200  # 增加预算，支持深度探索
        self.trigger_probability = 1.0

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
    
    def should_trigger_multi_fork(self, iteration: int) -> bool:
        """
        判断是否触发multi-fork
        
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
        
        # 概率触发
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
        if not self.depth_first_mode:
            # 兼容性：如果未启用深度模式，使用传统模式
            return self._explore_breadth_first(trace, iteration_id)

        print(f"\n[DynamicForkController] 🌊 Iteration {iteration_id}: Deep-First checkpoint/snapshot exploration on {trace.id}")

        # 第一步：检查是否有待探索的checkpoints
        if not self.checkpoint_queue:
            # 没有checkpoint，从根trace开始探索
            print(f"[DynamicForkController] 🌱 Starting fresh exploration from root trace")
            return self._start_depth_exploration(trace, iteration_id)
        else:
            # 有待探索的checkpoint，继续深度探索
            current_checkpoint = self.checkpoint_queue.pop()  # 深度优先：从栈顶取checkpoint
            print(f"[DynamicForkController] 📂 Resuming exploration from {current_checkpoint}")
            return self._resume_checkpoint_exploration(current_checkpoint, iteration_id)

    def _start_depth_exploration(self, trace: Trace, iteration_id: int) -> bool:
        """
        从根trace开始深度探索
        """
        print(f"[DynamicForkController] Step 1: Execute baseline to discover IO syscalls...")

        # 执行baseline以发现IO syscalls
        try:
            baseline_result = self.executor.execute_baseline(
                trace_file=trace.file_path,
                iteration_id=iteration_id
            )
            if baseline_result.normal_exit:
                print(f"[DynamicForkController] Baseline execution completed")
            else:
                print(f"[DynamicForkController] Warning: Baseline failed, continuing...")
        except Exception as e:
            print(f"[DynamicForkController] Warning: Baseline exception: {e}")

        io_syscalls = self._find_io_syscalls(trace)
        if not io_syscalls:
            print(f"[DynamicForkController] No IO syscalls found")
            return False

        print(f"[DynamicForkController] Found {len(io_syscalls)} IO syscalls: {io_syscalls}")

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
        for i in range(self.max_variants_per_checkpoint):
            # 这里需要根据syscall_index生成mutation
            mutation = self.mutator.mutate(None, fork_point=syscall_index)
            mutations.append(mutation)

        print(f"[DynamicForkController] Generated {len(mutations)} mutations for checkpoint")

        # 保存当前覆盖率状态作为checkpoint
        coverage_snapshot = self._save_coverage_state()

        # 创建checkpoint对象
        checkpoint = FuzzCheckpoint(
            trace_file=trace_file,
            syscall_index=syscall_index,
            depth=depth,
            coverage_state=coverage_snapshot,
            unexplored_mutations=mutations[1:],  # 保留除第一个外的所有mutations
            parent_checkpoint_id=parent_id,
            checkpoint_id=checkpoint_id,
            discovery_iteration=iteration_id
        )

        # 如果有未探索的mutations，添加到队列
        if checkpoint.unexplored_mutations:
            self.checkpoint_queue.append(checkpoint)
            print(f"[DynamicForkController] 📚 Queued checkpoint with {len(checkpoint.unexplored_mutations)} unexplored mutations")

        # 执行第一个mutation（深度优先）
        if mutations:
            first_mutation = mutations[0]
            print(f"[DynamicForkController] 🚀 Executing first mutation for deep exploration...")

            try:
                results = self.executor.execute_fork(
                    trace_file=trace_file,
                    fork_point=syscall_index,
                    mutation_variants=[first_mutation],
                    depth=depth,
                    iteration_id=iteration_id
                )

                if results and len(results) > 0:
                    result = results[0]
                    has_new_coverage = self.coverage_tracker.has_new_coverage(result.coverage_bitmap)

                    # 🔥 修复：深度优先探索的正确终止条件
                    if result.crashed:
                        print(f"[DynamicForkController] 💥 CRASH detected at depth={depth}! This is a successful exploration endpoint.")
                        print(f"[DynamicForkController] 🎯 Crash info: {result.crash_info if hasattr(result, 'crash_info') else 'Unknown crash'}")
                        self.stats['new_paths_discovered'] += 1

                        # Crash就是探索的成功终点，回退到checkpoint
                        print(f"[DynamicForkController] ⬅️  Backtracking to checkpoint after crash discovery...")
                        return True  # crash是成功的探索结果

                    elif has_new_coverage:
                        print(f"[DynamicForkController] 🎉 New coverage discovered! Continuing deep exploration...")
                        self.stats['new_paths_discovered'] += 1

                        # 找到下一个IO syscall继续深度探索
                        next_io_syscalls = self._find_next_io_syscalls(trace_file, syscall_index)
                        if next_io_syscalls:
                            next_syscall = next_io_syscalls[0]
                            print(f"[DynamicForkController] 🔄 Continuing to next IO syscall[{next_syscall}] at depth={depth+1}")

                            # 递归探索下一层
                            return self._explore_at_checkpoint(trace_file, next_syscall, depth + 1, iteration_id, checkpoint_id)
                        else:
                            print(f"[DynamicForkController] 🏁 No more IO syscalls, path exploration completed")
                            return True

                    else:
                        print(f"[DynamicForkController] 📊 No new coverage and no crash, continuing exploration...")

                        # 即使没有新覆盖率，也继续探索到下一个IO syscall（更aggressive的探索）
                        next_io_syscalls = self._find_next_io_syscalls(trace_file, syscall_index)
                        if next_io_syscalls and depth < self.max_depth - 1:
                            next_syscall = next_io_syscalls[0]
                            print(f"[DynamicForkController] 🔄 Aggressive exploration: continuing to syscall[{next_syscall}] at depth={depth+1}")
                            return self._explore_at_checkpoint(trace_file, next_syscall, depth + 1, iteration_id, checkpoint_id)
                        else:
                            print(f"[DynamicForkController] 🔚 Reached exploration limit, backtracking...")
                            return False
                else:
                    print(f"[DynamicForkController] ❌ Fork execution failed")
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

            if results and len(results) > 0:
                result = results[0]
                has_new_coverage = self.coverage_tracker.has_new_coverage(result.coverage_bitmap)

                # 🔥 修复：checkpoint恢复后的正确处理
                if result.crashed:
                    print(f"[DynamicForkController] 💥 CRASH detected from checkpoint restoration!")
                    print(f"[DynamicForkController] 🎯 Crash at checkpoint {checkpoint.checkpoint_id}, depth={checkpoint.depth}")
                    self.stats['new_paths_discovered'] += 1
                    return True  # crash是成功结果，继续处理其他checkpoints

                elif has_new_coverage:
                    print(f"[DynamicForkController] 🎉 New coverage from checkpoint restoration!")
                    self.stats['new_paths_discovered'] += 1

                    # 继续深度探索
                    next_io_syscalls = self._find_next_io_syscalls(checkpoint.trace_file, checkpoint.syscall_index)
                    if next_io_syscalls and checkpoint.depth < self.max_depth:
                        next_syscall = next_io_syscalls[0]
                        return self._explore_at_checkpoint(checkpoint.trace_file, next_syscall,
                                                         checkpoint.depth + 1, iteration_id, checkpoint.checkpoint_id)
                    else:
                        print(f"[DynamicForkController] 🏁 Reached exploration boundary")
                        return True

                else:
                    print(f"[DynamicForkController] 📊 No new coverage from restored checkpoint")

                    # 即使没有新覆盖率，也尝试继续探索（更aggressive）
                    next_io_syscalls = self._find_next_io_syscalls(checkpoint.trace_file, checkpoint.syscall_index)
                    if next_io_syscalls and checkpoint.depth < self.max_depth - 1:
                        next_syscall = next_io_syscalls[0]
                        print(f"[DynamicForkController] 🔄 Aggressive: continuing from checkpoint to syscall[{next_syscall}]")
                        return self._explore_at_checkpoint(checkpoint.trace_file, next_syscall,
                                                         checkpoint.depth + 1, iteration_id, checkpoint.checkpoint_id)
                    else:
                        print(f"[DynamicForkController] 🔚 Checkpoint exploration exhausted")
                        return False

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
    
    def _find_io_syscalls(self, trace: Trace) -> list:
        """
        简化版：找到所有IO syscalls
        
        Returns:
            IO syscall索引列表
        """
        # 导入TraceAnalyzer
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'analysis'))
        from trace_analyzer import TraceAnalyzer
        
        analyzer = TraceAnalyzer(trace.file_path)
        io_syscalls = []
        
        for sc in analyzer.syscalls:
            # 只考虑IO syscalls
            if sc.name in ['read', 'recv', 'recvfrom', 'getrandom', 'write', 'send']:
                # 跳过前10%的syscalls（初始化阶段）
                if sc.index < len(analyzer.syscalls) * 0.1:
                    continue
                io_syscalls.append(sc.index)
        
        return io_syscalls

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


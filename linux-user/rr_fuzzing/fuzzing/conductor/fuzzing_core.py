#!/usr/bin/env python3
"""
FuzzingCore - 第2层: 核心Fuzzing引擎 + 第5层: 监控与分析

主fuzzing循环协调器，编排所有fuzzing组件。
实现DETAILED_ARCHITECTURE.md中描述的第2层和第5层架构。

第5层集成 (DETAILED_ARCHITECTURE.md第382-408行):
- SyscallTree可视化器: 自动生成syscall tree HTML (重点功能)
- CrashAnalyzer: 自动分析和去重crashes
- CorpusManager: 自动保存和管理corpus
"""

import os
import sys
import time
import subprocess
import threading
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from pathlib import Path

from .trace_manager import TraceManager, Trace
from .mutator import BaseMutator, SmartMutator
from .coverage import CoverageTracker
from .qemu_executor import QEMUExecutor, ExecutionResult
from .persistent_qemu_executor import PersistentQEMUExecutor
from .fuzzing_metrics import FuzzingMetrics, FailureReason
from .iteration_result import (
    IterationResult, IterationStatus,
    create_success_result, create_failure_result
)
from .mutation_dependency_graph import MutationDependencyGraph

# ✅ 修复：先设置sys.path，再导入
_fuzzing_dir = Path(__file__).parent.parent.resolve()
if str(_fuzzing_dir) not in sys.path:
    sys.path.insert(0, str(_fuzzing_dir))

# 尝试导入PathFinder (优先使用双层CFG版本)
_HAS_PATH_FINDER = False
PathFinder = None
PathFinderConfig = None

# ✅ 优先尝试加载双层CFG版本
try:
    from multiprocess.dual_level_path_finder import DualLevelPathFinder
    PathFinder = DualLevelPathFinder
    _HAS_PATH_FINDER = True
    print("[FuzzingCore] ✅ 加载DualLevelPathFinder (双层CFG)")
except ImportError:
    # 如果双层CFG不可用，回退到原版PathFinder
    try:
        from multiprocess import path_finder as _pf_module
        PathFinder = _pf_module.PathFinder
        PathFinderConfig = _pf_module.PathFinderConfig
        _HAS_PATH_FINDER = True
        print("[FuzzingCore] ⚠️ 回退到单层PathFinder")
    except Exception as e:
        # Debug: 显示导入失败原因
        import traceback
        print(f"[DEBUG] PathFinder import failed: {e}")
        traceback.print_exc()

# 尝试导入RecipePool
_HAS_RECIPE_POOL = False
RecipePool = None
try:
    from multiprocess import recipe_pool as _rp_module
    RecipePool = _rp_module.RecipePool
    _HAS_RECIPE_POOL = True
except ImportError:
    pass

# 尝试导入DynamicForkController
_HAS_DYNAMIC_FORK = False
DynamicForkController = None
try:
    from multiprocess import dynamic_fork_controller as _dfc_module
    DynamicForkController = _dfc_module.DynamicForkController
    _HAS_DYNAMIC_FORK = True
except ImportError:
    pass

# 第5层: 导入监控和分析组件
try:
    from multiprocess.crash_analyzer import CrashAnalyzer as Layer5CrashAnalyzer
    from multiprocess.corpus_manager import CorpusManager
    _HAS_LAYER5_CRASH = True
    _HAS_LAYER5_CORPUS = True
except ImportError:
    _HAS_LAYER5_CRASH = False
    _HAS_LAYER5_CORPUS = False

# ✅ 方案A: 使用Realtime Tree Visualizer (从QEMU动态消息)
# ❌ 废弃: tree_visualizer (从静态trace文件，数据不准确)
# try:
#     from tree_visualizer import TreeVisualizer
#     _HAS_TREE_VIZ = True
# except ImportError:
#     _HAS_TREE_VIZ = False
#     print("[FuzzingCore] ⚠️  TreeVisualizer不可用")

# ✅ 实时tree visualizer不需要导入，将作为独立进程运行
_HAS_REALTIME_VIZ = False  # ⚠️ DISABLED: Visualizer O(N) search causing 10-100x slowdown


@dataclass
class FuzzingStatistics:
    """Fuzzing会话统计信息"""
    total_execs: int = 0
    paths_found: int = 0
    crashes_found: int = 0
    unique_crashes: int = 0
    timeouts: int = 0
    last_new_path: float = field(default_factory=time.time)
    start_time: float = field(default_factory=time.time)
    
    @property
    def execs_per_sec(self) -> float:
        """计算每秒执行次数"""
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0
        return self.total_execs / elapsed
    
    @property
    def elapsed_time(self) -> float:
        """获取已用时间"""
        return time.time() - self.start_time


class CrashDetector:
    """简单的crash检测器和去重器"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.crashes = []
        self.crash_hashes = set()
    
    def save_crash(self, result: ExecutionResult, trace: Trace, mutations: list):
        """保存crash信息"""
        import hashlib
        import json
        import os
        from pathlib import Path
        
        # 创建crash目录
        crash_dir = Path(self.output_dir) / "crashes"
        crash_dir.mkdir(parents=True, exist_ok=True)
        
        # 生成crash哈希 
        crash_data = f"{result.status}_{result.qemu_exit_code}_{result.signal_number}"
        crash_hash = hashlib.md5(crash_data.encode()).hexdigest()[:8]
        
        # 检查是否重复
        if crash_hash in self.crash_hashes:
            print(f"[CrashDetector] 重复的crash (hash={crash_hash}), 跳过")
            return False
        
        self.crash_hashes.add(crash_hash)
        crash_id = f"crash_{len(self.crashes):06d}_{crash_hash}"
        
        # 保存crash trace
        import shutil
        crash_trace = crash_dir / f"{crash_id}.bin"
        if os.path.exists(trace.file_path):
            shutil.copy(trace.file_path, crash_trace)
        
        # 保存crash元数据
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
        print(f"[CrashDetector] 💥 保存新crash: {crash_id}")
        return True


class FuzzingCore:
    """
    第2层: 核心Fuzzing循环协调器
    
    职责:
    1. 协调所有fuzzing组件
    2. 实现主fuzzing循环
    3. 管理fuzzing统计信息
    4. 处理crashes和新覆盖率
    5. 提供进度报告
    
    主循环 (架构: DETAILED_ARCHITECTURE.md第57-85行):
    1. 从TraceManager选择trace
    2. 使用Mutator生成变异
    3. 使用QEMUExecutor执行
    4. 使用CoverageTracker分析覆盖率
    5. 保存有趣的traces
    6. 检测并保存crashes
    7. 更新统计信息
    """
    
    def __init__(
        self,
        qemu_path: str,
        target_binary: str,
        initial_trace: str,
        output_dir: str = "fuzzing_output",
        mutator: Optional[BaseMutator] = None,
        enable_monitoring: bool = True,
        enable_pathfinder: bool = True,  # ✅ 新增：默认启用PathFinder
        enable_tree_viz: bool = False,   # 🔥 性能修复：禁用Visualizer(C端已生成tree,Python端重复且开销巨大)
        enable_persistent: bool = False,  # 持久化执行器（QEMUExecutor已是persistent fork server）
        use_energy_scheduler: bool = True,  # ✅ 新增：启用能量调度器 (2025-11-17)
        shared_coverage=None  # ✅ 多进程：SharedCoverage实例（多进程模式下使用）
    ):
        """
        初始化FuzzingCore

        参数:
            qemu_path: QEMU可执行文件路径
            target_binary: 目标程序路径
            initial_trace: 初始种子trace路径
            output_dir: 结果输出目录
            mutator: 自定义mutator (可选, 如果为None则创建BaseMutator)
            enable_monitoring: 启用第5层监控 (默认: True)
            enable_pathfinder: 启用PathFinder CFG分析 (默认: True)
            enable_tree_viz: 启用Syscall Tree可视化 (默认: True)
            enable_persistent: 启用持久化QEMU执行器 (默认: False)
            use_energy_scheduler: 启用高级能量调度器 (默认: True, 2025-11-17新增)
            shared_coverage: SharedCoverage实例（多进程模式下用于进程间coverage同步）
        """
        print(f"[FuzzingCore] 正在初始化...")

        # 第1层: Trace/Seed管理 - ✅ 2025-11-17: 支持Energy Scheduler
        if use_energy_scheduler:
            from .seed_manager_adapter import SeedManagerAdapter
            self.trace_manager = SeedManagerAdapter(
                initial_trace=initial_trace,
                use_advanced=True
            )
            print("[FuzzingCore] ✅ 启用高级能量调度器 (Energy Scheduler + AdvancedSeedQueue)")
        else:
            self.trace_manager = TraceManager(initial_trace=initial_trace)
            print("[FuzzingCore] 📝 使用传统TraceManager")
        
        # 第2层: 核心组件
        self.mutator = mutator if mutator else BaseMutator()
        # ✅ 多进程：传递shared_coverage给CoverageTracker
        self.coverage_tracker = CoverageTracker(pid=0, shared_coverage=shared_coverage)

        # ✅ 选择执行器：持久化 vs 传统
        self.enable_persistent = enable_persistent
        if enable_persistent:
            print("[FuzzingCore] 🚀 使用PersistentQEMUExecutor (预期提升30x性能)")
            self.execution_engine = PersistentQEMUExecutor(qemu_path, target_binary)
        else:
            print("[FuzzingCore] 📝 使用传统QEMUExecutor")
            self.execution_engine = QEMUExecutor(qemu_path, target_binary)

        self.crash_detector = CrashDetector(output_dir)

        # 统计信息
        self.stats = FuzzingStatistics()

        # ✅ Task #7: 添加FuzzingMetrics追踪所有失败原因
        self.metrics = FuzzingMetrics()

        # ✅ Task #6: 添加MutationDependencyGraph追踪mutation关系
        self.mutation_graph = MutationDependencyGraph()

        # 输出目录和路径
        self.output_dir = output_dir
        self.initial_trace = initial_trace
        self.target_binary = target_binary  # P0-1: 为PathFinder保存
        
        # ✅ 默认启用PathFinder（CFG引导的fuzzing）
        self.enable_pathfinder = enable_pathfinder
        self.path_finder = None
        self.recipe_pool = None
        
        if enable_pathfinder and _HAS_PATH_FINDER:
            try:
                print(f"[FuzzingCore] 🧭 初始化PathFinder...")
                # DualLevelPathFinder不需要PathFinderConfig
                if PathFinderConfig is not None:
                    cfg_config = PathFinderConfig(verbose=False)
                    self.path_finder = PathFinder(target_binary, config=cfg_config)
                else:
                    # DualLevelPathFinder使用简化的初始化
                    self.path_finder = PathFinder(target_binary, config=None)

                # 创建RecipePool（使用模块级变量，避免shadowing）
                if _HAS_RECIPE_POOL and RecipePool is not None:
                    self.recipe_pool = RecipePool(max_active=50, retirement_threshold=100)
                
                # Stats将在需要时显示
                
                # CFG分析触发配置
                self.cfg_analysis_interval = 50  # 每50次迭代
                self.last_cfg_analysis = 0
                
            except Exception as e:
                print(f"[FuzzingCore] ⚠️ PathFinder初始化失败: {e}")
                import traceback
                traceback.print_exc()
                self.path_finder = None
                self.recipe_pool = None
            
            # 🔥 修复：PathFinder采用延迟构建，初始化后总是可用
            if self.path_finder and self.path_finder.is_available():
                print(f"[FuzzingCore] ✅ PathFinder启用 (延迟CFG构建模式)")
                print(f"[FuzzingCore] ✅ RecipePool启用 (max_active=50)")
            elif self.path_finder and not self.path_finder.is_available():
                reason = getattr(self.path_finder, 'disabled_reason', '未知原因')
                print(f"[FuzzingCore] ⚠️ PathFinder已自动禁用: {reason}")
                self.path_finder = None
                self.recipe_pool = None
        elif enable_pathfinder and not _HAS_PATH_FINDER:
            print(f"[FuzzingCore] ⚠️ PathFinder不可用（需要安装angr）")
            print(f"  _HAS_PATH_FINDER={_HAS_PATH_FINDER}")
        
        # ✅ 启用Syscall Tree Visualizer
        self.enable_tree_viz = enable_tree_viz
        
        # ✅ 在__init__中启动Visualizer
        if enable_tree_viz:
            try:
                self._start_realtime_visualizer()
            except Exception as e:
                print(f"[FuzzingCore] ⚠️ Tree Visualizer启动失败: {e}")
        
        # ✅ 避免重复创建RecipePool
        if not self.recipe_pool and _HAS_RECIPE_POOL and isinstance(mutator, SmartMutator) and mutator.recipe_mode:
            self.recipe_pool = RecipePool(max_active=50, retirement_threshold=100)
            # 从mutator加载初始recipes
            if mutator.recipes:
                self.recipe_pool.add_recipes(mutator.recipes)
                print(f"[FuzzingCore] ✅ RecipePool已启用 ({len(mutator.recipes)} 个recipes)")
        
        # ✅ 修复：删除重复的PathFinder初始化
        # PathFinder已经在上面初始化过了（line 224-250）
        # 这里只设置CFG分析触发参数
        self.cfg_analysis_interval_iters = 20   # 🔥 修复：更激进的CFG分析频率
        self.cfg_analysis_interval_time = 30    # 🔥 修复：更短的时间间隔
        self.last_cfg_analysis_time = time.time()
        self.last_cfg_analysis_iter = 0
        
        # 第5层: 监控与分析
        self.enable_monitoring = enable_monitoring  # ✅ 确保定义
        self.layer5_crash_analyzer = None
        self.layer5_corpus_manager = None
        
        if enable_monitoring:
            print(f"[FuzzingCore] 🔍 启用第5层: 监控与分析")
            
            # 1. CrashAnalyzer (去重和分析)
            if _HAS_LAYER5_CRASH:
                self.layer5_crash_analyzer = Layer5CrashAnalyzer(Path(output_dir))
                print(f"  ✅ CrashAnalyzer已启用")
            else:
                print(f"  ⚠️  CrashAnalyzer不可用 (使用基础CrashDetector)")
            
            # 2. CorpusManager (持久化)
            if _HAS_LAYER5_CORPUS:
                self.layer5_corpus_manager = CorpusManager(Path(output_dir) / "corpus")
                print(f"  ✅ CorpusManager已启用")
            else:
                print(f"  ⚠️  CorpusManager不可用")
            
            # ✅ 3. Realtime Tree Visualizer (方案A: 集成版)
            if _HAS_REALTIME_VIZ:
                print(f"  ✅ Realtime Tree可视化器已启用 (准确的execution paths)")
            else:
                print(f"  ⚠️  Realtime Tree可视化器不可用")
        
        # ═══════════════════════════════════════════════════════════════
        # 方案A: Realtime Visualizer管理
        # ═══════════════════════════════════════════════════════════════
        self.realtime_viz_process = None
        self.realtime_viz_pipe = None
        self.realtime_viz_thread = None  # 用于读取visualizer输出
        
        # 🔥 启用DynamicForkController实现深度优先多层探索
        self.dynamic_fork_controller = None
        if _HAS_DYNAMIC_FORK and DynamicForkController is not None:
            try:
                self.dynamic_fork_controller = DynamicForkController(
                    executor=self.execution_engine,
                    path_finder=self.path_finder,
                    mutator=self.mutator,
                    recipe_pool=self.recipe_pool,
                    coverage_tracker=self.coverage_tracker,
                    trace_manager=self.trace_manager,  # ✅ 修复2: 传递trace_manager用于保存新种子
                    fuzzing_stats=self.stats,  # ✅ Pass stats for unified tracking
                    mutation_graph=self.mutation_graph  # ✅ Task #6补充: Pass mutation graph
                )
                print(f"[FuzzingCore] ✅ DynamicForkController已启用 (深度优先checkpoint/snapshot探索)")
            except Exception as e:
                print(f"[FuzzingCore] ⚠️ DynamicForkController初始化失败: {e}")
                import traceback
                traceback.print_exc()
                self.dynamic_fork_controller = None
        else:
            print(f"[FuzzingCore] ⚠️ DynamicForkController不可用")
        
        print(f"[FuzzingCore] ✅ 初始化完成")
        print(f"  输出目录: {output_dir}")
        print(f"  初始trace: {initial_trace}")
        print(f"  监控: {'已启用' if enable_monitoring else '已禁用'}")
        print(f"  PathFinder: {'已启用' if self.path_finder else '未启用'}")
        print(f"  Tree Visualizer: {'已启用' if enable_tree_viz else '未启用'}")
        print(f"  Dynamic Fork: {'已启用' if self.dynamic_fork_controller else '未启用'}")
    
    # ✅ 删除重复的_start_realtime_visualizer定义
    # 使用第655行的版本，它更完整且设置了正确的变量名
    
    def _extract_covered_blocks(self) -> set:
        """
        从覆盖率位图中提取已覆盖的基本块
        
        返回:
            已覆盖的块地址集合
        """
        covered = set()
        
        # Coverage bitmap中每个非零位置代表一个edge
        # Edge ID = (prev_block << 16) | curr_block (简化)
        # 我们提取所有covered edges的curr_block部分
        for i, val in enumerate(self.coverage_tracker.global_bitmap):
            if val > 0:
                # 简化处理：将bitmap index作为block ID
                # 实际应该从edge映射到block
                covered.add(i & 0xFFFF)  # 提取低16位作为block ID
        
        return covered

    def _select_coverage_driven_fork_points(self, trace: Trace, count: int) -> List[int]:
        """
        选择coverage驱动的fork点

        策略:
        1. 如果PathFinder可用，使用未覆盖分支附近的syscall作为fork点
        2. 否则，使用IO syscall轮换策略作为fallback

        参数:
            trace: 当前trace
            count: 需要的fork点数量

        返回:
            fork点索引列表
        """
        fork_points = []

        # 策略1: 使用PathFinder的未覆盖分支
        if self.path_finder and hasattr(self.path_finder, 'uncovered_branches'):
            uncovered = self.path_finder.uncovered_branches
            if uncovered and len(uncovered) > 0:
                # 从未覆盖分支中选择top N个
                top_branches = uncovered[:count * 2]  # 多选一些作为候选

                # 从trace中找到接近这些分支的syscall
                for branch in top_branches:
                    # 简化：使用分支地址的低位作为大致的syscall index
                    # 实际应该通过CFG分析找到最近的syscall
                    if 'to' in branch:
                        estimated_index = (branch['to'] % 50) + 10  # 粗略估计
                        fork_points.append(estimated_index)

                    if len(fork_points) >= count:
                        break

                if fork_points:
                    print(f"[FuzzingCore] 🎯 Using PathFinder-guided fork points: {fork_points[:count]}")
                    return fork_points[:count]

        # 策略2: Fallback to IO syscall rotation
        import random
        io_syscalls = [10, 15, 20, 25, 30]  # 简化：使用固定的IO syscall候选点

        # 轮换 + 随机扰动
        base_index = self.stats.total_execs % len(io_syscalls)
        selected = []
        for i in range(count):
            idx = (base_index + i) % len(io_syscalls)
            selected.append(io_syscalls[idx])

        # 20%概率随机选择
        if random.random() < 0.2:
            selected[-1] = random.choice(io_syscalls)

        return selected

    def _display_progress(self, force: bool = False):
        """显示fuzzing进度 (每100次执行或强制显示)"""
        if not force and self.stats.total_execs % 100 != 0:
            return
        
        cov_stats = self.coverage_tracker.get_stats()
        
        print(f"\n{'━' * 60}")
        print(f"Iteration: {self.stats.total_execs}")
        print(f"{'━' * 60}")
        print(f"Exec speed:  {self.stats.execs_per_sec:.1f} exec/s")

        # ✅ 兼容SeedManagerAdapter和TraceManager
        if hasattr(self.trace_manager, 'trace_pool'):
            trace_count = len(self.trace_manager.trace_pool)
        elif hasattr(self.trace_manager, 'trace_to_seed_map'):
            trace_count = len(self.trace_manager.trace_to_seed_map)
        else:
            trace_count = 0
        print(f"Trace pool:  {trace_count} traces")

        print(f"Coverage:    {cov_stats['total_edges']} edges")
        print(f"Paths found: {self.stats.paths_found}")
        print(f"Crashes:     {self.stats.crashes_found} "
              f"({len(self.crash_detector.crashes)} unique)")
        
        time_since_last = time.time() - self.stats.last_new_path
        print(f"Last path:   {time_since_last:.1f}s ago")
        print(f"{'━' * 60}")
    
    def run_single_iteration(self, iteration_id: int = 0) -> IterationResult:
        """
        运行单次fuzzing迭代

        参数:
            iteration_id: 当前迭代ID（用于tree可视化）

        返回:
            IterationResult: 迭代结果（包含成功/失败状态和详细信息）

        实现DETAILED_ARCHITECTURE.md中的详细fuzzing流程
        第416-1076行 (单次迭代)
        """
        # ✅ Task #7: 记录迭代开始
        self.metrics.success_counts['total_iterations'] += 1

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 步骤1: Trace选择
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        trace = self.trace_manager.select_trace()
        if not trace:
            # ✅ Task #7: 记录失败
            self.metrics.record_failure(
                reason=FailureReason.CONFIG_INVALID_TRACE,
                component="TraceManager",
                details="No available traces in pool",
                iteration=iteration_id
            )
            print("[FuzzingCore] ⚠️  池中无可用traces")
            # ✅ Task #8: 返回失败结果
            return create_failure_result(
                iteration_id=iteration_id,
                status=IterationStatus.NO_TRACE,
                error_message="No available traces in pool",
                error_component="TraceManager"
            )
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 步骤2: 深度优先探索 - 智能fork点选择
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        batch_size = 5  # 🔥 修复: 降低batch_size实现深度优先探索 (100 → 5)

        # 🔥 修复: Coverage驱动的fork点选择
        fork_points = self._select_coverage_driven_fork_points(trace, batch_size)

        # 迭代结果追踪
        has_any_success = False
        total_execs = 0
        total_mutations = 0
        new_coverage_found = False
        new_paths_found = 0
        crashes_found_count = 0

        for i, fork_point in enumerate(fork_points):
            mutations = self.mutator.mutate(trace)
            if not mutations:
                # ✅ Task #7: 记录失败
                self.metrics.record_failure(
                    reason=FailureReason.MUTATION_NO_CANDIDATES,
                    component="Mutator",
                    details=f"No mutations generated for trace {trace.id}",
                    iteration=iteration_id
                )
                continue

            total_mutations += 1

            # ✅ Task #6: 追踪mutation节点
            # ✅ 2025-11-18: 从FuzzInstruction中读取mutation_type
            if isinstance(mutations, list) and len(mutations) > 0:
                # mutations是FuzzInstruction列表，取第一个的type
                mut_type = getattr(mutations[0], 'mutation_type', 'unknown')
            else:
                # 兼容旧格式
                mut_type = getattr(self.mutator, 'last_mutation_type', 'unknown')

            node_id = self.mutation_graph.add_mutation(
                iteration=iteration_id,
                mutation_index=i,
                mutation_type=mut_type,
                parent_trace_id=trace.id,
                syscall_index=mutations.get('syscall_index') if isinstance(mutations, dict) else None,
                field_name=mutations.get('field') if isinstance(mutations, dict) else None,
            )

            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # 步骤3: 在智能选择的fork点执行mutation
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            results = self.execution_engine.execute_fork(trace.file_path, fork_point, [mutations], 0, iteration_id)

            # ✅ 记录成功的fork操作（修复统计bug）
            if results and len(results) > 0:
                self.metrics.success_counts['successful_forks'] += 1

            # 处理结果
            for result in results:
                if result is None:
                    continue

                self.stats.total_execs += 1
                trace.metadata.exec_count += 1  # 🔥 修复: 更新trace执行计数
                total_execs += 1
                has_any_success = True

                # ✅ Task #7: 记录成功的变异执行
                self.metrics.record_success('successful_mutations')

                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                # 步骤4: 覆盖率分析
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                has_new_coverage = False
                if result.coverage_bitmap:
                    has_new_coverage = self.coverage_tracker.has_new_coverage(
                        result.coverage_bitmap
                    )

                    if has_new_coverage:
                        new_coverage_found = True
                        new_paths_found += 1
                        self.stats.paths_found += 1
                        self.stats.last_new_path = time.time()
                        print(f"[FuzzingCore] 🎯 发现新覆盖率! "
                              f"(总边数: {self.coverage_tracker.get_stats()['total_edges']})")

                # 步骤4.5: 记录执行统计
                self.trace_manager.record_execution(
                    trace_id=trace.id,
                    trace_file=trace.file_path,
                    mutations=mutations,
                    has_new_coverage=has_new_coverage
                )

                # 更新停滞检测状态
                # 🔥 修复: 使用total_execs作为全局迭代计数器（与trace.exec_count不同）
                if isinstance(self.mutator, SmartMutator) and hasattr(self.mutator, 'update_stagnation_status'):
                    self.mutator.update_stagnation_status(
                        iteration=self.stats.total_execs,
                        has_new_coverage=has_new_coverage
                    )

                # ✅ Task #6: 更新mutation执行结果
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
        
        # ═════════════════════════════════════════════════════════════════
        # CFG引导的Fuzzing (关键修复!)
        # 🔥 修复：移除has_new_coverage依赖，允许主动CFG分析
        # ═════════════════════════════════════════════════════════════════
        if self.path_finder:
            should_run_cfg = False

            # 🔥 调试：打印当前状态
            if self.stats.total_execs % 10 == 0:  # 每10次迭代打印一次
                print(f"[FuzzingCore] 🔍 CFG检查: exec={self.stats.total_execs}, last={self.last_cfg_analysis_iter}, interval={self.cfg_analysis_interval_iters}")

            # ✅ P1: 混合触发条件
            # 条件1: 达到迭代阈值
            if self.stats.total_execs - self.last_cfg_analysis_iter >= self.cfg_analysis_interval_iters:
                should_run_cfg = True
                trigger_reason = f"{self.stats.total_execs - self.last_cfg_analysis_iter} 次迭代"

            # 条件2: 达到时间阈值
            elapsed_since_cfg = time.time() - self.last_cfg_analysis_time
            if elapsed_since_cfg >= self.cfg_analysis_interval_time:
                should_run_cfg = True
                trigger_reason = f"{elapsed_since_cfg:.0f} 秒"
            
            if should_run_cfg:
                print(f"\n[FuzzingCore] 🧭 运行CFG分析 (触发条件: {trigger_reason})...")
                self.last_cfg_analysis_iter = self.stats.total_execs
                self.last_cfg_analysis_time = time.time()

                try:
                    # 🔥 修复：确保CFG已准备就绪
                    if not self.path_finder.ensure_cfg_ready():
                        print(f"[FuzzingCore] ⚠️ PathFinder CFG初始化失败，尝试基于trace重建...")

                    build_ok = self.path_finder.build_from_trace(trace.file_path)
                    if not build_ok:
                        print(f"[FuzzingCore] ⚠️ PathFinder无法基于trace构建CFG，跳过本次分析")
                    else:
                        # 获取当前覆盖的BBs
                        covered_blocks = self._extract_covered_blocks()
                        
                        if covered_blocks:
                            # 使用最新trace数据增强CFG与syscall映射
                            syscall_trace_file = trace.file_path
                            bb_trace_file = syscall_trace_file + ".bbl"
                            if os.path.exists(bb_trace_file):
                                mapped = self.path_finder.enhance_from_trace_files(
                                    syscall_trace_file=syscall_trace_file,
                                    bb_trace_file=bb_trace_file,
                                    covered_set=covered_blocks
                                )
                                if mapped:
                                    print(f"[FuzzingCore] 🔗 PathFinder增强了 {mapped} 个CFG节点 (来自{os.path.basename(trace.file_path)})")
                            else:
                                print(f"[FuzzingCore] ⚠️ 未找到BB trace文件: {bb_trace_file}")

                            # 查找未覆盖的分支
                            uncovered = self.path_finder.find_uncovered_branches(covered_blocks)
                            print(f"[FuzzingCore] 📊 发现 {len(uncovered)} 个未覆盖的分支")
                            
                            if uncovered:
                                # 生成新recipes（最多20个）
                                new_recipes = self.path_finder.generate_recipes(
                                    uncovered,
                                    max_recipes=20
                                )
                                print(f"[FuzzingCore] 📝 生成了 {len(new_recipes)} 个新recipes")
                                
                                # 添加到RecipePool
                                if self.recipe_pool and new_recipes:
                                    self.recipe_pool.add_recipes(new_recipes)
                                    
                                    # 如果SmartMutator在recipe模式，更新其recipes
                                    if isinstance(self.mutator, SmartMutator) and self.mutator.recipe_mode:
                                        # 合并新recipes到SmartMutator
                                        self.mutator.recipes.extend(new_recipes)
                                        print(f"[FuzzingCore] ✅ 添加了 {len(new_recipes)} 个recipes到SmartMutator")
                                        print(f"[FuzzingCore] 📚 总recipes数: {len(self.mutator.recipes)}")
                
                except Exception as e:
                    # ✅ Task #7: 记录CFG分析失败
                    self.metrics.record_failure(
                        reason=FailureReason.UNKNOWN,
                        component="PathFinder",
                        details=f"CFG analysis failed: {str(e)}",
                        iteration=iteration_id
                    )
                    print(f"[FuzzingCore] ⚠️  CFG分析失败: {e}")
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 步骤5: Trace保存 (如果有趣)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if has_new_coverage:
            # 目前重用相同的trace文件 (第1阶段简化)
            # 第2阶段将实现带变异的trace重新记录
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
                    {'syscall_index': m.syscall_index, 'cmd': m.cmd}
                    for m in mutations
                ]
            )

            # ✅ 2025-11-17: Update Energy Scheduler context with new coverage
            if hasattr(self.trace_manager, 'update_context'):
                self.trace_manager.update_context(
                    new_coverage=new_edges if new_edges else set(),
                    no_progress=False
                )
        else:
            # ✅ 2025-11-17: Update Energy Scheduler context - no new coverage
            if hasattr(self.trace_manager, 'update_context'):
                self.trace_manager.update_context(
                    new_coverage=set(),
                    no_progress=True
                )

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 步骤5.5: Recipe反馈 (如果recipe模式)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if self.recipe_pool and hasattr(self.mutator, 'last_recipe_used'):
            recipe_used = getattr(self.mutator, 'last_recipe_used', None)
            
            if recipe_used:
                # 检查recipe是否成功
                if has_new_coverage:
                    # TODO: 检查目标分支是否真的被覆盖
                    # 目前，将任何新覆盖率视为部分成功
                    self.recipe_pool.update_recipe_result(
                        recipe_used,
                        success=True,
                        new_coverage=1
                    )
                    
                    # 获取recipe统计
                    recipe_id = recipe_used.get('id', -1)
                    if recipe_id in self.recipe_pool.stats:
                        stats = self.recipe_pool.stats[recipe_id]
                        print(f"[FuzzingCore] ✅ Recipe {recipe_id} 成功! "
                              f"(成功率: {stats.success_rate*100:.1f}%)")
                else:
                    # Recipe未能生成新覆盖率
                    self.recipe_pool.update_recipe_result(
                        recipe_used,
                        success=False,
                        new_coverage=0
                    )
        
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                # 步骤6: Crash检测和保存
                # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                if result.crashed:
                    self.stats.crashes_found += 1
                    crashes_found_count += 1
                    self.crash_detector.save_crash(result, trace, mutations)

                # 处理超时
                if result.timeout:
                    self.stats.timeouts += 1

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 步骤7: 统计更新与显示
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        self._display_progress()

        # ✅ Task #7: 记录成功的迭代
        self.metrics.record_success('successful_iterations')

        # ✅ Task #8: 返回IterationResult
        if not has_any_success:
            # 完全失败：没有任何成功的执行
            return create_failure_result(
                iteration_id=iteration_id,
                status=IterationStatus.NO_MUTATIONS,
                error_message="No successful executions",
                error_component="Executor",
                trace_id=trace.id
            )
        else:
            # 成功：至少有一次成功的执行
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
        """在单独线程中读取Realtime Visualizer的输出（参考fuzz_conductor.py）"""
        if not self.realtime_viz_process or not self.realtime_viz_process.stdout:
            return
        
        try:
            while True:
                line = self.realtime_viz_process.stdout.readline()
                if not line:
                    break
                # 只打印重要的visualizer消息（减少噪音）
                line_str = line.rstrip()
                if any(keyword in line_str for keyword in ['✅', '❌', '⚠️', 'FORK', 'ERROR', 'Tree', 'MSG', 'ITER', 'DEBUG', 'SimpleVisualizer', 'Connected', 'Initialized']):
                    print(f"[Visualizer] {line_str}", flush=True)
        except Exception as e:
            print(f"[FuzzingCore] Visualizer输出读取错误: {e}")
    
    def _start_realtime_visualizer(self):
        """
        启动Realtime Tree Visualizer作为独立进程
        
        参考fuzz_conductor.py的进程管理模式
        """
        if not _HAS_REALTIME_VIZ:
            return None
        # ✅ Tree visualizer不依赖于monitoring
        
        # 创建pipe路径（unique per session）
        self.realtime_viz_pipe = f"/tmp/rr_dynamic_trace_{os.getpid()}"
        output_html = Path(self.output_dir) / "realtime_tree.html"
        
        # 确保输出目录存在
        output_html.parent.mkdir(parents=True, exist_ok=True)
        
        # 清理旧pipe
        if os.path.exists(self.realtime_viz_pipe):
            os.remove(self.realtime_viz_pipe)
        
        # 启动visualizer进程
        visualizer_script = Path(__file__).parent.parent / "realtime_tree_visualizer.py"
        # visualizer_script = Path(__file__).parent.parent / "simple_tree_visualizer.py"
        
        cmd = [
            sys.executable,
            str(visualizer_script),
            "--pipe", self.realtime_viz_pipe,
            "--output", str(output_html),
            "--update-interval", "3.0"  # 每3秒更新一次
        ]
        
        print(f"\n[FuzzingCore] 📡 正在启动Realtime Tree Visualizer...")
        print(f"  Pipe: {self.realtime_viz_pipe}")
        print(f"  输出: {output_html}")
        
        try:
            self.realtime_viz_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # 合并stderr到stdout
                bufsize=1,  # Line buffered
                universal_newlines=True,  # Text mode for readline()
                encoding='utf-8'
            )
            
            # 启动线程读取visualizer输出（参考conductor模式）
            self.realtime_viz_thread = threading.Thread(
                target=self._read_visualizer_output,
                daemon=True
            )
            self.realtime_viz_thread.start()
            
            # 等待pipe创建（最多10秒）
            print(f"[FuzzingCore] ⏳ 等待visualizer创建pipe...")
            for i in range(20):
                if os.path.exists(self.realtime_viz_pipe):
                    print(f"[FuzzingCore] ✅ Visualizer pipe已创建")
                    break
                time.sleep(0.5)
            else:
                print(f"[FuzzingCore] ⚠️  Pipe创建超时，但继续运行")
            
            # 设置环境变量，让QEMU连接到pipe
            os.environ['RR_TRACE_PIPE'] = self.realtime_viz_pipe
            print(f"[FuzzingCore] ✅ Realtime Visualizer已启动")
            print(f"  - PID: {self.realtime_viz_process.pid}")
            print(f"  - Pipe: {self.realtime_viz_pipe}")
            print(f"  - RR_TRACE_PIPE环境变量: {os.environ.get('RR_TRACE_PIPE')}")
            
            # ✅ 验证pipe文件存在
            if os.path.exists(self.realtime_viz_pipe):
                print(f"  - Pipe文件: ✅ 存在")
            else:
                print(f"  - Pipe文件: ❌ 不存在!")
            
            return self.realtime_viz_pipe
            
        except Exception as e:
            print(f"[FuzzingCore] ❌ 启动Realtime Visualizer失败: {e}")
            return None
    
    def _stop_realtime_visualizer(self):
        """停止Realtime Visualizer进程（参考fuzz_conductor.py的清理模式）"""
        if not self.realtime_viz_process:
            return
        
        print(f"\n[FuzzingCore] 🛑 正在停止Realtime Visualizer...")
        
        try:
            # 尝试优雅终止
            self.realtime_viz_process.terminate()
            try:
                self.realtime_viz_process.wait(timeout=5)
                print(f"[FuzzingCore] ✅ Visualizer已优雅退出")
            except subprocess.TimeoutExpired:
                # 强制终止
                print(f"[FuzzingCore] ⚠️  Visualizer未响应，强制终止...")
                self.realtime_viz_process.kill()
                self.realtime_viz_process.wait(timeout=2)
        except Exception as e:
            print(f"[FuzzingCore] ⚠️  停止Visualizer时出错: {e}")
        
        # 清理pipe
        if self.realtime_viz_pipe and os.path.exists(self.realtime_viz_pipe):
            try:
                os.remove(self.realtime_viz_pipe)
            except:
                pass

        self.realtime_viz_process = None
        self.realtime_viz_pipe = None

    def _get_coverage_percentage(self):
        """获取当前覆盖率百分比"""
        try:
            stats = self.coverage_tracker.get_stats()
            return stats.get('bitmap_density', 0.0)
        except Exception:
            return 0.0

    def run_advanced(self, stop_conditions: dict):
        """
        运行主fuzzing循环 (高级停止条件版本)

        参数:
            stop_conditions: 停止条件字典，包含：
                - max_iterations: 最大迭代次数
                - max_time: 最大时间(秒)
                - max_crashes: 最大crash数量
                - max_paths: 最大新路径数量
                - coverage_target: 覆盖率目标(%)
                - no_progress_timeout: 无进展超时(秒)
                - infinite: 是否无限运行
        """
        # 兼容旧接口
        max_iterations = stop_conditions.get('max_iterations')
        max_time = stop_conditions.get('max_time')

        # 新的高级停止条件
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
        运行主fuzzing循环 (向后兼容版本)

        参数:
            max_iterations: 最大迭代次数 (None表示无限制)
            max_time: 最大时间(秒) (None表示无限制)
        """
        return self._run_with_conditions(max_iterations, max_time)

    def _run_with_conditions(self, max_iterations=None, max_time=None, max_crashes=None,
                           max_paths=None, coverage_target=None, no_progress_timeout=None,
                           infinite_mode=False):
        """
        执行实际的fuzzing循环，支持各种停止条件
        """
        # ═══════════════════════════════════════════════════════════════
        # ✅ 注意：Visualizer已在__init__中启动，不要重复启动
        # ═══════════════════════════════════════════════════════════════
        # 如果还未启动，现在启动
        if self.enable_tree_viz and not self.realtime_viz_process:
            self._start_realtime_visualizer()

        # 显示启动信息
        print(f"\n{'=' * 60}")
        print(f"[FuzzingCore] 开始fuzzing活动")
        if infinite_mode:
            print(f"  模式: 无限运行 (直到Ctrl+C)")
        else:
            if max_iterations:
                print(f"  最大迭代次数: {max_iterations}")
            if max_time:
                print(f"  最大时间: {max_time}秒")
            if max_crashes:
                print(f"  最大crash数: {max_crashes}")
            if max_paths:
                print(f"  最大新路径数: {max_paths}")
            if coverage_target:
                print(f"  覆盖率目标: {coverage_target}%")
            if no_progress_timeout:
                print(f"  无进展超时: {no_progress_timeout}秒")
        print(f"{'=' * 60}\n")

        # 初始化变量
        iteration = 0
        start_time = time.time()
        last_progress_time = time.time()
        initial_paths = self.stats.paths_found
        initial_coverage = self._get_coverage_percentage()

        try:
            while True:
                current_time = time.time()

                # 🔥 高级停止条件检查
                if not infinite_mode:
                    # 基础条件
                    if max_iterations and iteration >= max_iterations:
                        print(f"\n[FuzzingCore] ✅ 达到最大迭代次数 ({max_iterations})")
                        break

                    if max_time and (current_time - start_time) >= max_time:
                        print(f"\n[FuzzingCore] ⏰ 达到最大时间 ({max_time}秒)")
                        break

                    # 新的高级停止条件
                    if max_crashes and self.stats.crashes_found >= max_crashes:
                        print(f"\n[FuzzingCore] 🎯 发现足够crashes ({self.stats.crashes_found}/{max_crashes})")
                        break

                    if max_paths and (self.stats.paths_found - initial_paths) >= max_paths:
                        print(f"\n[FuzzingCore] 🛤️  发现足够新路径 ({self.stats.paths_found - initial_paths}/{max_paths})")
                        break

                    if coverage_target:
                        current_coverage = self._get_coverage_percentage()
                        if current_coverage >= coverage_target:
                            print(f"\n[FuzzingCore] 📊 达到覆盖率目标 ({current_coverage:.1f}%/{coverage_target}%)")
                            break

                    if no_progress_timeout:
                        # 检查是否有新路径
                        if self.stats.paths_found > initial_paths:
                            last_progress_time = current_time
                            initial_paths = self.stats.paths_found
                        elif (current_time - last_progress_time) >= no_progress_timeout:
                            print(f"\n[FuzzingCore] 📉 超过{no_progress_timeout}秒无新路径发现")
                            break
                
                # ✅ 新增：动态fork探索（基于概率）
                use_dynamic_fork = (self.dynamic_fork_controller and 
                                  self.dynamic_fork_controller.should_trigger_multi_fork(iteration))
                
                if use_dynamic_fork:
                    # 动态fork模式：在trace中间点fork多个variants
                    print(f"\n{'='*60}")
                    print(f"[FuzzingCore] 🌿 Iteration {iteration}: Dynamic Fork Mode")
                    print(f"{'='*60}")
                    trace = self.trace_manager.select_trace()
                    if trace:
                        print(f"[FuzzingCore] Selected trace: {trace.id} ({trace.file_path})")
                        try:
                            # ✅ 修复2: 设置current_trace_id以便保存种子时使用parent_id
                            self.dynamic_fork_controller.current_trace_id = trace.id
                            # ✅ 传递iteration_id
                            success = self.dynamic_fork_controller.explore_multi_path(
                                trace,
                                iteration_id=iteration
                            )
                            if success:
                                print(f"[FuzzingCore] ✅ Iteration {iteration}: Discovered new paths!")
                                self.stats.paths_found += 1
                        except Exception as e:
                            print(f"[FuzzingCore] ⚠️  Iteration {iteration} failed: {e}")
                            import traceback
                            traceback.print_exc()
                else:
                    # 正常单次迭代 (✅ 传递iteration_id)
                    result = self.run_single_iteration(iteration_id=iteration)
                    # ✅ Task #8: 使用IterationResult
                    # 打印详细结果（可选）
                    if result.is_failure():
                        print(f"[FuzzingCore] ⚠️  {result}")
                
                iteration += 1
        
        except KeyboardInterrupt:
            print(f"\n[FuzzingCore] 用户中断")
        
        finally:
            # ═══════════════════════════════════════════════════════════════
            # 方案A: 停止Realtime Visualizer并生成最终tree
            # ═══════════════════════════════════════════════════════════════
            print(f"\n[FuzzingCore] ⏳ 等待Visualizer接收所有消息...")
            time.sleep(5)  # ✅ 增加等待时间，确保所有消息都被接收
            print(f"[FuzzingCore] ⏳ 开始停止Visualizer...")
            self._stop_realtime_visualizer()
            
            # 最终统计
            self._display_final_statistics()
    
    def _display_final_statistics(self):
        """显示最终fuzzing统计信息"""
        cov_stats = self.coverage_tracker.get_stats()
        trace_stats = self.trace_manager.get_statistics()
        exec_stats = self.execution_engine.get_statistics()
        
        print(f"\n{'=' * 60}")
        print(f"Fuzzing活动完成")
        print(f"{'=' * 60}")
        print(f"\n📊 执行统计:")
        print(f"  总执行次数:  {self.stats.total_execs}")
        print(f"  执行速度:    {self.stats.execs_per_sec:.1f} exec/s")
        print(f"  总时间:      {self.stats.elapsed_time:.1f}s")
        
        print(f"\n🎯 覆盖率统计:")
        print(f"  总边数:      {cov_stats['total_edges']}")
        print(f"  发现新路径:  {self.stats.paths_found}")
        print(f"  位图密度:    {cov_stats['bitmap_density']:.2f}%")
        
        print(f"\n📦 语料库统计:")
        print(f"  总traces:    {trace_stats['total_traces']}")
        print(f"  活跃traces:  {trace_stats['active_traces']}")
        print(f"  已保存:      {trace_stats['traces_saved']}")
        
        print(f"\n💥 Crash统计:")
        print(f"  总crashes:   {self.stats.crashes_found}")
        print(f"  唯一crashes: {len(self.crash_detector.crashes)}")
        print(f"  Crash率:     {exec_stats['crash_rate']:.2%}")
        
        print(f"\n⏱️  超时统计:")
        print(f"  总超时:      {self.stats.timeouts}")
        print(f"  超时率:      {exec_stats['timeout_rate']:.2%}")
        
        print(f"\n{'=' * 60}\n")
        
        # 保存最终结果（corpus、统计信息等）
        self.save_final_results()
    
    def save_final_results(self):
        """
        将最终结果保存到磁盘
        
        第5层集成: 自动生成所有监控和分析报告
        """
        import json
        from pathlib import Path
        
        output_path = Path(self.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[FuzzingCore] 💾 正在保存最终结果...")
        
        # 保存corpus (第2层)
        self.trace_manager.save_corpus(self.output_dir)
        
        # 保存最终统计信息
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
                'executor': self.execution_engine.get_statistics(),
                # ✅ Task #7: 导出FuzzingMetrics
                'metrics': self.metrics.to_dict(),
                # ✅ Task #6: 导出MutationDependencyGraph
                'mutation_graph': self.mutation_graph.to_dict()
            }, f, indent=2)

        print(f"  ✅ 统计信息已保存到 {stats_file}")

        # ✅ Task #7: 保存FuzzingMetrics详细报告
        metrics_report_file = output_path / "metrics_report.txt"
        with open(metrics_report_file, 'w') as f:
            f.write(self.metrics.generate_report())
        print(f"  ✅ Metrics报告已保存到 {metrics_report_file}")

        # ✅ Task #6: 保存MutationDependencyGraph详细报告
        mutation_report_file = output_path / "mutation_analysis.txt"
        with open(mutation_report_file, 'w') as f:
            f.write(self.mutation_graph.generate_report())
        print(f"  ✅ Mutation分析报告已保存到 {mutation_report_file}")

        # ✅ Task #6: 导出完整的mutation图结构 (用于深入分析)
        if self.mutation_graph.nodes:
            mutation_graph_file = output_path / "mutation_graph.json"
            self.mutation_graph.export_to_json(mutation_graph_file)
            print(f"  ✅ Mutation图结构已保存到 {mutation_graph_file}")
        
        # ═══════════════════════════════════════════════════════════
        # 第5层: 监控与分析 (重点!)
        # ═══════════════════════════════════════════════════════════
        
        if self.enable_monitoring:
            print(f"\n[FuzzingCore] 🔍 第5层: 正在生成监控报告...")
            
            # 1. CorpusManager: 保存持久化corpus
            if self.layer5_corpus_manager:
                try:
                    # 注意: corpus_manager需要seed_queue对象，这里简化处理
                    print(f"  ✅ Corpus管理可用 (需要手动保存)")
                except Exception as e:
                    print(f"  ⚠️  Corpus保存失败: {e}")
            
            # 2. CrashAnalyzer: 生成crash报告
            if self.layer5_crash_analyzer:
                try:
                    print(f"\n[FuzzingCore] 💥 正在生成crash分析报告...")
                    self.layer5_crash_analyzer.print_summary(top_n=20, verbose=True)
                    
                    # 导出crash报告
                    crash_report = output_path / "crash_analysis.json"
                    self.layer5_crash_analyzer.export_to_file(crash_report, format='json')
                    print(f"  ✅ Crash报告: {crash_report}")
                except Exception as e:
                    print(f"  ⚠️  Crash分析失败: {e}")
            
            # ═══════════════════════════════════════════════════════════════
            # 3. ⭐ Realtime Tree已在fuzzing过程中实时生成 (方案A)
            # ═══════════════════════════════════════════════════════════════
            realtime_tree_path = output_path / "realtime_tree.html"
            if realtime_tree_path.exists():
                print(f"\n[FuzzingCore] 🌳 ✅ Realtime Syscall Tree已生成:")
                print(f"  📂 {realtime_tree_path}")
                print(f"  🌐 浏览器查看: file://{realtime_tree_path.absolute()}")
                print(f"  📊 数据来源: QEMU实时dynamic trace (准确!)")
            else:
                print(f"\n[FuzzingCore] ⚠️  Realtime Tree未生成 (visualizer可能未启动)")
            
            # ❌ 废弃: 静态tree生成（数据不准确）
            # if _HAS_TREE_VIZ:
            #     print(f"\n[FuzzingCore] 🌳 正在生成Syscall树 (重点功能)...")
            #     self._generate_syscall_trees(output_path)
            # else:
            #     print(f"  ⚠️  SyscallTree可视化器不可用")
        
        print(f"\n[FuzzingCore] ✅ 所有结果已保存到 {output_path}")
    
    def _generate_syscall_trees(self, output_path: Path):
        """
        生成Syscall树可视化 (第5层重点功能)
        
        生成统一的树状可视化，包含所有traces
        使用D3.js tree layout，真正的树形结构
        """
        trees_dir = output_path / "syscall_trees"
        trees_dir.mkdir(exist_ok=True)
        
        # 收集所有trace文件
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
            print(f"  ⚠️  未找到用于可视化的traces")
            return
        
        # 使用TreeVisualizer生成真正的树状可视化（带统计信息）
        print(f"  🌳 正在为{len(trace_files)}个traces生成树可视化...")
        
        try:
            viz = TreeVisualizer()
            
            for trace_file, label in zip(trace_files, labels):
                # ✅ 获取该trace的统计信息
                # 从文件名提取trace_id（如果是corpus文件）
                trace_id = None
                if 'corpus' in str(trace_file):
                    trace_id = Path(trace_file).stem
                # ✅ 修复: Initial trace应该独立，不使用corpus的stats
                # 因为initial trace没有mutation，不应该和mutated traces共享stats
                
                # 构建stats字典
                stats_dict = None
                if trace_id:
                    syscall_stats = self.trace_manager.get_syscall_stats(trace_id)
                    if syscall_stats:
                        stats_dict = {
                            'syscall_stats': syscall_stats,
                            'trace_id': trace_id
                        }
                        print(f"  📊 找到{trace_id}的stats: {len(syscall_stats)}个syscall有数据")
                else:
                    # Initial trace没有stats（所有mutation_applied=False）
                    print(f"  📊 {label}无stats (初始trace, 无变异)")
                
                # 添加trace（带统计信息）
                viz.add_trace(trace_file, label, stats=stats_dict)
            
            tree_html = trees_dir / "syscall_tree.html"
            if viz.generate_html(str(tree_html)):
                print(f"  ✅ 已生成树: {tree_html}")
                print(f"  📂 查看树: file://{tree_html.absolute()}")
            else:
                print(f"  ⚠️  生成树可视化失败")
        
        except Exception as e:
            print(f"  ⚠️  树生成失败: {e}")
            import traceback
            traceback.print_exc()
    
    def cleanup(self):
        """清理资源 (在程序退出时调用)"""
        print("[FuzzingCore] 正在清理资源...")
        
        # ═══════════════════════════════════════════════════════════════
        # 方案A: 确保Realtime Visualizer被停止
        # ═══════════════════════════════════════════════════════════════
        self._stop_realtime_visualizer()
        
        # ✅ 修复: 优雅地停止持久化的QEMU执行器
        if hasattr(self, 'execution_engine') and self.execution_engine:
            if hasattr(self.execution_engine, 'stop_persistent_mode'):
                # 新的持久化执行器
                self.execution_engine.stop_persistent_mode()
            elif hasattr(self.execution_engine, 'stop_persistent_qemu'):
                # 传统的执行器
                self.execution_engine.stop_persistent_qemu()
        
        # 清理共享覆盖率位图
        from .qemu_executor import QEMUExecutor
        QEMUExecutor.cleanup_shared_coverage()
        
        print("[FuzzingCore] ✅ 清理完成")
    
    def __del__(self):
        """析构函数以确保清理"""
        try:
            self.cleanup()
        except:
            pass

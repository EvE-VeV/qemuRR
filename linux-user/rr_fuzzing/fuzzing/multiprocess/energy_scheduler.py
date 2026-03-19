#!/usr/bin/env python3
"""
Advanced Energy Scheduler for Coverage-Guided Fuzzing

This module implements an advanced energy scheduling system that intelligently
allocates fuzzing resources (energy) to seeds based on multiple factors.
"""

import math
import random
import time
from collections import Counter
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class FuzzContext:
    """Fuzzing上下文信息"""
    current_time: float
    total_execs: int
    global_coverage: set
    no_new_coverage_count: int = 0
    
    def in_exploration_phase(self) -> bool:
        """判断是否处于探索阶段"""
        # 初期或长时间无新coverage时，处于探索阶段
        return self.total_execs < 1000 or self.no_new_coverage_count > 500


class AdvancedEnergyScheduler:
    """
    高级能量调度器
    
    基于多个因子计算seed的能量值，实现智能资源分配：
    1. Coverage新鲜度（40%）- 优先处理最近发现新coverage的seeds
    2. 路径深度（20%）- 深路径可能触发深层bug
    3. 执行速度（15%）- 快速seed可以更快迭代
    4. 输入熵（15%）- 高熵输入探索更多状态
    5. Crash潜力（10%）- 历史crash关联性
    
    动态调整探索vs利用平衡。
    """
    
    def __init__(
        self,
        coverage_weight: float = 0.40,
        depth_weight: float = 0.30,
        speed_weight: float = 0.10,
        entropy_weight: float = 0.10,
        crash_weight: float = 0.10,
    ):
        """
        初始化能量调度器
        
        Args:
            coverage_weight: Coverage新鲜度权重
            depth_weight: 路径深度权重
            speed_weight: 执行速度权重
            entropy_weight: 输入熵权重
            crash_weight: Crash潜力权重
        """
        # 权重配置
        self.coverage_weight = coverage_weight
        self.depth_weight = depth_weight
        self.speed_weight = speed_weight
        self.entropy_weight = entropy_weight
        self.crash_weight = crash_weight
        
        # 归一化权重
        total_weight = (
            coverage_weight + depth_weight + speed_weight + 
            entropy_weight + crash_weight
        )
        self.coverage_weight /= total_weight
        self.depth_weight /= total_weight
        self.speed_weight /= total_weight
        self.entropy_weight /= total_weight
        self.crash_weight /= total_weight
        
        # 缓存
        self._entropy_cache: Dict[str, float] = {}
        
        print(f"[EnergyScheduler] Initialized with weights:")
        print(f"  Coverage: {self.coverage_weight:.2f}")
        print(f"  Depth:    {self.depth_weight:.2f}")
        print(f"  Speed:    {self.speed_weight:.2f}")
        print(f"  Entropy:  {self.entropy_weight:.2f}")
        print(f"  Crash:    {self.crash_weight:.2f}")
    
    def calculate_energy(self, seed: Any, context: FuzzContext) -> float:
        """
        计算seed的能量值
        
        Args:
            seed: Seed对象
            context: Fuzzing上下文
        
        Returns:
            能量值（0.0 - 10.0）
        """
        # 计算各个因子的得分
        coverage_score = self._coverage_freshness(seed, context)
        depth_score = self._path_depth_score(seed)
        speed_score = self._execution_speed(seed)
        entropy_score = self._input_entropy(seed)
        crash_score = self._crash_potential(seed)
        
        # 加权综合
        energy = (
            self.coverage_weight * coverage_score +
            self.depth_weight * depth_score +
            self.speed_weight * speed_score +
            self.entropy_weight * entropy_score +
            self.crash_weight * crash_score
        )
        
        # 动态调整：探索阶段给予bonus
        if context.in_exploration_phase():
            energy *= 1.2
        
        # 归一化到合理范围 [0.5, 10.0]
        energy = max(0.5, min(10.0, energy * 10.0))
        
        return energy
    
    def _coverage_freshness(self, seed: Any, context: FuzzContext) -> float:
        """
        Coverage新鲜度评分
        
        评分标准：
        - 最近发现新coverage的seed得分更高
        - 使用指数衰减函数
        - 无新coverage的seed得基础分
        
        Returns:
            得分（0.0 - 1.0）
        """
        # 计算seed的新coverage
        if hasattr(seed, 'coverage') and hasattr(context, 'global_coverage'):
            new_edges = seed.coverage - context.global_coverage
            if not new_edges:
                return 0.5  # 无新coverage，基础分
            
            # 新coverage比例
            new_ratio = len(new_edges) / max(1, len(seed.coverage))
            
            # 时间衰减
            if hasattr(seed, 'discovery_time') and seed.discovery_time > 0:
                age = max(0, context.current_time - seed.discovery_time)  # 确保非负
                # 使用安全的指数衰减（限制age范围避免overflow）
                age = min(age, 10000)  # 限制最大age
                freshness = math.exp(-age / 1000)  # 1000秒半衰期
            else:
                freshness = 1.0
            
            # 综合得分
            score = 0.5 + 0.5 * freshness * new_ratio
            return min(1.0, score)
        
        return 0.5  # 默认中等分数
    
    def _path_depth_score(self, seed: Any) -> float:
        """
        路径深度评分
        
        深路径更有价值（可能触发深层bug）
        
        Returns:
            得分（0.0 - 1.0）
        """
        if not hasattr(seed, 'path_depth'):
            return 0.5
        
        max_depth = 1000  # 假设最大深度
        normalized_depth = min(seed.path_depth, max_depth) / max_depth
        
        # 使用更激进的幂律评分，让深路径获得显著更高的能量
        score = normalized_depth ** 0.5
        
        return score
    
    def _execution_speed(self, seed: Any) -> float:
        """
        执行速度评分
        
        执行快的seed可以更快迭代
        
        Returns:
            得分（0.0 - 1.0）
        """
        if not hasattr(seed, 'exec_time') or seed.exec_time == 0:
            return 1.0  # 默认快速
        
        # 归一化到[0, 1]（假设最大1秒）
        max_time = 1.0
        normalized_time = min(seed.exec_time, max_time) / max_time
        
        # 越快分数越高
        score = 1.0 - normalized_time
        
        return score
    
    def _input_entropy(self, seed: Any) -> float:
        """
        输入熵值评分
        
        高熵输入可能探索更多状态
        
        Returns:
            得分（0.0 - 1.0）
        """
        # 检查缓存
        if hasattr(seed, 'seed_id'):
            if seed.seed_id in self._entropy_cache:
                return self._entropy_cache[seed.seed_id]
        
        # 获取输入数据
        input_data = None
        if hasattr(seed, 'input_data'):
            input_data = seed.input_data
        elif hasattr(seed, 'trace_file'):
            # 简化：从trace文件读取
            try:
                with open(seed.trace_file, 'rb') as f:
                    input_data = f.read()[:1024]  # 只读前1024字节
            except:
                pass
        
        if not input_data or len(input_data) == 0:
            return 0.5  # 默认中等熵
        
        # 计算Shannon熵
        byte_counts = Counter(input_data)
        entropy = 0.0
        total = len(input_data)
        
        for count in byte_counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        
        # 归一化到[0, 1]（最大熵为8 bits）
        max_entropy = 8.0
        score = entropy / max_entropy
        
        # 缓存结果
        if hasattr(seed, 'seed_id'):
            self._entropy_cache[seed.seed_id] = score
        
        return score
    
    def _crash_potential(self, seed: Any) -> float:
        """
        Crash潜力评分
        
        基于历史crash记录评估seed的crash潜力
        
        Returns:
            得分（0.0 - 1.0）
        """
        # 如果seed本身就是crash
        if hasattr(seed, 'crash') and seed.crash:
            return 1.0
        
        # 检查parent和siblings的crash记录
        parent_crashed = 0
        siblings_crashed = 0
        
        if hasattr(seed, 'parent_crashed_count'):
            parent_crashed = seed.parent_crashed_count
        
        if hasattr(seed, 'siblings_crashed_count'):
            siblings_crashed = seed.siblings_crashed_count
        
        # 计算潜力分数
        if parent_crashed > 0 or siblings_crashed > 0:
            # 有crash历史，高潜力
            crash_count = parent_crashed + siblings_crashed
            score = min(1.0, 0.5 + 0.1 * crash_count)
            return score
        
        # generation也可以作为指标（早期seed可能更有价值）
        if hasattr(seed, 'generation'):
            # 早期generation得分略高
            generation_score = math.exp(-seed.generation / 100)
            return 0.3 + 0.2 * generation_score
        
        return 0.3  # 默认低潜力


class ExplorationExploitationBalance:
    """
    探索-利用平衡控制器
    
    动态调整fuzzer在探索（exploration）和利用（exploitation）之间的平衡：
    - 探索：尝试新的、多样化的输入
    - 利用：深入挖掘已知有价值的输入
    
    策略：
    1. 初期：高探索率（80%）
    2. 中期：平衡（50%）
    3. 后期：高利用率（30%）
    4. 动态调整：长时间无新coverage时提高探索率
    """
    
    def __init__(self, initial_rate: float = 0.7):
        """
        初始化平衡控制器
        
        Args:
            initial_rate: 初始探索率（0.0 - 1.0）
        """
        self.exploration_rate = initial_rate
        self.last_adjustment_time = time.time()
        self.adjustment_interval = 100  # 每100次执行调整一次
        
        print(f"[ExploreExploit] Initialized with rate: {self.exploration_rate:.2f}")
    
    def update_phase(self, fuzzing_stats: Dict[str, Any]):
        """
        根据fuzzing统计更新探索/利用比例
        
        Args:
            fuzzing_stats: Fuzzing统计信息字典，包含：
                - total_execs: 总执行次数
                - new_coverage_count: 新coverage数量
                - no_new_coverage_count: 无新coverage的连续次数
        """
        total_execs = fuzzing_stats.get('total_execs', 0)
        no_new_cov = fuzzing_stats.get('no_new_coverage_count', 0)
        
        # 阶段1: 初期 (0-1000 execs) - 高探索
        if total_execs < 1000:
            self.exploration_rate = 0.8
        
        # 阶段2: 中期 (1000-10000) - 平衡
        elif total_execs < 10000:
            self.exploration_rate = 0.5
        
        # 阶段3: 后期 (>10000) - 高利用
        else:
            self.exploration_rate = 0.3
        
        # 动态调整: 如果很久没发现新coverage，提高探索率
        if no_new_cov > 500:
            self.exploration_rate = min(0.9, self.exploration_rate + 0.2)
            print(f"[ExploreExploit] No new coverage for {no_new_cov} iters, "
                  f"increasing exploration rate to {self.exploration_rate:.2f}")
        elif no_new_cov > 200:
            self.exploration_rate = min(0.8, self.exploration_rate + 0.1)
        
        # 限制范围
        self.exploration_rate = max(0.1, min(0.9, self.exploration_rate))
    
    def should_explore(self) -> bool:
        """
        决定是否进行探索
        
        Returns:
            True表示探索，False表示利用
        """
        return random.random() < self.exploration_rate
    
    def get_mutation_intensity(self, is_exploration: bool) -> float:
        """
        获取变异强度
        
        探索模式使用更大的变异，利用模式使用更小的变异
        
        Args:
            is_exploration: 是否处于探索模式
        
        Returns:
            变异强度（0.0 - 1.0）
        """
        if is_exploration:
            # 探索：大幅变异
            return random.uniform(0.5, 1.0)
        else:
            # 利用：小幅变异
            return random.uniform(0.1, 0.4)


def test_energy_scheduler():
    """测试能量调度器"""
    print("Testing AdvancedEnergyScheduler...")
    
    # 创建调度器
    scheduler = AdvancedEnergyScheduler()
    
    # 创建测试seed
    @dataclass
    class TestSeed:
        seed_id: str
        coverage: set
        discovery_time: float
        path_depth: int
        exec_time: float
        input_data: bytes
        crash: bool = False
        generation: int = 0
    
    # 测试不同类型的seeds
    now = time.time()
    
    # Seed 1: 新发现，深路径
    seed1 = TestSeed(
        seed_id="seed1",
        coverage={1, 2, 3, 4, 5},
        discovery_time=now,
        path_depth=500,
        exec_time=0.1,
        input_data=b"test_data_1",
        generation=0
    )
    
    # Seed 2: 旧的，浅路径
    seed2 = TestSeed(
        seed_id="seed2",
        coverage={1, 2, 3},
        discovery_time=now - 1000,
        path_depth=50,
        exec_time=0.5,
        input_data=b"test_data_2",
        generation=10
    )
    
    # Seed 3: Crash seed
    seed3 = TestSeed(
        seed_id="seed3",
        coverage={1, 2, 3, 4},
        discovery_time=now - 100,
        path_depth=200,
        exec_time=0.2,
        input_data=b"crash_data",
        crash=True,
        generation=5
    )
    
    # 创建上下文
    context = FuzzContext(
        current_time=now,
        total_execs=1000,
        global_coverage={1, 2, 3},
        no_new_coverage_count=0
    )
    
    # 计算能量
    energy1 = scheduler.calculate_energy(seed1, context)
    energy2 = scheduler.calculate_energy(seed2, context)
    energy3 = scheduler.calculate_energy(seed3, context)
    
    print(f"Seed 1 energy: {energy1:.2f}")
    print(f"Seed 2 energy: {energy2:.2f}")
    print(f"Seed 3 energy: {energy3:.2f}")
    
    # 验证
    assert energy1 > energy2, "Fresh deep seed should have higher energy"
    assert energy3 > energy2, "Crash seed should have higher energy"
    
    print("✓ AdvancedEnergyScheduler test passed")


def test_exploration_exploitation():
    """测试探索-利用平衡"""
    print("\nTesting ExplorationExploitationBalance...")
    
    balance = ExplorationExploitationBalance()
    
    # 测试不同阶段
    stats_early = {'total_execs': 100, 'no_new_coverage_count': 0}
    balance.update_phase(stats_early)
    print(f"Early phase rate: {balance.exploration_rate:.2f}")
    assert balance.exploration_rate == 0.8
    
    stats_mid = {'total_execs': 5000, 'no_new_coverage_count': 0}
    balance.update_phase(stats_mid)
    print(f"Mid phase rate: {balance.exploration_rate:.2f}")
    assert balance.exploration_rate == 0.5
    
    stats_late = {'total_execs': 15000, 'no_new_coverage_count': 0}
    balance.update_phase(stats_late)
    print(f"Late phase rate: {balance.exploration_rate:.2f}")
    assert balance.exploration_rate == 0.3
    
    # 测试动态调整
    stats_stuck = {'total_execs': 15000, 'no_new_coverage_count': 600}
    balance.update_phase(stats_stuck)
    print(f"Stuck phase rate: {balance.exploration_rate:.2f}")
    assert balance.exploration_rate > 0.3
    
    print("✓ ExplorationExploitationBalance test passed")


if __name__ == '__main__':
    test_energy_scheduler()
    test_exploration_exploitation()


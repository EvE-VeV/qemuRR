#!/usr/bin/env python3
"""
Coverage-Guided Fuzzing 反馈循环

实现:
1. CoverageTracker: 跟踪BB覆盖率
2. SeedQueue: 管理seed队列，优先级调度
3. CoverageGuidedFuzzer: 集成coverage反馈的fuzzer

作者: RR-Fuzz Team
日期: 2025-10-31
"""

import os
import sys
import json
import time
import hashlib
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict
from enum import IntEnum
import heapq


class SeedPriority(IntEnum):
    """Seed优先级"""
    LOW = 3
    NORMAL = 2
    HIGH = 1
    CRITICAL = 0


@dataclass
class Seed:
    """
    Fuzzing Seed
    
    Attributes:
        trace_file: trace文件路径
        coverage: 覆盖的BB集合
        energy: 能量值（越高越优先）
        priority: 优先级
        parent_id: 父seed ID
        generation: 代数
        execution_time: 执行时间（秒）
        discovered_time: 发现时间（时间戳）
        execution_count: 执行次数
    """
    seed_id: str
    trace_file: str
    coverage: Set[int] = field(default_factory=set)
    energy: float = 1.0
    priority: SeedPriority = SeedPriority.NORMAL
    parent_id: Optional[str] = None
    generation: int = 0
    execution_time: float = 0.0
    discovered_time: float = field(default_factory=time.time)
    execution_count: int = 0
    crash: bool = False
    new_coverage_count: int = 0
    
    def __lt__(self, other):
        """用于堆排序（优先级高的在前）"""
        # 先按priority排序，再按energy排序
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.energy > other.energy
    
    def to_dict(self) -> Dict:
        """序列化为字典"""
        return {
            'seed_id': self.seed_id,
            'trace_file': self.trace_file,
            'coverage_size': len(self.coverage),
            'energy': self.energy,
            'priority': int(self.priority),
            'parent_id': self.parent_id,
            'generation': self.generation,
            'execution_time': self.execution_time,
            'discovered_time': self.discovered_time,
            'execution_count': self.execution_count,
            'crash': self.crash,
            'new_coverage_count': self.new_coverage_count
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'Seed':
        """从字典反序列化"""
        seed = Seed(
            seed_id=data['seed_id'],
            trace_file=data['trace_file'],
            energy=data.get('energy', 1.0),
            priority=SeedPriority(data.get('priority', 2)),
            parent_id=data.get('parent_id'),
            generation=data.get('generation', 0),
            execution_time=data.get('execution_time', 0.0),
            discovered_time=data.get('discovered_time', time.time()),
            execution_count=data.get('execution_count', 0),
            crash=data.get('crash', False),
            new_coverage_count=data.get('new_coverage_count', 0)
        )
        # coverage需要单独加载
        return seed


class SeedQueue:
    """
    Seed队列管理器
    
    使用优先级堆实现，支持:
    - 基于覆盖率的能量分配
    - 优先级调度
    - Seed修剪（去重、限制大小）
    """
    
    def __init__(self, max_size: int = 10000, dedup: bool = True):
        """
        Args:
            max_size: 最大seed数量
            dedup: 是否去重（基于coverage hash）
        """
        self.max_size = max_size
        self.dedup = dedup
        
        self.seeds: List[Seed] = []  # 最小堆
        self.seed_map: Dict[str, Seed] = {}  # seed_id -> Seed
        self.coverage_hashes: Set[str] = set()  # coverage去重
        
        self.stats = {
            'total_added': 0,
            'duplicates_rejected': 0,
            'pruned': 0
        }
    
    def add(self, seed: Seed) -> bool:
        """
        添加seed到队列
        
        Returns:
            True if added, False if rejected (duplicate/full)
        """
        # 去重检查
        if self.dedup:
            cov_hash = self._hash_coverage(seed.coverage)
            if cov_hash in self.coverage_hashes:
                self.stats['duplicates_rejected'] += 1
                return False
            self.coverage_hashes.add(cov_hash)
        
        # 添加到队列
        heapq.heappush(self.seeds, seed)
        self.seed_map[seed.seed_id] = seed
        self.stats['total_added'] += 1
        
        # 队列大小控制
        if len(self.seeds) > self.max_size:
            self._prune()
        
        return True
    
    def pop(self) -> Optional[Seed]:
        """获取下一个seed（最高优先级）"""
        if not self.seeds:
            return None
        
        seed = heapq.heappop(self.seeds)
        seed.execution_count += 1
        
        # 执行后可能需要重新入队（如果能量未耗尽）
        if seed.energy > 0.1 and not seed.crash:
            # 降低能量
            seed.energy *= 0.9
            heapq.heappush(self.seeds, seed)
        else:
            # 能量耗尽，从map移除
            del self.seed_map[seed.seed_id]
        
        return seed
    
    def peek(self) -> Optional[Seed]:
        """查看下一个seed（不弹出）"""
        return self.seeds[0] if self.seeds else None
    
    def update_seed_energy(self, seed_id: str, energy_delta: float):
        """更新seed能量"""
        if seed_id in self.seed_map:
            seed = self.seed_map[seed_id]
            seed.energy += energy_delta
            # 重新堆化
            heapq.heapify(self.seeds)
    
    def _prune(self):
        """修剪队列（移除低能量的seed）"""
        # 保留前max_size个seed
        self.seeds = heapq.nsmallest(self.max_size, self.seeds)
        heapq.heapify(self.seeds)
        
        # 更新seed_map
        self.seed_map = {s.seed_id: s for s in self.seeds}
        
        self.stats['pruned'] += 1
    
    def _hash_coverage(self, coverage: Set[int]) -> str:
        """计算coverage的hash（用于去重）"""
        sorted_cov = sorted(coverage)
        cov_str = ','.join(map(str, sorted_cov))
        return hashlib.md5(cov_str.encode()).hexdigest()
    
    def size(self) -> int:
        """队列大小"""
        return len(self.seeds)
    
    def is_empty(self) -> bool:
        """队列是否为空"""
        return len(self.seeds) == 0
    
    def save(self, filepath: str):
        """保存队列到文件"""
        data = {
            'seeds': [s.to_dict() for s in self.seeds],
            'stats': self.stats
        }
        Path(filepath).write_text(json.dumps(data, indent=2))
    
    def load(self, filepath: str):
        """从文件加载队列"""
        if not os.path.exists(filepath):
            return
        
        data = json.loads(Path(filepath).read_text())
        self.stats = data.get('stats', {})
        
        for seed_data in data.get('seeds', []):
            seed = Seed.from_dict(seed_data)
            # 需要从trace文件重新加载coverage
            # 这里先跳过，实际使用时需要实现
            heapq.heappush(self.seeds, seed)
            self.seed_map[seed.seed_id] = seed


class CoverageTracker:
    """
    Coverage跟踪器
    
    跟踪:
    - 全局BB覆盖率
    - 每个seed的新增coverage
    - Coverage趋势
    """
    
    def __init__(self):
        self.global_coverage: Set[int] = set()
        self.coverage_history: List[Tuple[float, int]] = []  # (timestamp, coverage_size)
        self.edge_coverage: Dict[Tuple[int, int], int] = defaultdict(int)  # (from, to) -> hit_count
        
        self.stats = {
            'total_bbs': 0,
            'new_coverage_events': 0,
            'last_new_coverage_time': 0.0
        }
    
    def update(self, bb_sequence: List[int]) -> Tuple[int, Set[int]]:
        """
        更新coverage
        
        Args:
            bb_sequence: BB执行序列
        
        Returns:
            (new_coverage_count, new_bbs)
        """
        current_bbs = set(bb_sequence)
        new_bbs = current_bbs - self.global_coverage
        
        if new_bbs:
            self.global_coverage.update(new_bbs)
            self.stats['new_coverage_events'] += 1
            self.stats['last_new_coverage_time'] = time.time()
            
            # 记录历史
            self.coverage_history.append((time.time(), len(self.global_coverage)))
        
        # 更新边覆盖
        for i in range(len(bb_sequence) - 1):
            edge = (bb_sequence[i], bb_sequence[i+1])
            self.edge_coverage[edge] += 1
        
        self.stats['total_bbs'] = len(self.global_coverage)
        
        return len(new_bbs), new_bbs
    
    def get_coverage_rate(self, total_bbs: int) -> float:
        """计算覆盖率"""
        if total_bbs == 0:
            return 0.0
        return len(self.global_coverage) / total_bbs
    
    def get_coverage_trend(self, window_size: int = 100) -> float:
        """
        计算coverage增长趋势
        
        Returns:
            正值表示增长，负值表示停滞
        """
        if len(self.coverage_history) < 2:
            return 0.0
        
        recent = self.coverage_history[-window_size:]
        if len(recent) < 2:
            return 0.0
        
        # 简单线性回归斜率
        time_diffs = [recent[i][0] - recent[0][0] for i in range(len(recent))]
        cov_diffs = [recent[i][1] - recent[0][1] for i in range(len(recent))]
        
        if sum(time_diffs) == 0:
            return 0.0
        
        slope = sum(cov_diffs) / sum(time_diffs)
        return slope
    
    def save(self, filepath: str):
        """保存coverage数据"""
        data = {
            'global_coverage': list(self.global_coverage),
            'coverage_history': self.coverage_history,
            'stats': self.stats
        }
        Path(filepath).write_text(json.dumps(data, indent=2))
    
    def load(self, filepath: str):
        """加载coverage数据"""
        if not os.path.exists(filepath):
            return
        
        data = json.loads(Path(filepath).read_text())
        self.global_coverage = set(data.get('global_coverage', []))
        self.coverage_history = [tuple(x) for x in data.get('coverage_history', [])]
        self.stats = data.get('stats', {})


class CoverageGuidedFuzzer:
    """
    Coverage-Guided Fuzzer协调器
    
    整合:
    - SeedQueue: 管理输入队列
    - CoverageTracker: 跟踪覆盖率
    - 能量分配策略
    """
    
    def __init__(self, queue_size: int = 10000, new_coverage_bonus: float = 2.0):
        """
        Args:
            queue_size: seed队列最大大小
            new_coverage_bonus: 新coverage的能量奖励倍数
        """
        self.seed_queue = SeedQueue(max_size=queue_size)
        self.coverage_tracker = CoverageTracker()
        self.new_coverage_bonus = new_coverage_bonus
        
        self.stats = {
            'iterations': 0,
            'new_coverage_seeds': 0,
            'crashes': 0
        }
    
    def add_seed(self, trace_file: str, bb_sequence: List[int], 
                 parent_id: Optional[str] = None, crash: bool = False) -> Optional[Seed]:
        """
        添加新seed
        
        Args:
            trace_file: trace文件路径
            bb_sequence: BB执行序列
            parent_id: 父seed ID
            crash: 是否crash
        
        Returns:
            Seed对象（如果添加成功），否则None
        """
        # 检查是否有新coverage
        new_cov_count, new_bbs = self.coverage_tracker.update(bb_sequence)
        
        # 只有新coverage或crash才加入队列
        if new_cov_count == 0 and not crash:
            return None
        
        # 创建seed
        seed_id = hashlib.md5(trace_file.encode()).hexdigest()[:16]
        seed = Seed(
            seed_id=seed_id,
            trace_file=trace_file,
            coverage=set(bb_sequence),
            energy=1.0,
            priority=SeedPriority.NORMAL,
            parent_id=parent_id,
            generation=self._get_generation(parent_id),
            new_coverage_count=new_cov_count,
            crash=crash
        )
        
        # 能量奖励
        if new_cov_count > 0:
            seed.energy *= (1.0 + new_cov_count * self.new_coverage_bonus)
            seed.priority = SeedPriority.HIGH
            self.stats['new_coverage_seeds'] += 1
        
        if crash:
            seed.priority = SeedPriority.CRITICAL
            self.stats['crashes'] += 1
        
        # 添加到队列
        if self.seed_queue.add(seed):
            return seed
        else:
            return None
    
    def get_next_seed(self) -> Optional[Seed]:
        """获取下一个要执行的seed"""
        self.stats['iterations'] += 1
        return self.seed_queue.pop()
    
    def _get_generation(self, parent_id: Optional[str]) -> int:
        """计算seed代数"""
        if parent_id is None:
            return 0
        
        if parent_id in self.seed_queue.seed_map:
            parent = self.seed_queue.seed_map[parent_id]
            return parent.generation + 1
        
        return 0
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            'fuzzer': self.stats,
            'queue': self.seed_queue.stats,
            'coverage': self.coverage_tracker.stats,
            'queue_size': self.seed_queue.size(),
            'global_coverage': len(self.coverage_tracker.global_coverage)
        }
    
    def save_state(self, output_dir: str):
        """保存fuzzer状态"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        self.seed_queue.save(str(output_path / 'seed_queue.json'))
        self.coverage_tracker.save(str(output_path / 'coverage.json'))
        
        # 保存统计信息
        (output_path / 'fuzzer_stats.json').write_text(
            json.dumps(self.get_stats(), indent=2)
        )
    
    def load_state(self, input_dir: str):
        """加载fuzzer状态"""
        input_path = Path(input_dir)
        if not input_path.exists():
            return
        
        self.seed_queue.load(str(input_path / 'seed_queue.json'))
        self.coverage_tracker.load(str(input_path / 'coverage.json'))


if __name__ == '__main__':
    # 简单测试
    print("Testing CoverageGuidedFuzzer...")
    
    fuzzer = CoverageGuidedFuzzer()
    
    # 添加初始seed
    seed1 = fuzzer.add_seed('/tmp/seed1.dat', [100, 101, 102, 103])
    print(f"Added seed1: {seed1.seed_id if seed1 else 'rejected'}")
    
    # 添加有新coverage的seed
    seed2 = fuzzer.add_seed('/tmp/seed2.dat', [100, 101, 104, 105], parent_id=seed1.seed_id if seed1 else None)
    print(f"Added seed2: {seed2.seed_id if seed2 else 'rejected'}")
    
    # 添加无新coverage的seed（应被拒绝）
    seed3 = fuzzer.add_seed('/tmp/seed3.dat', [100, 101, 102])
    print(f"Added seed3: {seed3.seed_id if seed3 else 'rejected (no new coverage)'}")
    
    # 获取下一个seed
    next_seed = fuzzer.get_next_seed()
    print(f"\nNext seed to execute: {next_seed.seed_id if next_seed else 'None'}")
    print(f"  Priority: {next_seed.priority if next_seed else 'N/A'}")
    print(f"  Energy: {next_seed.energy if next_seed else 'N/A'}")
    
    print(f"\nFuzzer stats: {fuzzer.get_stats()}")
    print("\n✅ Test complete!")


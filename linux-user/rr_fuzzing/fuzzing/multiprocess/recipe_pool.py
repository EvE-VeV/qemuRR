#!/usr/bin/env python3
"""
RecipePool - Recipe 池管理器 (Layer 3)

负责管理 PathFinder 生成的 Mutation Recipes，提供:
1. Recipe 添加和淘汰
2. 基于优先级和成功率的选择
3. Recipe 统计和评估
4. Recipe 持久化

架构: DETAILED_ARCHITECTURE.md Line 260-290
"""

import json
import time
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


@dataclass
class RecipeStats:
    """Recipe 统计信息"""
    attempt_count: int = 0
    success_count: int = 0
    new_coverage_count: int = 0
    last_success_time: float = 0.0
    
    @property
    def success_rate(self) -> float:
        """成功率"""
        if self.attempt_count == 0:
            return 0.0
        return self.success_count / self.attempt_count
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'attempt_count': self.attempt_count,
            'success_count': self.success_count,
            'new_coverage_count': self.new_coverage_count,
            'success_rate': self.success_rate,
            'last_success_time': self.last_success_time
        }


class RecipePool:
    """
    Recipe 池管理器 (Layer 3: Optimization)
    
    管理 PathFinder 生成的 mutation recipes，实现智能选择和淘汰策略。
    
    架构: DETAILED_ARCHITECTURE.md Line 260-290
    """
    
    def __init__(self, max_active: int = 50, retirement_threshold: int = 100):
        """
        初始化 RecipePool
        
        Args:
            max_active: 最大活跃 recipe 数量
            retirement_threshold: 淘汰阈值（尝试次数）
        """
        # Recipe 存储
        self.active_recipes: List[Dict] = []  # 活跃的 recipes
        self.retired_recipes: List[Dict] = []  # 已淘汰的 recipes
        
        # Recipe 索引 (syscall_name -> recipes)
        self.recipe_index: Dict[str, List[Dict]] = {}
        
        # Recipe 统计
        self.stats: Dict[str, RecipeStats] = {}
        
        # 配置
        self.max_active = max_active
        self.retirement_threshold = retirement_threshold
        
        # 全局统计
        self.total_added = 0
        self.total_retired = 0
        
        print(f"[RecipePool] Initialized (max_active={max_active}, "
              f"retirement_threshold={retirement_threshold})")
    
    def add_recipes(self, recipes: List[Dict]):
        """
        添加 recipes 到池中
        
        Args:
            recipes: Recipe 字典列表 (from PathFinder)
        """
        for recipe in recipes:
            recipe_id = recipe.get('id', len(self.active_recipes))
            recipe['id'] = recipe_id
            
            # 添加到活跃池
            self.active_recipes.append(recipe)
            self.total_added += 1
            
            # 建立索引
            syscall_name = recipe.get('syscall_name', '')
            if syscall_name:
                if syscall_name not in self.recipe_index:
                    self.recipe_index[syscall_name] = []
                self.recipe_index[syscall_name].append(recipe)
            
            # 初始化统计
            if recipe_id not in self.stats:
                self.stats[recipe_id] = RecipeStats()
        
        print(f"[RecipePool] Added {len(recipes)} recipes "
              f"(total active: {len(self.active_recipes)})")
        
        # 检查是否需要修剪
        if len(self.active_recipes) > self.max_active:
            self._prune_recipes()
    
    def get_recipe_for_trace(self, trace: Any) -> Optional[Dict]:
        """
        为给定 trace 选择最佳 recipe
        
        Args:
            trace: Trace 对象 (包含 syscalls 信息)
        
        Returns:
            Recipe 字典或 None
        
        架构: DETAILED_ARCHITECTURE.md Line 269-280
        """
        if not self.active_recipes:
            return None
        
        # 方法 1: 基于 trace 中的 syscalls 匹配
        matching_recipes = []
        
        # 假设 trace 有 syscalls 属性
        if hasattr(trace, 'syscalls'):
            for recipe in self.active_recipes:
                syscall_idx = recipe.get('syscall_index', -1)
                if 0 <= syscall_idx < len(trace.syscalls):
                    # Recipe 适用于这个 trace
                    matching_recipes.append(recipe)
        else:
            # 如果 trace 没有详细信息，返回所有 recipes
            matching_recipes = self.active_recipes
        
        if not matching_recipes:
            return None
        
        # 方法 2: 按优先级和尝试次数排序
        sorted_recipes = sorted(
            matching_recipes,
            key=lambda r: (
                r.get('priority', 5),  # 高优先级优先
                -self.stats[r['id']].attempt_count  # 尝试少的优先
            ),
            reverse=True
        )
        
        return sorted_recipes[0]
    
    def update_recipe_result(
        self, 
        recipe: Dict, 
        success: bool, 
        new_coverage: int = 0
    ):
        """
        更新 recipe 执行结果
        
        Args:
            recipe: Recipe 字典
            success: 是否成功（发现新 coverage）
            new_coverage: 新发现的 coverage 数量
        
        架构: DETAILED_ARCHITECTURE.md Line 282-289
        """
        recipe_id = recipe['id']
        
        if recipe_id not in self.stats:
            self.stats[recipe_id] = RecipeStats()
        
        stat = self.stats[recipe_id]
        stat.attempt_count += 1
        
        if success:
            stat.success_count += 1
            stat.new_coverage_count += new_coverage
            stat.last_success_time = time.time()
        
        # 检查是否应该淘汰
        if stat.attempt_count >= self.retirement_threshold:
            if stat.success_rate < 0.1:  # 成功率 < 10%
                self._retire_recipe(recipe)
    
    def _retire_recipe(self, recipe: Dict):
        """淘汰 recipe"""
        recipe_id = recipe['id']
        
        # 从活跃池移除
        self.active_recipes = [r for r in self.active_recipes if r['id'] != recipe_id]
        
        # 添加到淘汰池
        self.retired_recipes.append(recipe)
        self.total_retired += 1
        
        # 更新索引
        syscall_name = recipe.get('syscall_name', '')
        if syscall_name in self.recipe_index:
            self.recipe_index[syscall_name] = [
                r for r in self.recipe_index[syscall_name] if r['id'] != recipe_id
            ]
        
        print(f"[RecipePool] Retired recipe {recipe_id} "
              f"(attempts={self.stats[recipe_id].attempt_count}, "
              f"success_rate={self.stats[recipe_id].success_rate:.1%})")
    
    def _prune_recipes(self):
        """修剪 recipe 池（保留高质量的）"""
        if len(self.active_recipes) <= self.max_active:
            return
        
        # 按成功率和优先级排序
        sorted_recipes = sorted(
            self.active_recipes,
            key=lambda r: (
                self.stats[r['id']].success_rate,
                r.get('priority', 5),
                self.stats[r['id']].new_coverage_count
            ),
            reverse=True
        )
        
        # 保留前 N 个
        to_keep = sorted_recipes[:self.max_active]
        to_retire = sorted_recipes[self.max_active:]
        
        for recipe in to_retire:
            self._retire_recipe(recipe)
        
        print(f"[RecipePool] Pruned {len(to_retire)} recipes "
              f"(active: {len(self.active_recipes)})")
    
    def get_statistics(self) -> Dict:
        """获取 RecipePool 统计信息"""
        active_stats = [self.stats[r['id']] for r in self.active_recipes]
        
        return {
            'total_added': self.total_added,
            'active_recipes': len(self.active_recipes),
            'retired_recipes': len(self.retired_recipes),
            'total_retired': self.total_retired,
            'avg_success_rate': (
                sum(s.success_rate for s in active_stats) / len(active_stats)
                if active_stats else 0.0
            ),
            'total_attempts': sum(s.attempt_count for s in active_stats),
            'total_successes': sum(s.success_count for s in active_stats),
        }
    
    def save_to_file(self, output_path: Path):
        """保存 RecipePool 到文件"""
        data = {
            'active_recipes': self.active_recipes,
            'retired_recipes': self.retired_recipes,
            'stats': {
                str(recipe_id): stat.to_dict() 
                for recipe_id, stat in self.stats.items()
            },
            'metadata': {
                'total_added': self.total_added,
                'total_retired': self.total_retired,
                'timestamp': time.time()
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[RecipePool] Saved to {output_path}")
    
    def load_from_file(self, input_path: Path):
        """从文件加载 RecipePool"""
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        self.active_recipes = data.get('active_recipes', [])
        self.retired_recipes = data.get('retired_recipes', [])
        
        # 恢复统计
        stats_data = data.get('stats', {})
        for recipe_id_str, stat_dict in stats_data.items():
            recipe_id = int(recipe_id_str)
            self.stats[recipe_id] = RecipeStats(**stat_dict)
        
        # 重建索引
        self.recipe_index.clear()
        for recipe in self.active_recipes:
            syscall_name = recipe.get('syscall_name', '')
            if syscall_name:
                if syscall_name not in self.recipe_index:
                    self.recipe_index[syscall_name] = []
                self.recipe_index[syscall_name].append(recipe)
        
        metadata = data.get('metadata', {})
        self.total_added = metadata.get('total_added', len(self.active_recipes))
        self.total_retired = metadata.get('total_retired', len(self.retired_recipes))
        
        print(f"[RecipePool] Loaded from {input_path} "
              f"({len(self.active_recipes)} active recipes)")
    
    def print_summary(self):
        """打印 RecipePool 摘要"""
        stats = self.get_statistics()
        
        print("\n" + "=" * 60)
        print("RecipePool Summary")
        print("=" * 60)
        print(f"  Active recipes:     {stats['active_recipes']}")
        print(f"  Retired recipes:    {stats['retired_recipes']}")
        print(f"  Total added:        {stats['total_added']}")
        print(f"  Total attempts:     {stats['total_attempts']}")
        print(f"  Total successes:    {stats['total_successes']}")
        print(f"  Avg success rate:   {stats['avg_success_rate']:.1%}")
        print("=" * 60 + "\n")


def test_recipe_pool():
    """测试 RecipePool"""
    print("Testing RecipePool...")
    
    # 创建 pool
    pool = RecipePool(max_active=10)
    
    # 添加测试 recipes
    test_recipes = [
        {
            'id': i,
            'source_branch': f'0x{1000+i:x}',
            'target_branch': f'0x{2000+i:x}',
            'syscall_name': 'read' if i % 2 == 0 else 'write',
            'syscall_index': i,
            'priority': 5 + (i % 3),
            'mutation_type': 'FUZZ_CMD_MUTATE_ARG',
        }
        for i in range(15)
    ]
    
    pool.add_recipes(test_recipes)
    
    # 模拟使用
    class MockTrace:
        def __init__(self):
            self.syscalls = [None] * 20
    
    trace = MockTrace()
    
    for _ in range(50):
        recipe = pool.get_recipe_for_trace(trace)
        if recipe:
            # 模拟执行结果
            import random
            success = random.random() < 0.3
            new_cov = random.randint(0, 5) if success else 0
            pool.update_recipe_result(recipe, success, new_cov)
    
    # 打印摘要
    pool.print_summary()
    
    print("✅ RecipePool test passed")


if __name__ == '__main__':
    test_recipe_pool()


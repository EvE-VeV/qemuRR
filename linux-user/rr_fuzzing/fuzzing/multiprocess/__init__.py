"""
RR-Fuzz 多进程模糊测试模块

本包包含多进程并行模糊测试的组件：
- fuzz_master: 多进程模糊测试协调器
- corpus_manager: 语料库持久化和管理
- crash_analyzer: 崩溃分类和去重
- energy_scheduler: 智能种子能量调度
- seed_queue_advanced: 基于能量的高级种子队列
- shared_resources: 多进程共享内存和种子同步
- path_finder: 路径查找器（离线CFG分析和配方生成）
"""

# ✅ 修复：延迟导入，避免循环依赖
# 不要在__init__.py直接导入，而是让用户显式导入
# from .fuzz_master import FuzzMaster, WorkerConfig, WorkerStats
# from .shared_resources import SharedCoverage, WorkerSeedQueue
# from .recipe_pool import RecipePool, RecipeStats

# PathFinder 是可选的（需要 angr）
try:
    from .path_finder import PathFinder, MutationRecipe, PathFinderConfig
    _has_path_finder = True
except ImportError:
    PathFinder = None
    MutationRecipe = None
    PathFinderConfig = None
    _has_path_finder = False

__all__ = [
    # 模块名（用于 from multiprocess import module_name）
    'fuzz_master',
    'corpus_manager',
    'crash_analyzer',
    'energy_scheduler',
    'seed_queue_advanced',
    'shared_resources',
    'path_finder',
    'recipe_pool',
    'dynamic_fork_controller',
]


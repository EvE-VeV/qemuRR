"""
RR-Fuzz 多进程模糊测试模块

本包包含多进程并行模糊测试的组件：
- fuzz_master: 多进程模糊测试协调器
- corpus_manager: 语料库持久化和管理
- crash_analyzer: 崩溃分类和去重
- coverage_feedback: 高级覆盖率引导模糊测试
- energy_scheduler: 智能种子能量调度
- seed_queue_advanced: 基于能量的高级种子队列
- shared_resources: 多进程共享内存和种子同步
- multiprocess_extensions: FuzzConductor 的多进程扩展
- path_finder: 路径查找器（离线CFG分析和配方生成）
"""

# 导出主要类
from .fuzz_master import FuzzMaster
from .shared_resources import SharedCoverage, WorkerSeedQueue
from .multiprocess_extensions import MultiProcessFuzzConductor, create_multiprocess_conductor

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
    'coverage_feedback',
    'energy_scheduler',
    'seed_queue_advanced',
    'shared_resources',
    'multiprocess_extensions',
    'path_finder',
    # 类名（用于 from multiprocess import ClassName）
    'FuzzMaster',
    'SharedCoverage',
    'WorkerSeedQueue',
    'MultiProcessFuzzConductor',
    'create_multiprocess_conductor',
    'PathFinder',
    'MutationRecipe',
    'PathFinderConfig',
]


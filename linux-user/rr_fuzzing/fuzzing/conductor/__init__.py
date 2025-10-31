"""
RR-Fuzz Conductor 模块

本包包含单进程模糊测试指挥器的核心组件：
- constants: 所有常量定义和命令类型
- init_detector: 初始化阶段检测
- instruction: Fuzz 指令表示
- coverage: 基础覆盖率追踪
- shared_memory: 共享内存管理
- mutator: 智能变异引擎
- bb_trace_parser: 基本块轨迹解析器
"""

from .constants import *
from .init_detector import InitPhaseDetector
from .instruction import FuzzInstruction
from .coverage import CoverageTracker
from .shared_memory import FuzzSharedMemory
from .mutator import SmartMutator
from .bb_trace_parser import BBTraceParser, BBEntry

__all__ = [
    # Constants
    'FUZZ_CMD_NONE', 'FUZZ_CMD_MUTATE_ARG', 'FUZZ_CMD_REPLACE_BUFFER',
    'FUZZ_CMD_MUTATE_FLAGS', 'FUZZ_CMD_BOUNDARY_VALUE',
    'FUZZ_CMD_MUTATE_AUX_BUFFER', 'FUZZ_CMD_FLIP_BITS',
    'FUZZ_CMD_TRUNCATE', 'FUZZ_CMD_EXTEND', 'FUZZ_CMD_INTERESTING_VALUES',
    'FUZZ_CMD_LIGHT_MUTATION', 'FUZZ_CMD_OVERWRITE_AT_OFFSET',
    'FUZZ_MAGIC', 'FUZZ_MAX_INSTRUCTIONS', 'FUZZ_INSTRUCTION_DATA',
    'FUZZ_SHM_SIZE', 'COVERAGE_MAP_SIZE', 'FUZZ_FLAG_CAPTURE_SEED',
    'INIT_SYSCALLS', 'INIT_PHASE_THRESHOLD', 'IMPORTANT_SYSCALLS',
    # Classes
    'InitPhaseDetector', 'FuzzInstruction', 'CoverageTracker',
    'FuzzSharedMemory', 'SmartMutator', 'BBTraceParser', 'BBEntry'
]


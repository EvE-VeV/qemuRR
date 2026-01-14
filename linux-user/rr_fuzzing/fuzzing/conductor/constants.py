#!/usr/bin/env python3
"""
RR-Fuzz 常量和命令定义

本模块包含整个RR-Fuzz系统使用的所有常量和命令类型定义。
这些值必须与C端定义(rr_constants.h和rr_framework.h)保持一致。
"""

# ===== Fuzz命令类型 (必须与C端定义匹配) =====
FUZZ_CMD_NONE = 0                    # 无命令
FUZZ_CMD_MUTATE_ARG = 1              # 变异参数
FUZZ_CMD_REPLACE_BUFFER = 2          # 替换缓冲区
FUZZ_CMD_MUTATE_FLAGS = 3            # 变异标志
FUZZ_CMD_BOUNDARY_VALUE = 4          # 边界值
# Auxiliary data mutation commands
FUZZ_CMD_MUTATE_AUX_BUFFER = 5       # Mutate aux_data buffer
FUZZ_CMD_FLIP_BITS = 6               # 位翻转
FUZZ_CMD_TRUNCATE = 7                # 截断
FUZZ_CMD_EXTEND = 8                  # 扩展
FUZZ_CMD_INTERESTING_VALUES = 9      # 特殊值
FUZZ_CMD_LIGHT_MUTATION = 10         # 轻量变异
# Precise memory overwrite command
FUZZ_CMD_OVERWRITE_AT_OFFSET = 11    # Overwrite at specific offset

# ===== 共享内存常量 (必须与rr_constants.h匹配) =====
FUZZ_MAGIC = 0x46555A5A             # "FUZZ" - 共享内存魔数
FUZZ_MAX_INSTRUCTIONS = 32          # 最大指令队列长度
FUZZ_MAX_VARIANTS = 10              # 最大变体数量 (对应FuzzSharedMemory.variants[10])
FUZZ_INSTRUCTION_DATA = 256         # 每条指令的数据负载大小
# Shared memory configuration - must match C-side rr_constants.h
# Total size: Header(36B) + instructions[32](8960B) + variants[10](89640B) = 98636B
# Aligned to 128KB for future-proofing and page alignment
FUZZ_SHM_SIZE = 128 * 1024          

# Coverage feedback constants
COVERAGE_MAP_SIZE = 64 * 1024       
FUZZ_FLAG_CAPTURE_SEED = (1 << 0)   # 请求捕获种子的标志

# Initialization phase filtering
# 这些系统调用在初始化阶段不应该被变异
# 以避免破坏内存布局
INIT_SYSCALLS = {
    'mmap', 'brk', 'set_tid_address', 'set_robust_list', 'arch_prctl',
    'munmap', 'mprotect', 'rt_sigprocmask', 'rt_sigaction'
}

# 初始化阶段阈值: 在前N个系统调用中跳过初始化系统调用
# 注意: 这是一个启发式值，可以由InitPhaseDetector自动检测
INIT_PHASE_THRESHOLD = 25  # 默认值 (如果自动检测失败)

# ===== Mutation Type Names Mapping =====
# 将 cmd 值映射到可读的变异类型名称（用于崩溃元数据）
MUTATION_TYPE_NAMES = {
    FUZZ_CMD_NONE: "NONE",
    FUZZ_CMD_MUTATE_ARG: "MUTATE_ARG",
    FUZZ_CMD_REPLACE_BUFFER: "REPLACE_BUFFER",
    FUZZ_CMD_MUTATE_FLAGS: "MUTATE_FLAGS",
    FUZZ_CMD_BOUNDARY_VALUE: "BOUNDARY_VALUE",
    FUZZ_CMD_MUTATE_AUX_BUFFER: "MUTATE_AUX_BUFFER",
    FUZZ_CMD_FLIP_BITS: "FLIP_BITS",
    FUZZ_CMD_TRUNCATE: "TRUNCATE",
    FUZZ_CMD_EXTEND: "EXTEND",
    FUZZ_CMD_INTERESTING_VALUES: "INTERESTING_VALUES",
    FUZZ_CMD_LIGHT_MUTATION: "LIGHT_MUTATION",
    FUZZ_CMD_OVERWRITE_AT_OFFSET: "OVERWRITE_AT_OFFSET",
}

def get_mutation_type_name(cmd):
    """从 cmd 值获取可读的变异类型名称"""
    return MUTATION_TYPE_NAMES.get(cmd, f"UNKNOWN_{cmd}")

# 应该始终变异的重要I/O系统调用 (永不跳过)
# 扩展列表以包含所有关键IO操作
IMPORTANT_SYSCALLS = {
    # 网络IO
    'send', 'sendto', 'sendmsg', 'sendmmsg',
    'recv', 'recvfrom', 'recvmsg', 'recvmmsg',
    # 文件IO - 读/写
    'read', 'write', 'pread', 'pwrite', 'pread64', 'pwrite64',
    'readv', 'writev', 'preadv', 'pwritev',
    # 文件操作
    'open', 'openat', 'creat',
    'close', 'lseek',
    # 文件元数据
    'stat', 'fstat', 'lstat', 'newfstatat',
    'fstatat', 'statx',
    # 随机数/熵 (对fuzzing至关重要)
    'getrandom', 'random',
    # 进程间通信
    'mq_send', 'mq_receive',
}

# Primary IO syscalls - 直接输入/输出，mutation的主要目标
PRIMARY_IO_SYSCALLS = {
    # 文件IO - 读/写
    'read', 'write', 'pread', 'pwrite', 'pread64', 'pwrite64',
    'readv', 'writev', 'preadv', 'pwritev',
    # 网络IO
    'recv', 'recvfrom', 'recvmsg', 'recvmmsg',
    'send', 'sendto', 'sendmsg', 'sendmmsg',
    # 随机数/熵 (关键输入源)
    'getrandom',
}

# Secondary IO syscalls - 文件操作，影响IO行为
SECONDARY_IO_SYSCALLS = {
    'open', 'openat', 'creat',
    'lseek',
}

# Forbidden mutation syscalls - 不应该被mutate的syscalls
FORBIDDEN_MUTATION_SYSCALLS = {
    # 内存管理 (mutation会破坏内存布局)
    'mmap', 'munmap', 'mprotect', 'brk',
    # 线程/信号 (mutation会破坏程序运行机制)
    'set_tid_address', 'set_robust_list', 
    'rt_sigaction', 'rt_sigprocmask',
    'clone', 'clone3',
    # 进程控制 (不应该mutate)
    'exit', 'exit_group',
    # 文件描述符管理 (容易导致误报)
    'close', 'dup', 'dup2', 'dup3',
}


# ===== Validation Scores (Phase A: Relax & Rank) =====
# Used by PathFinder to rank mutations instead of binary blocking
VALIDATION_SCORE_INVALID = 0      # Absolute failure (Resource-level, Phase B)
VALIDATION_SCORE_UNKNOWN = 5      # Unknown transition (not in syscall_tree)
VALIDATION_SCORE_KNOWN = 10       # Known valid transition (in syscall_tree)
VALIDATION_SCORE_STATIC = 8       # Present in static CFG but not dynamic trace (Phase C)

/**
 * RR-Fuzz核心框架 - 简化版
 * 基于design.md的核心设计理念
 */

#ifndef RR_FRAMEWORK_H
#define RR_FRAMEWORK_H

#include "qemu/osdep.h"
#include "user/abitypes.h"
#include "cpu.h"

/* Include syscall number definitions */
#include "syscall_nr.h"

/* ================= 基础数据结构 ================= */

/* Forward declaration for aux data */
struct rr_aux_data;

/**
 * 系统调用记录结构 - 核心数据
 */
typedef struct syscall_record {
    uint32_t index;                     // 在trace中的序号
    int syscall_nr;                     // 系统调用号
    abi_long args[8];                   // 参数值
    abi_long retval;                    // 返回值

    /* 参数数据存储 (传统方式 - 保持向后兼容) */
    uint8_t *arg_data[8];               // 参数指向的数据
    size_t arg_size[8];                 // 每个参数数据的大小

    /* EnvFuzz风格的辅助数据 (新增) */
    struct rr_aux_data *aux_data;       // 辅助数据链表
    bool has_aux_data;                  // 是否有辅助数据

    /* 元数据 */
    bool creates_fd;                    // 是否创建文件描述符
    bool uses_fd;                       // 是否使用文件描述符
    int32_t created_fd;                 // 创建的文件描述符值

    struct syscall_record *next;        // 链表连接
} syscall_record_t;

/**
 * Fuzz命令类型枚举
 */
typedef enum {
    FUZZ_CMD_NONE = 0,
    FUZZ_CMD_MUTATE_ARG,            // 变异参数
    FUZZ_CMD_REPLACE_BUFFER,        // 替换缓冲区
    FUZZ_CMD_MUTATE_FLAGS,          // 变异标志位
    FUZZ_CMD_BOUNDARY_VALUE,        // 边界值测试
    
    /* ━━━━ Phase 1: 新增针对 aux_data 的变异命令 ━━━━ */
    FUZZ_CMD_MUTATE_AUX_BUFFER = 5, // 变异 aux_data 缓冲区内容
    FUZZ_CMD_FLIP_BITS = 6,         // 位翻转（随机翻转某些位）
    FUZZ_CMD_TRUNCATE = 7,          // 截断数据（减少大小）
    FUZZ_CMD_EXTEND = 8,            // 扩展数据（增加大小）
    FUZZ_CMD_INTERESTING_VALUES = 9 // 特殊值注入（边界值、魔数等）
} fuzz_cmd_type_t;

/**
 * Fuzzing指令结构 (固定大小版本，适合共享内存)
 */
typedef struct {
    fuzz_cmd_type_t cmd;                // 命令类型
    uint32_t syscall_index;             // 目标系统调用索引
    uint32_t arg_index;                 // 目标参数索引
    uint32_t data_len;                  // 数据长度
    uint8_t data[256];                  // 固定大小数据数组
} FuzzInstruction;

/**
 * 共享内存协议结构
 */
typedef struct {
    uint32_t magic;                     // 魔数：0x46555A5A ("FUZZ")
    uint32_t instruction_count;         // 指令数量
    uint32_t flags;                     // 控制标志（预留）
    uint32_t reserved;                  // 保留字段
    FuzzInstruction instructions[32];   // 指令数组（最多32条）
} FuzzSharedMemory;

#define FUZZ_MAGIC 0x46555A5A
#define FUZZ_MAX_INSTRUCTIONS 32

/* ================= 运行模式定义 ================= */

typedef enum {
    RR_MODE_DISABLED = 0,
    RR_MODE_RECORD = 1,
    RR_MODE_REPLAY = 2,
    RR_MODE_FUZZING = 3
} rr_mode_t;

/* ================= Fork策略定义 ================= */

/**
 * Fork点检测策略
 * 控制在何时触发fork（用于fuzzing）
 */
typedef enum {
    RR_FORK_STRATEGY_STRICT = 0,      // 严格模式：只有ret>0的I/O操作
    RR_FORK_STRATEGY_RELAXED = 1,     // 宽松模式：允许ENOENT/EACCES等探测性错误
    RR_FORK_STRATEGY_AGGRESSIVE = 2,  // 激进模式：任何I/O类syscall都fork
    RR_FORK_STRATEGY_FALLBACK = 3     // Fallback模式：N个syscall后强制fork
} rr_fork_strategy_t;

/* ================= 统一配置系统 ================= */

/**
 * RR-Fuzz配置结构
 * 仅包含实际使用的配置项
 */
typedef struct {
    /* 核心配置 */
    bool enabled;                       // 是否启用RR-Fuzz
    rr_mode_t mode;                     // 运行模式

    /* 文件路径配置 */
    char *trace_file;                   // trace文件路径
    char *shared_memory_name;           // 共享内存名称
    char *cmd_pipe_path;                // 命令管道路径
    char *status_pipe_path;             // 状态管道路径
    char *config_file;                  // 配置文件路径

    /* Fork Server配置 */
    bool fork_server_enabled;           // 是否启用Fork Server
    char *fork_syscall_name;            // Fork点系统调用名称（如"openat", "read"）
    rr_fork_strategy_t fork_strategy;   // Fork点检测策略
    int fork_fallback_threshold;        // Fallback策略：多少个syscall后强制fork（默认20）
    char *fork_syscall_pattern;         // Fork点匹配模式（如"*/input.txt"）
    
    /* @deprecated 废弃字段 - 仅保留向后兼容 */
    uint32_t fork_point;                // Fork点位置（已废弃，请使用fork_strategy自动检测）

    /* IPC配置 */
    size_t shared_memory_size;          // 共享内存大小
    int ipc_timeout;                    // IPC超时(毫秒)
    
    /* 高级配置 */
    bool use_legacy_capture;            // 是否使用传统捕获方式（默认false，仅用aux_data）
} rr_config_t;

extern rr_config_t g_rr_config;

/**
 * 框架全局状态
 */
typedef struct {
    rr_mode_t mode;
    bool enabled;

    /* Record/Replay状态 */
    syscall_record_t *trace_head;       // 轨迹头
    syscall_record_t *trace_tail;       // 轨迹尾
    uint32_t trace_length;              // 轨迹长度
    uint32_t replay_index;              // 重放索引

    /* FD映射表 */
    GHashTable *fd_map;                 // record_fd -> replay_fd映射
    GHashTable *addr_map;               // 地址映射(recorded_addr -> actual_addr)

    /* IPC通信 */
    int cmd_pipe_fd;                    // 命令管道
    int status_pipe_fd;                 // 状态管道
    void *shared_memory;                // 共享内存

    /* Fork Server */
    bool fork_server_active;            // Fork Server是否活跃
    pid_t child_pid;                    // 子进程PID

    /* 统计信息 */
    uint64_t total_syscalls;            // 总系统调用数
} rr_framework_t;

/* ================= 全局变量 ================= */

extern rr_framework_t *g_rr_framework;

/* ================= 核心函数 ================= */

/* 配置管理函数 */
int rr_config_init(void);
void rr_config_cleanup(void);
void rr_config_print(void);
const char *rr_config_get_mode_name(rr_mode_t mode);

/* 地址映射管理函数 */
void rr_add_addr_mapping(target_ulong recorded_addr, target_ulong actual_addr);
target_ulong rr_get_mapped_addr(target_ulong recorded_addr);
void rr_handle_mmap_post(target_ulong recorded_addr, target_ulong actual_addr);

/* 全局变量 */
extern target_ulong g_pending_mmap_recorded_addr;

/**
 * 初始化RR框架
 */
int rr_framework_init(void);

/**
 * 清理RR框架
 */
void rr_framework_cleanup(void);

/**
 * 检查框架是否启用
 */
static inline bool rr_framework_enabled(void) {
    return g_rr_framework && g_rr_framework->enabled;
}

/**
 * 核心系统调用处理函数
 * 这是被do_syscall调用的核心函数
 */
abi_long rr_do_syscall(CPUArchState *env, int num,
                       abi_long *arg1, abi_long *arg2, abi_long *arg3, abi_long *arg4,
                       abi_long *arg5, abi_long *arg6, abi_long *arg7, abi_long *arg8);

/**
 * 系统调用执行后的Hook函数
 * 用于记录模式
 */
void rr_syscall_post_hook(CPUArchState *env, int num, abi_long ret,
                          abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8);

/* ================= 模块函数声明 ================= */

/* Record模块 */
int rr_record_syscall(CPUArchState *env, int num, const abi_long *args, abi_long ret);
int rr_start_recording(const char *trace_file);
void rr_stop_recording(void);

/* Replay模块 - Hybrid 模式（传统二进制 trace） */
abi_long rr_replay_syscall(CPUArchState *env, int num, abi_long *args);
int rr_start_replay(const char *trace_file);
void rr_stop_replay(void);

/* Replay状态标记 - 用于协调 replay 和 post_hook */
extern __thread bool g_syscall_already_consumed;

/* Replay模块 - Pure 模式（EnvFuzz 风格） */
/* 声明已移至 rr_replay_pure.h */

/* Fork Server模块 */
int rr_start_fork_server(const char *syscall_name, const char *pattern);
void rr_stop_fork_server(void);
bool rr_check_fork_point(CPUArchState *env, int syscall_nr, const char *syscall_name, const abi_long *args);
int rr_fork_server_loop(void);
void rr_reset_fork_point(void);

/* IPC模块 */
int rr_ipc_init(void);
void rr_ipc_cleanup(void);
int rr_ipc_send_status(int status);
int rr_ipc_receive_command(void);

/* Fuzz Engine模块 */
int rr_fuzz_apply_instructions(const FuzzInstruction *instructions, size_t count);
void rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr);
int rr_fuzz_load_from_shared_memory(void *shm_ptr);
void rr_fuzz_get_stats(uint64_t *total, uint64_t *arg_mut, uint64_t *buf_mut, uint64_t *boundary);
void rr_fuzz_print_stats(void);
FuzzInstruction *rr_fuzz_generate_mutations(uint32_t target_syscall, int target_arg,
                                          const uint8_t *seed_data, size_t seed_len,
                                          size_t *out_count);
void rr_fuzz_cleanup(void);

/* ━━━━ Phase 1: Pure Replay + Fuzzing 集成 ━━━━ */
/**
 * 变异 aux_data 中的数据
 * 
 * 此函数用于在 Pure Replay 路径中对 aux_data 进行变异
 * 支持多种变异策略：缓冲区替换、位翻转、截断、扩展、特殊值注入
 * 
 * @param env CPU 环境
 * @param record 系统调用记录（包含 aux_data）
 * @param args 系统调用参数
 * @param syscall_nr 系统调用号
 */
void rr_fuzz_mutate_aux_data(CPUArchState *env, syscall_record_t *record,
                              abi_long *args, int syscall_nr);

/* Strace Replay模块 */
abi_long rr_replay_syscall_strace_optimized(CPUArchState *env, int num, abi_long *args);
void rr_strace_set_mode_optimized(bool strict_mode, bool skip_unmatched, int max_lookahead);
bool rr_strace_replay_enabled_optimized(void);
void rr_strace_get_replay_stats_optimized(uint64_t *total, uint64_t *matched,
                                         uint64_t *failed, uint64_t *skipped);

/* 
 * Snapshot模块 
 * 
 * ⚠️ 注意：大部分API为预留接口，当前仅为stub实现
 * 实际使用的API: rr_snapshot_auto_manage(), rr_snapshot_cleanup()
 * 
 * TODO: 实现完整的快照功能（保存/恢复CPU状态、内存状态等）
 */
int rr_snapshot_save(uint32_t syscall_index);              /* @stub 未实现 */
int rr_snapshot_restore(uint32_t syscall_index);           /* @stub 未实现 */
uint32_t rr_snapshot_get_latest(void);                     /* @stub 部分实现 */
int rr_snapshot_list(uint32_t *snapshots, size_t max_count); /* @unimplemented 未定义 */
bool rr_snapshot_should_save(int syscall_nr, uint32_t syscall_index); /* @unimplemented 未定义 */
void rr_snapshot_auto_manage(int syscall_nr, uint32_t syscall_index); /* ✓ 已实现（空操作） */
void rr_snapshot_cleanup(void);                            /* ✓ 已实现 */

/* 工具函数 */
uint8_t *rr_capture_string(CPUArchState *env, target_ulong addr, size_t *len);
uint8_t *rr_capture_buffer(CPUArchState *env, target_ulong addr, size_t size);

/* ================= 分级调试系统 ================= */

/* 调试级别定义 */
typedef enum {
    RR_DEBUG_OFF = 0,        // 关闭所有调试
    RR_DEBUG_ERROR = 1,      // 仅错误信息
    RR_DEBUG_WARN = 2,       // 错误和警告
    RR_DEBUG_INFO = 3,       // 错误、警告和基本信息
    RR_DEBUG_VERBOSE = 4,    // 详细调试信息
    RR_DEBUG_TRACE = 5       // 最详细的追踪信息
} rr_debug_level_t;

/* 调试配置结构 */
typedef struct {
    rr_debug_level_t level;     // 全局调试级别
    FILE *log_file;             // 日志输出文件
} rr_debug_config_t;

extern rr_debug_config_t g_rr_debug;

/* 调试函数声明 */
void rr_debug_init(void);
void rr_debug_set_level(rr_debug_level_t level);
void rr_debug_set_output(FILE *file);
void rr_debug_cleanup(void);
const char *rr_debug_level_name(rr_debug_level_t level);

/* 分级调试宏 */
#ifdef RR_DEBUG

#define RR_DEBUG_CHECK(debug_level) (g_rr_debug.level >= (debug_level))

#define RR_LOG_LEVEL(level, fmt, ...) \
    do { \
        if (RR_DEBUG_CHECK(level)) { \
            fprintf(g_rr_debug.log_file ? g_rr_debug.log_file : stderr, \
                   "[RR-%s] %s:%d " fmt "\n", \
                   rr_debug_level_name(level), __func__, __LINE__, ##__VA_ARGS__); \
            if (g_rr_debug.log_file) fflush(g_rr_debug.log_file); \
        } \
    } while(0)

#define RR_ERROR(fmt, ...)   RR_LOG_LEVEL(RR_DEBUG_ERROR, fmt, ##__VA_ARGS__)
#define RR_WARN(fmt, ...)    RR_LOG_LEVEL(RR_DEBUG_WARN, fmt, ##__VA_ARGS__)
#define RR_INFO(fmt, ...)    RR_LOG_LEVEL(RR_DEBUG_INFO, fmt, ##__VA_ARGS__)
#define RR_VERBOSE(fmt, ...) RR_LOG_LEVEL(RR_DEBUG_VERBOSE, fmt, ##__VA_ARGS__)
#define RR_TRACE(fmt, ...)   RR_LOG_LEVEL(RR_DEBUG_TRACE, fmt, ##__VA_ARGS__)

/* 条件调试宏 */
/* 简化的trace宏 - 全部基于RR_DEBUG_LEVEL */
#define RR_SYSCALL_TRACE(fmt, ...) RR_VERBOSE("[SYSCALL] " fmt, ##__VA_ARGS__)
#define RR_FD_TRACE(fmt, ...) RR_VERBOSE("[FD] " fmt, ##__VA_ARGS__)
#define RR_MEM_TRACE(fmt, ...) RR_TRACE("[MEM] " fmt, ##__VA_ARGS__)
#define RR_IPC_TRACE(fmt, ...) RR_VERBOSE("[IPC] " fmt, ##__VA_ARGS__)
#define RR_PERF_TRACE(fmt, ...) RR_VERBOSE("[PERF] " fmt, ##__VA_ARGS__)

/* 保持向后兼容 */
#define RR_LOG(fmt, ...) RR_INFO(fmt, ##__VA_ARGS__)

#else /* !RR_DEBUG */

#define RR_ERROR(fmt, ...)   do {} while(0)
#define RR_WARN(fmt, ...)    do {} while(0)
#define RR_INFO(fmt, ...)    do {} while(0)
#define RR_VERBOSE(fmt, ...) do {} while(0)
#define RR_TRACE(fmt, ...)   do {} while(0)
#define RR_SYSCALL_TRACE(fmt, ...) do {} while(0)
#define RR_FD_TRACE(fmt, ...) do {} while(0)
#define RR_MEM_TRACE(fmt, ...) do {} while(0)
#define RR_IPC_TRACE(fmt, ...) do {} while(0)
#define RR_PERF_TRACE(fmt, ...) do {} while(0)
#define RR_LOG(fmt, ...) do {} while(0)

#endif /* RR_DEBUG */

/* ========== EnvFuzz 风格：系统调用过滤 ========== */

/**
 * 判断系统调用是否应该被跳过（不记录/不重放，直接执行）
 * 
 * EnvFuzz 核心思想：只记录/重放需要确定性的系统调用
 * 对于内存管理、进程管理等系统调用，让它们自然执行
 */
static inline bool rr_should_skip_syscall(int syscall_nr)
{
    switch (syscall_nr) {
        /* 内存管理系统调用 - 应该实时执行 */
        case TARGET_NR_brk:
#ifdef TARGET_NR_mmap
        case TARGET_NR_mmap:
#endif
#ifdef TARGET_NR_mmap2
        case TARGET_NR_mmap2:
#endif
        case TARGET_NR_munmap:
        case TARGET_NR_mremap:
        case TARGET_NR_mprotect:
        case TARGET_NR_madvise:
            
        /* 架构特定的系统调用 */
#ifdef TARGET_NR_arch_prctl
        case TARGET_NR_arch_prctl:
#endif
            
        /* 线程/进程管理 - 实时执行（但不跳过record/replay getpid等） */
        case TARGET_NR_set_robust_list:
        case TARGET_NR_rseq:
        case TARGET_NR_clone:
#ifdef TARGET_NR_fork
        case TARGET_NR_fork:
#endif
#ifdef TARGET_NR_vfork
        case TARGET_NR_vfork:
#endif
#ifdef TARGET_NR_tgkill
        case TARGET_NR_tgkill:
#endif
            return true;
            
        default:
            return false;
    }
}

/**
 * 判断系统调用是否是输出类系统调用
 * 
 * 输出类系统调用必须真实执行以维持程序的I/O状态
 * 在Pure Replay模式下，这些系统调用不能被"重放"
 */
static inline bool rr_is_output_syscall(int syscall_nr)
{
    switch (syscall_nr) {
        case TARGET_NR_write:
#ifdef TARGET_NR_writev
        case TARGET_NR_writev:
#endif
#ifdef TARGET_NR_pwrite64
        case TARGET_NR_pwrite64:
#endif
#ifdef TARGET_NR_send
        case TARGET_NR_send:
#endif
#ifdef TARGET_NR_sendto
        case TARGET_NR_sendto:
#endif
#ifdef TARGET_NR_sendmsg
        case TARGET_NR_sendmsg:
#endif
            return true;
            
        default:
            return false;
    }
}

/* ========== 动态跟踪API（用于实时树可视化） ========== */
#define RR_ENABLE_DYNAMIC_TRACE 1

#ifdef RR_ENABLE_DYNAMIC_TRACE
#include "rr_dynamic_trace.h"
#endif

#endif /* RR_FRAMEWORK_H */
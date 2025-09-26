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

/**
 * 系统调用记录结构 - 核心数据
 */
typedef struct syscall_record {
    uint32_t index;                     // 在trace中的序号
    int syscall_nr;                     // 系统调用号
    abi_long args[8];                   // 参数值
    abi_long retval;                    // 返回值

    /* 参数数据存储 */
    uint8_t *arg_data[8];               // 参数指向的数据
    size_t arg_size[8];                 // 每个参数数据的大小

    /* 元数据 */
    bool creates_fd;                    // 是否创建文件描述符
    bool uses_fd;                       // 是否使用文件描述符
    int32_t created_fd;                 // 创建的文件描述符值

    struct syscall_record *next;        // 链表连接
} syscall_record_t;

/**
 * Fuzzing指令结构
 */
typedef struct {
    enum {
        FUZZ_CMD_NONE = 0,
        FUZZ_CMD_MUTATE_ARG,            // 变异参数
        FUZZ_CMD_REPLACE_BUFFER         // 替换缓冲区
    } cmd;

    int syscall_index;                  // 目标系统调用索引
    int arg_index;                      // 目标参数索引
    size_t data_len;                    // 新数据的长度
    uint8_t data[];                     // 柔性数组，存放新数据
} FuzzInstruction;

/* ================= 运行模式定义 ================= */

typedef enum {
    RR_MODE_DISABLED = 0,
    RR_MODE_RECORD = 1,
    RR_MODE_REPLAY = 2,
    RR_MODE_FUZZING = 3
} rr_mode_t;

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
    uint32_t fork_point;                // Fork点位置

    /* IPC配置 */
    size_t shared_memory_size;          // 共享内存大小
    int ipc_timeout;                    // IPC超时(毫秒)
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

    /* IPC通信 */
    int cmd_pipe_fd;                    // 命令管道
    int status_pipe_fd;                 // 状态管道
    void *shared_memory;                // 共享内存

    /* Fork Server */
    bool fork_server_active;            // Fork Server是否活跃
    pid_t child_pid;                    // 子进程PID

    /* 统计信息 */
    uint64_t total_syscalls;            // 总系统调用数
    uint64_t total_executions;          // 总执行数
} rr_framework_t;

/* ================= 全局变量 ================= */

extern rr_framework_t *g_rr_framework;

/* ================= 核心函数 ================= */

/* 配置管理函数 */
int rr_config_init(void);
void rr_config_cleanup(void);
void rr_config_print(void);
const char *rr_config_get_mode_name(rr_mode_t mode);

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
                       abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                       abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8);

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

/* Replay模块 */
abi_long rr_replay_syscall(CPUArchState *env, int num, abi_long *args);
int rr_start_replay(const char *trace_file);
void rr_stop_replay(void);

/* Fork Server模块 */
int rr_start_fork_server(uint32_t fork_point);
void rr_stop_fork_server(void);
bool rr_check_fork_point(void);
int rr_fork_server_loop(void);

/* IPC模块 */
int rr_ipc_init(void);
void rr_ipc_cleanup(void);
int rr_ipc_send_status(int status);
int rr_ipc_receive_command(void);

/* Fuzz Engine模块 */
int rr_fuzz_apply_instructions(const FuzzInstruction *instructions, size_t count);
void rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr);
FuzzInstruction *rr_fuzz_generate_mutations(uint32_t target_syscall, int target_arg,
                                          const uint8_t *seed_data, size_t seed_len,
                                          size_t *out_count);
void rr_fuzz_cleanup(void);

/* Snapshot模块 */
int rr_snapshot_save(uint32_t syscall_index);
int rr_snapshot_restore(uint32_t syscall_index);
uint32_t rr_snapshot_get_latest(void);
int rr_snapshot_list(uint32_t *snapshots, size_t max_count);
bool rr_snapshot_should_save(int syscall_nr, uint32_t syscall_index);
void rr_snapshot_auto_manage(int syscall_nr, uint32_t syscall_index);
void rr_snapshot_cleanup(void);

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
    bool syscall_trace;         // 系统调用追踪
    bool fd_tracking;           // 文件描述符追踪
    bool memory_ops;            // 内存操作追踪
    bool ipc_details;           // IPC通信详情
    bool performance_stats;     // 性能统计
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
#define RR_SYSCALL_TRACE(fmt, ...) \
    do { \
        if (g_rr_debug.syscall_trace) { \
            RR_VERBOSE("[SYSCALL] " fmt, ##__VA_ARGS__); \
        } \
    } while(0)

#define RR_FD_TRACE(fmt, ...) \
    do { \
        if (g_rr_debug.fd_tracking) { \
            RR_VERBOSE("[FD] " fmt, ##__VA_ARGS__); \
        } \
    } while(0)

#define RR_MEM_TRACE(fmt, ...) \
    do { \
        if (g_rr_debug.memory_ops) { \
            RR_TRACE("[MEM] " fmt, ##__VA_ARGS__); \
        } \
    } while(0)

#define RR_IPC_TRACE(fmt, ...) \
    do { \
        if (g_rr_debug.ipc_details) { \
            RR_VERBOSE("[IPC] " fmt, ##__VA_ARGS__); \
        } \
    } while(0)

#define RR_PERF_TRACE(fmt, ...) \
    do { \
        if (g_rr_debug.performance_stats) { \
            RR_VERBOSE("[PERF] " fmt, ##__VA_ARGS__); \
        } \
    } while(0)

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

#endif /* RR_FRAMEWORK_H */
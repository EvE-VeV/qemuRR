/**
 * 优化后的 RR-Fuzz Strace重放模块
 * 使用模块化设计和优化的数据结构
 */

#include "rr_framework.h"
#include "rr_syscallparser.h"
#include "rr_replay_strace.h"
#include "rr_syscall_dispatch.h"
#include "rr_mapping_manager.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>

/* ==================== 全局状态管理 ==================== */

/* Strace解析器实例 */
static rr_strace_parser_t *g_strace_parser = NULL;

/* 重放控制状态 - 简化版本 */
typedef struct {
    bool enabled;
    bool strict_mode;
    bool skip_unmatched;
    int max_lookahead;
    
    /* 统计信息 */
    uint64_t total_syscalls;
    uint64_t matched_syscalls;
    uint64_t skipped_syscalls;
    uint64_t error_syscalls;
    uint64_t fallback_syscalls;
    
    /* 状态信息 */
    char *trace_filename;
    size_t current_record_index;
    bool trace_exhausted;
    bool allow_fallback_execution;
} rr_strace_replay_state_t;

static rr_strace_replay_state_t g_strace_state = {0};
static char g_stats_filename[256] = {0};

/* 统计输出控制 */
#define STATS_PRINT_INTERVAL 10
static size_t g_last_stats_print = 0;

/* 当前正在处理的记录 */
static rr_strace_record_t *g_current_record = NULL;

/* 信号处理器标志 */
static volatile sig_atomic_t g_signal_received = 0;

/* ==================== 日志系统 ==================== */

typedef enum {
    STRACE_LOG_ERROR = 0,
    STRACE_LOG_WARN = 1,
    STRACE_LOG_INFO = 2,
    STRACE_LOG_VERBOSE = 3,
    STRACE_LOG_DEBUG = 4
} strace_log_level_t;

static strace_log_level_t g_strace_log_level = STRACE_LOG_INFO;

static void init_strace_log_level(void) {
    const char *level_str = getenv("RR_STRACE_LOG_LEVEL");
    if (!level_str) return;
    
    if (strcmp(level_str, "ERROR") == 0 || strcmp(level_str, "0") == 0) {
        g_strace_log_level = STRACE_LOG_ERROR;
    } else if (strcmp(level_str, "WARN") == 0 || strcmp(level_str, "1") == 0) {
        g_strace_log_level = STRACE_LOG_WARN;
    } else if (strcmp(level_str, "INFO") == 0 || strcmp(level_str, "2") == 0) {
        g_strace_log_level = STRACE_LOG_INFO;
    } else if (strcmp(level_str, "VERBOSE") == 0 || strcmp(level_str, "3") == 0) {
        g_strace_log_level = STRACE_LOG_VERBOSE;
    } else if (strcmp(level_str, "DEBUG") == 0 || strcmp(level_str, "4") == 0) {
        g_strace_log_level = STRACE_LOG_DEBUG;
    }
}

#define RR_ERROR(fmt, ...)   do { if (g_strace_log_level >= STRACE_LOG_ERROR) fprintf(stderr, "[STRACE-ERROR] " fmt "\n", ##__VA_ARGS__); } while(0)
#define RR_WARN(fmt, ...)    do { if (g_strace_log_level >= STRACE_LOG_WARN) fprintf(stderr, "[STRACE-WARN] " fmt "\n", ##__VA_ARGS__); } while(0)
#define RR_INFO(fmt, ...)    do { if (g_strace_log_level >= STRACE_LOG_INFO) fprintf(stderr, "[STRACE-INFO] " fmt "\n", ##__VA_ARGS__); } while(0)
#define RR_VERBOSE(fmt, ...) do { if (g_strace_log_level >= STRACE_LOG_VERBOSE) fprintf(stderr, "[STRACE-VERBOSE] " fmt "\n", ##__VA_ARGS__); } while(0)
#define RR_DEBUG(fmt, ...)   do { if (g_strace_log_level >= STRACE_LOG_DEBUG) fprintf(stderr, "[STRACE-DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)

/* ==================== 统计和信号处理 ==================== */

static void rr_strace_signal_handler(int sig);

void rr_strace_save_stats_to_file(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(fp, "=== OPTIMIZED STRACE REPLAY STATISTICS ===\n");
    fprintf(fp, "Generated: %s\n", timestamp);
    fprintf(fp, "Trace file: %s\n", g_strace_state.trace_filename ? g_strace_state.trace_filename : "unknown");
    fprintf(fp, "\n");
    
    fprintf(fp, "Total syscalls: %zu\n", g_strace_state.total_syscalls);
    fprintf(fp, "Successfully matched: %zu\n", g_strace_state.matched_syscalls);
    fprintf(fp, "Skipped: %zu\n", g_strace_state.skipped_syscalls);
    fprintf(fp, "Errors: %zu\n", g_strace_state.error_syscalls);
    fprintf(fp, "Fallback executions: %zu\n", g_strace_state.fallback_syscalls);
    
    if (g_strace_state.total_syscalls > 0) {
        double match_rate = (100.0 * g_strace_state.matched_syscalls / g_strace_state.total_syscalls);
        fprintf(fp, "Match rate: %.1f%%\n", match_rate);
        fprintf(fp, "Status: %s\n", g_strace_state.trace_exhausted ? "EXHAUSTED" : "ACTIVE");
    }
    
    // 添加映射管理器统计
    rr_mapping_stats_t mapping_stats;
    rr_mapping_get_stats(&mapping_stats);
    fprintf(fp, "\nMapping Statistics:\n");
    fprintf(fp, "FD hit rate: %.1f%%\n", 
           mapping_stats.fd_lookups > 0 ? 
           (100.0 * mapping_stats.fd_hits / mapping_stats.fd_lookups) : 0.0);
    fprintf(fp, "Addr hit rate: %.1f%%\n", 
           mapping_stats.addr_lookups > 0 ? 
           (100.0 * mapping_stats.addr_hits / mapping_stats.addr_lookups) : 0.0);
    
    fprintf(fp, "=== END ===\n");
    fclose(fp);
}

void rr_strace_replay_print_stats(void) {
    if (!g_strace_state.enabled) return;
    
    RR_INFO("=== OPTIMIZED STRACE REPLAY STATISTICS ===");
    RR_INFO("📊 Basic Statistics:");
    RR_INFO("  Total syscalls processed: %zu", g_strace_state.total_syscalls);
    RR_INFO("  Successfully matched: %zu (%.1f%%)", 
            g_strace_state.matched_syscalls,
            g_strace_state.total_syscalls > 0 ? 
            (100.0 * g_strace_state.matched_syscalls / g_strace_state.total_syscalls) : 0.0);
    RR_INFO("  Skipped syscalls: %zu", g_strace_state.skipped_syscalls);
    RR_INFO("  Error syscalls: %zu", g_strace_state.error_syscalls);
    RR_INFO("  Fallback executions: %zu", g_strace_state.fallback_syscalls);
    
    // 显示映射统计
    rr_mapping_print_stats();
    
    RR_INFO("=== END STATISTICS ===");
    fflush(stdout);
    fflush(stderr);
}

static void rr_strace_signal_handler(int sig) {
    g_signal_received = 1;
    RR_INFO("🚨 Signal %d received, printing final statistics...", sig);
    
    char stats_filename[256];
    snprintf(stats_filename, sizeof(stats_filename), "/tmp/rr_strace_stats_signal_%d.txt", getpid());
    rr_strace_save_stats_to_file(stats_filename);
    
    rr_strace_replay_print_stats();
    
    signal(sig, SIG_DFL);
    raise(sig);
}

static void rr_strace_check_periodic_stats(void) {
    if (g_strace_state.total_syscalls > 0 && 
        (g_strace_state.total_syscalls - g_last_stats_print) >= STATS_PRINT_INTERVAL) {
        
        if (g_stats_filename[0] != '\0') {
            rr_strace_save_stats_to_file(g_stats_filename);
        }
        
        g_last_stats_print = g_strace_state.total_syscalls;
    }
}

/* ==================== 优化的匹配算法 ==================== */

static rr_strace_record_t *optimized_find_matching_record(int syscall_nr, abi_long *args) {
    const char *syscall_name = rr_get_syscall_name_fast(syscall_nr);
    if (!syscall_name) {
        RR_WARN("Unknown syscall number: %d", syscall_nr);
        return NULL;
    }
    
    syscall_importance_t importance = rr_get_syscall_importance(syscall_nr);
    
    // 根据重要性调整搜索策略
    int max_skip;
    switch (importance) {
        case SYSCALL_IMPORTANCE_CRITICAL:
            max_skip = 50;
            break;
        case SYSCALL_IMPORTANCE_IMPORTANT:
            max_skip = 30;
            break;
        case SYSCALL_IMPORTANCE_OPTIONAL:
            max_skip = 15;
            break;
        case SYSCALL_IMPORTANCE_ENVIRONMENT:
            max_skip = 5;
            break;
        default:
            max_skip = 10;
            break;
    }
    
    RR_VERBOSE("Optimized matching for %s (importance=%d, max_skip=%d)", 
               syscall_name, importance, max_skip);
    
    int skip_count = 0;
    rr_strace_record_t *record = NULL;
    
    while (skip_count <= max_skip) {
        record = rr_strace_parser_get_next(g_strace_parser);
        if (!record) {
            g_strace_state.trace_exhausted = true;
            
            if (importance == SYSCALL_IMPORTANCE_CRITICAL) {
                RR_ERROR("Critical syscall %s cannot find match, trace exhausted", syscall_name);
            } else {
                RR_INFO("Syscall %s - trace exhausted, fallback execution", syscall_name);
            }
            
            return NULL;
        }
        
        g_strace_state.current_record_index++;
        
        // 精确匹配
        if (strcmp(record->syscall_name, syscall_name) == 0) {
            if (skip_count > 0) {
                RR_INFO("Optimized match successful after skipping %d records: %s", 
                        skip_count, record->syscall_name);
            } else {
                RR_VERBOSE("Direct match successful: %s", record->syscall_name);
            }
            return record;
        }
        
        skip_count++;
    }
    
    RR_ERROR("Optimized match failed after %d attempts for %s", max_skip + 1, syscall_name);
    return NULL;
}

/* ==================== 确定性系统调用处理 ==================== */

/**
 * 确定性uname处理 - 解决uname系统调用不稳定导致的执行路径分歧
 * 
 * 关键修复: 不要返回-1让QEMU执行，因为QEMU执行可能失败并触发fallback，
 * 导致插入额外的系统调用（openat /proc/sys/kernel/osrelease等），
 * 从而破坏trace的对齐。应该直接返回成功(0)。
 */
static abi_long rr_handle_deterministic_uname(CPUArchState *env, abi_long buf_addr) {
    g_strace_state.matched_syscalls++;
    RR_INFO("Deterministic uname: directly returning success to avoid fallback syscalls");
    
    // 关键: 直接返回0表示成功，不让QEMU执行uname
    // 这样可以避免uname失败后触发fallback（读取/proc/sys/kernel/osrelease）
    // 从而避免插入额外的系统调用，保持trace对齐
    return 0;
}

/* ==================== 主要接口函数 ==================== */

int rr_strace_replay_init(const char *trace_file) {
    init_strace_log_level();
    
    if (!trace_file) {
        RR_ERROR("trace_file is NULL");
        return -1;
    }
    
    RR_INFO("Initializing optimized strace replay with trace file: %s", trace_file);
    
    // 初始化状态
    memset(&g_strace_state, 0, sizeof(g_strace_state));
    g_strace_state.trace_filename = strdup(trace_file);
    if (!g_strace_state.trace_filename) {
        RR_ERROR("Failed to allocate memory for trace filename");
        return -1;
    }
    
    g_strace_state.strict_mode = false;
    g_strace_state.skip_unmatched = true;
    g_strace_state.max_lookahead = 5;
    g_strace_state.trace_exhausted = false;
    g_strace_state.allow_fallback_execution = true;
    
    // 初始化系统调用分发器
    if (rr_syscall_dispatch_init() < 0) {
        RR_ERROR("Failed to initialize syscall dispatcher");
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // 初始化映射管理器
    if (rr_mapping_manager_init(256, 128) < 0) {
        RR_ERROR("Failed to initialize mapping manager");
        rr_syscall_dispatch_cleanup();
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // 初始化strace解析器
    g_strace_parser = rr_strace_parser_init(trace_file);
    if (!g_strace_parser) {
        RR_ERROR("Failed to initialize strace parser");
        rr_mapping_manager_cleanup();
        rr_syscall_dispatch_cleanup();
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // 加载strace文件
    if (rr_strace_parser_load(g_strace_parser) < 0) {
        RR_ERROR("Failed to load strace file");
        rr_strace_parser_cleanup(g_strace_parser);
        g_strace_parser = NULL;
        rr_mapping_manager_cleanup();
        rr_syscall_dispatch_cleanup();
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // 获取统计信息
    size_t total_records, current_index;
    rr_strace_get_stats(g_strace_parser, &total_records, &current_index);
    
    g_strace_state.enabled = true;
    
    // 注册信号处理器
    signal(SIGINT, rr_strace_signal_handler);
    signal(SIGTERM, rr_strace_signal_handler);
    signal(SIGQUIT, rr_strace_signal_handler);
    
    // 设置统计文件名
    snprintf(g_stats_filename, sizeof(g_stats_filename), "/tmp/rr_strace_optimized_stats_%d.txt", getpid());
    rr_strace_save_stats_to_file(g_stats_filename);
    
    RR_INFO("Optimized strace replay initialized successfully");
    RR_INFO("- Trace file: %s", trace_file);
    RR_INFO("- Total records: %zu", total_records);
    RR_INFO("- Stats file: %s", g_stats_filename);
    
    return 0;
}

void rr_strace_replay_cleanup(void) {
    if (!g_strace_state.enabled) return;
    
    // 保存最终统计信息
    if (g_stats_filename[0] != '\0') {
        rr_strace_save_stats_to_file(g_stats_filename);
    }
    
    // 清理资源
    if (g_strace_parser) {
        rr_strace_parser_cleanup(g_strace_parser);
        g_strace_parser = NULL;
    }
    
    rr_mapping_manager_cleanup();
    rr_syscall_dispatch_cleanup();
    
    if (g_strace_state.trace_filename) {
        free(g_strace_state.trace_filename);
        g_strace_state.trace_filename = NULL;
    }
    
    memset(&g_strace_state, 0, sizeof(g_strace_state));
    
    RR_INFO("Optimized strace replay cleanup completed");
}

abi_long rr_replay_syscall_strace_optimized(CPUArchState *env, int num, abi_long *args) {
    RR_DEBUG("Processing syscall %d", num);
    
    if (!g_strace_state.enabled) {
        RR_ERROR("Module not initialized");
        return -1;
    }
    
    g_strace_state.total_syscalls++;
    
    // 检查trace是否已耗尽
    if (g_strace_state.trace_exhausted) {
        g_strace_state.fallback_syscalls++;
        const char *syscall_name = rr_get_syscall_name_fast(num);
        RR_VERBOSE("Trace exhausted, fallback execution for %s (%zu total fallbacks)", 
                  syscall_name ? syscall_name : "unknown", g_strace_state.fallback_syscalls);
        return -1;
    }
    
    // 检查周期性统计
    rr_strace_check_periodic_stats();
    
    // 查找匹配的记录
    rr_strace_record_t *record = optimized_find_matching_record(num, args);
    
    // 特殊处理不稳定的系统调用
    if (!record && num == 63) { // TARGET_NR_uname
        // uname没找到匹配记录，使用确定性处理
        RR_INFO("uname match failed, using deterministic handling");
        return rr_handle_deterministic_uname(env, args[0]);
    }
    if (!record) {
        g_strace_state.error_syscalls++;
        const char *syscall_name = rr_get_syscall_name_fast(num);
        RR_WARN("No matching record found for %s (%d)", 
                syscall_name ? syscall_name : "unknown", num);
        
        if (g_strace_state.skip_unmatched) {
            return -1;
        } else {
            errno = ENOSYS;
            return -1;
        }
    }
    
    g_strace_state.matched_syscalls++;
    
    RR_VERBOSE("Found matching record: %s, ret=%ld", record->syscall_name, record->ret_value);
    
    // 特殊处理: uname系统调用需要在修改参数前填充buffer
    // 因为参数修改会改变buffer地址，导致写入错误的位置
    if (num == 63) { // TARGET_NR_uname
        RR_INFO("uname syscall: filling buffer BEFORE parameter modification");
        
        struct new_utsname {
            char sysname[65];
            char nodename[65];
            char release[65];
            char version[65];
            char machine[65];
            char domainname[65];
        };
        
        struct new_utsname uts;
        memset(&uts, 0, sizeof(uts));
        strcpy(uts.sysname, "Linux");
        strcpy(uts.nodename, "replay-node");
        strcpy(uts.release, "6.8.0");
        strcpy(uts.version, "#1 SMP PREEMPT_DYNAMIC");
        strcpy(uts.machine, "x86_64");
        strcpy(uts.domainname, "(none)");
        
        // 使用原始的args[0]地址写入
        if (args[0]) {
            int copy_result = copy_to_user(args[0], &uts, sizeof(uts));
            RR_INFO("uname: copy_to_user result=%d, original_addr=0x%lx", copy_result, args[0]);
            if (copy_result == 0) {
                RR_INFO("uname: successfully filled buffer, returning 0");
                return 0;  // 成功，直接返回
            }
        }
    }
    
    // 保存原始参数用于比较
    abi_long orig_args[8];
    for (int i = 0; i < 8; i++) {
        orig_args[i] = args[i];
    }
    
    // 使用优化的参数处理
    // 应用记录的参数和FD映射
    rr_apply_syscall_args_optimized(record, args);
    rr_apply_fd_mapping_optimized(num, args);
    
    // 输出参数修改信息
    bool args_modified = false;
    for (int i = 0; i < 8; i++) {
        if (orig_args[i] != args[i]) {
            args_modified = true;
            RR_DEBUG("PARAM_OPTIMIZED: %s arg[%d] %ld -> %ld", 
                    record->syscall_name, i, orig_args[i], args[i]);
        }
    }
    
    if (args_modified) {
        RR_DEBUG("PARAM_OPTIMIZED: %s parameter replacement completed", record->syscall_name);
    }
    
    // 保存当前记录供POST-HOOK使用
    g_current_record = record;
    
    RR_VERBOSE("Optimized hybrid mode: letting QEMU execute real syscall with replayed args");
    return -1;  // 让QEMU执行真实系统调用
}

void rr_strace_syscall_post_hook_optimized(CPUArchState *env, int num, abi_long ret, abi_long *args) {
    if (!g_strace_state.enabled || !g_current_record) {
        return;
    }
    
    const char *syscall_name = rr_get_syscall_name_fast(num);
    RR_DEBUG("Optimized post-hook for %s, ret=%ld", 
             syscall_name ? syscall_name : "unknown", ret);
    
    // 使用优化的POST处理
    rr_syscall_post_hook_optimized(num, g_current_record, ret, args);
    
    // 清理当前记录
    g_current_record = NULL;
}

/* ==================== 配置接口 ==================== */

void rr_strace_set_mode_optimized(bool strict_mode, bool skip_unmatched, int max_lookahead) {
    g_strace_state.strict_mode = strict_mode;
    g_strace_state.skip_unmatched = skip_unmatched;
    g_strace_state.max_lookahead = max_lookahead;
    
    RR_INFO("Optimized mode updated - strict:%s, skip:%s, lookahead:%d",
            strict_mode ? "YES" : "NO",
            skip_unmatched ? "YES" : "NO",
            max_lookahead);
}

bool rr_strace_replay_enabled_optimized(void) {
    return g_strace_state.enabled;
}

void rr_strace_get_replay_stats_optimized(uint64_t *total, uint64_t *matched, 
                                         uint64_t *skipped, uint64_t *errors) {
    if (total) *total = g_strace_state.total_syscalls;
    if (matched) *matched = g_strace_state.matched_syscalls;
    if (skipped) *skipped = g_strace_state.skipped_syscalls;
    if (errors) *errors = g_strace_state.error_syscalls;
}

/* ==================== 兼容性包装器函数 ==================== */
/* 这些函数提供与 rr_main.c 期望的函数名兼容性 */

bool rr_strace_replay_enabled(void) {
    return rr_strace_replay_enabled_optimized();
}

abi_long rr_replay_syscall_strace(CPUArchState *env, int num, abi_long *args) {
    return rr_replay_syscall_strace_optimized(env, num, args);
}

void rr_strace_syscall_post_hook(CPUArchState *env, int num, abi_long ret, abi_long *args) {
    rr_strace_syscall_post_hook_optimized(env, num, ret, args);
}

/**
 * 优化后的 RR-Fuzz Strace重放模块
 * 使用模块化设计和优化的数据结构
 */

#include "../core/rr_framework.h"
#include "../core/rr_constants.h"
#include "../utils/rr_syscallparser.h"
#include "rr_replay_strace.h"
#include "../utils/rr_syscall_dispatch.h"
#include "../utils/rr_mapping_manager.h"
#include "../utils/rr_dynamic_trace.h"  /* 动态跟踪API */
#include "qemu.h"
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

/* 全局系统调用索引（供fork server使用） */
uint32_t g_strace_current_index = 0;

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

/* 当前正在处理的记录 (strace专用，区别于binary replay的g_current_record) */
__attribute__((unused)) static rr_strace_record_t *g_current_strace_record = NULL;
static rr_strace_record_t *g_current_record_strace = NULL;  /* 供 post_hook 使用 */

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

/* 
 * Strace模块专用日志宏 - 避免与框架日志宏冲突
 * 使用 STRACE_ 前缀以区分
 */
#define STRACE_ERROR(fmt, ...)   do { if (g_strace_log_level >= STRACE_LOG_ERROR) fprintf(stderr, "[STRACE-ERROR] " fmt "\n", ##__VA_ARGS__); } while(0)
#define STRACE_WARN(fmt, ...)    do { if (g_strace_log_level >= STRACE_LOG_WARN) fprintf(stderr, "[STRACE-WARN] " fmt "\n", ##__VA_ARGS__); } while(0)
#define STRACE_INFO(fmt, ...)    do { if (g_strace_log_level >= STRACE_LOG_INFO) fprintf(stderr, "[STRACE-INFO] " fmt "\n", ##__VA_ARGS__); } while(0)
#define STRACE_VERBOSE(fmt, ...) do { if (g_strace_log_level >= STRACE_LOG_VERBOSE) fprintf(stderr, "[STRACE-VERBOSE] " fmt "\n", ##__VA_ARGS__); } while(0)
#define STRACE_DEBUG(fmt, ...)   do { if (g_strace_log_level >= STRACE_LOG_DEBUG) fprintf(stderr, "[STRACE-DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)

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
    
    STRACE_INFO("=== OPTIMIZED STRACE REPLAY STATISTICS ===");
    STRACE_INFO("📊 Basic Statistics:");
    STRACE_INFO("  Total syscalls processed: %zu", g_strace_state.total_syscalls);
    STRACE_INFO("  Successfully matched: %zu (%.1f%%)", 
            g_strace_state.matched_syscalls,
            g_strace_state.total_syscalls > 0 ? 
            (100.0 * g_strace_state.matched_syscalls / g_strace_state.total_syscalls) : 0.0);
    STRACE_INFO("  Skipped syscalls: %zu", g_strace_state.skipped_syscalls);
    STRACE_INFO("  Error syscalls: %zu", g_strace_state.error_syscalls);
    STRACE_INFO("  Fallback executions: %zu", g_strace_state.fallback_syscalls);
    
    // 显示映射统计
    rr_mapping_print_stats();
    
    STRACE_INFO("=== END STATISTICS ===");
    fflush(stdout);
    fflush(stderr);
}

static void rr_strace_signal_handler(int sig) {
    g_signal_received = 1;
    STRACE_INFO("🚨 Signal %d received, printing final statistics...", sig);
    
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
        STRACE_WARN("Unknown syscall number: %d", syscall_nr);
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
    
    STRACE_VERBOSE("Optimized matching for %s (importance=%d, max_skip=%d)", 
               syscall_name, importance, max_skip);
    
    int skip_count = 0;
    rr_strace_record_t *record = NULL;
    
    while (skip_count <= max_skip) {
        record = rr_strace_parser_get_next(g_strace_parser);
        if (!record) {
            g_strace_state.trace_exhausted = true;
            
            if (importance == SYSCALL_IMPORTANCE_CRITICAL) {
                STRACE_ERROR("Critical syscall %s cannot find match, trace exhausted", syscall_name);
            } else {
                STRACE_INFO("Syscall %s - trace exhausted, fallback execution", syscall_name);
            }
            
            return NULL;
        }
        
        /* 🔥 修复：索引递增移到匹配成功后 */
        
        // === 智能匹配算法 - 三级策略 ===
        
        // Level 0: syscall号必须匹配
        if (strcmp(record->syscall_name, syscall_name) != 0) {
            skip_count++;
            /* 不匹配：继续循环但不递增索引 */
            continue;
        }
        
        // Level 1: 探测性匹配 (PROBE)
        // 识别"探测性"syscall: 返回ENOENT的文件访问
        if ((syscall_nr == 257 || syscall_nr == 262 || syscall_nr == 21) &&  // openat/newfstatat/access
            record->ret_value == -2) {  // ENOENT
            
            STRACE_VERBOSE("✓ Probe match: %s returned ENOENT", syscall_name);
            if (skip_count > 0) {
                STRACE_INFO("Probe match successful after skipping %d records: %s", 
                        skip_count, syscall_name);
            }
            /* 🔥 匹配成功，递增索引 */
            g_strace_state.current_record_index++;
            return record;
        }
        
        // Level 2: 语义匹配 (SEMANTIC)
        
        // openat 成功的情况 - 只检查访问模式
        if (syscall_nr == 257 && record->ret_value >= 0) {
            // 只检查访问模式（flags的低2位）
            if (record->arg_count > 2 && args) {
                int record_mode = record->args[2].value & 0x3;  // O_ACCMODE
                int current_mode = args[2] & 0x3;
                
                if (record_mode == current_mode) {
                    STRACE_VERBOSE("✓ Semantic match: openat mode=%s", 
                               record_mode == 0 ? "RDONLY" : 
                               record_mode == 1 ? "WRONLY" : "RDWR");
                    if (skip_count > 0) {
                        STRACE_INFO("Semantic match successful after skipping %d records: %s", 
                                skip_count, syscall_name);
                    }
                    g_strace_state.current_record_index++;
                    return record;
                }
            }
        }
        
        // newfstatat - 只检查flags
        if (syscall_nr == 262) {
            if (record->arg_count > 3 && args) {
                if (args[3] == record->args[3].value) {  // flags相同
                    STRACE_VERBOSE("✓ Semantic match: newfstatat flags=0x%lx", args[3]);
                    if (skip_count > 0) {
                        STRACE_INFO("Semantic match successful after skipping %d records: %s", 
                                skip_count, syscall_name);
                    }
                    g_strace_state.current_record_index++;
                    return record;
                }
            }
        }
        
        // mmap - 检查prot和flags，忽略地址和长度
        if (syscall_nr == 9) {
            if (record->arg_count > 3 && args) {
                bool prot_match = (args[2] == record->args[2].value);  // prot
                bool flags_match = (args[3] == record->args[3].value); // flags
                
                if (prot_match && flags_match) {
                    STRACE_VERBOSE("✓ Semantic match: mmap prot=0x%lx flags=0x%lx", 
                               args[2], args[3]);
                    if (skip_count > 0) {
                        STRACE_INFO("Semantic match successful after skipping %d records: %s", 
                                skip_count, syscall_name);
                    }
                    g_strace_state.current_record_index++;
                    return record;
                }
            }
        }
        
        // Level 3: 精确匹配（兜底策略）
        // syscall号已经匹配，直接返回
        STRACE_VERBOSE("✓ Exact match: %s", syscall_name);
        if (skip_count > 0) {
            STRACE_INFO("Exact match successful after skipping %d records: %s", 
                    skip_count, syscall_name);
        }
        g_strace_state.current_record_index++;
        return record;
    }
    
    STRACE_ERROR("Optimized match failed after %d attempts for %s", max_skip + 1, syscall_name);
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
__attribute__((unused)) static abi_long rr_handle_deterministic_uname(CPUArchState *env, abi_long buf_addr) {
    g_strace_state.matched_syscalls++;
    STRACE_INFO("Deterministic uname: directly returning success to avoid fallback syscalls");
    
    // 关键: 直接返回0表示成功，不让QEMU执行uname
    // 这样可以避免uname失败后触发fallback（读取/proc/sys/kernel/osrelease）
    // 从而避免插入额外的系统调用，保持trace对齐
    return 0;
}

/* ==================== 主要接口函数 ==================== */

int rr_strace_replay_init(const char *trace_file) {
    init_strace_log_level();
    
    if (!trace_file) {
        STRACE_ERROR("trace_file is NULL");
        return -1;
    }
    
    STRACE_INFO("Initializing optimized strace replay with trace file: %s", trace_file);
    
    // 初始化状态
    memset(&g_strace_state, 0, sizeof(g_strace_state));
    g_strace_state.trace_filename = strdup(trace_file);
    if (!g_strace_state.trace_filename) {
        STRACE_ERROR("Failed to allocate memory for trace filename");
        return -1;
    }
    
    g_strace_state.strict_mode = false;
    g_strace_state.skip_unmatched = true;
    g_strace_state.max_lookahead = 5;
    g_strace_state.trace_exhausted = false;
    g_strace_state.allow_fallback_execution = true;
    
    // 初始化系统调用分发器
    if (rr_syscall_dispatch_init() < 0) {
        STRACE_ERROR("Failed to initialize syscall dispatcher");
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // 初始化映射管理器
    if (rr_mapping_manager_init(256, 128) < 0) {
        STRACE_ERROR("Failed to initialize mapping manager");
        rr_syscall_dispatch_cleanup();
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // 初始化strace解析器
    g_strace_parser = rr_strace_parser_init(trace_file);
    if (!g_strace_parser) {
        STRACE_ERROR("Failed to initialize strace parser");
        rr_mapping_manager_cleanup();
        rr_syscall_dispatch_cleanup();
        free(g_strace_state.trace_filename);
        return -1;
    }
    
    // 加载strace文件
    if (rr_strace_parser_load(g_strace_parser) < 0) {
        STRACE_ERROR("Failed to load strace file");
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
    
    STRACE_INFO("Optimized strace replay initialized successfully");
    STRACE_INFO("- Trace file: %s", trace_file);
    STRACE_INFO("- Total records: %zu", total_records);
    STRACE_INFO("- Stats file: %s", g_stats_filename);
    
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
    
    STRACE_INFO("Optimized strace replay cleanup completed");
}

abi_long rr_replay_syscall_strace_optimized(CPUArchState *env, int num, abi_long *args) {
    STRACE_DEBUG("Processing syscall %d", num);
    
    if (!g_strace_state.enabled) {
        STRACE_ERROR("Module not initialized");
        return -1;
    }
    
    g_strace_state.total_syscalls++;
    
    // 检查trace是否已耗尽
    if (g_strace_state.trace_exhausted) {
        g_strace_state.fallback_syscalls++;
        const char *syscall_name = rr_get_syscall_name_fast(num);
        STRACE_VERBOSE("Trace exhausted, fallback execution for %s (%zu total fallbacks)", 
                  syscall_name ? syscall_name : "unknown", g_strace_state.fallback_syscalls);
        
        /* 🔥 关键修复：如果是fuzzing模式的子进程，trace耗尽后应该退出 */
        if (g_rr_framework && 
            g_rr_framework->mode == RR_MODE_FUZZING && 
            g_rr_framework->child_pid == 0) {
            STRACE_INFO("🎯 Trace exhausted in child process (PID=%d), exiting normally", getpid());
            exit(0);  // 子进程正常退出，父进程的waitpid()会返回
        }
        
        return -1;
    }
    
    // 检查周期性统计
    rr_strace_check_periodic_stats();
    
    // 查找匹配的记录
    rr_strace_record_t *record = optimized_find_matching_record(num, args);
    
    /* 🔥 修复：uname 不使用固定字符串，改为真实执行或从 trace 读取 */
    if (!record && num == 63) { // TARGET_NR_uname
        STRACE_INFO("uname not found in trace, executing real uname for environment compatibility");
        g_strace_state.fallback_syscalls++;
        return -1; // 让 QEMU 执行真实 uname，适应环境
    }
    if (!record) {
        g_strace_state.error_syscalls++;
        const char *syscall_name = rr_get_syscall_name_fast(num);
        STRACE_WARN("No matching record found for %s (%d)", 
                syscall_name ? syscall_name : "unknown", num);
        
        /* 🔥 如果连续多个系统调用找不到匹配，可能trace已经偏移，子进程应该退出 */
        if (g_rr_framework && 
            g_rr_framework->mode == RR_MODE_FUZZING && 
            g_rr_framework->child_pid == 0 && 
            g_strace_state.error_syscalls > 5) {  // 容忍5次失败
            STRACE_WARN("🎯 Too many unmatched syscalls in child process (%zu errors), exiting", 
                   g_strace_state.error_syscalls);
            exit(1);  // 异常退出，父进程会检测到
        }
        
        if (g_strace_state.skip_unmatched) {
            return -1;
        } else {
            errno = ENOSYS;
            return -1;
        }
    }
    
    g_strace_state.matched_syscalls++;
    
    /* 更新全局索引 */
    g_strace_current_index = g_strace_state.current_record_index;
    
    STRACE_VERBOSE("Found matching record: %s, ret=%ld", record->syscall_name, record->ret_value);
    
    /* 动态跟踪：系统调用进入 */
    rr_dynamic_trace_syscall_enter(
        env, 
        num, 
        (uint64_t*)args, 
        g_strace_state.current_record_index,
        false  /* 尚未变异 */
    );
    
    /* 🔥 修复：uname 不使用固定字符串，从 trace 获取或返回 -1 让宿主执行 */
    
    // 保存原始参数用于比较
    abi_long orig_args[RR_MAX_SYSCALL_ARGS];
    for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
        orig_args[i] = args[i];
    }
    (void)orig_args;  /* 可能在调试关闭时未使用 */
    
    // 使用优化的参数处理
    // 步骤1: 应用记录的参数和FD映射（来自trace）
    rr_apply_syscall_args_optimized(record, args);
    rr_apply_fd_mapping_optimized(num, args);
    
    // 输出trace参数修改信息
    bool args_modified = false;
    for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
        if (orig_args[i] != args[i]) {
            args_modified = true;
            STRACE_DEBUG("TRACE_REPLAY: %s arg[%d] %ld -> %ld", 
                    record->syscall_name, i, orig_args[i], args[i]);
        }
    }
    
    if (args_modified) {
        STRACE_DEBUG("TRACE_REPLAY: %s parameter replacement from trace completed", record->syscall_name);
    }
    
    /* ===== 🔥 关键修复：Fuzz变异注入点 ===== */
    /* 
     * 步骤2: 在Fuzzing模式下，对已重放的参数进行变异
     * 
     * 执行顺序：
     * 1. 参数从trace恢复（上面完成）
     * 2. 应用Fuzz变异（这里）
     * 3. 执行真实系统调用（下面返回-1）
     * 
     * 注意：g_rr_framework可能为NULL（如果使用纯strace模式）
     */
    if (g_rr_framework && g_rr_framework->mode == RR_MODE_FUZZING) {
        // 使用strace的记录索引作为syscall_index
        uint32_t syscall_index = (uint32_t)g_strace_state.current_record_index;
        
        STRACE_VERBOSE("Applying fuzz mutations at syscall_index=%u (%s)", 
                   syscall_index, record->syscall_name);
        
        /* 🔥 修复：保存当前参数，应用变异后再检测 */
        abi_long pre_fuzz_args[RR_MAX_SYSCALL_ARGS];
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
            pre_fuzz_args[i] = args[i];
        }
        (void)pre_fuzz_args;  /* 可能在调试关闭时未使用 */
        
        // 调用Fuzz引擎应用变异
        rr_fuzz_mutate_syscall(env, syscall_index, args, num);
        
        // 检测参数是否被Fuzz变异
        bool fuzz_modified = false;
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
            if (pre_fuzz_args[i] != args[i]) {
                fuzz_modified = true;
                STRACE_VERBOSE("FUZZ_MUTATED: %s arg[%d] %ld -> %ld", 
                          record->syscall_name, i, pre_fuzz_args[i], args[i]);
            }
        }
        
        if (fuzz_modified) {
            STRACE_INFO("🎯 FUZZING: %s at index %u - parameters mutated", 
                   record->syscall_name, syscall_index);
        }
    }
    
    // 保存当前记录供POST-HOOK使用
    g_current_record_strace = record;
    
    /* 🔥 修复：设置标记，告诉 post_hook 这条记录已经被处理 */
    g_syscall_already_consumed = true;
    
    STRACE_VERBOSE("Hybrid replay+fuzz mode: executing real syscall with modified args");
    return -1;  // 返回-1让QEMU执行真实系统调用
}

void rr_strace_syscall_post_hook_optimized(CPUArchState *env, int num, abi_long ret, abi_long *args) {
    if (!g_strace_state.enabled || !g_current_record_strace) {
        return;
    }
    
    const char *syscall_name = rr_get_syscall_name_fast(num);
    STRACE_DEBUG("Optimized post-hook for %s, ret=%ld", 
             syscall_name ? syscall_name : "unknown", ret);
    
    // 使用优化的POST处理
    rr_syscall_post_hook_optimized(num, g_current_record_strace, ret, args);
    
    /* 动态跟踪：系统调用退出 */
    bool was_fuzzed = (g_rr_framework && g_rr_framework->mode == RR_MODE_FUZZING);
    rr_dynamic_trace_syscall_exit(
        env,
        num,
        (uint64_t*)args,
        ret,
        g_strace_state.current_record_index,
        was_fuzzed
    );
    
    // 清理当前记录
    g_current_record = NULL;
}

/* ==================== 配置接口 ==================== */

void rr_strace_set_mode_optimized(bool strict_mode, bool skip_unmatched, int max_lookahead) {
    g_strace_state.strict_mode = strict_mode;
    g_strace_state.skip_unmatched = skip_unmatched;
    g_strace_state.max_lookahead = max_lookahead;
    
    STRACE_INFO("Optimized mode updated - strict:%s, skip:%s, lookahead:%d",
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

/**
 * RR-Fuzz Strace重放模块
 * 基于strace格式文件的智能重放实现
 * 提供比二进制trace更灵活和可调试的重放功能
 */

#include "rr_framework.h"
#include "rr_syscallparser.h"
#include "rr_replay_strace.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>

/* Forward declarations for missing functions - these should be in rr_framework.h */
/* get_syscall_name is not available, we'll implement a simple version */

/* Simple syscall name lookup - limited implementation */
static const char* get_syscall_name(int syscall_nr) {
    switch (syscall_nr) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 4: return "stat";
        case 5: return "fstat";
        case 6: return "lstat";
        case 8: return "lseek";
        case 9: return "mmap";
        case 10: return "mprotect";
        case 11: return "munmap";
        case 12: return "brk";
        case 13: return "rt_sigaction";
        case 14: return "rt_sigprocmask";
        case 15: return "rt_sigreturn";
        case 16: return "ioctl";
        case 17: return "pread64";
        case 18: return "pwrite64";
        case 19: return "readv";
        case 20: return "writev";
        case 21: return "access";
        case 22: return "pipe";
        case 39: return "getpid";
        case 63: return "uname";
        case 158: return "arch_prctl";
        case 221: return "fadvise64";
        case 231: return "exit_group";
        case 257: return "openat";
        case 262: return "newfstatat";
        case 272: return "set_tid_address";
        case 273: return "set_robust_list";
        case 302: return "prlimit64";
        case 334: return "rseq";
        case 318: return "getrandom";
        case 137: return "statfs";
        case 217: return "getdents64";
        case 202: return "futex";
        case 228: return "clock_gettime";
        case 186: return "gettid";
        case 102: return "getuid";
        case 104: return "getgid";
        case 107: return "geteuid";
        case 108: return "getegid";
        case 96: return "getrlimit";
        case 97: return "getrusage";
        case 99: return "sysinfo";
        case 201: return "time";
        case 230: return "clock_nanosleep";
        case 35: return "nanosleep";
        case 72: return "fcntl";
        case 78: return "getdents";
        case 79: return "getcwd";
        case 80: return "chdir";
        case 82: return "rename";
        case 83: return "mkdir";
        case 84: return "rmdir";
        case 87: return "unlink";
        case 88: return "symlink";
        case 89: return "readlink";
        case 90: return "chmod";
        case 91: return "fchmod";
        case 92: return "chown";
        case 93: return "fchown";
        case 94: return "lchown";
        default: 
            RR_VERBOSE("STRACE_REPLAY: Unknown syscall number: %d", syscall_nr);
            return NULL;
    }
}

/* Simple hash table implementation without GLib dependency */
#define MAX_FD_MAPPINGS 256
#define MAX_ADDR_MAPPINGS 128

typedef struct fd_mapping {
    int recorded_fd;
    int actual_fd;
    struct fd_mapping *next;
} fd_mapping_t;

/**
 * 内存地址映射表项
 */
typedef struct addr_mapping {
    target_ulong recorded_addr;
    target_ulong actual_addr;
    size_t size;
    struct addr_mapping *next;
} addr_mapping_t;

static fd_mapping_t *g_fd_mappings[MAX_FD_MAPPINGS] = {NULL};
static addr_mapping_t *g_addr_mappings[MAX_ADDR_MAPPINGS] = {NULL};

static int hash_fd(int fd) {
    return (unsigned int)fd % MAX_FD_MAPPINGS;
}

static int hash_addr(target_ulong addr) {
    return (unsigned int)(addr >> 12) % MAX_ADDR_MAPPINGS;  // 使用页地址作为hash
}

/* ==================== 性能测量工具 ==================== */

/**
 * 获取当前时间(微秒)
 */
static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/**
 * 性能测量结构体
 */
typedef struct {
    uint64_t start_time;
    uint64_t end_time;
} perf_timer_t;

/**
 * 开始性能测量
 */
static void perf_timer_start(perf_timer_t *timer) {
    timer->start_time = get_time_us();
}

/**
 * 结束性能测量并返回耗时(微秒)
 */
static uint64_t perf_timer_end(perf_timer_t *timer) {
    timer->end_time = get_time_us();
    return timer->end_time - timer->start_time;
}

/* ==================== FD映射函数 ==================== */

static void add_fd_mapping_simple(int recorded_fd, int actual_fd) {
    int hash = hash_fd(recorded_fd);
    fd_mapping_t *mapping = malloc(sizeof(fd_mapping_t));
    if (mapping) {
        mapping->recorded_fd = recorded_fd;
        mapping->actual_fd = actual_fd;
        mapping->next = g_fd_mappings[hash];
        g_fd_mappings[hash] = mapping;
        
        RR_VERBOSE("FD mapping added: %d → %d", recorded_fd, actual_fd);
    }
}

static int get_fd_mapping_simple(int recorded_fd) {
    int hash = hash_fd(recorded_fd);
    fd_mapping_t *mapping = g_fd_mappings[hash];
    while (mapping) {
        if (mapping->recorded_fd == recorded_fd) {
            return mapping->actual_fd;
        }
        mapping = mapping->next;
    }
    return recorded_fd; /* 如果没有映射，返回原值 */
}

static void remove_fd_mapping_simple(int recorded_fd) {
    int hash = hash_fd(recorded_fd);
    fd_mapping_t **mapping = &g_fd_mappings[hash];
    while (*mapping) {
        if ((*mapping)->recorded_fd == recorded_fd) {
            fd_mapping_t *to_free = *mapping;
            *mapping = (*mapping)->next;
            free(to_free);
            return;
        }
        mapping = &(*mapping)->next;
    }
}

static void cleanup_fd_mappings(void) {
    for (int i = 0; i < MAX_FD_MAPPINGS; i++) {
        fd_mapping_t *mapping = g_fd_mappings[i];
        while (mapping) {
            fd_mapping_t *next = mapping->next;
            free(mapping);
            mapping = next;
        }
        g_fd_mappings[i] = NULL;
    }
}

/* ==================== 内存地址映射函数 ==================== */

static void add_addr_mapping(target_ulong recorded_addr, target_ulong actual_addr, size_t size) {
    int hash = hash_addr(recorded_addr);
    addr_mapping_t *mapping = malloc(sizeof(addr_mapping_t));
    if (mapping) {
        mapping->recorded_addr = recorded_addr;
        mapping->actual_addr = actual_addr;
        mapping->size = size;
        mapping->next = g_addr_mappings[hash];
        g_addr_mappings[hash] = mapping;
        
        RR_VERBOSE("Address mapping added: 0x%x → 0x%x (size=%zu)", 
                  (unsigned int)recorded_addr, (unsigned int)actual_addr, size);
    }
}

static void remove_addr_mapping(target_ulong recorded_addr) {
    int hash = hash_addr(recorded_addr);
    addr_mapping_t **mapping = &g_addr_mappings[hash];
    while (*mapping) {
        if ((*mapping)->recorded_addr == recorded_addr) {
            addr_mapping_t *to_remove = *mapping;
            *mapping = (*mapping)->next;
            RR_VERBOSE("Address mapping removed: 0x%x", (unsigned int)recorded_addr);
            free(to_remove);
            return;
        }
        mapping = &((*mapping)->next);
    }
}

static void cleanup_addr_mappings(void) {
    for (int i = 0; i < MAX_ADDR_MAPPINGS; i++) {
        addr_mapping_t *mapping = g_addr_mappings[i];
        while (mapping) {
            addr_mapping_t *next = mapping->next;
            free(mapping);
            mapping = next;
        }
        g_addr_mappings[i] = NULL;
    }
}

/* Mock logging macros if not defined */
/* 强制使用直接日志输出，确保可见性 */
#ifdef RR_ERROR
#undef RR_ERROR
#endif
#ifdef RR_INFO
#undef RR_INFO
#endif
#ifdef RR_VERBOSE
#undef RR_VERBOSE
#endif
#ifdef RR_WARN
#undef RR_WARN
#endif

/* 日志级别控制 */
typedef enum {
    STRACE_LOG_ERROR = 0,    /* 只显示错误 */
    STRACE_LOG_WARN = 1,     /* 显示警告和错误 */
    STRACE_LOG_INFO = 2,     /* 显示信息、警告和错误 */
    STRACE_LOG_VERBOSE = 3,  /* 显示所有日志 */
    STRACE_LOG_DEBUG = 4     /* 显示调试信息 */
} strace_log_level_t;

static strace_log_level_t g_strace_log_level = STRACE_LOG_INFO;  /* 默认INFO级别 */

/* 从环境变量设置日志级别 */
static void init_strace_log_level(void) {
    const char *level_str = getenv("RR_STRACE_LOG_LEVEL");
    if (!level_str) {
        return;  /* 使用默认级别 */
    }
    
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

/* Define AT_FDCWD if not available */
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

/* ==================== 全局状态管理 ==================== */

/* Strace解析器实例 */
static rr_strace_parser_t *g_strace_parser = NULL;

/* 重放控制状态 */
typedef struct {
    bool enabled;                           /* 是否启用strace重放 */
    bool strict_mode;                       /* 严格模式：必须精确匹配 */
    bool skip_unmatched;                    /* 跳过不匹配的系统调用 */
    int max_lookahead;                      /* 最大前瞻匹配数量 */
    
    /* 统计信息 */
    uint64_t total_syscalls;                /* 总系统调用数 */
    uint64_t matched_syscalls;              /* 匹配的系统调用数 */
    uint64_t skipped_syscalls;              /* 跳过的系统调用数 */
    uint64_t error_syscalls;                /* 错误的系统调用数 */
    
    /* 文件描述符映射 */
    int fd_map_initialized;                 /* FD映射是否已初始化 */
    int next_fd;                            /* 下一个可用的文件描述符 */
    
    /* 调试信息 */
    char *trace_filename;                   /* trace文件名 */
    size_t current_record_index;            /* 当前记录索引 */
    
    /* 新增：记录不足处理策略 */
    bool trace_exhausted;                   /* trace文件已读完 */
    bool allow_fallback_execution;          /* 允许回退到正常执行 */
    size_t fallback_syscalls;               /* 回退执行的系统调用数量 */
    
    /* 新增：重要系统调用追踪 */
    size_t critical_syscalls;               /* 关键系统调用数量 */
    size_t critical_matched;                /* 关键系统调用匹配数量 */
    
    
    /* 简化的错误统计 */
    size_t total_errors;                    /* 总错误数量 */
} rr_strace_replay_state_t;

static rr_strace_replay_state_t g_strace_state = {0};
static char g_stats_filename[256] = {0};

/* 统计输出控制 */
#define STATS_PRINT_INTERVAL 10  /* 每10个系统调用输出一次简要统计 */
static size_t g_last_stats_print = 0;

/* 信号处理器标志 */
static volatile sig_atomic_t g_signal_received = 0;

/* 函数声明 */
static void rr_strace_signal_handler(int sig);

/**
 * 当前正在处理的记录
 * PRE-HOOK和POST-HOOK之间共享
 */
static rr_strace_record_t *g_current_record = NULL;

/* ==================== 统计更新函数 ==================== */

/**
 * 更新FD映射统计
 */
static inline void update_fd_mapping_stats(bool created, bool used, bool error) {
    if (error) g_strace_state.total_errors++;
}

/**
 * 更新地址映射统计
 */
static inline void update_addr_mapping_stats(bool created, bool used, bool error) {
    if (error) g_strace_state.total_errors++;
}

/* ==================== 配置和初始化 ==================== */

/**
 * 初始化strace重放模块
 */
int rr_strace_replay_init(const char *trace_file) {
    /* 初始化日志级别 */
    init_strace_log_level();
    
    if (!trace_file) {
        RR_ERROR("STRACE_REPLAY: trace_file is NULL");
        return -1;
    }
    
    RR_INFO("STRACE_REPLAY: Initializing with trace file: %s", trace_file);
    
    /* 初始化状态 */
    memset(&g_strace_state, 0, sizeof(g_strace_state));
    g_strace_state.trace_filename = strdup(trace_file);
    if (!g_strace_state.trace_filename) {
        RR_ERROR("STRACE_REPLAY: Failed to allocate memory for trace filename");
        return -1;
    }
    g_strace_state.strict_mode = false;        /* 默认宽松模式 */
    g_strace_state.skip_unmatched = true;      /* 默认跳过不匹配 */
    g_strace_state.max_lookahead = 5;          /* 允许跳过最多5条记录寻找匹配 */
    g_strace_state.next_fd = 10;               /* 从10开始分配FD */
    
    /* 新增：记录不足处理策略初始化 */
    g_strace_state.trace_exhausted = false;
    g_strace_state.allow_fallback_execution = true;  /* 允许回退执行 */
    g_strace_state.fallback_syscalls = 0;
    g_strace_state.critical_syscalls = 0;
    g_strace_state.critical_matched = 0;
    
    /* 初始化FD映射表 */
    cleanup_fd_mappings(); /* 清理之前的映射 */
    cleanup_addr_mappings(); /* 清理之前的地址映射 */
    g_strace_state.fd_map_initialized = 1;
    
    /* 初始化strace解析器 */
    g_strace_parser = rr_strace_parser_init(trace_file);
    if (!g_strace_parser) {
        RR_ERROR("STRACE_REPLAY: Failed to initialize strace parser");
        cleanup_fd_mappings();
        cleanup_addr_mappings();
        if (g_strace_state.trace_filename) {
            free(g_strace_state.trace_filename);
            g_strace_state.trace_filename = NULL;
        }
        return -1;
    }
    
    /* 加载strace文件 */
    if (rr_strace_parser_load(g_strace_parser) < 0) {
        RR_ERROR("STRACE_REPLAY: Failed to load strace file");
        rr_strace_parser_cleanup(g_strace_parser);
        g_strace_parser = NULL;
        cleanup_fd_mappings();
        cleanup_addr_mappings();
        if (g_strace_state.trace_filename) {
            free(g_strace_state.trace_filename);
            g_strace_state.trace_filename = NULL;
        }
        return -1;
    }
    
    /* 获取统计信息 */
    size_t total_records, current_index;
    rr_strace_get_stats(g_strace_parser, &total_records, &current_index);
    
    g_strace_state.enabled = true;
    
    /* 注册信号处理器确保异常退出时也能输出统计信息 */
    signal(SIGINT, rr_strace_signal_handler);
    signal(SIGTERM, rr_strace_signal_handler);
    signal(SIGQUIT, rr_strace_signal_handler);
    
    /* 设置统计文件名并创建初始统计文件 */
    snprintf(g_stats_filename, sizeof(g_stats_filename), "/tmp/rr_strace_stats_%d.txt", getpid());
    rr_strace_save_stats_to_file(g_stats_filename);
    
    RR_INFO("STRACE_REPLAY: Successfully initialized");
    RR_INFO("STRACE_REPLAY: - Trace file: %s", trace_file);
    RR_INFO("STRACE_REPLAY: - Total records: %zu", total_records);
    RR_INFO("STRACE_REPLAY: - Stats file: %s", g_stats_filename);
    RR_INFO("STRACE_REPLAY: - Strict mode: %s", g_strace_state.strict_mode ? "YES" : "NO");
    RR_INFO("STRACE_REPLAY: - Skip unmatched: %s", g_strace_state.skip_unmatched ? "YES" : "NO");
    RR_INFO("STRACE_REPLAY: - Max lookahead: %d", g_strace_state.max_lookahead);
    RR_INFO("STRACE_REPLAY: - Signal handlers registered for statistics output");
    
    return 0;
}

/**
 * 清理strace重放模块
 */
/**
 * 输出详细的重放统计信息
 */
void rr_strace_replay_print_stats(void) {
    if (!g_strace_state.enabled) {
        return;
    }
    
    RR_INFO("=== STRACE REPLAY COMPREHENSIVE STATISTICS ===");
    
    /* 基础统计 */
    RR_INFO("📊 Basic Statistics:");
    RR_INFO("  Total syscalls processed: %zu", g_strace_state.total_syscalls);
    RR_INFO("  Successfully matched: %zu (%.1f%%)", 
            g_strace_state.matched_syscalls,
            g_strace_state.total_syscalls > 0 ? 
            (100.0 * g_strace_state.matched_syscalls / g_strace_state.total_syscalls) : 0.0);
    RR_INFO("  Skipped syscalls: %zu", g_strace_state.skipped_syscalls);
    RR_INFO("  Error syscalls: %zu", g_strace_state.error_syscalls);
    RR_INFO("  Fallback executions: %zu", g_strace_state.fallback_syscalls);
    
    /* 关键系统调用统计 */
    RR_INFO("🎯 Critical Syscalls:");
    RR_INFO("  Critical syscalls: %zu", g_strace_state.critical_syscalls);
    RR_INFO("  Critical matched: %zu (%.1f%%)", 
            g_strace_state.critical_matched,
            g_strace_state.critical_syscalls > 0 ? 
            (100.0 * g_strace_state.critical_matched / g_strace_state.critical_syscalls) : 0.0);
    
    /* 简化的错误统计 */
    if (g_strace_state.total_errors > 0) {
        RR_INFO("❌ Total errors: %zu", g_strace_state.total_errors);
    }
    
    /* 状态信息 */
    RR_INFO("📋 Status Information:");
    RR_INFO("  Trace status: %s", g_strace_state.trace_exhausted ? "EXHAUSTED" : "ACTIVE");
    RR_INFO("  Current record index: %zu", g_strace_state.current_record_index);
    
    /* 总体评估 */
    double overall_success_rate = g_strace_state.total_syscalls > 0 ? 
        (100.0 * g_strace_state.matched_syscalls / g_strace_state.total_syscalls) : 0.0;
    RR_INFO("📈 Overall Assessment:");
    if (overall_success_rate >= 90.0) {
        RR_INFO("  Status: EXCELLENT (%.1f%% success rate)", overall_success_rate);
    } else if (overall_success_rate >= 75.0) {
        RR_INFO("  Status: GOOD (%.1f%% success rate)", overall_success_rate);
    } else if (overall_success_rate >= 50.0) {
        RR_INFO("  Status: FAIR (%.1f%% success rate)", overall_success_rate);
    } else {
        RR_INFO("  Status: POOR (%.1f%% success rate)", overall_success_rate);
    }
    
    RR_INFO("=== END COMPREHENSIVE STATISTICS ===");
    
    /* 强制刷新输出缓冲区，确保统计信息立即显示 */
    fflush(stdout);
    fflush(stderr);
}

/**
 * 输出简化的统计信息（用于周期性输出）
 */
static void rr_strace_replay_print_brief_stats(void) {
    if (!g_strace_state.enabled) {
        return;
    }
    
    double match_rate = g_strace_state.total_syscalls > 0 ? 
        (100.0 * g_strace_state.matched_syscalls / g_strace_state.total_syscalls) : 0.0;
    
    RR_INFO("📊 STRACE REPLAY PROGRESS: Total=%zu, Matched=%zu (%.1f%%), Errors=%zu, Index=%zu",
            g_strace_state.total_syscalls,
            g_strace_state.matched_syscalls,
            match_rate,
            g_strace_state.error_syscalls,
            g_strace_state.current_record_index);
    
    fflush(stdout);
    fflush(stderr);
}


/**
 * 将统计信息输出到文件
 */
void rr_strace_save_stats_to_file(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        return; /* 静默失败，避免过多错误输出 */
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(fp, "=== STRACE REPLAY STATISTICS ===\n");
    fprintf(fp, "Generated: %s\n", timestamp);
    fprintf(fp, "Trace file: %s\n", g_strace_state.trace_filename ? g_strace_state.trace_filename : "unknown");
    fprintf(fp, "\n");
    
    /* 核心统计信息 */
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
    
    fprintf(fp, "=== END ===\n");
    fclose(fp);
}

/**
 * 信号处理器 - 确保异常退出时也能输出统计信息
 */
static void rr_strace_signal_handler(int sig) {
    g_signal_received = 1;
    RR_INFO("🚨 Signal %d received, printing final statistics...", sig);
    
    /* 保存统计信息到文件 */
    char stats_filename[256];
    snprintf(stats_filename, sizeof(stats_filename), "/tmp/rr_strace_stats_signal_%d.txt", getpid());
    rr_strace_save_stats_to_file(stats_filename);
    
    rr_strace_replay_print_stats();
    
    /* 恢复默认信号处理器并重新发送信号 */
    signal(sig, SIG_DFL);
    raise(sig);
}

/**
 * 检查是否需要输出周期性统计信息
 */
static void rr_strace_check_periodic_stats(void) {
    /* 简化：只在程序结束时更新统计文件，避免频繁I/O */
    if (g_strace_state.total_syscalls > 0 && 
        (g_strace_state.total_syscalls - g_last_stats_print) >= STATS_PRINT_INTERVAL) {
        
        /* 更新统计文件 */
        if (g_stats_filename[0] != '\0') {
            rr_strace_save_stats_to_file(g_stats_filename);
        }
        
        g_last_stats_print = g_strace_state.total_syscalls;
    }
}

void rr_strace_replay_cleanup(void) {
    if (!g_strace_state.enabled) {
        return;
    }
    
    /* 保存最终统计信息到文件 */
    if (g_stats_filename[0] != '\0') {
        rr_strace_save_stats_to_file(g_stats_filename);
    }
    
    /* 清理资源 */
    if (g_strace_parser) {
        rr_strace_parser_cleanup(g_strace_parser);
        g_strace_parser = NULL;
    }
    
    if (g_strace_state.fd_map_initialized) {
        cleanup_fd_mappings();
        cleanup_addr_mappings();
        g_strace_state.fd_map_initialized = 0;
    }
    
    if (g_strace_state.trace_filename) {
        free(g_strace_state.trace_filename);
        g_strace_state.trace_filename = NULL;
    }
    
    memset(&g_strace_state, 0, sizeof(g_strace_state));
    
    RR_INFO("STRACE_REPLAY: Cleanup completed");
}

/* ==================== 文件描述符映射管理 ==================== */

/* ==================== 系统调用参数处理 ==================== */

/* ==================== 系统调用匹配和参数处理 ==================== */

/**
 * 增强的等价系统调用表和判断函数 - 从8对扩展到30+对
 */
static const struct {
    const char *name1;
    const char *name2;
    const char *category;
} enhanced_equivalent_syscalls[] = {
    // 文件I/O等价 (核心改进)
    {"write", "writev", "file_io"},
    {"read", "readv", "file_io"},
    {"pwrite64", "write", "file_io"},
    {"pread64", "read", "file_io"},
    {"sendfile", "write", "file_io"},
    
    // 文件操作等价
    {"open", "openat", "file_ops"},
    {"creat", "openat", "file_ops"},
    {"mkdir", "mkdirat", "file_ops"},
    {"rmdir", "unlinkat", "file_ops"},
    {"unlink", "unlinkat", "file_ops"},
    {"rename", "renameat", "file_ops"},
    {"symlink", "symlinkat", "file_ops"},
    {"link", "linkat", "file_ops"},
    
    // 文件状态等价 (重要改进)
    {"stat", "fstat", "file_stat"},
    {"stat", "newfstatat", "file_stat"},
    {"lstat", "newfstatat", "file_stat"},
    {"stat64", "newfstatat", "file_stat"},
    {"lstat64", "newfstatat", "file_stat"},
    {"fstat64", "fstat", "file_stat"},
    
    // 内存管理等价
    {"mmap", "mmap2", "memory"},
    {"brk", "sbrk", "memory"},
    
    // 进程管理等价
    {"clone", "fork", "process"},
    {"vfork", "fork", "process"},
    {"wait4", "waitpid", "process"},
    
    // 时间相关等价
    {"time", "gettimeofday", "time"},
    {"clock_gettime", "gettimeofday", "time"},
    
    // 信号相关等价
    {"signal", "rt_sigaction", "signal"},
    {"sigprocmask", "rt_sigprocmask", "signal"},
    
    {NULL, NULL, NULL}
};

/* 系统调用重要性分类 */
typedef enum {
    SYSCALL_CRITICAL,     // 关键调用，必须精确匹配
    SYSCALL_IMPORTANT,    // 重要调用，优先匹配
    SYSCALL_OPTIONAL,     // 可选调用，可以灵活处理
    SYSCALL_ENVIRONMENT,  // 环境调用，通常可以跳过
} syscall_importance_t;

static syscall_importance_t classify_syscall_importance(const char *name) {
    if (!name) return SYSCALL_IMPORTANT;
    
    // 关键文件操作 - 影响程序核心功能
    if (strcmp(name, "read") == 0 || strcmp(name, "write") == 0 ||
        strcmp(name, "openat") == 0 || strcmp(name, "close") == 0 ||
        strcmp(name, "mmap") == 0 || strcmp(name, "munmap") == 0) {
        return SYSCALL_CRITICAL;
    }
    
    // 重要系统操作
    if (strcmp(name, "brk") == 0 || strcmp(name, "clone") == 0 ||
        strcmp(name, "execve") == 0 || strcmp(name, "exit") == 0 ||
        strcmp(name, "getdents64") == 0) {
        return SYSCALL_IMPORTANT;
    }
    
    // 环境探测调用 - 经常变化，可以跳过
    if (strcmp(name, "access") == 0 || strcmp(name, "stat") == 0 ||
        strcmp(name, "uname") == 0 || strcmp(name, "getpid") == 0 ||
        strcmp(name, "gettid") == 0 || strcmp(name, "getuid") == 0 ||
        strcmp(name, "getgid") == 0 || strcmp(name, "geteuid") == 0 ||
        strcmp(name, "getegid") == 0) {
        return SYSCALL_ENVIRONMENT;
    }
    
    // 线程/同步相关 - 顺序经常变化
    if (strcmp(name, "futex") == 0 || strcmp(name, "set_robust_list") == 0 ||
        strcmp(name, "set_tid_address") == 0 || strcmp(name, "rt_sigprocmask") == 0 ||
        strcmp(name, "rt_sigaction") == 0) {
        return SYSCALL_OPTIONAL;
    }
    
    return SYSCALL_IMPORTANT;  // 默认为重要
}

static bool enhanced_are_equivalent_syscalls(const char *name1, const char *name2) {
    if (strcmp(name1, name2) == 0) {
        return true;
    }
    
    for (int i = 0; enhanced_equivalent_syscalls[i].name1 != NULL; i++) {
        if ((strcmp(name1, enhanced_equivalent_syscalls[i].name1) == 0 &&
             strcmp(name2, enhanced_equivalent_syscalls[i].name2) == 0) ||
            (strcmp(name1, enhanced_equivalent_syscalls[i].name2) == 0 &&
             strcmp(name2, enhanced_equivalent_syscalls[i].name1) == 0)) {
            return true;
        }
    }
    
    return false;
}

static bool should_skip_record_intelligently(rr_strace_record_t *record, syscall_importance_t target_importance) {
    if (!record || !record->syscall_name) return true;
    
    syscall_importance_t record_importance = classify_syscall_importance(record->syscall_name);
    
    // 如果目标是关键调用，不要轻易跳过任何记录
    if (target_importance == SYSCALL_CRITICAL) {
        return record_importance == SYSCALL_ENVIRONMENT;  // 只跳过环境调用
    }
    
    // 如果目标是环境调用，可以跳过大部分记录
    if (target_importance == SYSCALL_ENVIRONMENT) {
        return record_importance != SYSCALL_ENVIRONMENT;  // 跳过非环境调用
    }
    
    // 默认策略：跳过不重要的记录
    return record_importance == SYSCALL_OPTIONAL || 
           record_importance == SYSCALL_ENVIRONMENT;
}

/**
 * 检查是否为文件描述符相关的系统调用
 */
static bool is_fd_syscall(const char *syscall_name) {
    if (!syscall_name) return false;
    
    // FD相关的系统调用列表 - 扩展版本
    return (strcmp(syscall_name, "read") == 0 ||
            strcmp(syscall_name, "write") == 0 ||
            strcmp(syscall_name, "writev") == 0 ||
            strcmp(syscall_name, "readv") == 0 ||
            strcmp(syscall_name, "pread64") == 0 ||
            strcmp(syscall_name, "pwrite64") == 0 ||
            strcmp(syscall_name, "close") == 0 ||
            strcmp(syscall_name, "fstat") == 0 ||
            strcmp(syscall_name, "newfstatat") == 0 ||
            strcmp(syscall_name, "openat") == 0 ||
            strcmp(syscall_name, "open") == 0 ||
            strcmp(syscall_name, "dup") == 0 ||
            strcmp(syscall_name, "dup2") == 0 ||
            strcmp(syscall_name, "dup3") == 0 ||
            strcmp(syscall_name, "pipe") == 0 ||
            strcmp(syscall_name, "pipe2") == 0 ||
            strcmp(syscall_name, "socket") == 0 ||
            strcmp(syscall_name, "socketpair") == 0 ||
            strcmp(syscall_name, "accept") == 0 ||
            strcmp(syscall_name, "accept4") == 0 ||
            strcmp(syscall_name, "fcntl") == 0 ||
            strcmp(syscall_name, "ioctl") == 0 ||
            strcmp(syscall_name, "sendfile") == 0 ||
            strcmp(syscall_name, "splice") == 0);
}

/**
 * 建立动态FD映射关系
 */
static void establish_dynamic_fd_mapping(rr_strace_record_t *record, abi_long *args) {
    if (!record || !record->syscall_name) return;
    
    // 对于close系统调用，建立FD映射
    if (strcmp(record->syscall_name, "close") == 0) {
        int recorded_fd = (int)record->args[0].value;
        int actual_fd = (int)args[0];
        
        if (recorded_fd != actual_fd) {
            // 建立映射关系：recorded_fd -> actual_fd
            add_fd_mapping_simple(recorded_fd, actual_fd);
            RR_INFO("Dynamic FD mapping established: %d -> %d (close)", recorded_fd, actual_fd);
        }
    }
    
    // 对于其他FD相关系统调用，也可以建立映射
    else if (strcmp(record->syscall_name, "read") == 0 || 
             strcmp(record->syscall_name, "write") == 0 ||
             strcmp(record->syscall_name, "readv") == 0 ||
             strcmp(record->syscall_name, "writev") == 0) {
        int recorded_fd = (int)record->args[0].value;
        int actual_fd = (int)args[0];
        
        if (recorded_fd != actual_fd && recorded_fd > 2 && actual_fd > 2) {
            // 只为非标准FD建立映射
            add_fd_mapping_simple(recorded_fd, actual_fd);
            RR_INFO("Dynamic FD mapping established: %d -> %d (%s)", 
                    recorded_fd, actual_fd, record->syscall_name);
        }
    }
    
    // 对于dup系列系统调用的输入FD映射
    else if (strcmp(record->syscall_name, "dup") == 0 ||
             strcmp(record->syscall_name, "dup2") == 0 ||
             strcmp(record->syscall_name, "dup3") == 0) {
        int recorded_oldfd = (int)record->args[0].value;
        int actual_oldfd = (int)args[0];
        
        if (recorded_oldfd != actual_oldfd && recorded_oldfd > 2 && actual_oldfd > 2) {
            add_fd_mapping_simple(recorded_oldfd, actual_oldfd);
            RR_INFO("Dynamic FD mapping established: %d -> %d (%s input)", 
                    recorded_oldfd, actual_oldfd, record->syscall_name);
        }
    }
    
    // 对于socket相关系统调用，预建立映射
    else if (strcmp(record->syscall_name, "socket") == 0 ||
             strcmp(record->syscall_name, "accept") == 0 ||
             strcmp(record->syscall_name, "accept4") == 0) {
        // 这些在POST-HOOK中处理返回的FD
        RR_VERBOSE("Socket syscall %s will be handled in POST-HOOK", record->syscall_name);
    }
}

/* ==================== 增强匹配算法 ==================== */

/**
 * 应用文件描述符映射到参数
 */
static void apply_fd_mapping_to_args(const char *syscall_name, abi_long *args) {
    /* 根据系统调用类型映射相关的文件描述符参数 */
    if (strcmp(syscall_name, "read") == 0 || 
        strcmp(syscall_name, "write") == 0 ||
        strcmp(syscall_name, "writev") == 0 ||
        strcmp(syscall_name, "close") == 0 ||
        strcmp(syscall_name, "fstat") == 0 ||
        strcmp(syscall_name, "newfstatat") == 0) {
        /* 第一个参数是文件描述符 */
        args[0] = get_fd_mapping_simple(args[0]);
    } else if (strcmp(syscall_name, "openat") == 0) {
        /* 第一个参数是目录文件描述符 */
        if (args[0] != AT_FDCWD) {
            args[0] = get_fd_mapping_simple(args[0]);
        }
    } else if (strcmp(syscall_name, "mmap") == 0) {
        /* 第五个参数（args[4]）是文件描述符 */
        if (args[4] >= 0) {  /* 不是匿名映射 */
            args[4] = get_fd_mapping_simple(args[4]);
        }
    }
    /* 可以根据需要添加更多系统调用的FD映射逻辑 */
}

/**
 * 增强的系统调用匹配函数 - 支持自适应窗口和智能跳过
 */
static rr_strace_record_t *enhanced_find_matching_record(int syscall_nr, abi_long *args) {
    /* 开始性能测量 */
    perf_timer_t timer;
    perf_timer_start(&timer);
    
    const char *syscall_name = get_syscall_name(syscall_nr);
    /* 简化：不再统计查找次数 */
    if (!syscall_name) {
        RR_WARN("STRACE_REPLAY: Unknown syscall number: %d", syscall_nr);
        return NULL;
    }
    
    syscall_importance_t importance = classify_syscall_importance(syscall_name);
    
    // 根据重要性调整搜索策略
    int max_skip;
    switch (importance) {
        case SYSCALL_CRITICAL:
            max_skip = 50;  // 关键调用，大范围搜索
            break;
        case SYSCALL_IMPORTANT:
            max_skip = 30;  // 重要调用，中等范围
            break;
        case SYSCALL_OPTIONAL:
            max_skip = 15;  // 可选调用，小范围
            break;
        case SYSCALL_ENVIRONMENT:
            max_skip = 5;   // 环境调用，快速放弃
            break;
    }
    
    RR_VERBOSE("Enhanced matching for %s (importance=%d, max_skip=%d)", 
               syscall_name, importance, max_skip);
    
    int skip_count = 0;
    rr_strace_record_t *record = NULL;
    
    while (skip_count <= max_skip) {
        RR_DEBUG("About to call rr_strace_parser_get_next (attempt %d)", skip_count + 1);
        
        record = rr_strace_parser_get_next(g_strace_parser);
    if (!record) {
            RR_DEBUG("rr_strace_parser_get_next returned NULL - no more records");
            
            /* 标记trace已耗尽 */
            g_strace_state.trace_exhausted = true;
            
            /* 根据系统调用重要性决定处理策略 */
            if (importance == SYSCALL_CRITICAL) {
                RR_ERROR("STRACE_REPLAY: Critical syscall %s cannot find match, trace exhausted", syscall_name);
                RR_ERROR("STRACE_REPLAY: This may cause program malfunction");
            } else if (importance == SYSCALL_IMPORTANT) {
                RR_WARN("STRACE_REPLAY: Important syscall %s cannot find match, trace exhausted", syscall_name);
                RR_WARN("STRACE_REPLAY: Allowing fallback execution");
    } else {
                RR_INFO("STRACE_REPLAY: Optional/Environment syscall %s - trace exhausted, fallback execution", syscall_name);
            }
            
        RR_VERBOSE("STRACE_REPLAY: No more records available");
        return NULL;
    }
        
        RR_DEBUG("Got record: %s", record->syscall_name);
    
    g_strace_state.current_record_index++;
    
        RR_DEBUG("Enhanced match attempt %d - record %zu: %s vs expected %s (importance: target=%d, record=%d)", 
                  skip_count + 1, g_strace_state.current_record_index - 1, record->syscall_name, syscall_name,
                  importance, classify_syscall_importance(record->syscall_name));
        
        // 1. 精确匹配
        if (strcmp(record->syscall_name, syscall_name) == 0) {
            if (skip_count > 0) {
                RR_INFO("Enhanced match successful after skipping %d records: %s", 
                        skip_count, record->syscall_name);
            } else {
                RR_INFO("Enhanced direct match successful: %s", record->syscall_name);
            }
            
            /* 记录性能统计 */
            uint64_t elapsed = perf_timer_end(&timer);
            /* 简化：不再统计性能指标 */
            
            return record;
        }
        
        // 1.5. 智能FD匹配 - 对于FD相关系统调用，允许参数差异
        if (strcmp(record->syscall_name, syscall_name) == 0 && is_fd_syscall(syscall_name)) {
            RR_INFO("Enhanced FD-flexible match: %s (FD may differ)", syscall_name);
            
            /* 记录性能统计 */
            uint64_t elapsed = perf_timer_end(&timer);
            /* 简化：不再统计性能指标 */
            
            return record;
        }
        
        // 2. 增强的等价匹配
        if (enhanced_are_equivalent_syscalls(syscall_name, record->syscall_name)) {
            RR_INFO("Enhanced equivalent match: %s <-> %s (skipped %d)", 
                    syscall_name, record->syscall_name, skip_count);
            
            /* 记录性能统计 */
            uint64_t elapsed = perf_timer_end(&timer);
            /* 简化：不再统计性能指标 */
            
            return record;
        }
        
        // 3. 智能跳过决策
        if (should_skip_record_intelligently(record, importance)) {
            RR_VERBOSE("Intelligently skipping %s (looking for %s)", 
                       record->syscall_name, syscall_name);
            skip_count++;
            continue;
        }
        
        // 4. 对于环境调用，快速放弃
        if (importance == SYSCALL_ENVIRONMENT && skip_count >= 3) {
            RR_VERBOSE("Quick abandon for environment syscall %s", syscall_name);
            break;
        }
        
        // 5. 常规跳过
        RR_VERBOSE("STRACE_REPLAY: Skip record %zu: %s (looking for %s)", 
                  g_strace_state.current_record_index - 1, record->syscall_name, syscall_name);
        skip_count++;
    }
    
    /* 超过最大跳过次数，匹配失败 */
    RR_DEBUG("*** ENHANCED CRITICAL: Match failed after %d attempts ***", max_skip + 1);
    RR_DEBUG("Expected: %s (%d) [importance=%d]", syscall_name, syscall_nr, importance);
    RR_DEBUG("Last record: %s [importance=%d]",
            record ? record->syscall_name : "NULL", 
            record ? classify_syscall_importance(record->syscall_name) : -1);
    RR_ERROR("STRACE_REPLAY: Enhanced match failed after %d attempts", max_skip + 1);
    RR_ERROR("STRACE_REPLAY: Expected: %s (%d) [importance=%d]", syscall_name, syscall_nr, importance);
    RR_ERROR("STRACE_REPLAY: Last record: %s [importance=%d]", 
             record ? record->syscall_name : "NULL",
             record ? classify_syscall_importance(record->syscall_name) : -1);
    
    /* 记录失败的性能统计 */
    uint64_t elapsed = perf_timer_end(&timer);
    /* 简化：不再统计性能指标 */
    g_strace_state.total_errors++;  // 匹配失败记为错误
    
    return NULL;
}

/* ==================== 特殊系统调用处理 ==================== */

/* ==================== 系统调用重放主函数 ==================== */

/* ==================== 主要接口函数 ==================== */

/**
 * strace重放的主要系统调用处理函数
 * 这个函数替代原有的 rr_replay_syscall
 */
abi_long rr_replay_syscall_strace(CPUArchState *env, int num, abi_long *args) {
    /* 强制调试输出 */
    fprintf(stderr, "[FORCE_DEBUG] === ENTERING rr_replay_syscall_strace for syscall %d ===\n", num);
    fflush(stderr);
    RR_ERROR("STRACE_REPLAY: === DEFINITELY ENTERING rr_replay_syscall_strace for syscall %d ===", num);
    
    /* 立即输出当前统计信息，不管任何条件 */
    g_strace_state.total_syscalls++;
    fprintf(stderr, "[IMMEDIATE_STATS] Syscall %d: total=%zu, matched=%zu, errors=%zu\n", 
            num, g_strace_state.total_syscalls, g_strace_state.matched_syscalls, g_strace_state.error_syscalls);
    fflush(stderr);
    
    fprintf(stderr, "[FORCE_DEBUG2] About to check state variables\n");
    fflush(stderr);
    
    fprintf(stderr, "[FORCE_STATE_DEBUG] enabled=%d, trace_exhausted=%d\n", 
            g_strace_state.enabled, g_strace_state.trace_exhausted);
    fflush(stderr);
    
    if (!g_strace_state.enabled) {
        RR_ERROR("STRACE_REPLAY: Module not initialized");
        return -1;
    }
    
    /* 检查trace是否已耗尽 */
    if (g_strace_state.trace_exhausted) {
        g_strace_state.fallback_syscalls++;
        const char *syscall_name = get_syscall_name(num);
        RR_VERBOSE("STRACE_REPLAY: Trace exhausted, fallback execution for %s (%zu total fallbacks)", 
                  syscall_name ? syscall_name : "unknown", g_strace_state.fallback_syscalls);
        return -1;  /* 让QEMU执行正常的系统调用 */
    }
    
    g_strace_state.total_syscalls++;
    
    fprintf(stderr, "[FORCE_COUNT_DEBUG] SYSCALL_COUNT: Incremented total_syscalls to %zu\n", g_strace_state.total_syscalls);
    fflush(stderr);
    
    /* 检查是否需要输出周期性统计信息 */
    rr_strace_check_periodic_stats();
    
    /* 强制输出统计信息在特定的系统调用数量 */
    if (g_strace_state.total_syscalls == 20 || g_strace_state.total_syscalls == 50 || g_strace_state.total_syscalls == 75) {
        fprintf(stderr, "[FORCE_STATS] Triggering stats at syscall count %zu\n", g_strace_state.total_syscalls);
        fflush(stderr);
        rr_strace_replay_print_stats();
    }
    
    const char *syscall_name = get_syscall_name(num);
    
    /* 检查系统调用重要性并统计 */
    if (syscall_name) {
        syscall_importance_t importance = classify_syscall_importance(syscall_name);
        if (importance == SYSCALL_CRITICAL) {
            g_strace_state.critical_syscalls++;
        }
    }
    
    RR_VERBOSE("STRACE_REPLAY: Processing syscall %s (%d)", 
              syscall_name ? syscall_name : "unknown", num);
    
    /* 处理QEMU特有的系统调用，允许直接执行 */
    if (num == 63) { /* uname */
        fprintf(stderr, "[FORCE_DEBUG] Allowing QEMU-specific syscall: %s (%d)\n", syscall_name, num);
        fflush(stderr);
        return -1; /* 让QEMU正常执行这个系统调用 */
    }
    
    /* 查找匹配的记录 - 使用增强的匹配算法 */
    rr_strace_record_t *record = enhanced_find_matching_record(num, args);
    if (!record) {
        g_strace_state.error_syscalls++;
        RR_WARN("STRACE_REPLAY: No matching record found for %s (%d), skip_unmatched=%d", 
                syscall_name ? syscall_name : "unknown", num, g_strace_state.skip_unmatched);
        
        if (g_strace_state.skip_unmatched) {
            /* 跳过不匹配的调用，让系统执行 */
            RR_VERBOSE("STRACE_REPLAY: Skipping unmatched syscall %s, letting system execute", 
                      syscall_name ? syscall_name : "unknown");
            return -1;
        } else {
            /* 严格模式下返回错误 */
            RR_VERBOSE("STRACE_REPLAY: Strict mode, returning ENOSYS for unmatched syscall %s", 
                      syscall_name ? syscall_name : "unknown");
            errno = ENOSYS;
            return -1;
        }
    }
    
    g_strace_state.matched_syscalls++;
    
    /* 统计关键系统调用匹配 */
    if (syscall_name) {
        syscall_importance_t importance = classify_syscall_importance(syscall_name);
        if (importance == SYSCALL_CRITICAL) {
            g_strace_state.critical_matched++;
        }
    }
    
    RR_VERBOSE("STRACE_REPLAY: Found matching record: %s, ret=%ld, error=%d",
              record->syscall_name, record->ret_value, record->has_error);
    
    /* 新设计：真实执行 + 句柄映射 */
    
    /* 1. 映射输入句柄（FD等） */
    if (strcmp(record->syscall_name, "openat") == 0 ||
        strcmp(record->syscall_name, "read") == 0 ||
               strcmp(record->syscall_name, "write") == 0 ||
        strcmp(record->syscall_name, "writev") == 0 ||
        strcmp(record->syscall_name, "close") == 0) {
        apply_fd_mapping_to_args(record->syscall_name, args);
    }
    
    /* 1.5. 对于FD相关系统调用，建立动态映射 */
    if (is_fd_syscall(record->syscall_name)) {
        establish_dynamic_fd_mapping(record, args);
    }
    
    /* 2. 保存当前记录供POST-HOOK使用 */
    g_current_record = record;
    
    /* 3. 让QEMU真实执行所有系统调用 */
    RR_VERBOSE("STRACE_REPLAY: Allowing real execution of %s", record->syscall_name);
    
    /* 
     * 重要说明：返回-1是"真实执行+句柄映射"架构的核心设计
     * -1告诉QEMU框架："请执行真实的系统调用，不要使用模拟值"
     * 这样可以确保程序的功能正确性，同时在POST-HOOK中建立句柄映射
     * 这不是错误，而是让系统调用正常执行的信号
     */
    return -1;  // 信号：让QEMU执行真实系统调用
}

/* ==================== 配置和调试接口 ==================== */

/**
 * 设置strace重放模式
 */
void rr_strace_set_mode(bool strict_mode, bool skip_unmatched, int max_lookahead) {
    g_strace_state.strict_mode = strict_mode;
    g_strace_state.skip_unmatched = skip_unmatched;
    g_strace_state.max_lookahead = max_lookahead;
    
    RR_INFO("STRACE_REPLAY: Mode updated - strict:%s, skip:%s, lookahead:%d",
            strict_mode ? "YES" : "NO",
            skip_unmatched ? "YES" : "NO",
            max_lookahead);
}

/**
 * 获取strace重放统计信息
 */
void rr_strace_get_replay_stats(uint64_t *total, uint64_t *matched, 
                               uint64_t *skipped, uint64_t *errors) {
    if (total) *total = g_strace_state.total_syscalls;
    if (matched) *matched = g_strace_state.matched_syscalls;
    if (skipped) *skipped = g_strace_state.skipped_syscalls;
    if (errors) *errors = g_strace_state.error_syscalls;
}

/**
 * 打印当前strace重放状态
 */
void rr_strace_print_status(void) {
    RR_INFO("STRACE_REPLAY: === Current Status ===");
    RR_INFO("STRACE_REPLAY: Enabled: %s", g_strace_state.enabled ? "YES" : "NO");
    RR_INFO("STRACE_REPLAY: Trace file: %s", 
            g_strace_state.trace_filename ? g_strace_state.trace_filename : "NULL");
    RR_INFO("STRACE_REPLAY: Current record index: %zu", g_strace_state.current_record_index);
    RR_INFO("STRACE_REPLAY: Total syscalls: %lu", g_strace_state.total_syscalls);
    RR_INFO("STRACE_REPLAY: Matched: %lu", g_strace_state.matched_syscalls);
    RR_INFO("STRACE_REPLAY: Skipped: %lu", g_strace_state.skipped_syscalls);
    RR_INFO("STRACE_REPLAY: Errors: %lu", g_strace_state.error_syscalls);
    
    if (g_strace_state.total_syscalls > 0) {
        double match_rate = (double)g_strace_state.matched_syscalls / g_strace_state.total_syscalls * 100.0;
        RR_INFO("STRACE_REPLAY: Match rate: %.2f%%", match_rate);
    }
}

/**
 * 检查strace重放是否已启用
 */
bool rr_strace_replay_enabled(void) {
    /* 移除频繁调用的日志输出以提升性能 */
    return g_strace_state.enabled;
}

/**
 * POST-HOOK: 系统调用执行后的处理
 * 用于映射输出句柄（FD、地址、PID等）
 */
void rr_strace_syscall_post_hook(CPUArchState *env, int num, abi_long ret, abi_long *args) {
    if (!g_strace_state.enabled) {
        return;
    }
    
    if (!g_current_record) {
        RR_VERBOSE("STRACE_REPLAY: POST-HOOK: No current record for syscall %d", num);
        return;
    }
    
    const char *syscall_name = get_syscall_name(num);
    /* 只在DEBUG级别输出详细的POST-HOOK信息 */
    RR_DEBUG("STRACE_REPLAY: Post-hook for %s, recorded_ret=%d, actual_ret=%d", 
             syscall_name ? syscall_name : "unknown", 
             (int)g_current_record->ret_value, (int)ret);
    
    /* 映射输出句柄 */
    if (strcmp(g_current_record->syscall_name, "openat") == 0) {
        if (ret >= 0 && g_current_record->ret_value >= 0) {
            add_fd_mapping_simple(g_current_record->ret_value, ret);
            RR_DEBUG("POST_HOOK: FD mapping added: %d → %d (openat)", 
                     (int)g_current_record->ret_value, (int)ret);
        }
    } else if (strcmp(g_current_record->syscall_name, "close") == 0) {
        if (ret == 0 && g_current_record->ret_value == 0) {
            remove_fd_mapping_simple((int)g_current_record->args[0].value);
            RR_DEBUG("POST_HOOK: FD mapping removed: %d (close)", 
                     (int)g_current_record->args[0].value);
        }
    } else if (strcmp(g_current_record->syscall_name, "pipe") == 0 ||
               strcmp(g_current_record->syscall_name, "pipe2") == 0) {
        /* pipe返回两个FD：[0]读端，[1]写端 */
        /* 注意：pipe的FD信息通常在参数中，这里简化处理 */
        if (ret == 0 && g_current_record->ret_value == 0) {
            RR_DEBUG("POST_HOOK: Pipe syscall completed successfully, but FD mapping requires more complex parsing");
            /* TODO: 实现完整的pipe FD解析 */
        }
    } else if (strcmp(g_current_record->syscall_name, "dup") == 0 ||
               strcmp(g_current_record->syscall_name, "dup2") == 0 ||
               strcmp(g_current_record->syscall_name, "dup3") == 0) {
        /* dup系列返回新的FD */
        if (ret >= 0 && g_current_record->ret_value >= 0) {
            add_fd_mapping_simple(g_current_record->ret_value, ret);
            RR_DEBUG("POST_HOOK: FD mapping added: %d → %d (%s)", 
                     (int)g_current_record->ret_value, (int)ret, g_current_record->syscall_name);
        }
    } else if (strcmp(g_current_record->syscall_name, "fork") == 0 ||
               strcmp(g_current_record->syscall_name, "vfork") == 0 ||
               strcmp(g_current_record->syscall_name, "clone") == 0) {
        /* fork系列返回PID，需要PID映射 */
        if (ret > 0 && g_current_record->ret_value > 0) {
            /* 这里应该有PID映射机制，暂时用FD映射表代替 */
            add_fd_mapping_simple(g_current_record->ret_value, ret);
            RR_DEBUG("POST_HOOK: PID mapping added: %d → %d (%s)", 
                     (int)g_current_record->ret_value, (int)ret, g_current_record->syscall_name);
        }
    } else if (strcmp(g_current_record->syscall_name, "socket") == 0 ||
               strcmp(g_current_record->syscall_name, "socketpair") == 0 ||
               strcmp(g_current_record->syscall_name, "accept") == 0 ||
               strcmp(g_current_record->syscall_name, "accept4") == 0) {
        /* socket系列返回socket FD */
        if (ret >= 0 && g_current_record->ret_value >= 0) {
            add_fd_mapping_simple(g_current_record->ret_value, ret);
            RR_DEBUG("POST_HOOK: Socket FD mapping added: %d → %d (%s)", 
                     (int)g_current_record->ret_value, (int)ret, g_current_record->syscall_name);
        }
    } else if (strcmp(g_current_record->syscall_name, "mmap") == 0) {
        /* mmap返回内存地址 */
        if ((void*)ret != MAP_FAILED && g_current_record->ret_value != (target_ulong)MAP_FAILED) {
            target_ulong recorded_addr = (target_ulong)g_current_record->ret_value;
            target_ulong actual_addr = (target_ulong)ret;
            size_t size = (size_t)g_current_record->args[1].value;  // length参数
            
            add_addr_mapping(recorded_addr, actual_addr, size);
            RR_DEBUG("POST_HOOK: mmap address mapping added: 0x%x → 0x%x (size=%zu)", 
                     (unsigned int)recorded_addr, (unsigned int)actual_addr, size);
        }
    } else if (strcmp(g_current_record->syscall_name, "munmap") == 0) {
        /* munmap释放内存地址映射 */
        if (ret == 0 && g_current_record->ret_value == 0) {
            target_ulong recorded_addr = (target_ulong)g_current_record->args[0].value;
            remove_addr_mapping(recorded_addr);
            RR_DEBUG("POST_HOOK: munmap address mapping removed: 0x%x", (unsigned int)recorded_addr);
        }
    } else if (strcmp(g_current_record->syscall_name, "brk") == 0) {
        /* brk返回新的堆顶地址 */
        if (ret > 0 && g_current_record->ret_value > 0) {
            target_ulong recorded_addr = (target_ulong)g_current_record->ret_value;
            target_ulong actual_addr = (target_ulong)ret;
            
            // brk的映射比较特殊，这里简单处理
            add_addr_mapping(recorded_addr, actual_addr, 4096);  // 假设页大小
            RR_DEBUG("POST_HOOK: brk address mapping added: 0x%x → 0x%x", 
                     (unsigned int)recorded_addr, (unsigned int)actual_addr);
        }
    }
    
    /* 清理当前记录 */
    g_current_record = NULL;
}

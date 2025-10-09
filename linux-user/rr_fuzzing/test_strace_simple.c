/**
 * 简化的RR-Fuzz Strace重放功能测试程序
 * 不依赖完整的框架，专注测试解析器和重放逻辑
 */

#include "rr_syscallparser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdint.h>

/* 简化的类型定义 */
typedef long abi_long;
typedef unsigned long target_ulong;
typedef struct CPUArchState {
    int dummy;
} CPUArchState;

/* 简化的调试宏 */
#define RR_ERROR(fmt, ...) printf("ERROR: " fmt "\n", ##__VA_ARGS__)
#define RR_INFO(fmt, ...) printf("INFO: " fmt "\n", ##__VA_ARGS__)
#define RR_VERBOSE(fmt, ...) printf("VERBOSE: " fmt "\n", ##__VA_ARGS__)
#define RR_WARN(fmt, ...) printf("WARN: " fmt "\n", ##__VA_ARGS__)

/* 模拟系统调用名称映射 */
const char* get_syscall_name(int syscall_nr) {
    switch (syscall_nr) {
        case 0: return "read";
        case 1: return "write";
        case 3: return "close";
        case 9: return "mmap";
        case 12: return "brk";
        case 21: return "access";
        case 39: return "getpid";
        case 63: return "uname";
        case 257: return "openat";
        case 262: return "newfstatat";
        default: return "unknown";
    }
}

/**
 * 简化的strace重放器
 */
typedef struct {
    rr_strace_parser_t *parser;
    bool enabled;
    uint64_t total_calls;
    uint64_t matched_calls;
    uint64_t skipped_calls;
} simple_strace_replayer_t;

static simple_strace_replayer_t g_replayer = {0};

/**
 * 初始化简化重放器
 */
int simple_strace_init(const char *trace_file) {
    g_replayer.parser = rr_strace_parser_init(trace_file);
    if (!g_replayer.parser) {
        RR_ERROR("Failed to init parser");
        return -1;
    }
    
    if (rr_strace_parser_load(g_replayer.parser) != 0) {
        RR_ERROR("Failed to load trace file");
        rr_strace_parser_cleanup(g_replayer.parser);
        return -1;
    }
    
    g_replayer.enabled = true;
    
    size_t total_records, current_index;
    rr_strace_get_stats(g_replayer.parser, &total_records, &current_index);
    RR_INFO("Loaded %zu records from trace file", total_records);
    
    return 0;
}

/**
 * 查找匹配的记录
 */
rr_strace_record_t *find_next_matching_record(int syscall_nr) {
    const char *syscall_name = get_syscall_name(syscall_nr);
    
    /* 最多前瞻5条记录 */
    for (int i = 0; i < 5; i++) {
        rr_strace_record_t *record = rr_strace_parser_get_next(g_replayer.parser);
        if (!record) {
            RR_VERBOSE("No more records available");
            return NULL;
        }
        
        if (strcmp(record->syscall_name, syscall_name) == 0) {
            RR_VERBOSE("Found matching record: %s", record->syscall_name);
            return record;
        } else {
            RR_VERBOSE("Skipping record: expected %s, got %s", syscall_name, record->syscall_name);
            g_replayer.skipped_calls++;
        }
    }
    
    return NULL;
}

/**
 * 简化的重放函数
 */
abi_long simple_strace_replay(int syscall_nr, abi_long *args) {
    if (!g_replayer.enabled) {
        return -1;
    }
    
    g_replayer.total_calls++;
    
    rr_strace_record_t *record = find_next_matching_record(syscall_nr);
    if (!record) {
        RR_WARN("No matching record for syscall %s (%d)", get_syscall_name(syscall_nr), syscall_nr);
        return -1;  /* 让系统执行 */
    }
    
    g_replayer.matched_calls++;
    
    RR_VERBOSE("Replaying %s: ret=%ld, error=%d", 
              record->syscall_name, record->ret_value, record->has_error);
    
    if (record->has_error) {
        errno = record->error_code;
        return -1;
    }
    
    return record->ret_value;
}

/**
 * 清理资源
 */
void simple_strace_cleanup(void) {
    if (g_replayer.parser) {
        rr_strace_parser_cleanup(g_replayer.parser);
        g_replayer.parser = NULL;
    }
    
    RR_INFO("=== Replay Statistics ===");
    RR_INFO("Total calls: %llu", (unsigned long long)g_replayer.total_calls);
    RR_INFO("Matched calls: %llu", (unsigned long long)g_replayer.matched_calls);
    RR_INFO("Skipped calls: %llu", (unsigned long long)g_replayer.skipped_calls);
    
    if (g_replayer.total_calls > 0) {
        double match_rate = (double)g_replayer.matched_calls / g_replayer.total_calls * 100.0;
        RR_INFO("Match rate: %.2f%%", match_rate);
    }
    
    memset(&g_replayer, 0, sizeof(g_replayer));
}

/**
 * 测试用例
 */
typedef struct {
    const char *name;
    int syscall_nr;
    abi_long args[4];
} test_case_t;

static const test_case_t test_cases[] = {
    {"brk test", 12, {0}},
    {"uname test", 63, {0x7079a7ffe640}},
    {"access test", 21, {(abi_long)"/etc/ld.so.preload", 4}},
    {"openat test", 257, {-100, (abi_long)"/etc/ld.so.cache", 524288}},
    {"openat test 2", 257, {-100, (abi_long)"/lib/x86_64-linux-gnu/libselinux.so.1", 524288}},
    {"close test", 3, {5}},
};

static const int num_test_cases = sizeof(test_cases) / sizeof(test_cases[0]);

/**
 * 运行测试
 */
void run_tests(void) {
    printf("\n=== Running Test Cases ===\n");
    
    for (int i = 0; i < num_test_cases; i++) {
        const test_case_t *test = &test_cases[i];
        printf("\nTest %d: %s\n", i + 1, test->name);
        
        abi_long result = simple_strace_replay(test->syscall_nr, (abi_long*)test->args);
        
        printf("  Syscall: %s (%d)\n", get_syscall_name(test->syscall_nr), test->syscall_nr);
        printf("  Result: %ld\n", result);
        if (result == -1) {
            printf("  Errno: %d (%s)\n", errno, strerror(errno));
        }
    }
}

int main(int argc, char *argv[]) {
    const char *trace_file = "/home/webfuzz/Downloads/strace_final_trace.dat";
    
    if (argc > 1) {
        trace_file = argv[1];
    }
    
    printf("=== Simple Strace Replay Test ===\n");
    printf("Trace file: %s\n", trace_file);
    
    /* 初始化 */
    if (simple_strace_init(trace_file) < 0) {
        return 1;
    }
    
    /* 运行测试 */
    run_tests();
    
    /* 清理 */
    simple_strace_cleanup();
    
    return 0;
}

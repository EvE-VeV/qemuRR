/**
 * RR-Fuzz Strace重放功能测试程序
 */

#include "rr_framework.h"
#include "rr_replay_strace.h"
#include "rr_syscallparser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mock QEMU types and functions */
typedef struct CPUArchState {
    int dummy;
} CPUArchState;

/* Mock debugging macros */
#ifndef RR_ERROR
#define RR_ERROR(fmt, ...) printf("ERROR: " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef RR_INFO
#define RR_INFO(fmt, ...) printf("INFO: " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef RR_VERBOSE
#define RR_VERBOSE(fmt, ...) printf("VERBOSE: " fmt "\n", ##__VA_ARGS__)
#endif
#ifndef RR_WARN
#define RR_WARN(fmt, ...) printf("WARN: " fmt "\n", ##__VA_ARGS__)
#endif

/* Mock global variables */
target_ulong g_pending_mmap_recorded_addr = 0;

/* Mock syscall name function */
const char* get_syscall_name(int syscall_nr) {
    switch (syscall_nr) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
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

/* Test case structure */
typedef struct {
    const char *name;
    int syscall_nr;
    abi_long args[8];
    abi_long expected_ret;
    int expected_errno;
    bool should_succeed;
} test_case_t;

/* Test cases based on the strace file */
static const test_case_t test_cases[] = {
    /* brk(NULL) = 0x000055555557a000 */
    {
        .name = "brk test",
        .syscall_nr = 12,
        .args = {0, 0, 0, 0, 0, 0, 0, 0},
        .expected_ret = 0x000055555557a000,
        .should_succeed = true
    },
    
    /* uname(0x7079a7ffe640) = 0 */
    {
        .name = "uname test", 
        .syscall_nr = 63,
        .args = {0x7079a7ffe640, 0, 0, 0, 0, 0, 0, 0},
        .expected_ret = 0,
        .should_succeed = true
    },
    
    /* access("/etc/ld.so.preload",R_OK) = -1 errno=2 (No such file or directory) */
    {
        .name = "access test (should fail)",
        .syscall_nr = 21,
        .args = {(abi_long)"/etc/ld.so.preload", 4, 0, 0, 0, 0, 0, 0},  /* R_OK = 4 */
        .expected_ret = -1,
        .expected_errno = 2,
        .should_succeed = false
    },
    
    /* openat(-100,"/etc/ld.so.cache",O_RDONLY|O_CLOEXEC) = 5 */
    {
        .name = "openat test",
        .syscall_nr = 257,
        .args = {-100, (abi_long)"/etc/ld.so.cache", 524288, 0, 0, 0, 0, 0},
        .expected_ret = 5,  /* 但实际会被映射 */
        .should_succeed = true
    }
};

static const int num_test_cases = sizeof(test_cases) / sizeof(test_cases[0]);

/**
 * 运行单个测试用例
 */
static bool run_test_case(const test_case_t *test) {
    printf("\n=== Running test: %s ===\n", test->name);
    
    CPUArchState env = {0};
    abi_long args[8];
    memcpy(args, test->args, sizeof(args));
    
    /* 重置errno */
    errno = 0;
    
    /* 调用strace重放函数 */
    abi_long result = rr_replay_syscall_strace(&env, test->syscall_nr, args);
    
    printf("  Syscall: %s (%d)\n", get_syscall_name(test->syscall_nr), test->syscall_nr);
    printf("  Expected: %ld, Got: %ld\n", test->expected_ret, result);
    printf("  errno: %d\n", errno);
    
    /* 检查结果 */
    bool success = true;
    
    if (test->should_succeed) {
        if (result == -1) {
            printf("  RESULT: PASS (let system execute)\n");
        } else if (result != test->expected_ret) {
            /* 对于openat等会产生FD映射的调用，返回值可能不同 */
            if (test->syscall_nr == 257 && result > 0) {
                printf("  RESULT: PASS (FD mapped: %ld -> %ld)\n", test->expected_ret, result);
            } else {
                printf("  RESULT: FAIL (wrong return value)\n");
                success = false;
            }
        } else {
            printf("  RESULT: PASS\n");
        }
    } else {
        if (result == -1 && errno == test->expected_errno) {
            printf("  RESULT: PASS (failed as expected)\n");
        } else {
            printf("  RESULT: FAIL (should have failed with errno %d)\n", test->expected_errno);
            success = false;
        }
    }
    
    return success;
}

/**
 * 运行所有测试
 */
static void run_all_tests(void) {
    printf("=== RR-Fuzz Strace Replay Test Suite ===\n");
    
    int passed = 0;
    int total = num_test_cases;
    
    for (int i = 0; i < num_test_cases; i++) {
        if (run_test_case(&test_cases[i])) {
            passed++;
        }
    }
    
    printf("\n=== Test Summary ===\n");
    printf("Total tests: %d\n", total);
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", total - passed);
    printf("Success rate: %.2f%%\n", (double)passed / total * 100.0);
}

/**
 * 测试配置功能
 */
static void test_configuration(void) {
    printf("\n=== Testing Configuration ===\n");
    
    /* 测试模式设置 */
    rr_strace_set_mode(false, true, 3);
    printf("Set mode: strict=false, skip=true, lookahead=3\n");
    
    /* 测试统计获取 */
    uint64_t total, matched, skipped, errors;
    rr_strace_get_replay_stats(&total, &matched, &skipped, &errors);
    printf("Stats: total=%lu, matched=%lu, skipped=%lu, errors=%lu\n", 
           total, matched, skipped, errors);
    
    /* 打印状态 */
    rr_strace_print_status();
}

int main(int argc, char *argv[]) {
    const char *trace_file = "/home/webfuzz/Downloads/strace_final_trace.dat";
    
    if (argc > 1) {
        trace_file = argv[1];
    }
    
    printf("=== RR-Fuzz Strace Replay Test ===\n");
    printf("Trace file: %s\n", trace_file);
    
    /* 初始化strace重放 */
    if (rr_strace_replay_init(trace_file) < 0) {
        RR_ERROR("Failed to initialize strace replay");
        return 1;
    }
    
    /* 测试配置功能 */
    test_configuration();
    
    /* 运行功能测试 */
    run_all_tests();
    
    /* 清理 */
    rr_strace_replay_cleanup();
    
    return 0;
}

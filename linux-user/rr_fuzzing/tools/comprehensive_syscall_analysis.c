#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// 系统调用分类和处理状态
typedef enum {
    HANDLED_FULL,      // 完全处理（参数+返回数据）
    HANDLED_PARTIAL,   // 部分处理（仅参数或仅返回）
    HANDLED_BASIC,     // 基础处理（仅返回值）
    NOT_HANDLED        // 未处理
} syscall_status_t;

typedef struct {
    int nr;
    const char* name;
    const char* category;
    syscall_status_t status;
    const char* missing_data;
    const char* risk_level;
} syscall_info_t;

// 系统调用信息表
syscall_info_t syscalls[] = {
    // 内存管理
    {9, "mmap", "Memory", HANDLED_BASIC, "Address remapping logic", "MEDIUM"},
    {10, "mprotect", "Memory", HANDLED_BASIC, "None", "LOW"},
    {11, "munmap", "Memory", HANDLED_BASIC, "None", "LOW"},
    {12, "brk", "Memory", HANDLED_BASIC, "None", "LOW"},

    // 文件I/O - 已处理
    {0, "read", "I/O", HANDLED_FULL, "None", "LOW"},
    {1, "write", "I/O", HANDLED_PARTIAL, "Output verification", "LOW"},
    {3, "close", "I/O", HANDLED_BASIC, "None", "LOW"},
    {17, "pread64", "I/O", HANDLED_BASIC, "Buffer data", "MEDIUM"},
    {18, "pwrite64", "I/O", HANDLED_BASIC, "Buffer data", "MEDIUM"},

    // 文件操作 - 已处理
    {257, "openat", "File", HANDLED_FULL, "None", "LOW"},
    {269, "faccessat", "File", HANDLED_FULL, "None", "LOW"},
    {21, "access", "File", NOT_HANDLED, "Path string", "HIGH"},

    // 文件状态 - 部分处理
    {262, "newfstatat", "File", HANDLED_PARTIAL, "Struct stat data", "HIGH"},
    {4, "stat", "File", NOT_HANDLED, "Path + struct stat", "HIGH"},
    {5, "fstat", "File", NOT_HANDLED, "Struct stat data", "HIGH"},
    {6, "lstat", "File", NOT_HANDLED, "Path + struct stat", "HIGH"},

    // 系统信息 - 部分处理
    {63, "uname", "System", HANDLED_FULL, "None", "LOW"},
    {39, "getpid", "System", HANDLED_BASIC, "Deterministic override", "LOW"},
    {102, "getuid", "System", HANDLED_BASIC, "Deterministic override", "LOW"},
    {104, "getgid", "System", HANDLED_BASIC, "Deterministic override", "LOW"},

    // 目录操作 - 部分处理
    {217, "getdents64", "Directory", HANDLED_FULL, "None", "LOW"},

    // 网络/IPC - 未处理
    {41, "socket", "Network", NOT_HANDLED, "Socket type/options", "HIGH"},
    {42, "connect", "Network", NOT_HANDLED, "Address structure", "HIGH"},
    {43, "accept", "Network", NOT_HANDLED, "Address structure", "HIGH"},
    {44, "sendto", "Network", NOT_HANDLED, "Buffer + address", "HIGH"},
    {45, "recvfrom", "Network", NOT_HANDLED, "Buffer + address", "HIGH"},

    // 进程控制 - 未处理
    {56, "clone", "Process", NOT_HANDLED, "Complex state", "CRITICAL"},
    {57, "fork", "Process", NOT_HANDLED, "Process state", "CRITICAL"},
    {59, "execve", "Process", HANDLED_PARTIAL, "argv/envp arrays", "HIGH"},
    {60, "exit", "Process", HANDLED_BASIC, "None", "LOW"},
    {61, "wait4", "Process", NOT_HANDLED, "Status structure", "MEDIUM"},

    // 信号处理 - 未处理
    {13, "rt_sigaction", "Signal", NOT_HANDLED, "sigaction structure", "HIGH"},
    {14, "rt_sigprocmask", "Signal", NOT_HANDLED, "Signal set", "MEDIUM"},

    // 时间相关 - 未处理
    {96, "gettimeofday", "Time", NOT_HANDLED, "timeval structure", "HIGH"},
    {228, "clock_gettime", "Time", NOT_HANDLED, "timespec structure", "HIGH"},

    // 非确定性调用
    {318, "getrandom", "Random", HANDLED_BASIC, "Random data buffer", "CRITICAL"},
    {218, "set_tid_address", "System", HANDLED_BASIC, "Deterministic override", "MEDIUM"},

    // 架构特定
    {158, "arch_prctl", "Arch", HANDLED_BASIC, "None", "LOW"},

    // 控制/配置
    {16, "ioctl", "Control", HANDLED_BASIC, "Command-specific data", "HIGH"},
    {302, "prlimit64", "Control", HANDLED_BASIC, "Resource limit struct", "MEDIUM"},
    {273, "set_robust_list", "Control", HANDLED_BASIC, "None", "LOW"},
    {334, "rseq", "Control", HANDLED_BASIC, "None", "LOW"},
};

const int num_syscalls = sizeof(syscalls) / sizeof(syscall_info_t);

const char* status_str(syscall_status_t status) {
    switch(status) {
        case HANDLED_FULL: return "FULL";
        case HANDLED_PARTIAL: return "PARTIAL";
        case HANDLED_BASIC: return "BASIC";
        case NOT_HANDLED: return "NONE";
        default: return "UNKNOWN";
    }
}

int main(int argc, char *argv[]) {
    printf("=== RR-Fuzz 系统调用处理状态完整分析 ===\n\n");

    // 统计信息
    int count_full = 0, count_partial = 0, count_basic = 0, count_none = 0;
    int critical = 0, high = 0, medium = 0, low = 0;

    // 按类别分组显示
    const char* categories[] = {"Memory", "I/O", "File", "System", "Directory",
                               "Network", "Process", "Signal", "Time", "Random",
                               "Arch", "Control"};
    int num_categories = sizeof(categories) / sizeof(categories[0]);

    for (int cat = 0; cat < num_categories; cat++) {
        printf("=== %s 系统调用 ===\n", categories[cat]);
        printf("%-4s %-16s %-10s %-12s %s\n", "NR", "NAME", "STATUS", "RISK", "MISSING_DATA");
        printf("------------------------------------------------------------------------\n");

        int found_in_category = 0;
        for (int i = 0; i < num_syscalls; i++) {
            if (strcmp(syscalls[i].category, categories[cat]) == 0) {
                printf("%-4d %-16s %-10s %-12s %s\n",
                       syscalls[i].nr, syscalls[i].name, status_str(syscalls[i].status),
                       syscalls[i].risk_level, syscalls[i].missing_data);

                // 统计
                switch(syscalls[i].status) {
                    case HANDLED_FULL: count_full++; break;
                    case HANDLED_PARTIAL: count_partial++; break;
                    case HANDLED_BASIC: count_basic++; break;
                    case NOT_HANDLED: count_none++; break;
                }

                if (strcmp(syscalls[i].risk_level, "CRITICAL") == 0) critical++;
                else if (strcmp(syscalls[i].risk_level, "HIGH") == 0) high++;
                else if (strcmp(syscalls[i].risk_level, "MEDIUM") == 0) medium++;
                else low++;

                found_in_category = 1;
            }
        }
        if (found_in_category) printf("\n");
    }

    // 总体统计
    printf("=== 处理状态统计 ===\n");
    printf("完全处理 (FULL):    %2d (%.1f%%)\n", count_full, count_full*100.0/(count_full+count_partial+count_basic+count_none));
    printf("部分处理 (PARTIAL): %2d (%.1f%%)\n", count_partial, count_partial*100.0/(count_full+count_partial+count_basic+count_none));
    printf("基础处理 (BASIC):   %2d (%.1f%%)\n", count_basic, count_basic*100.0/(count_full+count_partial+count_basic+count_none));
    printf("未处理 (NONE):      %2d (%.1f%%)\n", count_none, count_none*100.0/(count_full+count_partial+count_basic+count_none));
    printf("总计:               %2d\n", count_full+count_partial+count_basic+count_none);

    printf("\n=== 风险等级统计 ===\n");
    printf("严重 (CRITICAL): %2d\n", critical);
    printf("高   (HIGH):     %2d\n", high);
    printf("中   (MEDIUM):   %2d\n", medium);
    printf("低   (LOW):      %2d\n", low);

    // 整体就绪度评分
    double readiness = (count_full*1.0 + count_partial*0.7 + count_basic*0.3) / (count_full+count_partial+count_basic+count_none) * 100.0;
    printf("\n=== 整体评估 ===\n");
    printf("当前就绪度评分: %.1f%%\n", readiness);

    if (readiness >= 80.0) {
        printf("🟢 状态: 基本就绪，可进行生产环境测试\n");
    } else if (readiness >= 60.0) {
        printf("🟡 状态: 部分就绪，需要针对性改进\n");
    } else {
        printf("🔴 状态: 不够就绪，需要大量改进工作\n");
    }

    return 0;
}
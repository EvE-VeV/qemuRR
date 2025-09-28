#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// 系统调用名称映射表
const char* get_syscall_name(int nr) {
    static const char* names[400] = {0};
    static int initialized = 0;

    if (!initialized) {
        names[0] = "read"; names[1] = "write"; names[2] = "open"; names[3] = "close";
        names[4] = "stat"; names[5] = "fstat"; names[6] = "lstat"; names[7] = "poll";
        names[8] = "lseek"; names[9] = "mmap"; names[10] = "mprotect"; names[11] = "munmap";
        names[12] = "brk"; names[13] = "rt_sigaction"; names[14] = "rt_sigprocmask"; names[15] = "rt_sigreturn";
        names[16] = "ioctl"; names[17] = "pread64"; names[18] = "pwrite64"; names[19] = "readv";
        names[20] = "writev"; names[21] = "access"; names[22] = "pipe"; names[23] = "select";
        names[39] = "getpid"; names[63] = "uname"; names[102] = "getuid"; names[104] = "getgid";
        names[158] = "arch_prctl"; names[217] = "getdents64"; names[218] = "set_tid_address";
        names[231] = "exit_group"; names[257] = "openat"; names[262] = "newfstatat";
        names[273] = "set_robust_list"; names[302] = "prlimit64"; names[318] = "getrandom";
        names[334] = "rseq"; names[137] = "statfs";
        initialized = 1;
    }

    if (nr >= 0 && nr < 400 && names[nr]) {
        return names[nr];
    }
    return "unknown";
}

// 检查replay关键问题
typedef struct {
    int total_syscalls;
    int needs_string_data;      // 需要字符串数据的系统调用数
    int needs_buffer_data;      // 需要缓冲区数据的系统调用数
    int has_string_data;        // 实际有字符串数据的系统调用数
    int has_buffer_data;        // 实际有缓冲区数据的系统调用数
    int fd_creating_calls;      // 创建FD的系统调用数
    int memory_dependent;       // 依赖内存地址的系统调用数
    int deterministic_issues;   // 可能有非确定性问题的系统调用数
} replay_readiness_t;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <rr_trace_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("Cannot open RR trace file: %s\n", argv[1]);
        return 1;
    }

    // 读取RR trace文件头
    uint32_t magic, version, count;
    fread(&magic, 4, 1, f);
    fread(&version, 4, 1, f);
    fread(&count, 4, 1, f);

    printf("=== RR-Fuzz Replay Readiness Analysis ===\n");
    printf("Trace File: %s\n", argv[1]);
    printf("Magic: 0x%x, Version: %u, Total Records: %u\n\n", magic, version, count);

    replay_readiness_t analysis = {0};
    analysis.total_syscalls = count;

    printf("=== Critical Replay Issues Analysis ===\n");
    printf("%-4s %-15s %-20s %-12s %-12s %s\n",
           "IDX", "NAME", "RETVAL", "ARG_DATA", "REPLAY_RISK", "ISSUE");
    printf("--------------------------------------------------------------------------------\n");

    for (int i = 0; i < count; i++) {
        uint32_t index;
        int32_t syscall_nr;
        int64_t args[8];
        int64_t retval;
        size_t arg_size[8];
        uint8_t creates_fd, uses_fd;
        int32_t created_fd;

        // 读取记录的各个字段
        if (fread(&index, 4, 1, f) != 1 || fread(&syscall_nr, 4, 1, f) != 1) {
            break;
        }

        // 读取参数和返回值
        fread(args, sizeof(int64_t) * 8, 1, f);
        fread(&retval, sizeof(int64_t), 1, f);
        fread(arg_size, sizeof(size_t) * 8, 1, f);
        fread(&creates_fd, 1, 1, f);
        fread(&uses_fd, 1, 1, f);
        fread(&created_fd, 4, 1, f);

        const char *name = get_syscall_name(syscall_nr);

        // 分析replay关键问题
        const char *risk = "LOW";
        const char *issue = "OK";
        int has_arg_data = 0;

        // 检查参数数据
        for (int j = 0; j < 8; j++) {
            if (arg_size[j] > 0) {
                has_arg_data = 1;
                break;
            }
        }

        // 分析不同系统调用的replay需求
        switch (syscall_nr) {
            case 0: // read
                analysis.needs_buffer_data++;
                if (has_arg_data) analysis.has_buffer_data++;
                if (!has_arg_data && retval > 0) {
                    risk = "CRITICAL";
                    issue = "Missing read buffer data";
                }
                break;

            case 1: // write
                analysis.needs_buffer_data++;
                if (has_arg_data) analysis.has_buffer_data++;
                if (!has_arg_data && retval > 0) {
                    risk = "HIGH";
                    issue = "Missing write buffer data";
                }
                break;

            case 2: // open
            case 257: // openat
                analysis.needs_string_data++;
                if (has_arg_data) analysis.has_string_data++;
                if (!has_arg_data) {
                    risk = "CRITICAL";
                    issue = "Missing filename string";
                }
                if (creates_fd) analysis.fd_creating_calls++;
                break;

            case 269: // faccessat
                analysis.needs_string_data++;
                if (has_arg_data) analysis.has_string_data++;
                if (!has_arg_data) {
                    risk = "HIGH";
                    issue = "Missing access path string";
                }
                break;

            case 9: // mmap
                analysis.memory_dependent++;
                if (retval != -1) {
                    risk = "MEDIUM";
                    issue = "Address remapping needed";
                }
                break;

            case 217: // getdents64
                analysis.needs_buffer_data++;
                if (has_arg_data) analysis.has_buffer_data++;
                if (!has_arg_data && retval > 0) {
                    risk = "CRITICAL";
                    issue = "Missing directory entries";
                }
                break;

            case 63: // uname
            case 262: // newfstatat/fstatat
                analysis.needs_buffer_data++;
                if (has_arg_data) analysis.has_buffer_data++;
                if (!has_arg_data && retval == 0) {
                    risk = "HIGH";
                    issue = "Missing struct data";
                }
                break;

            case 318: // getrandom
            case 20: // getpid (if not overridden)
            case 218: // set_tid_address
                analysis.deterministic_issues++;
                risk = "MEDIUM";
                issue = "Non-deterministic call";
                break;
        }

        // 简化显示参数数据状态
        char arg_status[13] = "NO";
        if (has_arg_data) strcpy(arg_status, "YES");

        printf("%-4u %-15s %-20ld %-12s %-12s %s\n",
               index, name, retval, arg_status, risk, issue);

        // 跳过参数数据
        int arg_index;
        do {
            if (fread(&arg_index, sizeof(int), 1, f) != 1) break;
            if (arg_index == -1) break;
            size_t size;
            if (fread(&size, sizeof(size_t), 1, f) != 1) break;
            fseek(f, size, SEEK_CUR);
        } while (arg_index != -1);
    }

    printf("\n=== Replay Readiness Summary ===\n");
    printf("Total system calls: %d\n", analysis.total_syscalls);
    printf("Calls needing string data: %d (have: %d)\n",
           analysis.needs_string_data, analysis.has_string_data);
    printf("Calls needing buffer data: %d (have: %d)\n",
           analysis.needs_buffer_data, analysis.has_buffer_data);
    printf("FD-creating calls: %d\n", analysis.fd_creating_calls);
    printf("Memory-dependent calls: %d\n", analysis.memory_dependent);
    printf("Non-deterministic calls: %d\n", analysis.deterministic_issues);

    printf("\n=== Critical Issues ===\n");
    if (analysis.needs_string_data > analysis.has_string_data) {
        printf("⚠️  CRITICAL: Missing %d string parameters needed for replay\n",
               analysis.needs_string_data - analysis.has_string_data);
    }
    if (analysis.needs_buffer_data > analysis.has_buffer_data) {
        printf("⚠️  HIGH: Missing %d buffer contents needed for replay\n",
               analysis.needs_buffer_data - analysis.has_buffer_data);
    }
    if (analysis.memory_dependent > 0) {
        printf("⚠️  MEDIUM: %d memory-dependent calls need address remapping\n",
               analysis.memory_dependent);
    }

    printf("\n=== Recommendation ===\n");
    double readiness = 0.0;
    int total_critical = analysis.needs_string_data + analysis.needs_buffer_data;
    int total_have = analysis.has_string_data + analysis.has_buffer_data;

    if (total_critical > 0) {
        readiness = (double)total_have / total_critical * 100.0;
    } else {
        readiness = 100.0; // No critical data needed
    }

    printf("Replay Readiness Score: %.1f%%\n", readiness);

    if (readiness >= 90.0) {
        printf("✅ READY: Should replay successfully\n");
    } else if (readiness >= 70.0) {
        printf("⚠️  PARTIAL: May replay with some issues\n");
    } else {
        printf("❌ NOT READY: Likely to fail replay due to missing data\n");
    }

    fclose(f);
    return 0;
}
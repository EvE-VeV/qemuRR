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
        names[334] = "rseq";
        initialized = 1;
    }

    if (nr >= 0 && nr < 400 && names[nr]) {
        return names[nr];
    }
    return "unknown";
}

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

    printf("=== RR-Fuzz Complete Trace Analysis ===\n");
    printf("Magic: 0x%x, Version: %u, Total Records: %u\n\n", magic, version, count);

    printf("=== Complete System Call Sequence ===\n");
    printf("%-4s %-3s %-15s %-20s %-15s %s\n", "IDX", "NR", "NAME", "RETVAL", "TYPE", "ARGS[0]");
    printf("--------------------------------------------------------------------------------\n");

    int non_deterministic_count = 0;
    int memory_calls = 0;
    int io_calls = 0;
    int fd_creating_calls = 0;

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

        // 分析系统调用类型
        const char *type = "NORMAL";
        if (creates_fd) {
            type = "FD_CREATE";
            fd_creating_calls++;
        } else if (syscall_nr == 20 || syscall_nr == 218 || syscall_nr == 318) {
            type = "NON_DETERM";
            non_deterministic_count++;
        } else if (syscall_nr == 9 || syscall_nr == 10 || syscall_nr == 11 || syscall_nr == 12) {
            type = "MEMORY";
            memory_calls++;
        } else if (syscall_nr == 0 || syscall_nr == 1 || syscall_nr == 17) {
            type = "IO";
            io_calls++;
        } else if (syscall_nr == 231) {
            type = "TERMINATION";
        }

        printf("%-4u %-3d %-15s %-20ld %-15s 0x%lx\n",
               index, syscall_nr, name, retval, type, args[0]);

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

    printf("\n=== Statistical Analysis ===\n");
    printf("Total syscalls: %u\n", count);
    printf("Non-deterministic calls: %d\n", non_deterministic_count);
    printf("Memory management calls: %d\n", memory_calls);
    printf("I/O calls: %d\n", io_calls);
    printf("FD creating calls: %d\n", fd_creating_calls);

    fclose(f);
    return 0;
}
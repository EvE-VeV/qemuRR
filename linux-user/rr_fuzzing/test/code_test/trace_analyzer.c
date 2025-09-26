#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// 复制轨迹文件结构
typedef struct {
    uint32_t index;
    int32_t syscall_nr;
    long args[8];
    long retval;
    uint32_t creates_fd;
    int32_t created_fd;
    void *arg_data[8];
    size_t arg_size[8];
} syscall_record_t;

const char* get_syscall_name(int syscall_nr) {
    switch(syscall_nr) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 9: return "mmap";
        case 10: return "mprotect";
        case 11: return "munmap";
        case 12: return "brk";
        case 16: return "ioctl";
        case 17: return "pread64";
        case 21: return "access";
        case 63: return "uname";
        case 137: return "statfs";
        case 158: return "arch_prctl";
        case 217: return "getdents64";
        case 218: return "set_tid_address";
        case 257: return "openat";
        case 262: return "newfstatat";
        case 273: return "set_robust_list";
        case 302: return "prlimit64";
        case 318: return "getrandom";
        case 334: return "rseq";
        default: return "unknown";
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <trace_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // 读取文件头
    uint32_t magic, version, record_count;
    fread(&magic, sizeof(magic), 1, f);
    fread(&version, sizeof(version), 1, f);
    fread(&record_count, sizeof(record_count), 1, f);

    printf("=== RR-Fuzz Trace File Analysis ===\n");
    printf("Magic: 0x%08X (%c%c%c%c)\n", magic,
           (char)(magic & 0xFF), (char)((magic >> 8) & 0xFF),
           (char)((magic >> 16) & 0xFF), (char)((magic >> 24) & 0xFF));
    printf("Version: %u\n", version);
    printf("Record Count: %u\n", record_count);
    printf("\n=== System Call Records ===\n");

    syscall_record_t record;
    int count = 0;

    while (fread(&record, sizeof(syscall_record_t), 1, f) == 1 && count < record_count) {
        printf("[%03d] %-12s(%d) -> %ld",
               record.index,
               get_syscall_name(record.syscall_nr),
               record.syscall_nr,
               record.retval);

        if (record.creates_fd) {
            printf(" [creates_fd=%d]", record.created_fd);
        }
        printf("\n");

        // 跳过参数数据
        int arg_index;
        while (fread(&arg_index, sizeof(int), 1, f) == 1) {
            if (arg_index == -1) break; // 结束标记

            size_t size;
            fread(&size, sizeof(size_t), 1, f);
            fseek(f, size, SEEK_CUR); // 跳过数据
            printf("      arg[%d]: %zu bytes data\n", arg_index, size);
        }

        count++;
        if (count >= 10) {
            printf("... (showing first 10 records)\n");
            break;
        }
    }

    fclose(f);
    return 0;
}
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 从framework头文件复制的结构定义
typedef struct syscall_record {
    uint32_t index;
    int32_t syscall_nr;
    int64_t args[8];
    int64_t retval;
    size_t arg_size[8];
    uint8_t *arg_data[8];
    uint8_t creates_fd;
    uint8_t uses_fd;
    int32_t created_fd;
    struct syscall_record *next;
} syscall_record_t;

// 系统调用名称映射
const char* get_syscall_name(int nr) {
    static const char* names[400] = {0};
    static int initialized = 0;

    if (!initialized) {
        names[0] = "read"; names[1] = "write"; names[2] = "open"; names[3] = "close";
        names[4] = "stat"; names[5] = "fstat"; names[6] = "lstat"; names[7] = "poll";
        names[8] = "lseek"; names[9] = "mmap"; names[10] = "mprotect"; names[11] = "munmap";
        names[12] = "brk"; names[13] = "rt_sigaction"; names[14] = "rt_sigprocmask";
        names[16] = "ioctl"; names[17] = "pread64"; names[18] = "pwrite64";
        names[21] = "access"; names[39] = "getpid"; names[63] = "uname";
        names[102] = "getuid"; names[104] = "getgid"; names[158] = "arch_prctl";
        names[217] = "getdents64"; names[218] = "set_tid_address";
        names[257] = "openat"; names[262] = "newfstatat"; names[273] = "set_robust_list";
        names[302] = "prlimit64"; names[318] = "getrandom"; names[334] = "rseq";
        initialized = 1;
    }

    if (nr >= 0 && nr < 400 && names[nr]) {
        return names[nr];
    }
    return "unknown";
}

// 打印十六进制数据
void print_hex_data(const uint8_t *data, size_t size, const char* desc) {
    if (!data || size == 0) return;

    printf("    %s (%zu bytes): ", desc, size);
    if (size <= 64) {
        // 对于小数据，完整显示
        for (size_t i = 0; i < size; i++) {
            printf("%02x ", data[i]);
        }
    } else {
        // 对于大数据，显示前32和后32字节
        for (size_t i = 0; i < 32; i++) {
            printf("%02x ", data[i]);
        }
        printf("... ");
        for (size_t i = size - 32; i < size; i++) {
            printf("%02x ", data[i]);
        }
    }
    printf("\n");
}

// 尝试将数据解释为字符串
void try_print_as_string(const uint8_t *data, size_t size, const char* desc) {
    if (!data || size == 0) return;

    // 检查是否看起来像字符串
    int printable = 1;
    for (size_t i = 0; i < size - 1 && i < 256; i++) {
        if (data[i] == 0) {
            // 找到字符串结束
            break;
        }
        if (data[i] < 32 || data[i] > 126) {
            printable = 0;
            break;
        }
    }

    if (printable) {
        printf("    %s (as string): \"%.256s\"\n", desc, (char*)data);
    }
}

// 分析参数数据内容
void analyze_arg_data(int syscall_nr, int arg_idx, const uint8_t *data, size_t size) {
    if (!data || size == 0) return;

    char desc[64];
    snprintf(desc, sizeof(desc), "arg[%d] data", arg_idx);

    // 根据系统调用类型智能解析参数
    switch (syscall_nr) {
        case 257: // openat
        case 269: // faccessat
            if (arg_idx == 1) {
                try_print_as_string(data, size, "file path");
                return;
            }
            break;

        case 4: // stat
        case 5: // fstat
        case 6: // lstat
        case 262: // newfstatat
            if (arg_idx == 0 && (syscall_nr == 4 || syscall_nr == 6)) {
                try_print_as_string(data, size, "stat path");
                return;
            }
            if ((arg_idx == 1 && (syscall_nr == 5 || syscall_nr == 4 || syscall_nr == 6)) ||
                (arg_idx == 2 && syscall_nr == 262)) {
                printf("    %s (struct stat): ", desc);
                if (size >= 144) {
                    // 简单解析stat结构的几个关键字段
                    uint64_t st_dev = *(uint64_t*)data;
                    uint64_t st_ino = *(uint64_t*)(data + 8);
                    uint32_t st_mode = *(uint32_t*)(data + 24);
                    printf("dev=0x%lx ino=%lu mode=0%o\n", st_dev, st_ino, st_mode);
                } else {
                    printf("size=%zu (incomplete)\n", size);
                }
                return;
            }
            break;

        case 63: // uname
            if (arg_idx == 0) {
                printf("    %s (struct utsname):\n", desc);
                if (size >= 390) {
                    printf("      sysname: %.65s\n", (char*)data);
                    printf("      nodename: %.65s\n", (char*)(data + 65));
                    printf("      release: %.65s\n", (char*)(data + 130));
                    printf("      version: %.65s\n", (char*)(data + 195));
                    printf("      machine: %.65s\n", (char*)(data + 260));
                }
                return;
            }
            break;

        case 0: // read
        case 1: // write
            if (arg_idx == 1) {
                printf("    %s (I/O buffer, %zu bytes):\n", desc, size);
                // 尝试显示为文本（如果是可打印字符）
                int is_text = 1;
                for (size_t i = 0; i < size && i < 256; i++) {
                    if (data[i] != 0 && (data[i] < 32 || data[i] > 126) && data[i] != '\n' && data[i] != '\t') {
                        is_text = 0;
                        break;
                    }
                }
                if (is_text) {
                    printf("      (as text): \"%.256s%s\"\n",
                           (char*)data, size > 256 ? "..." : "");
                } else {
                    print_hex_data(data, size > 64 ? 64 : size, "      (hex preview)");
                }
                return;
            }
            break;

        case 217: // getdents64
            if (arg_idx == 1) {
                printf("    %s (directory entries, %zu bytes)\n", desc, size);
                // TODO: 解析dirent64结构
                return;
            }
            break;

        case 318: // getrandom
            if (arg_idx == 0) {
                printf("    %s (random data, %zu bytes): ", desc, size);
                for (size_t i = 0; i < size && i < 32; i++) {
                    printf("%02x", data[i]);
                }
                if (size > 32) printf("...");
                printf("\n");
                return;
            }
            break;
    }

    // 默认处理：显示原始数据
    print_hex_data(data, size, desc);
    try_print_as_string(data, size, desc);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <rr_trace_file>\n", argv[0]);
        printf("\nThis tool analyzes the detailed format and content of RR-Fuzz trace files.\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("Cannot open RR trace file: %s\n", argv[1]);
        return 1;
    }

    // 读取文件头
    uint32_t magic, version, count;
    if (fread(&magic, 4, 1, f) != 1 ||
        fread(&version, 4, 1, f) != 1 ||
        fread(&count, 4, 1, f) != 1) {
        printf("Failed to read trace file header\n");
        fclose(f);
        return 1;
    }

    printf("=== RR-Fuzz Trace File Format Analysis ===\n");
    printf("File: %s\n", argv[1]);
    printf("Magic: 0x%08X (%s)\n", magic, magic == 0x52525254 ? "Valid" : "Invalid");
    printf("Version: %u\n", version);
    printf("Total Records: %u\n", count);
    printf("Header Size: 12 bytes\n\n");

    if (magic != 0x52525254) {
        printf("❌ Invalid magic number! Expected 0x52525254\n");
        fclose(f);
        return 1;
    }

    printf("=== Record Format Analysis ===\n");
    printf("Each record contains:\n");
    printf("  - index (4 bytes)\n");
    printf("  - syscall_nr (4 bytes)\n");
    printf("  - args[8] (64 bytes)\n");
    printf("  - retval (8 bytes)\n");
    printf("  - arg_size[8] (64 bytes)\n");
    printf("  - creates_fd (1 byte)\n");
    printf("  - uses_fd (1 byte)\n");
    printf("  - created_fd (4 bytes)\n");
    printf("  - arg_data (variable length)\n");
    printf("  Total fixed size: 150 bytes + variable arg_data\n\n");

    // 统计信息
    uint64_t total_size = 12; // 文件头
    int records_with_data = 0;
    uint64_t total_arg_data_size = 0;

    printf("=== Detailed Record Content ===\n");

    for (int i = 0; i < count && i < 20; i++) { // 只分析前20条记录
        uint32_t index;
        int32_t syscall_nr;
        int64_t args[8];
        int64_t retval;
        size_t arg_size[8];
        uint8_t creates_fd, uses_fd;
        int32_t created_fd;

        // 读取固定部分
        if (fread(&index, 4, 1, f) != 1 ||
            fread(&syscall_nr, 4, 1, f) != 1 ||
            fread(args, sizeof(int64_t) * 8, 1, f) != 1 ||
            fread(&retval, sizeof(int64_t), 1, f) != 1 ||
            fread(arg_size, sizeof(size_t) * 8, 1, f) != 1 ||
            fread(&creates_fd, 1, 1, f) != 1 ||
            fread(&uses_fd, 1, 1, f) != 1 ||
            fread(&created_fd, 4, 1, f) != 1) {
            printf("Failed to read record %d\n", i);
            break;
        }

        total_size += 150; // 固定部分大小
        const char *name = get_syscall_name(syscall_nr);

        printf("\n--- Record #%u ---\n", index);
        printf("  Syscall: %s (%d)\n", name, syscall_nr);
        printf("  Return Value: %ld (0x%lx)\n", retval, retval);
        printf("  Creates FD: %s", creates_fd ? "yes" : "no");
        if (creates_fd) printf(" (fd=%d)", created_fd);
        printf("\n");
        printf("  Uses FD: %s\n", uses_fd ? "yes" : "no");

        printf("  Arguments:\n");
        for (int j = 0; j < 8; j++) {
            if (args[j] != 0 || arg_size[j] > 0) {
                printf("    arg[%d] = 0x%lx (%ld)", j, args[j], args[j]);
                if (arg_size[j] > 0) {
                    printf(" [has %zu bytes data]", arg_size[j]);
                }
                printf("\n");
            }
        }

        // 读取参数数据
        int has_arg_data = 0;
        while (1) {
            int arg_index;
            if (fread(&arg_index, sizeof(int), 1, f) != 1) {
                printf("Failed to read arg_index\n");
                break;
            }

            if (arg_index == -1) {
                break; // 参数数据结束标记
            }

            size_t size;
            if (fread(&size, sizeof(size_t), 1, f) != 1) {
                printf("Failed to read arg data size\n");
                break;
            }

            uint8_t *data = malloc(size);
            if (!data) {
                printf("Failed to allocate memory for arg data\n");
                fseek(f, size, SEEK_CUR);
                continue;
            }

            if (fread(data, 1, size, f) != size) {
                printf("Failed to read arg data\n");
                free(data);
                break;
            }

            has_arg_data = 1;
            total_arg_data_size += size;
            total_size += sizeof(int) + sizeof(size_t) + size;

            printf("  Captured Data:\n");
            analyze_arg_data(syscall_nr, arg_index, data, size);

            free(data);
        }

        total_size += sizeof(int); // -1 结束标记

        if (has_arg_data) {
            records_with_data++;
        }
    }

    if (count > 20) {
        printf("\n... (showing only first 20 records) ...\n");

        // 快速统计剩余记录
        for (int i = 20; i < count; i++) {
            fseek(f, 150, SEEK_CUR); // 跳过固定部分
            total_size += 150;

            // 跳过参数数据
            while (1) {
                int arg_index;
                if (fread(&arg_index, sizeof(int), 1, f) != 1) break;
                total_size += sizeof(int);

                if (arg_index == -1) break;

                size_t size;
                if (fread(&size, sizeof(size_t), 1, f) != 1) break;
                total_size += sizeof(size_t) + size;
                total_arg_data_size += size;
                fseek(f, size, SEEK_CUR);
                records_with_data++;
            }
        }
    }

    printf("\n=== Summary Statistics ===\n");
    printf("Total File Size: %lu bytes\n", total_size);
    printf("Header Size: 12 bytes (%.1f%%)\n", 12.0 * 100.0 / total_size);
    printf("Record Fixed Data: %lu bytes (%.1f%%)\n",
           (uint64_t)count * 150, (count * 150.0) * 100.0 / total_size);
    printf("Variable Argument Data: %lu bytes (%.1f%%)\n",
           total_arg_data_size, total_arg_data_size * 100.0 / total_size);
    printf("Records with Captured Data: %d/%u (%.1f%%)\n",
           records_with_data, count, records_with_data * 100.0 / count);

    printf("\n=== Storage Efficiency ===\n");
    printf("Average Record Size: %.1f bytes\n", (total_size - 12.0) / count);
    printf("Average Arg Data per Record: %.1f bytes\n", (double)total_arg_data_size / count);

    fclose(f);
    return 0;
}
/**
 * RR-Fuzz记录模块
 * 实现Record模式的系统调用记录逻辑，对应design.md中的rr_record.c
 */

#include "rr_framework.h"
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

static FILE *g_trace_file = NULL;

/**
 * 开始记录到文件
 */
int rr_start_recording(const char *trace_file)
{
    RR_VERBOSE("Starting recording initialization");

    if (!trace_file) {
        trace_file = "rr_trace.dat";
        RR_INFO("Using default trace file: %s", trace_file);
    }

    RR_INFO("Opening trace file for writing: %s", trace_file);
    g_trace_file = fopen(trace_file, "wb");
    if (!g_trace_file) {
        RR_ERROR("Failed to open trace file: %s", trace_file);
        return -1;
    }

    /* 写入文件头 */
    uint32_t magic = 0x52525254; // "RRTR"
    uint32_t version = 1;
    uint32_t placeholder_count = 0; // 占位符，将在结束时更新
    RR_VERBOSE("Writing trace file header: magic=0x%x, version=%u", magic, version);
    fwrite(&magic, sizeof(magic), 1, g_trace_file);
    fwrite(&version, sizeof(version), 1, g_trace_file);
    fwrite(&placeholder_count, sizeof(placeholder_count), 1, g_trace_file);

    RR_INFO("Recording started successfully to: %s", trace_file);
    return 0;
}

/**
 * 停止记录
 */
void rr_stop_recording(void)
{
    if (g_trace_file) {
        RR_VERBOSE("STOP_RECORDING: Finalizing trace file");

        /* 获取文件大小 */
        fseek(g_trace_file, 0, SEEK_END);
        long file_size = ftell(g_trace_file);

        /* 写入轨迹长度到文件头 */
        uint32_t record_count = g_rr_framework ? g_rr_framework->trace_length : 0;
        RR_VERBOSE("STOP_RECORDING: Updating header with record_count=%u, file_size=%ld", record_count, file_size);

        fseek(g_trace_file, sizeof(uint32_t) * 2, SEEK_SET);  // 跳过magic和version
        size_t written = fwrite(&record_count, sizeof(record_count), 1, g_trace_file);
        if (written != 1) {
            RR_ERROR("STOP_RECORDING: Failed to write record count to header");
        } else {
            RR_VERBOSE("STOP_RECORDING: Successfully wrote record_count=%u to header", record_count);
        }

        fflush(g_trace_file);
        fclose(g_trace_file);
        g_trace_file = NULL;

        RR_INFO("Recording stopped: %u syscalls recorded, %ld bytes written", record_count, file_size);
    } else {
        RR_VERBOSE("STOP_RECORDING: Recording stop called but no trace file was open");
    }
}

/**
 * 捕获字符串参数数据
 * 实现design.md中提到的指针参数解引用
 */
uint8_t *rr_capture_string(CPUArchState *env, target_ulong addr, size_t *len)
{
    if (addr == 0) {
        *len = 0;
        return NULL;
    }

    /* 使用target_strlen获取字符串长度 */
    size_t str_len = 0;
    target_ulong current = addr;

    /* 简单实现：逐字节读取直到遇到\0，最多读取4096字节 */
    while (str_len < 4096) {
        uint8_t byte;
        if (cpu_memory_rw_debug(env_cpu(env), current, &byte, 1, 0) != 0) {
            break;
        }
        if (byte == 0) {
            break;
        }
        str_len++;
        current++;
    }

    if (str_len == 0) {
        *len = 0;
        return NULL;
    }

    /* 分配并读取完整字符串（包括\0） */
    uint8_t *data = g_malloc(str_len + 1);
    if (cpu_memory_rw_debug(env_cpu(env), addr, data, str_len + 1, 0) != 0) {
        g_free(data);
        *len = 0;
        return NULL;
    }

    *len = str_len + 1;
    return data;
}

/**
 * 捕获缓冲区参数数据
 */
uint8_t *rr_capture_buffer(CPUArchState *env, target_ulong addr, size_t size)
{
    if (addr == 0 || size == 0 || size > 64 * 1024) { // 限制最大64KB
        return NULL;
    }

    uint8_t *data = g_malloc(size);
    if (cpu_memory_rw_debug(env_cpu(env), addr, data, size, 0) != 0) {
        g_free(data);
        return NULL;
    }

    return data;
}

/**
 * 检测系统调用是否创建FD
 */
static bool syscall_creates_fd(int syscall_nr, abi_long ret)
{
    if (ret < 0) {
        return false;
    }

    switch (syscall_nr) {
#ifdef TARGET_NR_open
        case TARGET_NR_open:
#endif
        case TARGET_NR_openat:
#ifdef TARGET_NR_creat
        case TARGET_NR_creat:
#endif
        case TARGET_NR_socket:
#ifdef TARGET_NR_pipe
        case TARGET_NR_pipe:
#endif
#ifdef TARGET_NR_pipe2
        case TARGET_NR_pipe2:
#endif
        case TARGET_NR_dup:
#ifdef TARGET_NR_dup2
        case TARGET_NR_dup2:
#endif
#ifdef TARGET_NR_dup3
        case TARGET_NR_dup3:
#endif
            return true;
        default:
            return false;
    }
}

/**
 * 智能捕获系统调用参数数据
 * 实现design.md中的智能判断数据长度逻辑
 */
static void capture_syscall_args(CPUArchState *env, int syscall_nr,
                                 const abi_long *args, abi_long ret, syscall_record_t *record)
{
    switch (syscall_nr) {
#ifdef TARGET_NR_open
        case TARGET_NR_open:
#endif
        case TARGET_NR_openat:
            /* 第一个参数(或第二个对于openat)是文件路径字符串 */
#ifdef TARGET_NR_open
            if (syscall_nr == TARGET_NR_openat) {
#else
            if (true) {  /* openat is always available */
#endif
                record->arg_data[1] = rr_capture_string(env, args[1], &record->arg_size[1]);
            } else {
                record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            }
            break;

        case TARGET_NR_read:
            /* 第二个参数是缓冲区，第三个参数是大小 */
            if (args[2] > 0 && args[2] <= 64 * 1024) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                if (record->arg_data[1]) {
                    record->arg_size[1] = args[2];
                }
            }
            break;

        case TARGET_NR_write:
            /* 第二个参数是数据，第三个参数是大小 */
            if (args[2] > 0 && args[2] <= 64 * 1024) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                if (record->arg_data[1]) {
                    record->arg_size[1] = args[2];
                }
            }
            break;

        case TARGET_NR_faccessat:
            /* 第二个参数是文件路径字符串 */
            record->arg_data[1] = rr_capture_string(env, args[1], &record->arg_size[1]);
            break;

        case TARGET_NR_execve:
            /* 第一个参数是程序路径 */
            record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            // TODO: 捕获argv和envp数组
            break;

#ifdef TARGET_NR_uname
        case TARGET_NR_uname:
            /* 第一个参数是struct utsname *，需要在syscall返回后捕获 */
            if (args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], sizeof(struct utsname));
                if (record->arg_data[0]) {
                    record->arg_size[0] = sizeof(struct utsname);
                }
            }
            break;
#endif

#ifdef TARGET_NR_newfstatat
        case TARGET_NR_newfstatat:
#endif
#ifdef TARGET_NR_fstatat64
        case TARGET_NR_fstatat64:
#endif
            /* 第二个参数是路径字符串，第三个参数是stat结构体 */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_string(env, args[1], &record->arg_size[1]);
            }
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], 144); // sizeof(struct stat)
                if (record->arg_data[2]) {
                    record->arg_size[2] = 144;
                }
            }
            break;

        case TARGET_NR_getdents64:
            /* 第二个参数是目录项缓冲区 */
            if (args[1] != 0 && args[2] > 0 && args[2] <= 32 * 1024) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                if (record->arg_data[1]) {
                    record->arg_size[1] = args[2];
                }
            }
            break;

#ifdef TARGET_NR_stat
        case TARGET_NR_stat:
            /* 第一个参数是路径字符串，第二个参数是stat结构体 */
            record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            if (ret == 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct stat));
                if (record->arg_data[1]) {
                    record->arg_size[1] = sizeof(struct stat);
                }
            }
            break;
#endif

#ifdef TARGET_NR_lstat
        case TARGET_NR_lstat:
            /* 第一个参数是路径字符串，第二个参数是stat结构体 */
            record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            if (ret == 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct stat));
                if (record->arg_data[1]) {
                    record->arg_size[1] = sizeof(struct stat);
                }
            }
            break;
#endif

#ifdef TARGET_NR_fstat
        case TARGET_NR_fstat:
            /* 第二个参数是stat结构体 */
            if (ret == 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct stat));
                if (record->arg_data[1]) {
                    record->arg_size[1] = sizeof(struct stat);
                }
            }
            break;
#endif

#ifdef TARGET_NR_access
        case TARGET_NR_access:
            /* 第一个参数是路径字符串 */
            record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            break;
#endif

#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64:
#endif
#ifdef TARGET_NR_pwrite64
        case TARGET_NR_pwrite64:
#endif
            /* 捕获缓冲区数据 */
            if (args[1] != 0 && args[2] > 0 && args[2] <= 64*1024) {
#ifdef TARGET_NR_pread64
                if (syscall_nr == TARGET_NR_pread64 && ret > 0) {
                    /* pread64: 需要在调用后捕获读取的数据 */
                    record->arg_data[1] = rr_capture_buffer(env, args[1], ret);
                    record->arg_size[1] = ret;
                }
#endif
#ifdef TARGET_NR_pwrite64
                if (syscall_nr == TARGET_NR_pwrite64) {
                    /* pwrite64: 需要在调用前捕获要写入的数据 */
                    record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                    record->arg_size[1] = args[2];
                }
#endif
            }
            break;

#ifdef TARGET_NR_gettimeofday
        case TARGET_NR_gettimeofday:
            if (ret == 0 && args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], sizeof(struct timeval));
                if (record->arg_data[0]) {
                    record->arg_size[0] = sizeof(struct timeval);
                }
            }
            break;
#endif

#ifdef TARGET_NR_clock_gettime
        case TARGET_NR_clock_gettime:
            if (ret == 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct timespec));
                if (record->arg_data[1]) {
                    record->arg_size[1] = sizeof(struct timespec);
                }
            }
            break;
#endif

        // write系统调用已在前面处理

        // I/O向量操作
#ifdef TARGET_NR_readv
        case TARGET_NR_readv:
            /* TODO: 处理 iovec 结构体数组 - 复杂数据结构 */
            // 暂时记录向量个数
            if (args[2] > 0 && args[2] <= 1024) {
                // 这里需要遍历iovec数组捕获所有缓冲区
                // 暂时不实现完整的iovec处理
            }
            break;
#endif

#ifdef TARGET_NR_writev
        case TARGET_NR_writev:
            /* TODO: 处理 iovec 结构体数组 */
            // 类似readv的复杂处理逻辑
            break;
#endif

        // getrandom - 关键的非确定性调用
        case TARGET_NR_getrandom:
            /* 捕获实际返回的随机数据 */
            if (ret > 0 && args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], ret);
                record->arg_size[0] = ret;
            }
            break;

        // execve系统调用已在前面处理

#ifdef TARGET_NR_wait4
        case TARGET_NR_wait4:
            /* 捕获status结构体 */
            if (ret >= 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(int));
                record->arg_size[1] = sizeof(int);
            }
            break;
#endif

        // 信号处理
#ifdef TARGET_NR_rt_sigaction
        case TARGET_NR_rt_sigaction:
            /* 捕获sigaction结构体 */
            if (args[1] != 0) {
                // 新的sigaction结构体
                record->arg_data[1] = rr_capture_buffer(env, args[1], 152); // sizeof(struct sigaction)
                record->arg_size[1] = 152;
            }
            if (ret == 0 && args[2] != 0) {
                // 旧的sigaction结构体（返回值）
                record->arg_data[2] = rr_capture_buffer(env, args[2], 152);
                record->arg_size[2] = 152;
            }
            break;
#endif

#ifdef TARGET_NR_rt_sigprocmask
        case TARGET_NR_rt_sigprocmask:
            /* 捕获信号掩码 */
            if (args[1] != 0) {
                // 新的信号掩码
                record->arg_data[1] = rr_capture_buffer(env, args[1], 8); // sizeof(sigset_t)
                record->arg_size[1] = 8;
            }
            if (ret == 0 && args[2] != 0) {
                // 旧的信号掩码（返回值）
                record->arg_data[2] = rr_capture_buffer(env, args[2], 8);
                record->arg_size[2] = 8;
            }
            break;
#endif

        // ioctl - 复杂的设备控制调用
        case TARGET_NR_ioctl:
            /* ioctl的参数非常复杂，依赖于具体的command */
            // 记录command类型，但数据部分需要按command分类处理
            // 暂时不捕获数据，因为参数格式完全依赖于设备和命令
            break;

        // 内存管理相关
#ifdef TARGET_NR_mremap
        case TARGET_NR_mremap:
            /* mremap需要地址重映射支持 */
            // 不捕获参数数据，依赖地址重映射机制
            break;
#endif

        // 网络相关系统调用
#ifdef TARGET_NR_socket
        case TARGET_NR_socket:
            /* socket创建，参数简单，主要是返回的fd */
            // 不需要捕获特殊数据，FD映射机制会处理
            break;
#endif

#ifdef TARGET_NR_connect
        case TARGET_NR_connect:
            /* 捕获sockaddr结构体 */
            if (args[1] != 0 && args[2] > 0 && args[2] <= 128) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
            }
            break;
#endif

#ifdef TARGET_NR_accept
        case TARGET_NR_accept:
#endif
#ifdef TARGET_NR_accept4
        case TARGET_NR_accept4:
#endif
            /* 捕获sockaddr结构体 */
            if (ret >= 0 && args[1] != 0 && args[2] != 0) {
                // 先读取地址长度
                uint32_t addr_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[2], (uint8_t*)&addr_len, sizeof(uint32_t), 0) == 0) {
                    if (addr_len > 0 && addr_len <= 128) {
                        record->arg_data[1] = rr_capture_buffer(env, args[1], addr_len);
                        record->arg_size[1] = addr_len;
                        // 同时捕获地址长度
                        record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(uint32_t));
                        record->arg_size[2] = sizeof(uint32_t);
                    }
                }
            }
            break;

#ifdef TARGET_NR_sendto
        case TARGET_NR_sendto:
            /* 捕获要发送的数据和目标地址 */
            if (args[1] != 0 && args[2] > 0 && args[2] <= 64*1024) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
            }
            if (args[4] != 0 && args[5] > 0 && args[5] <= 128) {
                record->arg_data[4] = rr_capture_buffer(env, args[4], args[5]);
                record->arg_size[4] = args[5];
            }
            break;
#endif

#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
            /* 捕获接收到的数据和源地址 */
            if (ret > 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], ret);
                record->arg_size[1] = ret;
            }
            if (args[4] != 0 && args[5] != 0) {
                // 捕获源地址和地址长度
                uint32_t addr_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[5], (uint8_t*)&addr_len, sizeof(uint32_t), 0) == 0) {
                    if (addr_len > 0 && addr_len <= 128) {
                        record->arg_data[4] = rr_capture_buffer(env, args[4], addr_len);
                        record->arg_size[4] = addr_len;
                        record->arg_data[5] = rr_capture_buffer(env, args[5], sizeof(uint32_t));
                        record->arg_size[5] = sizeof(uint32_t);
                    }
                }
            }
            break;
#endif

        // 管道相关
#ifdef TARGET_NR_pipe
        case TARGET_NR_pipe:
            /* 捕获返回的两个文件描述符 */
            if (ret == 0 && args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], 2 * sizeof(int));
                record->arg_size[0] = 2 * sizeof(int);
            }
            break;
#endif

#ifdef TARGET_NR_pipe2
        case TARGET_NR_pipe2:
            /* 类似pipe但有额外的flags参数 */
            if (ret == 0 && args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], 2 * sizeof(int));
                record->arg_size[0] = 2 * sizeof(int);
            }
            break;
#endif

        // 资源限制
        case TARGET_NR_prlimit64:
            /* 捕获rlimit结构体 */
            if (args[2] != 0) {
                // 新的资源限制
                record->arg_data[2] = rr_capture_buffer(env, args[2], 16); // sizeof(struct rlimit64)
                record->arg_size[2] = 16;
            }
            if (ret == 0 && args[3] != 0) {
                // 旧的资源限制（返回值）
                record->arg_data[3] = rr_capture_buffer(env, args[3], 16);
                record->arg_size[3] = 16;
            }
            break;

        // 可以继续添加更多系统调用的特殊处理
        default:
            // 对于未特殊处理的系统调用，不捕获参数数据
            break;
    }
}

/**
 * 记录系统调用
 */
int rr_record_syscall(CPUArchState *env, int num, const abi_long *args, abi_long ret)
{
    RR_VERBOSE("RECORD_SYSCALL: Called for syscall %d, ret=%ld", num, ret);

    if (!g_trace_file) {
        RR_ERROR("Record syscall called but no trace file open");
        return -1;
    }

    RR_VERBOSE("RECORD_SYSCALL: Trace file is open, continuing with recording");
    RR_SYSCALL_TRACE("Recording syscall %d, ret=%ld", num, ret);

    /* 创建记录 */
    syscall_record_t *record = g_malloc0(sizeof(syscall_record_t));
    record->index = g_rr_framework->trace_length++;
    record->syscall_nr = num;
    memcpy(record->args, args, sizeof(abi_long) * 8);
    record->retval = ret;

    fprintf(stderr, "DEBUG_rr_record_syscall: Recording index=%u, syscall=%d, ret=%ld\n",
            record->index, record->syscall_nr, record->retval);

    /* 检测FD创建 */
    record->creates_fd = syscall_creates_fd(num, ret);
    if (record->creates_fd) {
        record->created_fd = (int32_t)ret;
        RR_FD_TRACE("Syscall %d creates FD: %d", num, record->created_fd);
    }

    /* 智能捕获参数数据 */
    capture_syscall_args(env, num, args, ret, record);

    /* 添加到轨迹链表 */
    if (g_rr_framework->trace_tail) {
        g_rr_framework->trace_tail->next = record;
    } else {
        g_rr_framework->trace_head = record;
    }
    g_rr_framework->trace_tail = record;

    /* 写入文件 - 逐字段写入以避免结构体对齐问题 */
    RR_VERBOSE("RECORD_SYSCALL: Writing record to trace file (index=%u, syscall=%d)", record->index, num);
    fprintf(stderr, "DEBUG_rr_record_syscall: Writing index=%u, syscall=%d, ret=%ld\n",
            record->index, record->syscall_nr, record->retval);

    // 写入基本字段
    fprintf(stderr, "DEBUG_WRITE: FINAL CHECK - index=%u, syscall_nr=%d\n", record->index, record->syscall_nr);
    fprintf(stderr, "DEBUG_WRITE: index addr=%p, value=%u\n", &record->index, record->index);
    fprintf(stderr, "DEBUG_WRITE: syscall_nr addr=%p, value=%d\n", &record->syscall_nr, record->syscall_nr);

    // 打印内存的十六进制内容
    uint8_t *ptr = (uint8_t*)&record->index;
    fprintf(stderr, "DEBUG_WRITE: index memory: %02x %02x %02x %02x\n", ptr[0], ptr[1], ptr[2], ptr[3]);
    ptr = (uint8_t*)&record->syscall_nr;
    fprintf(stderr, "DEBUG_WRITE: syscall_nr memory: %02x %02x %02x %02x\n", ptr[0], ptr[1], ptr[2], ptr[3]);

    // Write using a simple binary buffer approach
    uint8_t buffer[8]; // 4 bytes for uint32_t + 4 bytes for int

    // Pack data manually into buffer
    uint32_t idx = record->index;
    int32_t sys = (int32_t)record->syscall_nr;

    buffer[0] = (idx) & 0xFF;
    buffer[1] = (idx >> 8) & 0xFF;
    buffer[2] = (idx >> 16) & 0xFF;
    buffer[3] = (idx >> 24) & 0xFF;

    buffer[4] = (sys) & 0xFF;
    buffer[5] = (sys >> 8) & 0xFF;
    buffer[6] = (sys >> 16) & 0xFF;
    buffer[7] = (sys >> 24) & 0xFF;

    fprintf(stderr, "DEBUG_WRITE: Manual pack - index=%u, syscall=%d\n", idx, sys);
    fprintf(stderr, "DEBUG_WRITE: Buffer bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
            buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]);

    if (fwrite(buffer, 8, 1, g_trace_file) != 1) {
        RR_ERROR("Failed to write record header");
        return -1;
    }
    fprintf(stderr, "DEBUG_WRITE: Successfully wrote binary buffer\n");

    // Flush and verify
    fflush(g_trace_file);
    fprintf(stderr, "DEBUG_WRITE: Flushed file buffer\n");

    // VERIFICATION: read back what we just wrote
    long current_pos = ftell(g_trace_file);
    fseek(g_trace_file, current_pos - 8, SEEK_SET);
    uint8_t verify_buffer[8];
    fread(verify_buffer, 8, 1, g_trace_file);

    uint32_t verify_index = verify_buffer[0] | (verify_buffer[1] << 8) | (verify_buffer[2] << 16) | (verify_buffer[3] << 24);
    int32_t verify_syscall_nr = verify_buffer[4] | (verify_buffer[5] << 8) | (verify_buffer[6] << 16) | (verify_buffer[7] << 24);

    fprintf(stderr, "DEBUG_VERIFY: Read back index=%u, syscall_nr=%d\n", verify_index, verify_syscall_nr);
    fseek(g_trace_file, current_pos, SEEK_SET);

    if (fwrite(record->args, sizeof(abi_long) * 8, 1, g_trace_file) != 1 ||
        fwrite(&record->retval, sizeof(abi_long), 1, g_trace_file) != 1 ||
        fwrite(record->arg_size, sizeof(size_t) * 8, 1, g_trace_file) != 1 ||
        fwrite(&record->creates_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fwrite(&record->uses_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fwrite(&record->created_fd, sizeof(int32_t), 1, g_trace_file) != 1) {
        RR_ERROR("RECORD_SYSCALL: Failed to write syscall record fields");
        return -1;
    }
    fprintf(stderr, "DEBUG_WRITE: Successfully wrote all fields\n");

    /* 写入参数数据 */
    int arg_count = 0;
    for (int i = 0; i < 8; i++) {
        if (record->arg_data[i] && record->arg_size[i] > 0) {
            RR_VERBOSE("RECORD_SYSCALL: Writing arg %d data (size=%zu)", i, record->arg_size[i]);
            fwrite(&i, sizeof(int), 1, g_trace_file);
            fwrite(&record->arg_size[i], sizeof(size_t), 1, g_trace_file);
            fwrite(record->arg_data[i], record->arg_size[i], 1, g_trace_file);
            arg_count++;
        }
    }

    /* 写入结束标记 */
    int end_marker = -1;
    fwrite(&end_marker, sizeof(int), 1, g_trace_file);
    fflush(g_trace_file);

    RR_VERBOSE("RECORD_SYSCALL: Successfully recorded syscall %d (index=%u, args=%d, total_syscalls=%u)",
               num, record->index, arg_count, g_rr_framework->trace_length);
    RR_LOG("Recorded syscall %d: %s -> %ld", record->index,
           (num >= 0 && num < 400) ? "syscall" : "unknown", ret);

    /* 立即更新文件头中的记录计数（每10个记录更新一次，减少开销） */
    if (g_rr_framework->trace_length % 10 == 0) {
        long header_pos = ftell(g_trace_file);
        fseek(g_trace_file, sizeof(uint32_t) * 2, SEEK_SET);  // 跳过magic和version
        uint32_t record_count = g_rr_framework->trace_length;
        fwrite(&record_count, sizeof(record_count), 1, g_trace_file);
        fseek(g_trace_file, header_pos, SEEK_SET);  // 恢复位置
        fflush(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: Updated header with record_count=%u", record_count);
    }

    return 0;
}
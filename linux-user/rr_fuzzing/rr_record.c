/**
 * RR-Fuzz记录模块
 * 实现Record模式的系统调用记录逻辑，对应design.md中的rr_record.c
 */

#include "rr_framework.h"
#include <fcntl.h>

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
    RR_VERBOSE("Writing trace file header: magic=0x%x, version=%u", magic, version);
    fwrite(&magic, sizeof(magic), 1, g_trace_file);
    fwrite(&version, sizeof(version), 1, g_trace_file);

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
                                 const abi_long *args, syscall_record_t *record)
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
                record->arg_size[1] = args[2];
            }
            break;

        case TARGET_NR_write:
            /* 第二个参数是数据，第三个参数是大小 */
            if (args[2] > 0 && args[2] <= 64 * 1024) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
            }
            break;

        case TARGET_NR_execve:
            /* 第一个参数是程序路径 */
            record->arg_data[0] = rr_capture_string(env, args[0], &record->arg_size[0]);
            // TODO: 捕获argv和envp数组
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

    /* 检测FD创建 */
    record->creates_fd = syscall_creates_fd(num, ret);
    if (record->creates_fd) {
        record->created_fd = (int32_t)ret;
        RR_FD_TRACE("Syscall %d creates FD: %d", num, record->created_fd);
    }

    /* 智能捕获参数数据 */
    capture_syscall_args(env, num, args, record);

    /* 添加到轨迹链表 */
    if (g_rr_framework->trace_tail) {
        g_rr_framework->trace_tail->next = record;
    } else {
        g_rr_framework->trace_head = record;
    }
    g_rr_framework->trace_tail = record;

    /* 写入文件 */
    RR_VERBOSE("RECORD_SYSCALL: Writing record to trace file (index=%u, syscall=%d)", record->index, num);
    size_t written = fwrite(record, sizeof(syscall_record_t), 1, g_trace_file);
    if (written != 1) {
        RR_ERROR("RECORD_SYSCALL: Failed to write syscall record (written=%zu)", written);
        return -1;
    }

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
        long current_pos = ftell(g_trace_file);
        fseek(g_trace_file, sizeof(uint32_t) * 2, SEEK_SET);  // 跳过magic和version
        uint32_t record_count = g_rr_framework->trace_length;
        fwrite(&record_count, sizeof(record_count), 1, g_trace_file);
        fseek(g_trace_file, current_pos, SEEK_SET);  // 恢复位置
        fflush(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: Updated header with record_count=%u", record_count);
    }

    return 0;
}
/**
 * RR-Fuzz记录模块
 * 实现Record模式的系统调用记录逻辑，对应design.md中的rr_record.c
 */

#define RR_DEBUG 1

#include "../core/rr_framework.h"
#include "../core/rr_bb_trace.h"
#include "rr_aux_data.h"
#include "../core/rr_constants.h"
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

static FILE *g_trace_file = NULL;

static rr_aux_data_t *record_aux_scalar(uint8_t mask, const abi_long *value)
{
    abi_long val = value ? *value : 0;
    return rr_aux_create(AUX_SCALAR, mask, &val, sizeof(val));
}

/**
 * 辅助函数：将 arg_data 转换为 aux_data（用于 fuzzing）
 * @param record: syscall record
 * @param arg_index: 参数索引 (0-7)
 * @param data: 数据指针（如果为 NULL，使用 record->arg_data[arg_index]）
 * @param size: 数据大小（如果为 0，使用 record->arg_size[arg_index]）
 * @return: 成功返回 true，失败返回 false
 */
static bool rr_promote_arg_to_aux(syscall_record_t *record, int arg_index, 
                                   const uint8_t *data, size_t size)
{
    if (!record || arg_index < 0 || arg_index >= RR_MAX_SYSCALL_ARGS) {
        return false;
    }
    
    /* 如果没有提供数据，尝试使用 arg_data */
    if (!data) {
        data = record->arg_data[arg_index];
        if (!data) return false;
    }
    
    /* 如果没有提供大小，尝试使用 arg_size */
    if (size == 0) {
        size = record->arg_size[arg_index];
        if (size == 0) return false;
    }
    
    /* 创建 aux_data */
    uint8_t *aux_data_copy = g_malloc(size);
    if (!aux_data_copy) return false;
    
    memcpy(aux_data_copy, data, size);
    
    rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, (1 << arg_index), 
                                       aux_data_copy, size);
    if (!aux) {
        g_free(aux_data_copy);
        return false;
    }
    
    /* 添加到 aux_data 链表 */
    rr_aux_append(&record->aux_data, aux);
    record->has_aux_data = true;
    
    return true;
}

/**
 * 释放syscall_record_t及其关联数据
 */
void rr_record_dispose(syscall_record_t *record)
{
    if (!record) {
        return;
    }

    /* 释放所有arg_data */
    for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
        if (record->arg_data[i]) {
            g_free(record->arg_data[i]);
            record->arg_data[i] = NULL;
        }
    }

    /* 释放aux_data链表 */
    if (record->aux_data) {
        rr_aux_free(record->aux_data);
        record->aux_data = NULL;
    }

    /* 释放记录本身 */
    g_free(record);
}

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

    /* 初始化BB trace */
    if (rr_bb_trace_init(trace_file) < 0) {
        RR_WARN("Failed to initialize BB trace (continuing without BB trace)");
    } else {
        RR_INFO("BB trace initialized successfully");
    }

    RR_INFO("Recording started successfully to: %s", trace_file);
    return 0;
}

/**
 * 停止记录
 */
void rr_stop_recording(void)
{
    /* 清理BB trace */
    rr_bb_trace_cleanup();
    
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

    /* 简单实现：逐字节读取直到遇到\0，最多读取 PATH_MAX 字节 */
    while (str_len < RR_MAX_PATH_LENGTH) {
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
    if (addr == 0 || size == 0 || size > RR_MAX_BUFFER_TOTAL) {
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
 * 使用 aux_data 系统捕获参数数据 (EnvFuzz风格)
 * 自动智能捕获，无需配置
 */
static void capture_syscall_args_aux(CPUArchState *env, int syscall_nr,
                                    const abi_long *args, abi_long ret, syscall_record_t *record)
{
    /* 自动捕获关键数据，使用智能阈值控制 */

    switch (syscall_nr) {
        case TARGET_NR_brk: {
            /* 记录 brk 返回的新堆顶地址 */
            if (ret > 0) {
                rr_aux_data_t *aux = record_aux_scalar(0, &ret);
                if (aux) {
                    rr_aux_append(&record->aux_data, aux);
                    record->has_aux_data = true;
                }
            }
            break;
        }

#if defined(TARGET_NR_mmap)
        case TARGET_NR_mmap:
#endif
#if defined(TARGET_NR_mmap2)
        case TARGET_NR_mmap2:
#endif
        {
            if (ret != (abi_long)-1) {
                rr_aux_mmap_info_t info = {
                    .addr = (uint64_t)ret,
                    .length = (uint64_t)args[1],
                    .prot = (int64_t)args[2],
                    .flags = (int64_t)args[3],
                    .fd = (int64_t)args[4],
                    .offset = (uint64_t)args[5],
                };
                rr_aux_data_t *aux = rr_aux_create(AUX_STRUCT, 0, &info, sizeof(info));
                if (aux) {
                    rr_aux_append(&record->aux_data, aux);
                    record->has_aux_data = true;
                }
            }
            break;
        }

        case TARGET_NR_munmap:
        case TARGET_NR_mprotect:
        case TARGET_NR_mremap:
        case TARGET_NR_madvise: {
            /* 记录这些内存管理调用的参数，用于重放阶段的校验 */
            rr_aux_mm_params_t mm_aux = {
                .addr = (uint64_t)args[0],
                .len = (uint64_t)args[1],
                .extra1 = (int64_t)args[2],
                .extra2 = (int64_t)args[3],
            };
            rr_aux_data_t *aux = rr_aux_create(AUX_STRUCT, 0, &mm_aux, sizeof(mm_aux));
            if (aux) {
                rr_aux_append(&record->aux_data, aux);
                record->has_aux_data = true;
            }
            break;
        }

        case TARGET_NR_clone:
#ifdef TARGET_NR_fork
        case TARGET_NR_fork:
#endif
#ifdef TARGET_NR_vfork
        case TARGET_NR_vfork:
#endif
        {
            if (ret > 0) {
                rr_aux_data_t *aux = record_aux_scalar(0, &ret);
                if (aux) {
                    rr_aux_append(&record->aux_data, aux);
                    record->has_aux_data = true;
                }
            }
            break;
        }

        case TARGET_NR_read:
            /* read 的数据在返回后才有效 */
            if (ret > 0 && args[1] != 0) {
                if (rr_aux_should_record(ret, args[0], syscall_nr)) {
                    uint8_t *data = rr_capture_buffer(env, args[1], ret);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, ret);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                        }
                        g_free(data);
                    }
                }
            }
            break;

        case TARGET_NR_write:
            /* write 的数据在调用前就存在 */
            if (args[2] > 0 && args[1] != 0) {
                if (rr_aux_should_record(args[2], args[0], syscall_nr)) {
                    uint8_t *data = rr_capture_buffer(env, args[1], args[2]);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, args[2]);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                        }
                        g_free(data);
                    }
                }
            }
            break;

#ifdef TARGET_NR_getrandom
        case TARGET_NR_getrandom:
#else
        case 318: /* x86_64 getrandom */
#endif
            /* 关键的非确定性调用 - 总是记录 */
            RR_VERBOSE("AUX_CAPTURE: getrandom ret=%ld, args[0]=0x%lx", ret, args[0]);
            if (ret > 0 && args[0] != 0) {
                uint8_t *data = rr_capture_buffer(env, args[0], ret);
                RR_VERBOSE("AUX_CAPTURE: rr_capture_buffer returned %p, size=%ld", data, ret);
                if (data) {
                    rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 0, data, ret);
                    RR_VERBOSE("AUX_CAPTURE: rr_aux_create returned %p", aux);
                    if (aux) {
                        rr_aux_append(&record->aux_data, aux);
                        record->has_aux_data = true;
                        RR_VERBOSE("AUX_CAPTURE: Successfully created aux_data for getrandom, size=%ld", ret);
                    }
                    g_free(data);
                }
            }
            break;

#ifdef TARGET_NR_openat
        case TARGET_NR_openat:
            /* 捕获文件路径 */
            if (args[1] != 0) {
                size_t len;
                uint8_t *data = rr_capture_string(env, args[1], &len);
                if (data && len > 0) {
                    rr_aux_data_t *aux = rr_aux_create(AUX_STRING, 1, data, len);
                    if (aux) {
                        rr_aux_append(&record->aux_data, aux);
                        record->has_aux_data = true;
                    }
                    g_free(data);
                }
            }
            break;
#endif

#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64:
            if (ret > 0 && args[1] != 0) {
                if (rr_aux_should_record(ret, args[0], syscall_nr)) {
                    uint8_t *data = rr_capture_buffer(env, args[1], ret);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, ret);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                        }
                        g_free(data);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_sendto
        case TARGET_NR_sendto:
            /* sendto 的数据在调用前就存在（类似 write）*/
            RR_VERBOSE("AUX_CAPTURE: sendto - args[2]=%ld, args[1]=0x%lx, args[0]=%d", args[2], args[1], (int)args[0]);
            if (args[2] > 0 && args[1] != 0 && args[2] <= RR_MAX_BUFFER_TOTAL) {
                bool should_record = rr_aux_should_record(args[2], args[0], syscall_nr);
                RR_VERBOSE("AUX_CAPTURE: rr_aux_should_record returned %d for sendto (size=%ld, fd=%d)", should_record, args[2], (int)args[0]);
                if (should_record) {
                    uint8_t *data = rr_capture_buffer(env, args[1], args[2]);
                    RR_VERBOSE("AUX_CAPTURE: rr_capture_buffer returned %p", data);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, args[2]);
                        RR_VERBOSE("AUX_CAPTURE: rr_aux_create returned %p", aux);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                            RR_VERBOSE("AUX_CAPTURE: Successfully created aux_data for sendto, size=%ld", args[2]);
                        }
                        g_free(data);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
            /* 捕获接收到的数据 */
            if (ret > 0 && args[1] != 0) {
                if (rr_aux_should_record(ret, args[0], syscall_nr)) {
                    uint8_t *data = rr_capture_buffer(env, args[1], ret);
                    if (data) {
                        rr_aux_data_t *aux = rr_aux_create(AUX_BUFFER, 1, data, ret);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            record->has_aux_data = true;
                        }
                        g_free(data);
                    }
                }
            }
            break;
#endif

        default:
            /* 其他系统调用暂不支持 aux_data */
            break;
    }
}

/**
 * 智能捕获系统调用参数数据 (传统方式 - 保持向后兼容)
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

        /* TARGET_NR_read 已在 capture_syscall_args_aux 中处理（syscall 执行后） */

        case TARGET_NR_write:
            /* 第二个参数是数据，第三个参数是大小 */
            if (args[2] > 0 && args[2] <= RR_MAX_BUFFER_TOTAL) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                if (record->arg_data[1]) {
                    record->arg_size[1] = args[2];
                    
                    /* 🔥 添加 aux_data for fuzzing */
                    rr_promote_arg_to_aux(record, 1, NULL, 0);
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
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_GETDENTS_BUF_SIZE) {
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
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_BUFFER_TOTAL) {
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
                    
                    /* 🔥 添加 aux_data for fuzzing */
                    rr_promote_arg_to_aux(record, 1, NULL, 0);
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
            /* 捕获 iovec 结构体数组（简化：只记录 iovec 结构本身） */
            if (ret > 0 && args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_IOVEC_COUNT) {
                size_t iov_size = sizeof(struct iovec) * args[2];
                record->arg_data[1] = rr_capture_buffer(env, args[1], iov_size);
                record->arg_size[1] = iov_size;
                /* TODO: 完整实现需要遍历每个 iovec 捕获实际数据缓冲区 */
            }
            break;
#endif

#ifdef TARGET_NR_writev
        case TARGET_NR_writev:
            /* 捕获 iovec 结构体数组（简化处理） */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_IOVEC_COUNT) {
                size_t iov_size = sizeof(struct iovec) * args[2];
                record->arg_data[1] = rr_capture_buffer(env, args[1], iov_size);
                record->arg_size[1] = iov_size;
                
                /* 🔥 添加 aux_data for fuzzing */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
                /* TODO: 完整实现需要遍历每个 iovec 捕获实际数据缓冲区 */
            }
            break;
#endif

#ifdef TARGET_NR_preadv
        case TARGET_NR_preadv:
            /* preadv = readv + offset */
            if (ret > 0 && args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_IOVEC_COUNT) {
                size_t iov_size = sizeof(struct iovec) * args[2];
                record->arg_data[1] = rr_capture_buffer(env, args[1], iov_size);
                record->arg_size[1] = iov_size;
            }
            break;
#endif

#ifdef TARGET_NR_pwritev
        case TARGET_NR_pwritev:
            /* pwritev = writev + offset */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_IOVEC_COUNT) {
                size_t iov_size = sizeof(struct iovec) * args[2];
                record->arg_data[1] = rr_capture_buffer(env, args[1], iov_size);
                record->arg_size[1] = iov_size;
            }
            break;
#endif

#ifdef TARGET_NR_flock
        case TARGET_NR_flock:
            /* flock 参数简单（fd, operation），不需要捕获额外数据 */
            break;
#endif

        // getrandom - 关键的非确定性调用
#ifdef TARGET_NR_getrandom
        case TARGET_NR_getrandom:
#else
        case 318: /* x86_64 getrandom */
#endif
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
            if (ret == 0 && args[2]) {
                /* 对于成功的 ioctl,尝试捕获输出缓冲区 */
                unsigned long cmd = args[1];
                
                /* 提取 ioctl 方向和大小信息 */
                /* Linux ioctl 编码: _IOC(dir,type,nr,size) */
                /* dir: _IOC_NONE=0, _IOC_WRITE=1, _IOC_READ=2, _IOC_READ|_IOC_WRITE=3 */
                int ioc_dir = (cmd >> 30) & 0x03;
                int ioc_size = (cmd >> 16) & 0x3FFF;
                
                /* 如果有输出 (_IOC_READ) 且有合理大小 */
                if ((ioc_dir & 2) && ioc_size > 0 && ioc_size < RR_MAX_IOCTL_PAYLOAD) {
                    uint8_t *buf = g_malloc0(ioc_size);
                    if (cpu_memory_rw_debug(env_cpu(env), args[2], buf, ioc_size, 0) == 0) {
                        /* 使用 AUX_IOCTL_OUTPUT 类型记录输出缓冲区 */
                        record->aux_data = rr_aux_create(AUX_IOCTL_OUTPUT, 2, buf, ioc_size);
                        record->has_aux_data = true;
                        RR_VERBOSE("ioctl: Captured %d bytes output buffer for cmd=0x%lx", 
                                   ioc_size, cmd);
                    }
                    g_free(buf);
                } else {
                    RR_VERBOSE("ioctl: cmd=0x%lx, dir=%d, size=%d (not capturing)", 
                               cmd, ioc_dir, ioc_size);
                }
            }
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
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_SOCKADDR_SIZE) {
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
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_BUFFER_TOTAL) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
                
                /* 🔥 关键修复：同时创建 aux_data for fuzzing */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
            }
            if (args[4] != 0 && args[5] > 0 && args[5] <= RR_MAX_SOCKADDR_SIZE) {
                record->arg_data[4] = rr_capture_buffer(env, args[4], args[5]);
                record->arg_size[4] = args[5];
                
                /* 目标地址也可以 fuzz（可选） */
                rr_promote_arg_to_aux(record, 4, NULL, 0);
            }
            break;
#endif

#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
            /* 捕获接收到的数据和源地址 */
            if (ret > 0 && args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], ret);
                record->arg_size[1] = ret;
                
                /* 接收数据也可以用于 fuzzing（用于回放时的比对/变异） */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
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

#ifdef TARGET_NR_bind
        case TARGET_NR_bind:
            /* 捕获 sockaddr 结构体 */
            if (args[1] != 0 && args[2] > 0 && args[2] <= RR_MAX_SOCKADDR_SIZE) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
            }
            break;
#endif

#ifdef TARGET_NR_listen
        case TARGET_NR_listen:
            /* listen 参数简单（fd, backlog），不需要捕获额外数据 */
            break;
#endif

#ifdef TARGET_NR_getsockname
        case TARGET_NR_getsockname:
            /* 捕获本地地址（输出参数） */
            if (ret == 0 && args[1] != 0 && args[2] != 0) {
                uint32_t addr_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[2], (uint8_t*)&addr_len, sizeof(uint32_t), 0) == 0) {
                    if (addr_len > 0 && addr_len <= RR_MAX_SOCKADDR_SIZE) {
                        record->arg_data[1] = rr_capture_buffer(env, args[1], addr_len);
                        record->arg_size[1] = addr_len;
                        record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(uint32_t));
                        record->arg_size[2] = sizeof(uint32_t);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_getpeername
        case TARGET_NR_getpeername:
            /* 捕获对端地址（输出参数） */
            if (ret == 0 && args[1] != 0 && args[2] != 0) {
                uint32_t addr_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[2], (uint8_t*)&addr_len, sizeof(uint32_t), 0) == 0) {
                    if (addr_len > 0 && addr_len <= RR_MAX_SOCKADDR_SIZE) {
                        record->arg_data[1] = rr_capture_buffer(env, args[1], addr_len);
                        record->arg_size[1] = addr_len;
                        record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(uint32_t));
                        record->arg_size[2] = sizeof(uint32_t);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_setsockopt
        case TARGET_NR_setsockopt:
            /* 捕获 socket 选项数据（输入参数） */
            if (args[3] != 0 && args[4] > 0 && args[4] <= RR_MAX_IOCTL_PAYLOAD) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], args[4]);
                record->arg_size[3] = args[4];
            }
            break;
#endif

#ifdef TARGET_NR_getsockopt
        case TARGET_NR_getsockopt:
            /* 捕获 socket 选项数据（输出参数） */
            if (ret == 0 && args[3] != 0 && args[4] != 0) {
                uint32_t opt_len;
                if (cpu_memory_rw_debug(env_cpu(env), args[4], (uint8_t*)&opt_len, sizeof(uint32_t), 0) == 0) {
                    if (opt_len > 0 && opt_len <= RR_MAX_IOCTL_PAYLOAD) {
                        record->arg_data[3] = rr_capture_buffer(env, args[3], opt_len);
                        record->arg_size[3] = opt_len;
                        record->arg_data[4] = rr_capture_buffer(env, args[4], sizeof(uint32_t));
                        record->arg_size[4] = sizeof(uint32_t);
                    }
                }
            }
            break;
#endif

#ifdef TARGET_NR_recvmsg
        case TARGET_NR_recvmsg:
            /* recvmsg 使用 msghdr 结构，包含 iovec、控制消息等 */
            if (ret > 0 && args[1] != 0) {
                /* 捕获整个 msghdr 结构（简化处理） */
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct msghdr));
                record->arg_size[1] = sizeof(struct msghdr);
                
                /* 🔥 添加 aux_data for fuzzing */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
                /* TODO: 完整实现需要递归捕获 iovec 和 control message */
            }
            break;
#endif

#ifdef TARGET_NR_sendmsg
        case TARGET_NR_sendmsg:
            /* sendmsg 同样使用 msghdr 结构 */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct msghdr));
                record->arg_size[1] = sizeof(struct msghdr);
                
                /* 🔥 添加 aux_data for fuzzing */
                rr_promote_arg_to_aux(record, 1, NULL, 0);
                /* TODO: 完整实现需要递归捕获 iovec */
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

        // Phase 2: 扩展 Syscall 支持
        
#ifdef TARGET_NR_fcntl
        case TARGET_NR_fcntl:
#endif
#ifdef TARGET_NR_fcntl64
        case TARGET_NR_fcntl64:
#endif
#if defined(TARGET_NR_fcntl) || defined(TARGET_NR_fcntl64)
            /* fcntl 的第三个参数取决于 cmd */
            {
                int cmd = (int)args[1];
                switch (cmd) {
                    case F_GETFD:
                    case F_GETFL:
                    case F_GETOWN:
                        // 这些命令没有第三个参数
                        break;
                    case F_DUPFD:
                    case F_DUPFD_CLOEXEC:
                    case F_SETFD:
                    case F_SETFL:
                    case F_SETOWN:
                        // 这些命令的第三个参数是整数，已在 args 中
                        break;
                    case F_GETLK:
                    case F_SETLK:
                    case F_SETLKW:
                        // 这些命令使用 struct flock
                        if (args[2] != 0) {
                            record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct flock));
                            record->arg_size[2] = sizeof(struct flock);
                        }
                        break;
                }
            }
            break;
#endif  // defined(TARGET_NR_fcntl) || defined(TARGET_NR_fcntl64)

#ifdef TARGET_NR_poll
        case TARGET_NR_poll:
            /* 捕获 pollfd 数组 */
            if (args[0] != 0 && args[1] > 0 && args[1] <= RR_MAX_IOVEC_COUNT) {
                size_t pollfd_size = sizeof(struct pollfd) * args[1];
                record->arg_data[0] = rr_capture_buffer(env, args[0], pollfd_size);
                record->arg_size[0] = pollfd_size;
            }
            break;
#endif

#ifdef TARGET_NR_ppoll
        case TARGET_NR_ppoll:
            /* 类似 poll，但还有 timespec 和 sigmask */
            if (args[0] != 0 && args[1] > 0 && args[1] <= RR_MAX_IOVEC_COUNT) {
                size_t pollfd_size = sizeof(struct pollfd) * args[1];
                record->arg_data[0] = rr_capture_buffer(env, args[0], pollfd_size);
                record->arg_size[0] = pollfd_size;
            }
            if (args[2] != 0) {
                // timespec
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct timespec));
                record->arg_size[2] = sizeof(struct timespec);
            }
            break;
#endif

#ifdef TARGET_NR_epoll_wait
        case TARGET_NR_epoll_wait:
            /* 捕获 epoll_event 数组（输出） */
            if (ret > 0 && args[1] != 0) {
                size_t events_size = sizeof(struct epoll_event) * ret;
                record->arg_data[1] = rr_capture_buffer(env, args[1], events_size);
                record->arg_size[1] = events_size;
            }
            break;
#endif

#ifdef TARGET_NR_epoll_pwait
        case TARGET_NR_epoll_pwait:
            /* 类似 epoll_wait，但还有 sigmask */
            if (ret > 0 && args[1] != 0) {
                size_t events_size = sizeof(struct epoll_event) * ret;
                record->arg_data[1] = rr_capture_buffer(env, args[1], events_size);
                record->arg_size[1] = events_size;
            }
            break;
#endif

#ifdef TARGET_NR_select
        case TARGET_NR_select:
            /* 捕获 fd_set 结构体 */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(fd_set));
                record->arg_size[1] = sizeof(fd_set);
            }
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(fd_set));
                record->arg_size[2] = sizeof(fd_set);
            }
            if (args[3] != 0) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(fd_set));
                record->arg_size[3] = sizeof(fd_set);
            }
            if (args[4] != 0) {
                record->arg_data[4] = rr_capture_buffer(env, args[4], sizeof(struct timeval));
                record->arg_size[4] = sizeof(struct timeval);
            }
            break;
#endif

#ifdef TARGET_NR_pselect6
        case TARGET_NR_pselect6:
            /* pselect6 类似 select，但使用 timespec 而不是 timeval */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(fd_set));
                record->arg_size[1] = sizeof(fd_set);
            }
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(fd_set));
                record->arg_size[2] = sizeof(fd_set);
            }
            if (args[3] != 0) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(fd_set));
                record->arg_size[3] = sizeof(fd_set);
            }
            if (args[4] != 0) {
                record->arg_data[4] = rr_capture_buffer(env, args[4], sizeof(struct timespec));
                record->arg_size[4] = sizeof(struct timespec);
            }
            if (args[5] != 0) {
                /* sigmask */
                record->arg_data[5] = rr_capture_buffer(env, args[5], 8); // sizeof(sigset_t)
                record->arg_size[5] = 8;
            }
            break;
#endif

#ifdef TARGET_NR_nanosleep
        case TARGET_NR_nanosleep:
            /* 捕获 timespec 结构体（输入和输出） */
            if (args[0] != 0) {
                record->arg_data[0] = rr_capture_buffer(env, args[0], sizeof(struct timespec));
                record->arg_size[0] = sizeof(struct timespec);
            }
            if (ret == 0 && args[1] != 0) {
                /* 剩余时间（可选，仅在被中断时） */
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct timespec));
                record->arg_size[1] = sizeof(struct timespec);
            }
            break;
#endif

#ifdef TARGET_NR_clock_nanosleep
        case TARGET_NR_clock_nanosleep:
            /* clock_nanosleep 类似 nanosleep 但有时钟 ID */
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct timespec));
                record->arg_size[2] = sizeof(struct timespec);
            }
            if (ret == 0 && args[3] != 0) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(struct timespec));
                record->arg_size[3] = sizeof(struct timespec);
            }
            break;
#endif

#ifdef TARGET_NR_timer_create
        case TARGET_NR_timer_create:
            /* timer_create 返回 timer_t (timer ID) */
            if (ret == 0 && args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(int)); // timer_t is int
                record->arg_size[2] = sizeof(int);
            }
            if (args[1] != 0) {
                /* sigevent structure */
                record->arg_data[1] = rr_capture_buffer(env, args[1], sizeof(struct sigevent));
                record->arg_size[1] = sizeof(struct sigevent);
            }
            break;
#endif

#ifdef TARGET_NR_timer_settime
        case TARGET_NR_timer_settime:
            /* 设置定时器 */
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct itimerspec));
                record->arg_size[2] = sizeof(struct itimerspec);
            }
            if (ret == 0 && args[3] != 0) {
                /* 旧值（可选） */
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(struct itimerspec));
                record->arg_size[3] = sizeof(struct itimerspec);
            }
            break;
#endif

#ifdef TARGET_NR_timerfd_create
        case TARGET_NR_timerfd_create:
            /* timerfd_create 参数简单，返回 fd */
            break;
#endif

#ifdef TARGET_NR_timerfd_settime
        case TARGET_NR_timerfd_settime:
            /* 设置 timerfd */
            if (args[2] != 0) {
                record->arg_data[2] = rr_capture_buffer(env, args[2], sizeof(struct itimerspec));
                record->arg_size[2] = sizeof(struct itimerspec);
            }
            if (ret == 0 && args[3] != 0) {
                record->arg_data[3] = rr_capture_buffer(env, args[3], sizeof(struct itimerspec));
                record->arg_size[3] = sizeof(struct itimerspec);
            }
            break;
#endif

#ifdef TARGET_NR_signalfd
        case TARGET_NR_signalfd:
            /* 捕获信号掩码 */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], 8); // sizeof(sigset_t)
                record->arg_size[1] = 8;
            }
            break;
#endif

#ifdef TARGET_NR_signalfd4
        case TARGET_NR_signalfd4:
            /* signalfd4 = signalfd + flags */
            if (args[1] != 0) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], 8); // sizeof(sigset_t)
                record->arg_size[1] = 8;
            }
            break;
#endif

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

    /* 🔥 修复：不跳过任何 syscall，确保 record/replay 一致 */
    /* 之前 skip 的 mmap/brk/getpid 会导致 replay 无法匹配 */

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

    RR_VERBOSE("RECORD_SYSCALL: Recording index=%u, syscall=%d, ret=%ld",
            record->index, record->syscall_nr, record->retval);
    
    /* 更新BB trace的syscall索引 */
    rr_bb_trace_update_syscall_idx(record->index);

    /* 检测FD创建 */
    record->creates_fd = syscall_creates_fd(num, ret);
    if (record->creates_fd) {
        record->created_fd = (int32_t)ret;
        RR_FD_TRACE("Syscall %d creates FD: %d", num, record->created_fd);
        /* 注意: FD映射在 rr_syscall_post_hook 中统一处理，不在record阶段添加 */
    }

    /* 智能捕获参数数据 */
    /* 
     * 🔥 修复双重捕获问题：
     * - 默认只使用 aux_data (EnvFuzz风格)
     * - 仅当配置 use_legacy_capture=true 时才使用传统方式
     * - 避免重复捕获相同数据
     */
    if (g_rr_config.use_legacy_capture) {
        RR_VERBOSE("RECORD_SYSCALL: Using legacy capture for syscall %d", num);
        capture_syscall_args(env, num, args, ret, record);
    }
    
    /* 使用 aux_data 系统捕获（推荐方式） */
    RR_VERBOSE("RECORD_SYSCALL: About to call capture_syscall_args_aux for syscall %d, ret=%ld, record=%p", 
               num, ret, record);
    capture_syscall_args_aux(env, num, args, ret, record);
    RR_VERBOSE("RECORD_SYSCALL: After capture_syscall_args_aux, record=%p, has_aux_data=%d, aux_data=%p", 
               record, record->has_aux_data, record->aux_data);

    /* 添加到轨迹链表 */
    if (g_rr_framework->trace_tail) {
        g_rr_framework->trace_tail->next = record;
    } else {
        g_rr_framework->trace_head = record;
    }
    g_rr_framework->trace_tail = record;

    /* 写入文件 - 逐字段写入以避免结构体对齐问题 */
    RR_VERBOSE("RECORD_SYSCALL: Writing record to trace file (index=%u, syscall=%d)", record->index, num);
    
    // 写入基本字段（使用二进制缓冲区）
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

    
    if (fwrite(buffer, 8, 1, g_trace_file) != 1) {
        RR_ERROR("Failed to write record header");
        return -1;
    }

    /* 🔥 修复：减少频繁的 fflush，只在每 100 条记录时刷新一次 */
    if (g_rr_framework->trace_length % 100 == 0) {
        fflush(g_trace_file);
    }

    if (fwrite(record->args, sizeof(abi_long) * 8, 1, g_trace_file) != 1 ||
        fwrite(&record->retval, sizeof(abi_long), 1, g_trace_file) != 1 ||
        fwrite(record->arg_size, sizeof(size_t) * 8, 1, g_trace_file) != 1 ||
        fwrite(&record->creates_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fwrite(&record->uses_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fwrite(&record->created_fd, sizeof(int32_t), 1, g_trace_file) != 1) {
        RR_ERROR("RECORD_SYSCALL: Failed to write syscall record fields");
        return -1;
    }

    /* 写入参数数据 */
    int arg_count = 0;
    for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
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

    /* 写入 aux_data（如果有） */
    RR_VERBOSE("RECORD_SYSCALL: Before aux write - record=%p, has_aux_data=%d, aux_data=%p", 
               record, record->has_aux_data, record->aux_data);
    if (record->has_aux_data && record->aux_data) {
        /* 写入 aux_data 标记 */
        uint32_t aux_magic = 0x41555844; // "AUXD"
        long pos_before = ftell(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: Writing AUXD magic 0x%08x at pos %ld", aux_magic, pos_before);
        size_t written = fwrite(&aux_magic, sizeof(uint32_t), 1, g_trace_file);
        if (written != 1) {
            RR_ERROR("RECORD_SYSCALL: Failed to write AUXD magic!");
        }
        long pos_after = ftell(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: After writing AUXD, pos=%ld (delta=%ld)", pos_after, pos_after - pos_before);
        
        /* 统计 aux_data 数量 */
        uint32_t aux_count = 0;
        rr_aux_data_t *curr = record->aux_data;
        while (curr) {
            aux_count++;
            curr = curr->next;
        }
        fwrite(&aux_count, sizeof(uint32_t), 1, g_trace_file);
        
        /* 写入每个 aux_data */
        curr = record->aux_data;
        while (curr) {
            fwrite(&curr->kind, sizeof(uint8_t), 1, g_trace_file);
            fwrite(&curr->arg_mask, sizeof(uint8_t), 1, g_trace_file);
            fwrite(&curr->size, sizeof(uint32_t), 1, g_trace_file);
            fwrite(curr->data, curr->size, 1, g_trace_file);
            
            RR_VERBOSE("RECORD_SYSCALL: Wrote aux_data kind=%d, arg=%d, size=%u",
                       curr->kind, curr->arg_mask, curr->size);
            curr = curr->next;
        }
    } else {
        /* 写入无 aux_data 标记 */
        uint32_t no_aux = 0;
        RR_VERBOSE("RECORD_SYSCALL: Writing no_aux marker (has_aux_data=%d, aux_data=%p)", 
                   record->has_aux_data, record->aux_data);
        fwrite(&no_aux, sizeof(uint32_t), 1, g_trace_file);
    }

    /* 🔥 重要：每次写完 record 后立即 flush，确保数据完整性 */
    fflush(g_trace_file);
    
    if (num == 44) {
        RR_INFO("🎯 RECORDED SENDTO: index=%u, has_aux=%d", record->index, record->has_aux_data);
    }
    RR_VERBOSE("RECORD_SYSCALL: Successfully recorded syscall %d (index=%u, args=%d, aux=%s, total_syscalls=%u)",
               num, record->index, arg_count, record->has_aux_data ? "yes" : "no", g_rr_framework->trace_length);
    RR_LOG("Recorded syscall %d: %s -> %ld", record->index,
           (num >= 0 && num < 400) ? "syscall" : "unknown", ret);

    /* 优化：每100个记录更新一次头部，减少 fseek 开销 */
    if (g_rr_framework->trace_length % 100 == 0) {
        long header_pos = ftell(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: Before header update - ftell=%ld", header_pos);
        fseek(g_trace_file, sizeof(uint32_t) * 2, SEEK_SET);  // 跳过magic和version
        uint32_t record_count = g_rr_framework->trace_length;
        fwrite(&record_count, sizeof(record_count), 1, g_trace_file);
        fseek(g_trace_file, header_pos, SEEK_SET);  // 恢复位置
        long after_seek = ftell(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: After header update - ftell=%ld (should be %ld)", after_seek, header_pos);
        fflush(g_trace_file);
        RR_VERBOSE("RECORD_SYSCALL: Updated header with record_count=%u", record_count);
    }

    return 0;
}
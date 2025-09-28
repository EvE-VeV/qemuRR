/**
 * RR-Fuzz重放模块
 * 实现Replay模式的核心逻辑，对应design.md中的rr_replay.c
 */

#include "rr_framework.h"
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>

static FILE *g_trace_file = NULL;
static syscall_record_t *g_current_record = NULL;

/**
 * 开始重放
 */
int rr_start_replay(const char *trace_file)
{
    RR_VERBOSE("Starting replay initialization");

    if (!trace_file) {
        trace_file = "rr_trace.dat";
        RR_INFO("Using default trace file: %s", trace_file);
    }

    RR_INFO("Opening trace file for reading: %s", trace_file);
    g_trace_file = fopen(trace_file, "rb");
    if (!g_trace_file) {
        RR_ERROR("Failed to open trace file: %s", trace_file);
        return -1;
    }

    /* 读取并验证文件头 */
    uint32_t magic, version;
    RR_VERBOSE("Reading trace file header");
    if (fread(&magic, sizeof(magic), 1, g_trace_file) != 1 ||
        fread(&version, sizeof(version), 1, g_trace_file) != 1) {
        RR_ERROR("Failed to read trace file header");
        fclose(g_trace_file);
        return -1;
    }

    if (magic != 0x52525254) { // "RRTR"
        RR_ERROR("Invalid trace file magic: 0x%x (expected 0x52525254)", magic);
        fclose(g_trace_file);
        return -1;
    }

    RR_VERBOSE("Trace header validated: magic=0x%x, version=%u", magic, version);
    RR_INFO("Started replay from: %s (version %u)", trace_file, version);

    /* 读取记录数量 */
    uint32_t record_count = 0;
    size_t count_read = fread(&record_count, sizeof(record_count), 1, g_trace_file);
    if (count_read != 1) {
        RR_ERROR("Failed to read record count from trace file");
        fclose(g_trace_file);
        return -1;
    }

    long header_end_pos = ftell(g_trace_file);
    RR_INFO("Trace contains %u syscall records", record_count);
    RR_VERBOSE("Header ends at position %ld, ready to read records", header_end_pos);

    return 0;
}

/**
 * 停止重放
 */
void rr_stop_replay(void)
{
    if (g_trace_file) {
        RR_VERBOSE("Closing trace file");
        fclose(g_trace_file);
        g_trace_file = NULL;
        RR_INFO("Replay stopped");
    } else {
        RR_VERBOSE("Replay stop called but no trace file was open");
    }
}

/**
 * 读取下一条记录
 */
static syscall_record_t *read_next_record(void)
{
    if (!g_trace_file) {
        RR_ERROR("READ_NEXT_RECORD: No trace file open");
        return NULL;
    }

    RR_VERBOSE("READ_NEXT_RECORD: Attempting to read next record from trace file");
    syscall_record_t *record = g_malloc0(sizeof(syscall_record_t));

    /* 读取基本记录 - 逐字段读取以避免结构体对齐问题 */
    long pos = ftell(g_trace_file);
    RR_VERBOSE("READ_NEXT_RECORD: Reading record at file position %ld", pos);

    // 读取手动打包的二进制数据以匹配记录格式
    uint8_t buffer[8]; // 4字节index + 4字节syscall_nr
    if (fread(buffer, 8, 1, g_trace_file) != 1) {
        RR_ERROR("READ_NEXT_RECORD: Failed to read record header");
        g_free(record);
        return NULL;
    }

    // 手动解包
    record->index = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
    record->syscall_nr = (int32_t)(buffer[4] | (buffer[5] << 8) | (buffer[6] << 16) | (buffer[7] << 24));

    fprintf(stderr, "DEBUG_READ: Binary unpack - index=%u, syscall=%d\n", record->index, record->syscall_nr);
    fprintf(stderr, "DEBUG_READ: Buffer bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
            buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]);

    // 读取其余字段
    if (fread(record->args, sizeof(abi_long) * 8, 1, g_trace_file) != 1 ||
        fread(&record->retval, sizeof(abi_long), 1, g_trace_file) != 1 ||
        fread(record->arg_size, sizeof(size_t) * 8, 1, g_trace_file) != 1 ||
        fread(&record->creates_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fread(&record->uses_fd, sizeof(bool), 1, g_trace_file) != 1 ||
        fread(&record->created_fd, sizeof(int32_t), 1, g_trace_file) != 1) {
        RR_ERROR("READ_NEXT_RECORD: Failed to read record fields");
        if (feof(g_trace_file)) {
            RR_ERROR("READ_NEXT_RECORD: Hit end of file");
        }
        if (ferror(g_trace_file)) {
            RR_ERROR("READ_NEXT_RECORD: File read error");
        }
        g_free(record);
        return NULL;
    }

    RR_VERBOSE("READ_NEXT_RECORD: Successfully read record fields");
    RR_VERBOSE("READ_NEXT_RECORD: Record data - index=%u, syscall=%d, ret=%ld",
               record->index, record->syscall_nr, record->retval);

    /* 读取参数数据 */
    int arg_index;
    while (fread(&arg_index, sizeof(int), 1, g_trace_file) == 1) {
        if (arg_index == -1) { // 结束标记
            break;
        }

        if (arg_index >= 0 && arg_index < 8) {
            size_t size;
            if (fread(&size, sizeof(size), 1, g_trace_file) == 1 && size > 0 && size <= 64 * 1024) {
                record->arg_data[arg_index] = g_malloc(size);
                if (fread(record->arg_data[arg_index], size, 1, g_trace_file) == 1) {
                    record->arg_size[arg_index] = size;
                } else {
                    g_free(record->arg_data[arg_index]);
                    record->arg_data[arg_index] = NULL;
                    record->arg_size[arg_index] = 0;
                }
            }
        }
    }

    return record;
}

/**
 * 应用FD映射
 * 实现design.md中的句柄映射逻辑
 */
static void apply_fd_mapping(abi_long *args, int syscall_nr)
{
    switch (syscall_nr) {
        case TARGET_NR_read:
        case TARGET_NR_write:
        case TARGET_NR_close:
#ifdef TARGET_NR_lseek
        case TARGET_NR_lseek:
#endif
#ifdef TARGET_NR_fstat
        case TARGET_NR_fstat:
#endif
            /* 第一个参数是FD */
            if (args[0] >= 0) {
                gpointer mapped_fd = g_hash_table_lookup(g_rr_framework->fd_map,
                                                        GINT_TO_POINTER((int)args[0]));
                if (mapped_fd) {
                    args[0] = GPOINTER_TO_INT(mapped_fd);
                }
            }
            break;

#ifdef TARGET_NR_dup2
        case TARGET_NR_dup2:
#endif
            /* 两个参数都是FD */
            for (int i = 0; i < 2; i++) {
                if (args[i] >= 0) {
                    gpointer mapped_fd = g_hash_table_lookup(g_rr_framework->fd_map,
                                                            GINT_TO_POINTER((int)args[i]));
                    if (mapped_fd) {
                        args[i] = GPOINTER_TO_INT(mapped_fd);
                    }
                }
            }
            break;

        // 可以添加更多系统调用的FD映射处理
        default:
            break;
    }
}

/**
 * 更新FD映射表
 */
static void update_fd_mapping(int syscall_nr, const abi_long *orig_args, abi_long ret)
{
    if (ret < 0) {
        return; // 系统调用失败，不更新映射
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
            /* 这些调用创建新FD，需要建立映射 */
            if (g_current_record && g_current_record->creates_fd) {
                int record_fd = g_current_record->created_fd;
                int replay_fd = (int)ret;
                g_hash_table_insert(g_rr_framework->fd_map,
                                   GINT_TO_POINTER(record_fd),
                                   GINT_TO_POINTER(replay_fd));
                RR_LOG("FD mapping: record_fd=%d -> replay_fd=%d", record_fd, replay_fd);
            }
            break;

        case TARGET_NR_dup:
#ifdef TARGET_NR_dup2
        case TARGET_NR_dup2:
#endif
#ifdef TARGET_NR_dup3
        case TARGET_NR_dup3:
#endif
            /* 复制FD的调用 */
            if (g_current_record && g_current_record->creates_fd) {
                int record_fd = g_current_record->created_fd;
                int replay_fd = (int)ret;
                g_hash_table_insert(g_rr_framework->fd_map,
                                   GINT_TO_POINTER(record_fd),
                                   GINT_TO_POINTER(replay_fd));
            }
            break;

        case TARGET_NR_close:
            /* 关闭FD，从映射表中移除 */
            g_hash_table_remove(g_rr_framework->fd_map, GINT_TO_POINTER((int)orig_args[0]));
            break;

        default:
            break;
    }
}

/**
 * 重放系统调用
 * 实现design.md中的同步检查和句柄映射
 */
abi_long rr_replay_syscall(CPUArchState *env, int num, abi_long *args)
{
    fprintf(stderr, "DEBUG_rr_replay_syscall: Entry for syscall %d\n", num);
    fprintf(stderr, "DEBUG_rr_replay_syscall: g_rr_framework=%p\n", g_rr_framework);
    fprintf(stderr, "DEBUG_rr_replay_syscall: g_trace_file=%p\n", g_trace_file);

    if (!g_rr_framework) {
        fprintf(stderr, "DEBUG_rr_replay_syscall: g_rr_framework is NULL, returning -1\n");
        RR_ERROR("REPLAY_SYSCALL: g_rr_framework is NULL");
        return -1;
    }

    if (!g_trace_file) {
        fprintf(stderr, "DEBUG_rr_replay_syscall: g_trace_file is NULL, returning -1\n");
        RR_ERROR("REPLAY_SYSCALL: g_trace_file is NULL");
        return -1;
    }

    RR_VERBOSE("REPLAY_SYSCALL: Called for syscall %d, replay_index=%u", num, g_rr_framework->replay_index);
    RR_VERBOSE("REPLAY_SYSCALL: g_trace_file=%p, g_current_record=%p", g_trace_file, g_current_record);

    /* 维护全局索引同步 - design.md的核心要求 */
    fprintf(stderr, "DEBUG_rr_replay_syscall: replay_index=%u, g_current_record=%p\n", g_rr_framework->replay_index, g_current_record);
    if (g_rr_framework->replay_index == 0 || !g_current_record) {
        fprintf(stderr, "DEBUG_rr_replay_syscall: Need to read next record\n");
        RR_VERBOSE("REPLAY_SYSCALL: Reading next record (current_record=%p)", g_current_record);
        g_current_record = read_next_record();
        if (!g_current_record) {
            fprintf(stderr, "DEBUG_rr_replay_syscall: read_next_record returned NULL\n");
            RR_ERROR("REPLAY_SYSCALL: End of trace reached at index %u", g_rr_framework->replay_index);
            return -1;
        }
        fprintf(stderr, "DEBUG_rr_replay_syscall: Got record index=%u, syscall=%d, ret=%ld\n",
                g_current_record->index, g_current_record->syscall_nr, g_current_record->retval);
        RR_VERBOSE("REPLAY_SYSCALL: Got record index=%u, syscall=%d, ret=%ld",
                   g_current_record->index, g_current_record->syscall_nr, g_current_record->retval);
    }

    /* 智能同步 - 如果系统调用不匹配，继续读取直到找到匹配的 */
    while (g_current_record && g_current_record->syscall_nr != num) {
        fprintf(stderr, "DEBUG_rr_replay_syscall: MISMATCH - recorded=%d, actual=%d, skipping\n",
                g_current_record->syscall_nr, num);
        RR_VERBOSE("REPLAY_SYSCALL: Skipping unmatched syscall (recorded=%d, actual=%d)",
                   g_current_record->syscall_nr, num);

        /* 清理当前记录 */
        for (int i = 0; i < 8; i++) {
            if (g_current_record->arg_data[i]) {
                g_free(g_current_record->arg_data[i]);
            }
        }
        g_free(g_current_record);

        /* 读取下一条记录 */
        g_current_record = read_next_record();
        if (!g_current_record) {
            RR_ERROR("REPLAY_SYSCALL: End of trace reached while looking for syscall %d", num);
            return -1;
        }
        RR_VERBOSE("REPLAY_SYSCALL: Trying next record index=%u, syscall=%d",
                   g_current_record->index, g_current_record->syscall_nr);
    }

    if (g_current_record->syscall_nr != num) {
        RR_ERROR("REPLAY_SYSCALL: Could not find matching syscall for %d", num);
        return -1;
    }

    fprintf(stderr, "DEBUG_rr_replay_syscall: FOUND MATCH - syscall=%d at record index=%u\n",
            num, g_current_record->index);
    RR_VERBOSE("REPLAY_SYSCALL: Found matching syscall %d at record index %u",
               num, g_current_record->index);

    /* 应用FD映射 */
    apply_fd_mapping(args, num);

    /* 应用Fuzzing变异（如果在Fuzzing模式） */
    rr_fuzz_mutate_syscall(env, g_rr_framework->replay_index, args, num);

    /* 自动快照管理 */
    rr_snapshot_auto_manage(num, g_rr_framework->replay_index);

    /* 处理特殊系统调用 */
    abi_long ret = g_current_record->retval;

    switch (num) {
#ifdef TARGET_NR_mmap
        case TARGET_NR_mmap:
#endif
#ifdef TARGET_NR_mmap2
        case TARGET_NR_mmap2:
#endif
            /* mmap在replay时的策略：
             * 1. 如果原来记录失败，replay也应该失败
             * 2. 如果原来记录成功，让系统调用正常执行，但不强制相同地址
             * 3. 记录地址映射关系供后续使用 */
            fprintf(stderr, "DEBUG_MMAP_REPLAY: Original recorded ret=0x%lx\n", (unsigned long)ret);

            if (ret == (abi_long)-1) {
                /* 原来记录的是失败，replay也应该失败 */
                RR_VERBOSE("MMAP_REPLAY: Recorded failed mmap, forcing failure");
                /* 这里我们不修改ret，让其保持为-1 */
            } else {
                /* 原来记录成功，对于mmap我们采用混合策略：
                 * 1. 不强制返回相同地址
                 * 2. 让系统调用继续执行以分配实际内存
                 * 3. 但确保程序行为一致性 */
                fprintf(stderr, "DEBUG_MMAP_REPLAY: Recorded successful mmap, allowing normal execution\n");
                RR_VERBOSE("MMAP_REPLAY: Allowing normal mmap execution for consistency");

                /* 注意：这里我们需要返回一个特殊值告诉上层代码：
                 * "请执行原始的mmap系统调用，因为我们需要实际的内存分配"
                 *
                 * 在rr_main.c中：
                 * if (rr_ret != -1) {
                 *     ret = rr_ret;  // 使用replay的结果
                 * } else {
                 *     ret = do_syscall1(...);  // 执行原始系统调用
                 * }
                 */

                /* 清理当前记录并手动递增索引，因为我们提前返回，
                 * 不会执行到函数结尾的标准递增逻辑 */
                for (int i = 0; i < 8; i++) {
                    if (g_current_record->arg_data[i]) {
                        g_free(g_current_record->arg_data[i]);
                    }
                }
                g_free(g_current_record);
                g_current_record = NULL;
                g_rr_framework->replay_index++; /* 必须手动递增，因为return -1跳过函数结尾 */

                /* 返回-1让调用者执行原始mmap */
                return -1;
            }
            break;

        case TARGET_NR_read:
            /* 如果记录了读取的数据，需要写回到目标缓冲区 */
            if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0 && ret > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                       g_current_record->arg_data[1],
                                       MIN(ret, g_current_record->arg_size[1]), 1) != 0) {
                    RR_LOG("Failed to write back read data");
                }
            }
            break;

        case TARGET_NR_uname:
            /* 写回utsname结构体数据 */
            if (g_current_record->arg_data[0] && g_current_record->arg_size[0] > 0 && ret == 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[0],
                                       g_current_record->arg_data[0],
                                       g_current_record->arg_size[0], 1) != 0) {
                    RR_LOG("Failed to write back uname data");
                }
            }
            break;

#ifdef TARGET_NR_newfstatat
        case TARGET_NR_newfstatat:
#endif
#ifdef TARGET_NR_fstatat64
        case TARGET_NR_fstatat64:
#endif
            /* 写回stat结构体数据 */
            if (g_current_record->arg_data[2] && g_current_record->arg_size[2] > 0 && ret == 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[2],
                                       g_current_record->arg_data[2],
                                       g_current_record->arg_size[2], 1) != 0) {
                    RR_LOG("Failed to write back stat data");
                }
            }
            break;

        case TARGET_NR_getdents64:
            /* 写回目录项数据 */
            if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0 && ret > 0) {
                size_t bytes_to_write = MIN(ret, g_current_record->arg_size[1]);
                if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                       g_current_record->arg_data[1],
                                       bytes_to_write, 1) != 0) {
                    RR_LOG("Failed to write back getdents64 data");
                }
            }
            break;

#ifdef TARGET_NR_stat
        case TARGET_NR_stat:
            /* 写回stat结构体数据 */
            if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0 && ret == 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                       g_current_record->arg_data[1],
                                       g_current_record->arg_size[1], 1) != 0) {
                    RR_LOG("Failed to write back stat data");
                }
            }
            break;
#endif

#ifdef TARGET_NR_lstat
        case TARGET_NR_lstat:
            /* 写回stat结构体数据 */
            if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0 && ret == 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                       g_current_record->arg_data[1],
                                       g_current_record->arg_size[1], 1) != 0) {
                    RR_LOG("Failed to write back lstat data");
                }
            }
            break;
#endif

#ifdef TARGET_NR_fstat
        case TARGET_NR_fstat:
            /* 写回stat结构体数据 */
            if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0 && ret == 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                       g_current_record->arg_data[1],
                                       g_current_record->arg_size[1], 1) != 0) {
                    RR_LOG("Failed to write back fstat data");
                }
            }
            break;
#endif

#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64:
            /* 写回读取的数据 */
            if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0 && ret > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                       g_current_record->arg_data[1],
                                       MIN(ret, g_current_record->arg_size[1]), 1) != 0) {
                    RR_LOG("Failed to write back pread64 data");
                }
            }
            break;
#endif

#ifdef TARGET_NR_gettimeofday
        case TARGET_NR_gettimeofday:
            /* 写回timeval结构体数据 */
            if (g_current_record->arg_data[0] && g_current_record->arg_size[0] > 0 && ret == 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[0],
                                       g_current_record->arg_data[0],
                                       g_current_record->arg_size[0], 1) != 0) {
                    RR_LOG("Failed to write back gettimeofday data");
                }
            }
            break;
#endif

#ifdef TARGET_NR_clock_gettime
        case TARGET_NR_clock_gettime:
            /* 写回timespec结构体数据 */
            if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0 && ret == 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                       g_current_record->arg_data[1],
                                       g_current_record->arg_size[1], 1) != 0) {
                    RR_LOG("Failed to write back clock_gettime data");
                }
            }
            break;
#endif

#ifdef TARGET_NR_pipe
        case TARGET_NR_pipe:
#endif
#ifdef TARGET_NR_pipe2
        case TARGET_NR_pipe2:
#endif
            /* 管道调用返回两个FD，需要写回到参数指向的数组 */
            if (ret == 0 && args[0] != 0) {
                int pipe_fds[2];
                // 这里需要从记录中恢复管道FD，简化处理
                pipe_fds[0] = g_current_record->created_fd;
                pipe_fds[1] = g_current_record->created_fd + 1; // 简化假设
                if (cpu_memory_rw_debug(env_cpu(env), args[0], (uint8_t*)pipe_fds,
                                       sizeof(pipe_fds), 1) != 0) {
                    RR_LOG("Failed to write back pipe FDs");
                }
            }
            break;

        // getrandom数据恢复
        case TARGET_NR_getrandom:
            /* 写回随机数据 */
            if (g_current_record->arg_data[0] && g_current_record->arg_size[0] > 0 && ret > 0) {
                size_t copy_size = MIN(ret, g_current_record->arg_size[0]);
                if (cpu_memory_rw_debug(env_cpu(env), args[0],
                                       g_current_record->arg_data[0], copy_size, 1) != 0) {
                    RR_LOG("Failed to write back getrandom data");
                }
            }
            break;

        // 信号处理数据恢复
#ifdef TARGET_NR_rt_sigaction
        case TARGET_NR_rt_sigaction:
            /* 写回旧的sigaction结构体 */
            if (g_current_record->arg_data[2] && g_current_record->arg_size[2] > 0 && ret == 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[2],
                                       g_current_record->arg_data[2],
                                       g_current_record->arg_size[2], 1) != 0) {
                    RR_LOG("Failed to write back rt_sigaction data");
                }
            }
            break;
#endif

#ifdef TARGET_NR_rt_sigprocmask
        case TARGET_NR_rt_sigprocmask:
            /* 写回旧的信号掩码 */
            if (g_current_record->arg_data[2] && g_current_record->arg_size[2] > 0 && ret == 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[2],
                                       g_current_record->arg_data[2],
                                       g_current_record->arg_size[2], 1) != 0) {
                    RR_LOG("Failed to write back rt_sigprocmask data");
                }
            }
            break;
#endif

        // 网络相关数据恢复
#ifdef TARGET_NR_accept
        case TARGET_NR_accept:
#endif
#ifdef TARGET_NR_accept4
        case TARGET_NR_accept4:
#endif
            /* 写回客户端地址信息 */
            if (ret >= 0) {
                if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0) {
                    if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                           g_current_record->arg_data[1],
                                           g_current_record->arg_size[1], 1) != 0) {
                        RR_LOG("Failed to write back accept sockaddr data");
                    }
                }
                if (g_current_record->arg_data[2] && g_current_record->arg_size[2] > 0) {
                    if (cpu_memory_rw_debug(env_cpu(env), args[2],
                                           g_current_record->arg_data[2],
                                           g_current_record->arg_size[2], 1) != 0) {
                        RR_LOG("Failed to write back accept addrlen data");
                    }
                }
            }
            break;

#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
            /* 写回接收到的数据和源地址 */
            if (ret > 0) {
                if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0) {
                    size_t copy_size = MIN(ret, g_current_record->arg_size[1]);
                    if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                           g_current_record->arg_data[1], copy_size, 1) != 0) {
                        RR_LOG("Failed to write back recvfrom data");
                    }
                }
                // 写回源地址
                if (g_current_record->arg_data[4] && g_current_record->arg_size[4] > 0) {
                    if (cpu_memory_rw_debug(env_cpu(env), args[4],
                                           g_current_record->arg_data[4],
                                           g_current_record->arg_size[4], 1) != 0) {
                        RR_LOG("Failed to write back recvfrom sockaddr data");
                    }
                }
                if (g_current_record->arg_data[5] && g_current_record->arg_size[5] > 0) {
                    if (cpu_memory_rw_debug(env_cpu(env), args[5],
                                           g_current_record->arg_data[5],
                                           g_current_record->arg_size[5], 1) != 0) {
                        RR_LOG("Failed to write back recvfrom addrlen data");
                    }
                }
            }
            break;
#endif

        // 进程相关数据恢复
#ifdef TARGET_NR_wait4
        case TARGET_NR_wait4:
            /* 写回子进程状态 */
            if (ret >= 0 && g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1],
                                       g_current_record->arg_data[1],
                                       g_current_record->arg_size[1], 1) != 0) {
                    RR_LOG("Failed to write back wait4 status data");
                }
            }
            break;
#endif

        // 管道数据恢复已在前面处理

        // 文件访问权限检查系统调用
#ifdef TARGET_NR_access
        case TARGET_NR_access:
            // access系统调用不需要数据写回，仅依赖返回值
            // 记录的字符串数据用于验证，但不需要恢复
            break;
#endif

        case TARGET_NR_faccessat:
            // faccessat系统调用不需要数据写回，仅依赖返回值
            // 记录的字符串数据用于验证，但不需要恢复
            break;

        // 写入操作增强验证
        case TARGET_NR_write:
            // write系统调用的数据验证（可选）
            if (g_current_record->arg_data[1] && g_current_record->arg_size[1] > 0) {
                // 可选：验证写入数据的一致性
                // 通常write不需要数据恢复，仅验证返回值和FD映射
                RR_LOG("Write operation with %zu bytes data recorded", g_current_record->arg_size[1]);
            }
            break;

        // 资源限制数据恢复
        case TARGET_NR_prlimit64:
            /* 写回旧的资源限制 */
            if (ret == 0 && g_current_record->arg_data[3] && g_current_record->arg_size[3] > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[3],
                                       g_current_record->arg_data[3],
                                       g_current_record->arg_size[3], 1) != 0) {
                    RR_LOG("Failed to write back prlimit64 data");
                }
            }
            break;

        default:
            /* 大部分系统调用只需要返回记录的返回值 */
            break;
    }

    /* 更新FD映射 */
    update_fd_mapping(num, args, ret);

    /* 准备下一条记录 */
    /* 清理当前记录的参数数据 */
    for (int i = 0; i < 8; i++) {
        if (g_current_record->arg_data[i]) {
            g_free(g_current_record->arg_data[i]);
        }
    }
    g_free(g_current_record);
    g_current_record = NULL;

    g_rr_framework->replay_index++;

    RR_VERBOSE("REPLAY_SYSCALL: Successfully replayed syscall %u: %d -> %ld",
               g_rr_framework->replay_index - 1, num, ret);
    return ret;
}

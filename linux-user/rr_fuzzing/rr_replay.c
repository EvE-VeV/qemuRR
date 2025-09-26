/**
 * RR-Fuzz重放模块
 * 实现Replay模式的核心逻辑，对应design.md中的rr_replay.c
 */

#include "rr_framework.h"
#include <unistd.h>

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

    /* 读取基本记录 */
    long pos = ftell(g_trace_file);
    RR_VERBOSE("READ_NEXT_RECORD: Reading record at file position %ld, struct size=%zu",
               pos, sizeof(syscall_record_t));

    size_t bytes_read = fread(record, 1, sizeof(syscall_record_t), g_trace_file);
    if (bytes_read != sizeof(syscall_record_t)) {
        RR_ERROR("READ_NEXT_RECORD: Failed to read record structure (read %zu bytes, expected %zu)",
                 bytes_read, sizeof(syscall_record_t));
        if (feof(g_trace_file)) {
            RR_ERROR("READ_NEXT_RECORD: Hit end of file");
        }
        if (ferror(g_trace_file)) {
            RR_ERROR("READ_NEXT_RECORD: File read error");
        }
        g_free(record);
        return NULL;
    }

    RR_VERBOSE("READ_NEXT_RECORD: Successfully read %zu bytes", bytes_read);
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
     RR_VERBOSE("REPLAY_SYSCALL: Called for syscall %d, replay_index=%u", num, g_rr_framework->replay_index);
 
     /* 维护全局索引同步 - design.md的核心要求 */
     if (g_rr_framework->replay_index == 0 || !g_current_record) {
         RR_VERBOSE("REPLAY_SYSCALL: Reading next record (current_record=%p)", g_current_record);
         g_current_record = read_next_record();
         if (!g_current_record) {
             RR_ERROR("REPLAY_SYSCALL: End of trace reached at index %u", g_rr_framework->replay_index);
             return -1;
         }
         RR_VERBOSE("REPLAY_SYSCALL: Got record index=%u, syscall=%d, ret=%ld",
                    g_current_record->index, g_current_record->syscall_nr, g_current_record->retval);
     }
 
     /* 严格同步检查 - 防止"脱轨" */
     if (g_current_record->syscall_nr != num) {
         RR_ERROR("REPLAY_SYSCALL: Syscall mismatch at index %u: expected %d, got %d",
                  g_rr_framework->replay_index, g_current_record->syscall_nr, num);
         return -1;
     }
     RR_VERBOSE("REPLAY_SYSCALL: Syscall match successful, proceeding with replay");
 
     /* 应用FD映射 */
     apply_fd_mapping(args, num);
 
     /* 应用Fuzzing变异（如果在Fuzzing模式） */
     rr_fuzz_mutate_syscall(env, g_rr_framework->replay_index, args, num);
 
     /* 自动快照管理 */
     rr_snapshot_auto_manage(num, g_rr_framework->replay_index);
 
     /* 处理特殊系统调用 */
     abi_long ret = g_current_record->retval;
 
     switch (num) {
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
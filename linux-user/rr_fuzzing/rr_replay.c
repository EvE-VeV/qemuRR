/**
 * RR-Fuzz 混合重放模块
 * Hybrid Replay Mode - 传统二进制 trace 重放
 * 
 * 负责：
 * - 二进制 trace 的读取和同步
 * - Hybrid 模式的系统调用重放（应用参数 + 执行真实 syscall）
 * - 调度 Pure Replay（当有 aux_data 时）
 */

#define RR_DEBUG 1

#include "rr_framework.h"
#include "rr_aux_data.h"
#include "rr_replay_pure.h"
#include <sys/mman.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>

static FILE *g_trace_file = NULL;
static syscall_record_t *g_current_record = NULL;

/* 标记：当前系统调用是否已从 trace 读取并递增索引 */
__thread bool g_syscall_already_consumed = false;

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

    RR_INFO("Trace contains %u syscall records", record_count);

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

    /* 读取 aux_data（如果有） */
    uint32_t aux_marker = 0;
    RR_VERBOSE("READ_NEXT_RECORD: About to read aux_marker at file pos %ld", ftell(g_trace_file));
    if (fread(&aux_marker, sizeof(uint32_t), 1, g_trace_file) == 1) {
        RR_VERBOSE("READ_NEXT_RECORD: Read aux_marker = 0x%08x", aux_marker);
        if (aux_marker == 0x41555844) { // "AUXD" magic
            RR_VERBOSE("READ_NEXT_RECORD: Found AUXD magic, reading aux_data");
            /* 读取 aux_data 数量 */
            uint32_t aux_count = 0;
            ssize_t read_result = fread(&aux_count, sizeof(uint32_t), 1, g_trace_file);
            RR_VERBOSE("READ_NEXT_RECORD: fread aux_count result=%zd, aux_count=%u", read_result, aux_count);
            if (read_result == 1 && aux_count > 0) {
                RR_VERBOSE("READ_NEXT_RECORD: aux_count = %u", aux_count);
                record->has_aux_data = true;
                
                /* 读取每个 aux_data */
                for (uint32_t i = 0; i < aux_count; i++) {
                    uint8_t kind, arg_mask;
                    uint32_t size;
                    
                    if (fread(&kind, sizeof(uint8_t), 1, g_trace_file) != 1 ||
                        fread(&arg_mask, sizeof(uint8_t), 1, g_trace_file) != 1 ||
                        fread(&size, sizeof(uint32_t), 1, g_trace_file) != 1) {
                        RR_ERROR("READ_NEXT_RECORD: Failed to read aux_data header");
                        break;
                    }
                    
                    /* 读取数据 */
                    uint8_t *data = g_malloc(size);
                    if (fread(data, size, 1, g_trace_file) == 1) {
                        rr_aux_data_t *aux = rr_aux_create((rr_aux_kind_t)kind, arg_mask, data, size);
                        if (aux) {
                            rr_aux_append(&record->aux_data, aux);
                            RR_VERBOSE("READ_NEXT_RECORD: Read aux_data kind=%d, arg=%d, size=%u",
                                       kind, arg_mask, size);
                        }
                    }
                    g_free(data);
                }
            } else {
                RR_VERBOSE("READ_NEXT_RECORD: No aux_data count (read_result=%zd, aux_count=%u)", read_result, aux_count);
            }
        } else {
            RR_VERBOSE("READ_NEXT_RECORD: No AUXD magic (marker=0x%08x)", aux_marker);
        }
        /* 如果 aux_marker == 0，说明没有 aux_data，这是正常的 */
    } else {
        RR_ERROR("READ_NEXT_RECORD: Failed to read aux_marker at pos %ld", ftell(g_trace_file));
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

#ifdef TARGET_NR_mmap
        case TARGET_NR_mmap:
#endif
#ifdef TARGET_NR_mmap2
        case TARGET_NR_mmap2:
#endif
            /* mmap的第5个参数（args[4]）是文件描述符 */
            if (args[4] >= 0) {  /* 不是匿名映射 */
                gpointer mapped_fd = g_hash_table_lookup(g_rr_framework->fd_map,
                                                        GINT_TO_POINTER((int)args[4]));
                if (mapped_fd) {
                    RR_VERBOSE("FD_MAPPING: mmap fd %d -> %d", (int)args[4], GPOINTER_TO_INT(mapped_fd));
                    args[4] = GPOINTER_TO_INT(mapped_fd);
                } else {
                    RR_WARN("FD_MAPPING: mmap fd %d not found in mapping table", (int)args[4]);
                }
            }
            break;

        // 可以添加更多系统调用的FD映射处理
        default:
            break;
    }
}

/* 
 * 注：update_fd_mapping() 函数已移除
 * FD映射功能由 apply_fd_mapping() 处理
 * Pure Replay 功能已移至 rr_replay_pure.c 
 */

/**
 * 重放系统调用
 * 
 * 自动智能模式：
 * 1. 如果 trace 中有 aux_data → Pure Replay（完全独立路径）
 * 2. 否则 → Hybrid Replay（传统路径）
 * 
 * Pure 和 Hybrid 完全分离，互不影响
 */
abi_long rr_replay_syscall(CPUArchState *env, int num, abi_long *args)
{
    RR_VERBOSE("REPLAY_SYSCALL: Entry for syscall %d", num);
    RR_VERBOSE("REPLAY_SYSCALL: g_rr_framework=%p", g_rr_framework);
    RR_VERBOSE("REPLAY_SYSCALL: g_trace_file=%p", g_trace_file);

    /* 重置标记 */
    g_syscall_already_consumed = false;

    if (!g_rr_framework) {
        RR_VERBOSE("REPLAY_SYSCALL: g_rr_framework is NULL, returning -1");
        RR_ERROR("REPLAY_SYSCALL: g_rr_framework is NULL");
        return -1;
    }

    if (!g_trace_file) {
        RR_VERBOSE("REPLAY_SYSCALL: g_trace_file is NULL, returning -1");
        RR_ERROR("REPLAY_SYSCALL: g_trace_file is NULL");
        return -1;
    }

    RR_VERBOSE("REPLAY_SYSCALL: Called for syscall %d, replay_index=%u", num, g_rr_framework->replay_index);
    RR_VERBOSE("REPLAY_SYSCALL: g_trace_file=%p, g_current_record=%p", g_trace_file, g_current_record);

    /* 注释：不再使用skip检查，总是尝试从trace读取
     * 原因：trace可能包含任何syscall（取决于record时的逻辑或trace文件版本）
     * 如果trace里没有匹配的记录，在查找过程中会自然地返回-1真实执行
     * 🔥 修复：不跳过任何 syscall，与 record 策略保持一致
     */

    /* 维护全局索引同步 - design.md的核心要求 */
    RR_VERBOSE("REPLAY_SYSCALL: replay_index=%u, g_current_record=%p", g_rr_framework->replay_index, g_current_record);
    if (g_rr_framework->replay_index == 0 || !g_current_record) {
        RR_VERBOSE("REPLAY_SYSCALL: Need to read next record");
        RR_VERBOSE("REPLAY_SYSCALL: Reading next record (current_record=%p)", g_current_record);
        g_current_record = read_next_record();
        if (!g_current_record) {
            RR_VERBOSE("REPLAY_SYSCALL: read_next_record returned NULL");
            /* EnvFuzz风格：找不到record时，不崩溃，真实执行 */
            RR_WARN("REPLAY_SYSCALL: End of trace at index %u for syscall %d, executing directly", 
                    g_rr_framework->replay_index, num);
            return -1;  /* 真实执行系统调用 */
        }
        RR_VERBOSE("REPLAY_SYSCALL: Got record index=%u, syscall=%d, ret=%d",
                g_current_record->index, g_current_record->syscall_nr, (int)g_current_record->retval);
        RR_VERBOSE("REPLAY_SYSCALL: Got record index=%u, syscall=%d, ret=%d",
                   g_current_record->index, g_current_record->syscall_nr, (int)g_current_record->retval);
                   
    }

    /* 智能同步 - 如果系统调用不匹配，继续读取直到找到匹配的 */
    while (g_current_record && g_current_record->syscall_nr != num) {
        RR_VERBOSE("REPLAY_SYSCALL: MISMATCH - recorded=%d, actual=%d, skipping",
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
            /* EnvFuzz风格：找不到record时，不崩溃，真实执行 */
            RR_WARN("REPLAY_SYSCALL: Syscall %d not found in trace (end of trace), executing directly", num);
            return -1;  /* 真实执行系统调用 */
        }
        RR_VERBOSE("REPLAY_SYSCALL: Trying next record index=%u, syscall=%d",
                   g_current_record->index, g_current_record->syscall_nr);
    }

    if (g_current_record->syscall_nr != num) {
        RR_ERROR("REPLAY_SYSCALL: Could not find matching syscall for %d", num);
        return -1;
    }

    RR_VERBOSE("REPLAY_SYSCALL: FOUND MATCH - syscall=%d at record index=%u",
            num, g_current_record->index);
    RR_VERBOSE("REPLAY_SYSCALL: Found matching syscall %d at record index %u",
               num, g_current_record->index);

    abi_long ret = g_current_record->retval;

    /* ========== 特殊处理 1：Output Syscalls ========== */
    /* 输出系统调用必须真实执行以维持I/O状态，但需要先消费 record */
    if (rr_is_output_syscall(num)) {
        RR_VERBOSE("REPLAY_SYSCALL: Output syscall %d, consuming record and executing directly", num);
        
        /* 清理当前记录 */
        for (int i = 0; i < 8; i++) {
            if (g_current_record->arg_data[i]) {
                g_free(g_current_record->arg_data[i]);
            }
        }
        if (g_current_record->aux_data) {
            rr_aux_free(g_current_record->aux_data);
        }
        g_free(g_current_record);
        g_current_record = NULL;
        
        /* 推进索引 */
        g_rr_framework->replay_index++;
        
        /* 设置标志，防止 post_hook 重复处理 */
        g_syscall_already_consumed = true;
        
        return -1; /* 执行真实 syscall */
    }

    /* ========== 特殊处理 2：内存管理 Syscalls ========== */
    /* mmap 等需要真实分配内存，但强制使用 recorded 地址 */
    bool is_mmap = false;
#ifdef TARGET_NR_mmap
    if (num == TARGET_NR_mmap) is_mmap = true;
#endif
#ifdef TARGET_NR_mmap2
    if (num == TARGET_NR_mmap2) is_mmap = true;
#endif
    
    if (is_mmap && ret != (abi_long)-1) {
        /* mmap 成功的情况，需要真实分配内存 */
        RR_VERBOSE("REPLAY_SYSCALL: mmap detected, need real allocation at 0x%lx", (unsigned long)ret);
        
        /* 设置全局变量，让 syscall.c 使用 MAP_FIXED */
        extern target_ulong g_pending_mmap_recorded_addr;
        extern target_ulong g_pending_mmap_length;
        g_pending_mmap_recorded_addr = (target_ulong)ret;
        g_pending_mmap_length = args[1];  /* length */
        
        /* 清理当前记录 */
        for (int i = 0; i < 8; i++) {
            if (g_current_record->arg_data[i]) {
                g_free(g_current_record->arg_data[i]);
            }
        }
        if (g_current_record->aux_data) {
            rr_aux_free(g_current_record->aux_data);
        }
        g_free(g_current_record);
        g_current_record = NULL;
        
        /* 推进索引 */
        g_rr_framework->replay_index++;
        
        /* 设置标志，防止 post_hook 重复处理 */
        g_syscall_already_consumed = true;
        
        RR_VERBOSE("REPLAY_SYSCALL: Returning -1 to trigger real mmap with MAP_FIXED");
        return -1; /* 让 QEMU 执行真实 mmap，但使用 MAP_FIXED */
    }

    /* ========== 路径分叉：Pure vs Hybrid ========== */
    
    if (g_current_record->has_aux_data) {
        /* 
         * 路径1：Pure Replay 或 Pure Fuzzing
         * 
         * ✅ 修复: 在 Fuzzing 模式下，跳过 Pure Replay，直接变异和应用
         *    避免数据被写入两次，提升性能 30-50%
         */
        
        if (g_rr_framework->mode == RR_MODE_FUZZING) {
            /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
             * Fuzzing 模式：直接变异和应用（跳过 Pure Replay）
             * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
            RR_VERBOSE("FUZZING: Direct mutation path (skip Pure Replay)");
            
            /* 1️⃣ 变异 aux_data 结构体 */
            rr_fuzz_mutate_aux_data(env, g_current_record, args, num);
            
            /* 2️⃣ 应用变异后的 aux_data 到 guest 内存（只写一次）*/
            ret = rr_replay_syscall_pure_reapply(env, num, args, g_current_record);
            
            if (ret != -1) {
                RR_INFO("🎯 FUZZING: Mutations applied directly, ret=%d", (int)ret);
                goto replay_success;
            } else {
                /* Reapply 失败：回退到 Hybrid */
                RR_WARN("FUZZING: Failed to apply mutations, fallback to hybrid");
                /* 继续执行下面的 Hybrid 路径 */
            }
            
        } else {
            /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
             * 非 Fuzzing 模式：正常 Pure Replay
             * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
            RR_VERBOSE("REPLAY: Pure replay path for syscall %d (has aux_data)", num);
            
            ret = rr_replay_syscall_pure(env, num, args, g_current_record);
            
            if (ret != -1) {
                /* Pure Replay 成功：直接返回 */
                RR_VERBOSE("REPLAY: Pure replay succeeded, ret=%d", (int)ret);
                goto replay_success;
            }
            
            /* Pure 失败：回退到 Hybrid */
            RR_VERBOSE("REPLAY: Pure replay not supported for syscall %d, using hybrid", num);
            /* 继续执行下面的 Hybrid 路径 */
        }
    }

    /* 
     * 路径2：Hybrid Replay（传统模式）
     * - 应用 FD 映射
     * - 支持 Fuzzing 变异
     * - 快照管理
     * - 执行真实 syscall
     */
    RR_VERBOSE("REPLAY_SYSCALL: Hybrid replay path for syscall %d", num);

    /* 🔥 特殊处理：read 返回 0 (EOF) 时，即使没有 aux_data，也应该直接返回 0 */
    if (num == TARGET_NR_read && ret == 0) {
        RR_VERBOSE("REPLAY_SYSCALL: read returned 0 (EOF), returning directly without real syscall");
        goto replay_success;
    }

    /* 应用FD映射 */
    apply_fd_mapping(args, num);

    /* 应用Fuzzing变异（如果在Fuzzing模式） */
    rr_fuzz_mutate_syscall(env, g_rr_framework->replay_index, args, num);

    /* 自动快照管理 */
    rr_snapshot_auto_manage(num, g_rr_framework->replay_index);

    /* 🔥 修复: Hybrid 模式只处理 mmap 特殊情况，其他 syscall 让真实执行自然填充数据 */
    /* 数据恢复应该在 Pure Replay (rr_replay_pure.c) 中进行 */

    switch (num) {
#ifdef TARGET_NR_mmap
        case TARGET_NR_mmap:
#endif
#ifdef TARGET_NR_mmap2
        case TARGET_NR_mmap2:
#endif
            /* 
             * ✅ 简化的 mmap 处理策略：
             * 1. 如果记录失败 → replay也失败（返回-1）
             * 2. 如果记录成功：
             *    - 匿名映射 → 让系统分配
             *    - 文件映射 → 转换为匿名映射
             * 3. 记录地址映射供后续使用
             * 
             * 优化：移除了未测试的fallback逻辑，简化为单一路径
             */
            RR_VERBOSE("MMAP_REPLAY: Recorded ret=0x%lx", (unsigned long)ret);

            if (ret == (abi_long)-1) {
                /* 记录失败 → replay也失败 */
                RR_VERBOSE("MMAP_REPLAY: Recorded failure, keeping ret=-1");
            } else {
                /* 记录成功 → 确保replay也成功 */
                g_pending_mmap_recorded_addr = (target_ulong)ret;
                
                /* 检查是否为文件映射 */
                bool is_file_mapping = (args[4] != -1 && args[4] != (abi_long)4294967295UL);
                
                if (is_file_mapping) {
                    /* 文件映射 → 转换为匿名映射（简化策略） */
                    RR_VERBOSE("MMAP_REPLAY: File mapping (fd=%d) → converting to anonymous", (int)args[4]);
                    
                    abi_long original_flags = args[3];
                    args[3] = MAP_PRIVATE | MAP_ANONYMOUS;
                    
                    /* 保留部分标志（去除MAP_FIXED让系统选择地址） */
                    if (original_flags & MAP_GROWSDOWN) {
                        args[3] |= MAP_GROWSDOWN;
                    }
                    
                    args[4] = -1;   /* fd = -1 */
                    args[5] = 0;    /* offset = 0 */
                    args[0] = 0;    /* 让系统选择地址 */
                } else {
                    /* 匿名映射 → 让系统正常分配 */
                    RR_VERBOSE("MMAP_REPLAY: Anonymous mapping, allowing normal allocation");
                }
                
                /* 清理记录并推进索引 */
                for (int i = 0; i < 8; i++) {
                    if (g_current_record->arg_data[i]) {
                        g_free(g_current_record->arg_data[i]);
                    }
                }
                if (g_current_record->aux_data) {
                    rr_aux_free(g_current_record->aux_data);
                }
                g_free(g_current_record);
                g_current_record = NULL;
                g_rr_framework->replay_index++;
                g_syscall_already_consumed = true;
                
                /* 返回-1让系统执行mmap */
                return -1;
            }
            break;

        /* 🔥 Hybrid 路径不需要任何数据恢复逻辑 - 所有数据由真实 syscall 填充 */

        default:
            /* 大部分系统调用只需要返回记录的返回值 */
            break;
    }

    /* 🔥 关键修复: Hybrid 模式在返回前必须清理记录并推进索引 */
    /* 清理当前记录的参数数据 */
    for (int i = 0; i < 8; i++) {
        if (g_current_record->arg_data[i]) {
            g_free(g_current_record->arg_data[i]);
        }
    }
    
    /* 清理 aux_data */
    if (g_current_record->aux_data) {
        rr_aux_free(g_current_record->aux_data);
        g_current_record->aux_data = NULL;
    }
    
    /* 释放记录并推进索引 */
    g_free(g_current_record);
    g_current_record = NULL;
    g_rr_framework->replay_index++;
    
    /* 设置标记，告诉 post_hook 不要重复处理 */
    g_syscall_already_consumed = true;
    
    /* 返回 -1，让 QEMU 执行真实 syscall (使用变异后的参数) */
    RR_VERBOSE("REPLAY_SYSCALL: Hybrid mode, record cleaned, executing real syscall %d", num);
    return -1;

replay_success:
    /* Pure Replay 成功路径：已经返回确定性结果，清理记录 */
    /* 清理当前记录的参数数据 */
    for (int i = 0; i < 8; i++) {
        if (g_current_record->arg_data[i]) {
            g_free(g_current_record->arg_data[i]);
        }
    }
    
    /* 清理 aux_data */
    if (g_current_record->aux_data) {
        rr_aux_free(g_current_record->aux_data);
        g_current_record->aux_data = NULL;
    }
    
    g_free(g_current_record);
    g_current_record = NULL;

    g_rr_framework->replay_index++;
    
    /* 设置标记，告诉 post_hook 不要重复处理 */
    g_syscall_already_consumed = true;

    RR_VERBOSE("REPLAY_SYSCALL: Successfully replayed syscall %u: %d -> %d",
               g_rr_framework->replay_index - 1, num, (int)ret);
    return ret;
}

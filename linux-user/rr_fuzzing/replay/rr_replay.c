/**
 * RR-Fuzz 混合重放模块 (当前聚焦映射闭环，P0阶段)
 * Hybrid Replay Mode - 传统二进制 trace 重放
 * 
 * 负责：
 * - 二进制 trace 的读取和同步
 * - Hybrid 模式的系统调用重放（应用参数 + 执行真实 syscall）
 * - 调度 Pure Replay（当有 aux_data 时）
 */

#define RR_DEBUG 1

#include "../core/rr_framework.h"
#include "../record/rr_aux_data.h"
#include "rr_replay_pure.h"
#include "../core/rr_constants.h"
#include "../utils/rr_dynamic_trace.h"
#include <sys/mman.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include "../utils/rr_syscall_dispatch.h"

FILE *g_trace_file = NULL;  // ✅ 改为非static，让fork_server可以访问
syscall_record_t *g_current_record = NULL;  // 非static，供fork_server访问
char *g_rr_trace_path = NULL;  // ✅ 保存trace文件路径，供child重新打开

/* 标记：当前系统调用是否已从 trace 读取并递增索引 */
__thread bool g_syscall_already_consumed = false;
__thread syscall_record_t *g_pending_post_record = NULL;

/**
 * @brief 初始化 Replay 模式并打开 trace 文件用于重放
 * 
 * 该函数是 RR-Fuzz Replay/Fuzzing 模式的入口点，负责：
 * 1. 打开二进制 trace 文件（.dat 格式）进行读取
 * 2. 读取并验证 trace 文件头（magic, version）
 * 3. 读取 trace 中的系统调用记录数量
 * 4. 支持文件已打开时的重置（rewind）机制
 * 
 * **文件头验证**:
 * - Magic: 0x52525254 ("RRTR")
 * - Version: 1
 * - Record Count: 实际记录数量
 * 
 * @param trace_file Trace 文件路径。如果为 NULL，使用默认文件名 "rr_trace.dat"
 * 
 * @return int
 *         - 0: 初始化成功，trace 文件已打开并验证
 *         - -1: 初始化失败（文件无法打开或格式无效）
 * 
 * @note 该函数在 replay 和 fuzzing 模式下都会被调用
 * @note 如果 trace 文件已打开（g_trace_file != NULL），会执行 rewind() 而不是重新打开
 *       这支持 fork-server 中子进程复用父进程打开的文件句柄
 * @note 会保存 trace 文件路径到 g_rr_trace_path，供子进程重新打开使用
 * 
 * @warning Magic 不匹配或文件头读取失败会导致初始化失败
 * @warning 该函数不会预加载所有 trace 记录，而是在 replay 过程中按需读取
 * 
 * @see rr_stop_replay() 对应的停止函数，会关闭文件
 * @see rr_replay_syscall() replay 时读取记录的核心函数
 * @see rr_reset_trace_position() fork-server 使用的重置函数
 * @see g_trace_file 全局 trace 文件句柄
 * @see g_rr_trace_path 保存的 trace 路径
 */
int rr_start_replay(const char *trace_file)
{
    RR_VERBOSE("Starting replay initialization");

    if (!trace_file) {
        trace_file = "rr_trace.dat";
        RR_INFO("Using default trace file: %s", trace_file);
    }

    /* ✅ 保存trace路径，供child重新打开 */
    if (g_rr_trace_path == NULL || strcmp(g_rr_trace_path, trace_file) != 0) {
        if (g_rr_trace_path) free(g_rr_trace_path);
        g_rr_trace_path = strdup(trace_file);
    }
    
    /* 如果文件已打开，重置文件指针而不是重新打开 */
    if (g_trace_file) {
        RR_INFO("Trace file already open, rewinding to start");
        rewind(g_trace_file);
    } else {
        RR_INFO("Opening trace file for reading: %s", trace_file);
        g_trace_file = fopen(trace_file, "rb");
        if (!g_trace_file) {
            RR_ERROR("Failed to open trace file: %s", trace_file);
            return -1;
        }
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
 * 重置 trace 文件指针到开头（用于 fork server）
 */
void rr_reset_trace_position(void)
{
    if (!g_trace_file) {
        RR_WARN("Cannot reset trace: file not open");
        return;
    }
    
    RR_INFO("Resetting trace file position to start");
    rewind(g_trace_file);
    
    /* 跳过 header (12 bytes: magic + version + count) */
    fseek(g_trace_file, 12, SEEK_SET);
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
 * @brief 从 trace 文件读取并解析下一条系统调用记录
 * 
 * 该函数负责反序列化二进制 trace 格式，重构 syscall_record_t 结构体。
 * 它是 Replay 过程中的数据源。
 * 
 * **反序列化流程**:
 * 1. **Header**: 读取 index (4B) 和 syscall_nr (4B)，手动解包以处理大端/小端问题
 * 2. **Fields**: 读取 args, retval, arg_sizes, fd_flags 等固定长度字段
 * 3. **Arg Data**: 读取变长参数数据 (arg_index, size, data)
 * 4. **Aux Data**: 检查 AUXD magic (0x41555844)，如果存在则读取辅助数据链表
 * 
 * **文件格式细节**:
 * - index/syscall_nr 使用手动打包 (buffer[0-7])，确保跨平台一致性
 * - 变长数据以 -1 作为结束标记 (end_marker)
 * - Aux Data 是可选的尾部数据，仅当 record->has_aux_data 为 true 时存在
 * 
 * @return syscall_record_t* 
 *         - 指向新分配并填充的记录结构体的指针
 *         - NULL: 如果到达文件末尾 (EOF) 或发生读取错误
 * 
 * @note 调用者负责释放返回的结构体 (通常由 replay 循环管理)
 * @note 能够自动处理带有或不带有 aux_data 的记录格式
 * 
 * @warning 函数内部使用 g_malloc 分配内存，必须确保释放以避免泄漏
 * @warning 文件读取错误会打印 ERROR 日志但返回 NULL，调用者需区分 EOF 和错误
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
               record->index, record->syscall_nr, (long)record->retval);

    /* 读取参数数据 */
    int arg_index;
    while (fread(&arg_index, sizeof(int), 1, g_trace_file) == 1) {
        if (arg_index == -1) { // 结束标记
            break;
        }

        if (arg_index >= 0 && arg_index < RR_MAX_SYSCALL_ARGS) {
            size_t size;
            if (fread(&size, sizeof(size), 1, g_trace_file) == 1 && size > 0 && size <= RR_MAX_BUFFER_TOTAL) {
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
                int mapped_fd = rr_fd_mapping_get((int)args[0]);
                args[0] = mapped_fd;
            }
            break;

#ifdef TARGET_NR_dup2
        case TARGET_NR_dup2:
#endif
            /* 两个参数都是FD */
            for (int i = 0; i < 2; i++) {
                if (args[i] >= 0) {
                    int mapped_fd = rr_fd_mapping_get((int)args[i]);
                    args[i] = mapped_fd;
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
                int mapped_fd = rr_fd_mapping_get((int)args[4]);
                if (mapped_fd != (int)args[4]) {
                    RR_VERBOSE("FD_MAPPING: mmap fd %d -> %d", (int)args[4], mapped_fd);
                }
                args[4] = mapped_fd;
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
 * @brief 重放单个系统调用 - Hybrid/Pure 自动分发
 * 
 * 这是 Replay/Fuzzing 模式下的核心函数，根据 trace 中的数据自动选择重放策略：
 * - **Pure Replay**: 如果 record 有 aux_data 且不是 brk/mmap，完全在用户态恢复，不执行真实 syscall
 * - **Hybrid Replay**: 如果没有 aux_data 或是特殊 syscall，应用 FD 映射后执行真实 syscall
 * 
 * **工作流程**:
 * 1. 从 trace 文件读取下一条记录并同步 (syscall_nr 匹配)
 * 2. 检测并退出 silent replay mode（如果到达 fork point）
 * 3. 判断是否可以 Pure Replay
 *    - Yes: 调用 rr_replay_syscall_pure()，直接从 aux_data 恢复，返回记录的 retval
 *    - No: Hybrid 路径，应用 FD/地址映射，返回 -1 让 QEMU 执行真实 syscall
 * 4. Fuzzing 模式：应用 mutation（fuzz_mutate_syscall）
 * 
 * **Trace 同步机制**:
 * - 如果当前 syscall 与 trace 不匹配，会自动跳过 trace 中的记录直到找到匹配的
 * - 这提供了一定的容错能力，允许 record 和 replay 之间有小的差异
 * 
 * **Special Cases**:
 * - Output syscalls (write/writev): 强制使用 Hybrid，保持 I/O 状态同步
 * - mmap/brk: 强制使用 Hybrid，因为需要 QEMU 管理内存映射
 * 
 * @param env CPU 架构状态指针（用于读/写 guest 内存）
 * @param num 当前系统调用编号
 * @param args 系统调用参数数组（8个参数），Pure Replay 中会修改这些值
 * 
 * @return abi_long
 *         - 非 -1: Pure Replay 成功，直接返回记录的 retval 给 QEMU
 *         - -1: Hybrid Replay，让 QEMU 执行真实 syscall（参数可能已被修改）
 * 
 * @note 会自动递增 g_rr_framework->replay_index
 * @note 支持动态跟踪（RR_ENABLE_DYNAMIC_TRACE）用于可视化
 * @note 维护全局状态：g_current_record, g_pending_post_record
 * 
 * @warning ⚠️ 复杂的状态管理: g_syscall_already_consumed, g_pending_mmap_recorded_addr 等
 *          需要仔细维护以避免重复消费或遗漏 record
 * @warning Fuzzing mutation 会修改 args 数组，影响后续执行
 * 
 * @see rr_start_replay() 必须先调用该函数打开 trace 文件
 * @see rr_replay_syscall_pure() Pure Replay 的实现
 * @see read_next_record() 从 trace 文件读取记录
 * @see apply_fd_mapping() 应用 FD 映射的核心逻辑
 * @see rr_fuzz_mutate_syscall() Fuzzing 模式下的 mutation 应用
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

    /* ✅ 检查是否到达fork_point，关闭silent mode */
    if (g_rr_framework->silent_replay_mode) {
        uint32_t target_fork_point = g_rr_framework->checkpoint_target;
        if (g_rr_framework->replay_index >= target_fork_point) {
            g_rr_framework->silent_replay_mode = false;
            RR_INFO("✅ [Hybrid] Reached fork_point[%u], switching to normal mode", target_fork_point);
            
            // ✅ 发送iteration消息
            // extern int g_dynamic_trace_pipe_fd;
            if (g_dynamic_trace_pipe_fd >= 0) {
                rr_dynamic_trace_iteration(g_rr_framework->current_iteration_id, getpid());
            }
        }
    }
    
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
            
            /* ✅ 修复：真实执行也要发送dynamic trace！*/
            // extern bool g_dynamic_trace_enabled;
            // extern int g_dynamic_trace_pipe_fd;
            RR_INFO("🔍 About to send dynamic trace: silent=%d, enabled=%d, pipe_fd=%d",
                    g_rr_framework->silent_replay_mode, g_dynamic_trace_enabled, g_dynamic_trace_pipe_fd);
            if (!g_rr_framework->silent_replay_mode) {
                uint64_t args_copy[8];
                for (int i = 0; i < 8; i++) {
                    args_copy[i] = ((uint64_t*)args)[i];
                }
                rr_dynamic_trace_syscall_enter(env, num, args_copy, 
                                                g_rr_framework->replay_index, false);
                RR_INFO("✅ Sent dynamic trace for syscall %d at index %u",
                        num, g_rr_framework->replay_index);
            }
            
            /* ✅ 递增replay_index（即使真实执行也要计数）*/
            g_rr_framework->replay_index++;
            
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

        /* 动态跟踪：记录被跳过的 syscall（用于 tree 完整性） */
#ifdef RR_ENABLE_DYNAMIC_TRACE
        uint64_t dummy_args[8] = {0};
        rr_dynamic_trace_syscall_enter(env, g_current_record->syscall_nr, dummy_args, 
                                         g_rr_framework->replay_index, 0);
        rr_dynamic_trace_syscall_exit(env, g_current_record->syscall_nr, dummy_args,
                                        g_current_record->retval, g_rr_framework->replay_index, 0);
#endif

        /* 清理当前记录 (使用统一的 dispose 函数) */
        rr_record_dispose(g_current_record);
        
        /* 🔥 关键修复: 跳过record时也要递增 replay_index */
        g_rr_framework->replay_index++;

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

    /* 检查是否应用了mutation */
    int has_mutation = 0;
    if (g_rr_framework->mode == RR_MODE_FUZZING) {
        /* 预先检查是否有mutation（用于设置is_fuzzed标志） */
        for (size_t i = 0; i < g_instruction_count; i++) {
            if (g_fuzz_instructions[i].syscall_index == g_current_record->index) {
                has_mutation = 1;
                break;
            }
        }
    }

    /* 动态跟踪：系统调用进入（二进制重放路径） */
#ifdef RR_ENABLE_DYNAMIC_TRACE
    rr_dynamic_trace_syscall_enter(env, num, (uint64_t*)args, 
                                     g_rr_framework->replay_index, has_mutation);
#endif

    abi_long ret = g_current_record->retval;

    /* ========== 特殊处理 1：Output Syscalls ========== */
    /* 输出系统调用必须真实执行以维持I/O状态，但需要先消费 record */
    /* 🔥 注意：对于output syscalls，我们需要在这里先应用mutation，然后再执行真实syscall */
    if (rr_is_output_syscall(num)) {
        RR_VERBOSE("REPLAY_SYSCALL: Output syscall %d, consuming record and executing directly", num);
        
        /* 🔥 关键修复：在执行output syscall之前先应用mutation */
        if (g_rr_framework->mode == RR_MODE_FUZZING) {
            uint32_t syscall_index = g_current_record->index;
            RR_INFO("🎯 FUZZING MODE: Applying mutations for OUTPUT syscall %d at index %u", num, syscall_index);
            rr_fuzz_mutate_syscall(env, syscall_index, args, num);
        }
        
        /* 清理当前记录 */
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
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
    if (is_mmap && g_current_record && g_current_record->has_aux_data) {
        rr_aux_data_t *aux = rr_aux_find(g_current_record->aux_data, 0);
        if (aux && aux->data && aux->size == sizeof(rr_aux_mmap_info_t)) {
            rr_aux_mmap_info_t info;
            memcpy(&info, aux->data, sizeof(info));

            RR_VERBOSE("REPLAY_SYSCALL: Hybrid mmap referencing recorded addr=0x%lx len=%lu",
                       (unsigned long)info.addr, (unsigned long)info.length);

            /* 记录原始地址和长度，交由 post_hook 建立映射 */
            g_pending_mmap_recorded_addr = (target_ulong)info.addr;
            g_pending_mmap_length = (target_ulong)info.length;

            /* 参数使用当前值（不强制 MAP_FIXED） */
            args[2] = (abi_long)info.prot;
            args[3] = (abi_long)info.flags;
            args[4] = (abi_long)info.fd;
            args[5] = (abi_long)info.offset;
        }
    }

    /* ========== 路径分叉：Pure vs Hybrid ========== */
    
    if (g_current_record->has_aux_data &&
        !(num == TARGET_NR_brk
#if defined(TARGET_NR_mmap)
          || num == TARGET_NR_mmap
#endif
#if defined(TARGET_NR_mmap2)
          || num == TARGET_NR_mmap2
#endif
        )) {
        /* 
         * 路径1：Pure Replay
         * 当有aux_data时，尝试纯重放（不执行真实syscall）
         * 🔥 P0修复：在Pure Replay之前先应用Fuzzing变异
         */
        RR_VERBOSE("REPLAY: Pure replay path for syscall %d (has aux_data)", num);
        
        /* 
         * 🔥 新策略：对于buffer mutation，先恢复aux_data再应用mutation
         * 这样mutation可以覆盖已有的数据
         */
        
        /* 步骤1：先恢复aux_data到buffer（如果有的话） */
        ret = rr_replay_syscall_pure(env, num, args, g_current_record);
        
        if (ret == -1) {
            /* Pure replay失败，使用hybrid模式 */
            RR_VERBOSE("REPLAY: Pure replay not supported for syscall %d, using hybrid", num);
            goto try_hybrid;
        }
        
        /* 步骤2：在fuzzing模式下，应用mutation覆盖已恢复的数据 */
        if (g_rr_framework->mode == RR_MODE_FUZZING) {
            uint32_t syscall_index = g_current_record->index;
            RR_INFO("🎯 FUZZING: Applying mutations AFTER aux_data restore for syscall %d at index %u", 
                    num, syscall_index);
            
            /* 应用变异到args和已恢复的guest内存 */
            int mutation_result = rr_fuzz_mutate_syscall(env, syscall_index, args, num);
            
            if (mutation_result > 0) {
                RR_INFO("🎯 FUZZING: Buffer mutation applied, overwrote aux_data");
            }
        }
        
        /* Pure Replay成功：直接返回 */
        RR_VERBOSE("REPLAY: Pure replay succeeded, ret=%d", (int)ret);
        goto replay_success;
        
try_hybrid:
        /* 继续原来的hybrid逻辑 */
        {}
    }

    if ((num == TARGET_NR_clone
#ifdef TARGET_NR_fork
        || num == TARGET_NR_fork
#endif
#ifdef TARGET_NR_vfork
        || num == TARGET_NR_vfork
#endif
        ) && g_current_record && g_current_record->has_aux_data) {
        rr_aux_data_t *aux = rr_aux_find(g_current_record->aux_data, 0);
        if (aux && aux->data && aux->size == sizeof(int64_t)) {
            pid_t recorded_pid = (pid_t)(*(int64_t *)aux->data);
            RR_VERBOSE("REPLAY_SYSCALL: Recorded child PID=%d", recorded_pid);
            /* TODO: establish recorded→replay PID mapping */
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

    /* ✅ 2025-11-17: IO Return Value Mutation - Hybrid模式下的返回值覆盖 */
    /* 关键修复: 在执行真实syscall之前检查是否需要覆盖返回值 */
    /* 如果有覆盖，跳过真实syscall，直接返回覆盖的值 */
    if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_retval_override()) {
        abi_long original_ret = ret;
        ret = rr_fuzz_get_retval_override();  /* 获取覆盖值并清除标志 */

        RR_INFO("🎯 IO RETVAL OVERRIDE (Hybrid): syscall %d (%s): %ld → %ld",
                num, rr_get_syscall_name_fast(num), (long)original_ret, (long)ret);

        fprintf(stderr, "[REPLAY-HYBRID] 🎯 RETVAL OVERRIDE: %ld → %ld\n", (long)original_ret, (long)ret);
        fflush(stderr);

        /* ✅ 2025-11-17: Hybrid路径的Buffer Fill */
        if (rr_fuzz_has_buffer_fill()) {
            target_ulong buf_addr = 0;
            size_t buf_size = 0;
            const uint8_t *pattern = NULL;

            size_t fill_size = rr_fuzz_get_buffer_fill(&buf_addr, &buf_size, &pattern);

            if (fill_size > 0 && buf_addr != 0 && pattern != NULL) {
                if (cpu_memory_rw_debug(env_cpu(env), buf_addr, (uint8_t *)pattern, fill_size, 1) == 0) {
                    fprintf(stderr, "[REPLAY-HYBRID] 🎨 BUFFER FILLED: addr=0x%lx, size=%zu\n",
                            (unsigned long)buf_addr, fill_size);
                    fflush(stderr);
                }
            }
        }

        /* 跳过真实syscall执行，直接返回覆盖的值 */
        goto replay_success;
    }

    /* 应用FD映射 */
    apply_fd_mapping(args, num);

    /* TODO(P1): Fuzzing变异逻辑将在映射闭环完成后添加 */

    /* 自动快照管理 */
    rr_snapshot_auto_manage(num, g_rr_framework->replay_index);

    /* 🔥 Hybrid 模式: 所有syscall都执行真实调用,由post_hook处理映射 */
    /* mmap等特殊syscall的地址映射在post_hook中完成 */

    /* 🔥 关键修复: Hybrid 模式在返回前必须清理记录并推进索引 */
    g_pending_post_record = g_current_record;
    g_current_record = NULL;
    g_rr_framework->replay_index++;
    
    /* 设置标记，告诉 post_hook 不要重复处理 */
    g_syscall_already_consumed = true;
    
    /* 返回 -1，让 QEMU 执行真实 syscall (使用变异后的参数) */
    RR_VERBOSE("REPLAY_SYSCALL: Hybrid mode, record cleaned, executing real syscall %d", num);
    return -1;

replay_success:
    /* Pure Replay 成功路径：已经返回确定性结果，清理记录 */

    /* ✅ 2025-11-17: 在清理record之前，先保存recorded_ret用于调试 */
    abi_long recorded_ret_for_debug = g_current_record ? g_current_record->retval : -999;

    g_pending_post_record = g_current_record;
    g_current_record = NULL;

    g_rr_framework->replay_index++;

    /* 设置标记，告诉 post_hook 不要重复处理 */
    g_syscall_already_consumed = true;

    /* ✅ 新增：应用返回值覆盖（IO返回值变异） */
    if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_retval_override()) {
        abi_long original_ret = ret;
        ret = rr_fuzz_get_retval_override();  // 这会自动清除标志

        RR_INFO("🎯 IO RETVAL OVERRIDE: syscall %d (%s): recorded=%ld, ret_before=%ld → ret_after=%ld",
                num, rr_get_syscall_name_fast(num), (long)recorded_ret_for_debug, (long)original_ret, (long)ret);

        fprintf(stderr, "[REPLAY] 🎯 RETVAL OVERRIDE: recorded=%ld, before=%ld → after=%ld\n",
                (long)recorded_ret_for_debug, (long)original_ret, (long)ret);
        fflush(stderr);
    }

    /* ✅ 2025-11-17: 泛化Buffer Fill - 填充IO buffer内容 */
    if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_buffer_fill()) {
        target_ulong buf_addr = 0;
        size_t buf_size = 0;
        const uint8_t *pattern = NULL;

        size_t fill_size = rr_fuzz_get_buffer_fill(&buf_addr, &buf_size, &pattern);

        if (fill_size > 0 && buf_addr != 0 && pattern != NULL) {
            /* 填充guest buffer */
            if (cpu_memory_rw_debug(env_cpu(env), buf_addr, (uint8_t *)pattern, fill_size, 1) == 0) {
                RR_INFO("🎨 BUFFER FILLED: syscall %d (%s): addr=0x%lx, size=%zu",
                        num, rr_get_syscall_name_fast(num), (unsigned long)buf_addr, fill_size);

                fprintf(stderr, "[REPLAY] 🎨 BUFFER FILLED: addr=0x%lx, size=%zu (first 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x)\n",
                        (unsigned long)buf_addr, fill_size,
                        pattern[0], pattern[1], pattern[2], pattern[3],
                        pattern[4], pattern[5], pattern[6], pattern[7]);
                fflush(stderr);
            } else {
                RR_WARN("Failed to fill buffer at addr=0x%lx, size=%zu", (unsigned long)buf_addr, fill_size);
            }
        }
    }

    /* 动态跟踪：系统调用退出（二进制重放路径） */
#ifdef RR_ENABLE_DYNAMIC_TRACE
    rr_dynamic_trace_syscall_exit(env, num, (uint64_t*)args, ret,
                                    g_rr_framework->replay_index - 1, has_mutation);
#endif

    RR_VERBOSE("REPLAY_SYSCALL: Successfully replayed syscall %u: %d -> %d",
               g_rr_framework->replay_index - 1, num, (int)ret);
    return ret;
}

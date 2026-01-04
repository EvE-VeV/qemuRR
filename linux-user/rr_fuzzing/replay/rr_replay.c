/**
 * RR-Fuzz Hybrid Replay Module
 * Traditional binary trace replay functionality.
 * 
 * Responsible for:
 * - Binary trace reading and synchronization
 * - Hybrid mode system call replay (parameter application + real syscall execution)
 * - Pure Replay dispatching (for records with aux_data)
 */

#define RR_DEBUG 1

#include "../core/rr_framework.h"
#include "../record/rr_aux_data.h"
#include "rr_replay_pure.h"
#include "../core/rr_constants.h"
#include "../utils/rr_dynamic_trace.h"
#include "../utils/rr_syscall_tree.h"
#include <sys/mman.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include "../utils/rr_syscall_dispatch.h"

FILE *g_trace_file = NULL;  // Accessible by fork_server
syscall_record_t *g_current_record = NULL;  // Accessible by fork_server
char *g_rr_trace_path = NULL;  // Saves trace file path for child processes

/* Flag: Indicates if the current syscall has been consumed from trace and index incremented */
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

    /* Save trace path for children to reopen */
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
            RR_ERROR("Failed to open trace file: %s (%s)", trace_file, strerror(errno));
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
    
    /* Skip header (12 bytes: magic + version + count) */
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
 * @note Caller is responsible for freeing the returned structure (usually managed by the replay loop).
 * @note Automatically handles record formats with or without aux_data.
 * 
 * @warning Uses g_malloc internally; ensure free to avoid leaks.
 * @warning File read errors print ERROR logs but return NULL; caller must distinguish EOF and error.
 */
/* Visible for rr_fork_server.c */
syscall_record_t *read_next_record(void)
{
    /* 🔥 DEBUG: Find who calls this! */
    
    if (!g_trace_file) {
        /* Try opening trace file */RR_ERROR("READ_NEXT_RECORD: No trace file open");
        return NULL;
    }

    RR_VERBOSE("READ_NEXT_RECORD: Attempting to read next record from trace file");
    syscall_record_t *record = g_malloc0(sizeof(syscall_record_t));

    /* Read basic record - field by field to avoid alignment issues */

    // Read manually packed binary data to match record format
    uint8_t buffer[8]; // 4字节index + 4字节syscall_nr
    if (fread(buffer, 8, 1, g_trace_file) != 1) {
        if (feof(g_trace_file)) {
             RR_VERBOSE("READ_NEXT_RECORD: End of trace file (EOF)");
        } else {
             RR_ERROR("READ_NEXT_RECORD: Failed to read record header (Error: %s)", strerror(errno));
        }
        g_free(record);
        return NULL;
    }

    // Manual unpacking
    record->index = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
    record->syscall_nr = (int32_t)(buffer[4] | (buffer[5] << 8) | (buffer[6] << 16) | (buffer[7] << 24));

    // Read remaining fields
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

    /* Read parameter data */
    int arg_index;
    while (fread(&arg_index, sizeof(int), 1, g_trace_file) == 1) {
        if (arg_index == -1) { // End marker
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

    /* Read aux_data if available */
    uint32_t aux_marker = 0;
    RR_VERBOSE("READ_NEXT_RECORD: About to read aux_marker at file pos %ld", ftell(g_trace_file));
    if (fread(&aux_marker, sizeof(uint32_t), 1, g_trace_file) == 1) {
        RR_VERBOSE("READ_NEXT_RECORD: Read aux_marker = 0x%08x", aux_marker);
        if (aux_marker == 0x41555844) { // "AUXD" magic
            RR_VERBOSE("READ_NEXT_RECORD: Found AUXD magic, reading aux_data");
            /* Read aux_data count */
            uint32_t aux_count = 0;
            ssize_t read_result = fread(&aux_count, sizeof(uint32_t), 1, g_trace_file);
            RR_VERBOSE("READ_NEXT_RECORD: fread aux_count result=%zd, aux_count=%u", read_result, aux_count);
            if (read_result == 1 && aux_count > 0) {
                RR_VERBOSE("READ_NEXT_RECORD: aux_count = %u", aux_count);
                record->has_aux_data = true;
                
                /* Read each aux_data exit */
                for (uint32_t i = 0; i < aux_count; i++) {
                    uint8_t kind, arg_mask;
                    uint32_t size;
                    
                    if (fread(&kind, sizeof(uint8_t), 1, g_trace_file) != 1 ||
                        fread(&arg_mask, sizeof(uint8_t), 1, g_trace_file) != 1 ||
                        fread(&size, sizeof(uint32_t), 1, g_trace_file) != 1) {
                        RR_ERROR("READ_NEXT_RECORD: Failed to read aux_data header");
                        break;
                    }
                    
                    /* Read data */
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
        /* If aux_marker == 0, there is no aux_data; this is normal */
    } else {
        RR_ERROR("READ_NEXT_RECORD: Failed to read aux_marker at pos %ld", ftell(g_trace_file));
    }

    return record;
}

/**
 * Apply FD mapping
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
            /* First argument is FD */
            if (args[0] >= 0) {
                int mapped_fd = rr_fd_mapping_get((int)args[0]);
                args[0] = mapped_fd;
            }
            break;

#ifdef TARGET_NR_dup2
        case TARGET_NR_dup2:
#endif
            /* Both arguments are FDs */
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
            /* 5th argument of mmap (args[4]) is the FD */
            if (args[4] >= 0) {  /* Not anonymous mapping */
                int mapped_fd = rr_fd_mapping_get((int)args[4]);
                if (mapped_fd != (int)args[4]) {
                    RR_VERBOSE("FD_MAPPING: mmap fd %d -> %d", (int)args[4], mapped_fd);
                }
                args[4] = mapped_fd;
            }
            break;

        // More syscall FD mapping handling can be added here
        default:
            break;
    }
}

/* 
 * NOTE: update_fd_mapping() has been removed.
 * FD mapping is handled by apply_fd_mapping().
 * Pure Replay functionality moved to rr_replay_pure.c. 
 */

/**
 * @brief Replay a single syscall - Hybrid/Pure automatic dispatch.
 * 
 * Core function in Replay/Fuzzing mode, automatically selecting strategy based on trace data:
 * - **Pure Replay**: Fully restored in userspace via aux_data; no real syscall executed (except brk/mmap).
 * - **Hybrid Replay**: Executed as a real syscall with FD/address mappings applied.
 * 
 * **Workflow**:
 * 1. Read next record from trace and synchronize (syscall_nr match).
 * 2. Detect and exit silent replay mode (if fork point reached).
 * 3. Determine if Pure Replay is possible.
 *    - Yes: Call rr_replay_syscall_pure(), return recorded retval.
 *    - No: Hybrid path, apply mappings, return -1 to let QEMU execute real syscall.
 * 4. Fuzzing mode: apply mutations (fuzz_mutate_syscall).
 * 
 * **Trace Synchronization**:
 * - Automatically skips trace records if current syscall doesn't match until a match is found.
 * - Provides fault tolerance allowing minor differences between record and replay.
 * 
 * **Special Cases**:
 * - Output syscalls (write/writev): Forced Hybrid to maintain I/O state.
 * - mmap/brk: Forced Hybrid because QEMU must manage memory mappings.
 */
 * @param env CPU architecture state pointer (for guest memory R/W).
 * @param num Current syscall number.
 * @param args Syscall argument array (8 arguments); may be modified for Pure Replay.
 * 
 * @return abi_long
 *         - Not -1: Pure Replay successful; returns recorded retval to QEMU.
 *         - -1: Hybrid Replay; let QEMU execute real syscall (args may be modified).
 * 
 * @note Automatically increments g_rr_framework->replay_index.
 * @note Supports Dynamic Trace (RR_ENABLE_DYNAMIC_TRACE) for visualization.
 * @note Maintains global state: g_current_record, g_pending_post_record.
 * 
 * @warning ⚠️ Complex state management: g_syscall_already_consumed, g_pending_mmap_recorded_addr, etc.
 *          Must be carefully maintained to avoid double consumption or missed records.
 * @warning Fuzzing mutation modifies the args array, affecting subsequent execution.
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

    /* Reset flags */
    g_syscall_already_consumed = false;
    if (g_rr_framework) g_rr_framework->last_syscall_mutated = false;

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

    /* No skip check: always attempt to read from trace to ensure consistency */

    /* Check if fork_point is reached to disable silent mode */
    if (g_rr_framework->silent_replay_mode) {
        uint32_t target_fork_point = g_rr_framework->checkpoint_target;
        if (g_rr_framework->replay_index >= target_fork_point) {
            g_rr_framework->silent_replay_mode = false;
            RR_INFO("✅ [Hybrid] Reached fork_point[%u], switching to normal mode", target_fork_point);
            
            // Send iteration message
            // extern int g_dynamic_trace_pipe_fd;
            if (g_dynamic_trace_pipe_fd >= 0) {
                rr_dynamic_trace_iteration(g_rr_framework->current_iteration_id, getpid());
            }
        }
    }
    
    /* Maintain global index synchronization - core requirement from design.md */
    RR_VERBOSE("REPLAY_SYSCALL: replay_index=%u, g_current_record=%p", g_rr_framework->replay_index, g_current_record);
    if (g_rr_framework->replay_index == 0 || !g_current_record) {
        RR_VERBOSE("REPLAY_SYSCALL: Need to read next record");
        RR_VERBOSE("REPLAY_SYSCALL: Reading next record (current_record=%p)", g_current_record);
        g_current_record = read_next_record();
        
        if (!g_current_record) {
             RR_INFO("End of Trace reached (EOF) during replay/fuzzing. Terminating execution.");
             /* This is normal behavior when trace is exhausted */
             exit(0);
        }
        if (!g_current_record) {
            RR_VERBOSE("REPLAY_SYSCALL: read_next_record returned NULL");
            /* EnvFuzz style: If record is not found, don't crash, execute for real */
            RR_WARN("REPLAY_SYSCALL: End of trace at index %u for syscall %d, executing directly", 
                    g_rr_framework->replay_index, num);
            
            /* ✅ Fix: Real execution also needs to send dynamic trace! */
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
            
            /* ✅ Increment replay_index (even for real execution) */
            g_rr_framework->replay_index++;
            
            return -1;  /* Execute syscall directly */
        }
        RR_VERBOSE("REPLAY_SYSCALL: Got record index=%u, syscall=%d, ret=%d",
                g_current_record->index, g_current_record->syscall_nr, (int)g_current_record->retval);
        RR_VERBOSE("REPLAY_SYSCALL: Got record index=%u, syscall=%d, ret=%d",
                   g_current_record->index, g_current_record->syscall_nr, (int)g_current_record->retval);
                   
    }

    /* Smart synchronization - if syscall doesn't match, continue reading until a match is found */
    while (g_current_record && g_current_record->syscall_nr != num) {
        RR_VERBOSE("REPLAY_SYSCALL: MISMATCH - recorded=%d, actual=%d, skipping",
                g_current_record->syscall_nr, num);
        RR_VERBOSE("REPLAY_SYSCALL: Skipping unmatched syscall (recorded=%d, actual=%d)",
                   g_current_record->syscall_nr, num);

        /* Dynamic trace: Record skipped syscall (for tree integrity) */
#ifdef RR_ENABLE_DYNAMIC_TRACE
        uint64_t dummy_args[8] = {0};
        rr_dynamic_trace_syscall_enter(env, g_current_record->syscall_nr, dummy_args, 
                                         g_rr_framework->replay_index, 0);
        rr_dynamic_trace_syscall_exit(env, g_current_record->syscall_nr, dummy_args,
                                        g_current_record->retval, g_rr_framework->replay_index, 0);
#endif

        /* Clear current record (using unified dispose function) */
        rr_record_dispose(g_current_record);
        
        /* 🔥 Key Fix: Increment replay_index even when skipping records */
        g_rr_framework->replay_index++;

        /* Read next record */
        g_current_record = read_next_record();
        if (!g_current_record) {
             // Check if Tree Export is enabled (via environment variable)
             const char *tree_output = getenv("RR_TREE_OUTPUT");
             // fprintf(stderr, "[REPLAY-DEBUG] EOF reached. tree_output=%s\n", tree_output ? tree_output : "NULL");
             if (tree_output) {
                 rr_tree_export_json(tree_output);
             }
             
             RR_VERBOSE("[REPLAY] End of Trace reached (EOF). Terminating execution.");
             exit(0);
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

    /* Check if mutation is applied */
    int has_mutation = 0;
    if (g_rr_framework->mode == RR_MODE_FUZZING) {
        /* Pre-check for mutations (for setting is_fuzzed flag) */
        for (size_t i = 0; i < g_instruction_count; i++) {
            if (g_fuzz_instructions[i].syscall_index == g_current_record->index) {
                has_mutation = 1;
                break;
            }
        }
    }

    /* Dynamic trace: Syscall enter (binary replay path) */
#ifdef RR_ENABLE_DYNAMIC_TRACE
    rr_dynamic_trace_syscall_enter(env, num, (uint64_t*)args, 
                                     g_rr_framework->replay_index, has_mutation);
#endif

    abi_long ret = g_current_record->retval;

    /* Special Case 1: Output Syscalls */
    /* Output syscalls must be executed to maintain I/O state, but record must be consumed */
    /* Mutations are applied before executing the real syscall */
    if (rr_is_output_syscall(num)) {
        RR_INFO("REPLAY_SYSCALL: Output syscall %d (Hybrid Replay), consuming record and executing directly", num);
        
        /* Apply mutation before executing output syscall */
        if (g_rr_framework->mode == RR_MODE_FUZZING) {
            uint32_t syscall_index = g_current_record->index;
            RR_INFO("🎯 FUZZING MODE: Applying mutations for OUTPUT syscall %d at index %u", num, syscall_index);
            int m_res = rr_fuzz_mutate_syscall(env, syscall_index, args, num);
            if (m_res > 0) g_rr_framework->last_syscall_mutated = true;
        }
        
        /* Clear current record */
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
        
        /* Advance index */
        g_rr_framework->replay_index++;
        
        /* Set flag to prevent post_hook from double processing */
        g_syscall_already_consumed = true;
        
        return -1; /* Execute real syscall */
    }

    /* Special Case 2: Memory Management Syscalls */
    /* mmap and others require real allocation, but force recorded address */
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

            /* Record original address and length, let post_hook establish mapping */
            g_pending_mmap_recorded_addr = (target_ulong)info.addr;
            g_pending_mmap_length = (target_ulong)info.length;

            /* Use current parameters (do not force MAP_FIXED) */
            args[2] = (abi_long)info.prot;
            args[3] = (abi_long)info.flags;
            args[4] = (abi_long)info.fd;
            args[5] = (abi_long)info.offset;
        }
    }

    /* ========== Path Bifurcation: Pure vs Hybrid ========== */
    
    if (g_current_record->has_aux_data &&
        !(num == TARGET_NR_brk
#if defined(TARGET_NR_mmap)
          || num == TARGET_NR_mmap
#endif
#if defined(TARGET_NR_mmap2)
          || num == TARGET_NR_mmap2
#endif
        /* 🔥 P0 Fix: Force Hybrid Replay for File Ops (Open/Close) */
        /* These syscalls MUST go through hybrid path to register FD mappings */
#if defined(TARGET_NR_open)
        || num == TARGET_NR_open
#endif
#if defined(TARGET_NR_openat)
        || num == TARGET_NR_openat
#endif
#if defined(TARGET_NR_creat)
        || num == TARGET_NR_creat
#endif
#if defined(TARGET_NR_close)
        || num == TARGET_NR_close
#endif
#if defined(TARGET_NR_lseek)
        || num == TARGET_NR_lseek
#endif
        )) {

        /* 
         * Path 1: Pure Replay
         * If aux_data is available, attempt pure replay without real syscall.
         * Fuzzing mutations are applied before Pure Replay.
         */
        RR_VERBOSE("REPLAY: Pure replay path for syscall %d (has aux_data)", num);
        
        /* 
         * Strategy: Restore aux_data to buffer first, then apply mutation 
         * to allow mutations to overwrite existing data.
         */
        
        /* Step 1: Restore aux_data to buffer first (if any) */
        ret = rr_replay_syscall_pure(env, num, args, g_current_record);
        
        if (ret == -1) {
            /* Pure replay failed, use hybrid mode */
            RR_VERBOSE("REPLAY: Pure replay not supported for syscall %d, using hybrid", num);
            goto try_hybrid;
        }
        
        /* Apply mutation to args and restored guest memory in fuzzing mode */
        if (g_rr_framework->mode == RR_MODE_FUZZING) {
            uint32_t syscall_index = g_current_record->index;
            RR_INFO("🎯 FUZZING: Applying mutations AFTER aux_data restore for syscall %d at index %u", 
                    num, syscall_index);
            
            /* Apply mutations to args and restored guest memory */
            int mutation_result = rr_fuzz_mutate_syscall(env, syscall_index, args, num);
            
            if (mutation_result > 0) {
                RR_INFO("🎯 FUZZING: Buffer mutation applied, overwrote aux_data");
                g_rr_framework->last_syscall_mutated = true;
            }
        }
        
        /* Pure Replay success: return directly */
        RR_VERBOSE("REPLAY: Pure replay succeeded, ret=%d", (int)ret);
        goto replay_success;
        
try_hybrid:
        /* Continue with existing hybrid logic */
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
     * Path 2: Hybrid Replay (Traditional mode)
     * - Apply FD mapping
     * - Support Fuzzing mutations
     * - Snapshot management
     * - Execute real syscall
     */
    RR_VERBOSE("REPLAY_SYSCALL: Hybrid replay path for syscall %d", num);

    /* 🔥 Special Case: When read returns 0 (EOF), directly return 0 even without aux_data */
    if (num == TARGET_NR_read && ret == 0) {
        RR_VERBOSE("REPLAY_SYSCALL: read returned 0 (EOF), returning directly without real syscall");
        goto replay_success;
    }

    /* ✅ 2025-11-17: IO Return Value Mutation - Return value override in Hybrid mode */
    /* Key fix: Check if return value override is needed before executing real syscall */
    /* If overridden, skip real syscall and return the overridden value directly */
    if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_retval_override()) {
        abi_long original_ret = ret;
        ret = rr_fuzz_get_retval_override();  /* Get override value and clear flag */

        RR_INFO("🎯 IO RETVAL OVERRIDE (Hybrid): syscall %d (%s): %ld → %ld",
                num, rr_get_syscall_name_fast(num), (long)original_ret, (long)ret);

        fprintf(stderr, "[REPLAY-HYBRID] 🎯 RETVAL OVERRIDE: %ld → %ld\n", (long)original_ret, (long)ret);
        fflush(stderr);

        /* ✅ 2025-11-17: Buffer Fill in Hybrid path */
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

        /* Skip real syscall execution, return overridden value directly */
        goto replay_success;
    }

    /* Apply FD mapping */
    apply_fd_mapping(args, num);

    /* TODO(P1): Fuzzing mutation logic will be added after mapping loop closure is complete */

    /* Automatic snapshot management */
    rr_snapshot_auto_manage(num, g_rr_framework->replay_index);

    /* 🔥 Hybrid Mode: All syscalls execute real calls, mappings handled by post_hook */
    /* Address mapping for special syscalls like mmap is completed in post_hook */

    /* 🔥 Key Fix: Hybrid mode must clean record and advance index before returning */
    g_pending_post_record = g_current_record;
    g_current_record = NULL;
    g_rr_framework->replay_index++;
    
    /* Set flag to notify post_hook not to double process */
    g_syscall_already_consumed = true;
    
    /* Return -1 to let QEMU execute real syscall (with mutated arguments) */
    RR_VERBOSE("REPLAY_SYSCALL: Hybrid mode, record cleaned, executing real syscall %d", num);
    return -1;

    /* Pure Replay success path: Deterministic result returned, clean record */
    /* Save recorded_ret for debugging before record cleanup */
    abi_long recorded_ret_for_debug = g_current_record ? g_current_record->retval : -999;

    g_pending_post_record = g_current_record;
    g_current_record = NULL;

    g_rr_framework->replay_index++;

    /* Set flag to notify post_hook not to process again */
    g_syscall_already_consumed = true;

    /* Apply return value override (IO return value mutation) */
    if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_retval_override()) {
        abi_long original_ret = ret;
        ret = rr_fuzz_get_retval_override();  // This clears the flag automatically

        RR_INFO("🎯 IO RETVAL OVERRIDE: syscall %d (%s): recorded=%ld, ret_before=%ld → ret_after=%ld",
                num, rr_get_syscall_name_fast(num), (long)recorded_ret_for_debug, (long)original_ret, (long)ret);

        fprintf(stderr, "[REPLAY] 🎯 RETVAL OVERRIDE: recorded=%ld, before=%ld → after=%ld\n",
                (long)recorded_ret_for_debug, (long)original_ret, (long)ret);
        fflush(stderr);
    }

    /* Generalized Buffer Fill - Fill IO buffer content */
    if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_buffer_fill()) {
        target_ulong buf_addr = 0;
        size_t buf_size = 0;
        const uint8_t *pattern = NULL;

        size_t fill_size = rr_fuzz_get_buffer_fill(&buf_addr, &buf_size, &pattern);

        if (fill_size > 0 && buf_addr != 0 && pattern != NULL) {
            /* Fill guest buffer */
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

replay_success:
    /* Dynamic trace: Syscall exit (binary replay path) */
#ifdef RR_ENABLE_DYNAMIC_TRACE
    rr_dynamic_trace_syscall_exit(env, num, (uint64_t*)args, ret,
                                    g_rr_framework->replay_index - 1, false);
#endif

    RR_VERBOSE("REPLAY_SYSCALL: Successfully replayed syscall %u: %d -> %d",
               g_rr_framework->replay_index - 1, num, (int)ret);
    return ret;
}

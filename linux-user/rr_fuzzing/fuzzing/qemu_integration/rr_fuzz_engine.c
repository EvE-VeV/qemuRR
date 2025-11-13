/**
 * RR-Fuzz变异引擎
 * 实现Fuzzing指令的应用和参数变异
 * 
 * 设计理念：
 * 1. 从共享内存读取Fuzz指令（由Conductor生成）
 * 2. 在系统调用重放时应用变异
 * 3. 支持多种变异策略（参数变异、缓冲区替换、边界值测试等）
 */

#include "../../core/rr_framework.h"
#include "../../utils/rr_syscall_dispatch.h"

/* ==================== 全局状态 ==================== */

// 当前生效的Fuzz指令集（从共享内存加载）
// ✅ Phase 1: 改为非 static，供 rr_fuzz_aux_mutations.c 使用
FuzzInstruction g_fuzz_instructions[FUZZ_MAX_INSTRUCTIONS];
size_t g_instruction_count = 0;

// 变异统计
typedef struct {
    uint64_t total_mutations;       // 总变异次数
    uint64_t arg_mutations;         // 参数变异
    uint64_t buffer_mutations;      // 缓冲区变异
    uint64_t boundary_tests;        // 边界值测试
} fuzz_stats_t;

// ✅ Phase 1: 改为非 static，供 rr_fuzz_aux_mutations.c 使用
fuzz_stats_t g_fuzz_stats = {0};

/**
 * 从共享内存加载Fuzz指令
 * 
 * 此函数由Fork Server在收到'F'命令后调用
 * 从共享内存读取Conductor生成的变异指令
 * 
 * @param shm_ptr 共享内存指针
 * @return 成功返回0，失败返回-1
 */
int rr_fuzz_load_from_shared_memory(void *shm_ptr)
{
    if (!shm_ptr) {
        RR_WARN("Shared memory pointer is NULL");
        return -1;
    }

    FuzzSharedMemory *shm = (FuzzSharedMemory *)shm_ptr;

    // 验证魔数
    if (shm->magic != FUZZ_MAGIC) {
        RR_ERROR("Invalid shared memory magic: 0x%x (expected 0x%x)", 
                 shm->magic, FUZZ_MAGIC);
        return -1;
    }

    // ✅ 新结构：匹配Python端的checksum计算
    // Python: checksum = FUZZ_MAGIC ^ sequence ^ num_variants ^ fork_point ^ depth
    uint32_t expected_checksum = shm->magic ^ shm->sequence ^ shm->num_variants ^ shm->fork_point ^ shm->current_depth;
    if (shm->checksum != expected_checksum) {
        RR_WARN("Shared memory checksum mismatch: got 0x%x, expected 0x%x (seq=%u, variants=%u, fork_pt=%u, depth=%u)",
                shm->checksum, expected_checksum, shm->sequence, shm->num_variants, shm->fork_point, shm->current_depth);
        RR_WARN("Possible incomplete write, skipping this round");
        g_instruction_count = 0;
        return -1;  // 返回错误，让调用方知道数据不完整
    }

    // ✅ 简化：直接从variants[0]加载（兼容旧行为）
    if (shm->num_variants > 0) {
        FuzzVariant *variant = &shm->variants[0];
        g_instruction_count = variant->instruction_count;
        
        if (g_instruction_count > FUZZ_MAX_INSTRUCTIONS) {
            RR_ERROR("Too many instructions: %zu (max %d)", 
                     g_instruction_count, FUZZ_MAX_INSTRUCTIONS);
            return -1;
        }
        
        // 复制指令到本地缓冲区
        memcpy(g_fuzz_instructions, variant->instructions, 
               sizeof(FuzzInstruction) * g_instruction_count);
    } else {
        // 无variants，表示无指令
        RR_VERBOSE("No fuzz instructions in shared memory (num_variants=0)");
        g_instruction_count = 0;
        return 0;
    }

    // ✅ DEBUG: 详细验证加载后的状态
    fprintf(stderr, "[DEBUG-LOAD] PID=%d, g_instruction_count=%zu (address=%p)\n", 
            getpid(), g_instruction_count, &g_instruction_count);
    fprintf(stderr, "[DEBUG-LOAD] First instruction: syscall_idx=%u, cmd=%d\n",
            g_fuzz_instructions[0].syscall_index, g_fuzz_instructions[0].cmd);

    RR_INFO("Loaded %zu fuzz instructions from shared memory (seq=%u, checksum=0x%x)", 
            g_instruction_count, shm->sequence, shm->checksum);
    
    // 输出调试信息
    for (size_t i = 0; i < g_instruction_count; i++) {
        RR_VERBOSE("  [%zu] syscall_idx=%u, cmd=%d, arg_idx=%u, data_len=%u",
                   i, g_fuzz_instructions[i].syscall_index,
                   g_fuzz_instructions[i].cmd,
                   g_fuzz_instructions[i].arg_index,
                   g_fuzz_instructions[i].data_len);
    }

    return 0;
}

/**
 * 应用Fuzzing指令（旧接口，保留兼容性）
 * 
 * @deprecated 推荐使用 rr_fuzz_load_from_shared_memory
 */
int rr_fuzz_apply_instructions(const FuzzInstruction *instructions, size_t count)
{
    if (!instructions || count == 0) {
        g_instruction_count = 0;
        return 0;
    }

    if (count > FUZZ_MAX_INSTRUCTIONS) {
        RR_ERROR("Too many instructions: %zu (max %d)", count, FUZZ_MAX_INSTRUCTIONS);
        return -1;
    }

    g_instruction_count = count;
    memcpy(g_fuzz_instructions, instructions, sizeof(FuzzInstruction) * count);

    RR_INFO("Applied %zu fuzzing instructions (legacy API)", count);
    return 0;
}

/**
 * 应用系统调用参数变异
 * 
 * 根据Fuzz指令对系统调用参数进行变异
 * 支持多种变异策略，针对不同类型的参数
 * 
 * @param env CPU环境（用于写入guest内存）
 * @param syscall_index 系统调用在trace中的索引
 * @param args 系统调用参数数组（会被修改）
 * @param syscall_nr 系统调用号
 * @return int >0表示应用了buffer mutation, 0表示无buffer mutation, <0表示错误
 */
static int apply_mutations_for_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr)
{
    int has_buffer_mutation = 0;  // 标记是否应用了buffer mutation
    
    // ✅ DEBUG: 详细检查进入apply时的状态
    fprintf(stderr, "\n[APPLY] ========== START ==========\n");
    fprintf(stderr, "[APPLY] PID=%d, syscall_index=%u, nr=%d\n", getpid(), syscall_index, syscall_nr);
    fprintf(stderr, "[APPLY] g_instruction_count=%zu (address=%p, value_at_addr=%zu)\n", 
            g_instruction_count, &g_instruction_count, *(size_t*)&g_instruction_count);
    if (g_instruction_count > 0) {
        fprintf(stderr, "[APPLY] First instruction: syscall_idx=%u, cmd=%d\n",
                g_fuzz_instructions[0].syscall_index, g_fuzz_instructions[0].cmd);
    }
    fflush(stderr);
    
    if (g_instruction_count == 0) {
        fprintf(stderr, "[APPLY] ERROR: g_instruction_count is 0!\n");
        fprintf(stderr, "[APPLY] This means instructions were cleared after reload!\n");
        fflush(stderr);
        return 0;  // 没有变异指令
    }

    // 获取系统调用的类型和重要性（用于智能变异）
    const char *syscall_name = rr_get_syscall_name_fast(syscall_nr);
    
    fprintf(stderr, "[APPLY] Searching for mutations: syscall_idx=%u, nr=%d (%s)\n",
            syscall_index, syscall_nr, syscall_name ? syscall_name : "unknown");
    fflush(stderr);

    /* 遍历所有指令，寻找匹配的系统调用索引 */
    for (size_t i = 0; i < g_instruction_count; i++) {
        FuzzInstruction *instr = &g_fuzz_instructions[i];
        
        fprintf(stderr, "[APPLY] Checking instr[%zu]: syscall_idx=%u vs target=%u, cmd=%d\n", 
                   i, instr->syscall_index, syscall_index, instr->cmd);
        fflush(stderr);

        // 跳过不匹配的系统调用
        if (instr->syscall_index != syscall_index) {
            fprintf(stderr, "[APPLY]   Skip: mismatch (%u != %u)\n", instr->syscall_index, syscall_index);
            fflush(stderr);
            continue;
        }
        
        fprintf(stderr, "[APPLY]   *** MATCH FOUND! cmd=%d ***\n", instr->cmd);
        fflush(stderr);

        // 检查参数索引有效性
        fprintf(stderr, "[APPLY] Checking arg_index: %u (must be < 8)\n", instr->arg_index);
        fflush(stderr);
        
        if (instr->arg_index >= 8) {
            fprintf(stderr, "[APPLY] ERROR: Invalid arg_index %u for syscall %s\n",
                    instr->arg_index, syscall_name ? syscall_name : "unknown");
            fflush(stderr);
            RR_WARN("Invalid arg_index %u for syscall %s", 
                    instr->arg_index, syscall_name ? syscall_name : "unknown");
            continue;
        }
        
        fprintf(stderr, "[APPLY] arg_index check passed, entering switch(cmd=%d)\n", instr->cmd);
        fflush(stderr);

        RR_VERBOSE("Applying mutation [%zu/%zu] to %s arg[%u]: cmd=%d",
                   i + 1, g_instruction_count, 
                   syscall_name ? syscall_name : "unknown",
                   instr->arg_index, instr->cmd);

        switch (instr->cmd) {
            case FUZZ_CMD_MUTATE_ARG:
                /* 变异参数值 - 适用于整数参数 */
                if (instr->data_len >= sizeof(abi_long)) {
                    __attribute__((unused)) abi_long old_value = args[instr->arg_index];  // 🔥 P0修复：先保存旧值
                    abi_long new_value = *(abi_long *)instr->data;
                    args[instr->arg_index] = new_value;  // 然后修改
                    
                    RR_INFO("🔧 MUTATE_ARG: %s[%u] %ld → %ld (syscall_idx=%u)",
                           syscall_name ? syscall_name : "unknown",
                           instr->arg_index, old_value, new_value, syscall_index);
                    
                    g_fuzz_stats.arg_mutations++;
                }
                break;

            case FUZZ_CMD_REPLACE_BUFFER:
                /* 替换缓冲区内容 - 适用于字符串/数据块 */
                if (instr->data_len > 0) {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0) {
                        RR_INFO("🔧 REPLACE_BUFFER: %s[%u] addr=0x%lx, len=%u (syscall_idx=%u)",
                               syscall_name ? syscall_name : "unknown",
                               instr->arg_index, addr, instr->data_len, syscall_index);
                        
                        /* 🔥 修复：真正写入 guest 内存 */
                        if (cpu_memory_rw_debug(env_cpu(env), addr, instr->data, instr->data_len, 1) == 0) {
                            g_fuzz_stats.buffer_mutations++;
                            has_buffer_mutation = 1;  // 🔥 标记为buffer mutation
                            RR_VERBOSE("REPLACE_BUFFER: Successfully wrote %u bytes to guest addr 0x%lx",
                                      instr->data_len, addr);
                        } else {
                            RR_WARN("REPLACE_BUFFER: Failed to write to guest memory at 0x%lx", addr);
                        }
                    }
                }
                break;

            case FUZZ_CMD_MUTATE_FLAGS:
                /* 变异标志位 - 对flags参数进行位操作 */
                if (instr->data_len >= sizeof(abi_long)) {
                    __attribute__((unused)) abi_long old_value = args[instr->arg_index];  // 🔥 P0修复：先保存旧值
                    abi_long xor_mask = *(abi_long *)instr->data;
                    args[instr->arg_index] ^= xor_mask;  // 然后修改
                    
                    RR_INFO("🔧 MUTATE_FLAGS: %s[%u] 0x%lx → 0x%lx (XOR 0x%lx)",
                           syscall_name ? syscall_name : "unknown",
                           instr->arg_index, old_value, args[instr->arg_index], xor_mask);
                    
                    g_fuzz_stats.arg_mutations++;
                }
                break;

            case FUZZ_CMD_BOUNDARY_VALUE:
                /* 边界值测试 - 使用特殊值（0, -1, MAX等） */
                if (instr->data_len >= sizeof(abi_long)) {
                    __attribute__((unused)) abi_long old_value = args[instr->arg_index];
                    abi_long boundary = *(abi_long *)instr->data;
                    args[instr->arg_index] = boundary;
                    
                    RR_INFO("🔧 BOUNDARY_VALUE: %s[%u] %ld → %ld",
                           syscall_name ? syscall_name : "unknown",
                           instr->arg_index, old_value, boundary);
                    
                    g_fuzz_stats.boundary_tests++;
                }
                break;

            case FUZZ_CMD_FLIP_BITS:
                /* 🔥 P0新增：AFL风格位翻转 - 翻转指定的bits */
                {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0 && instr->data_len > 0) {
                        /* instr->data 包含：[offset(4字节)][bit_mask(剩余)] */
                        if (instr->data_len >= 4) {
                            uint32_t offset = *(uint32_t *)instr->data;
                            uint32_t mask_len = instr->data_len - 4;
                            uint8_t *bit_mask = instr->data + 4;
                            
                            /* 读取guest内存 */
                            uint8_t *buffer = g_malloc(mask_len);
                            if (cpu_memory_rw_debug(env_cpu(env), addr + offset, buffer, mask_len, 0) == 0) {
                                /* 应用位翻转 */
                                for (uint32_t j = 0; j < mask_len; j++) {
                                    buffer[j] ^= bit_mask[j];
                                }
                                
                                /* 写回guest内存 */
                                if (cpu_memory_rw_debug(env_cpu(env), addr + offset, buffer, mask_len, 1) == 0) {
                                    RR_INFO("🔧 FLIP_BITS: %s[%u] addr=0x%lx+%u, flipped %u bytes",
                                           syscall_name ? syscall_name : "unknown",
                                           instr->arg_index, addr, offset, mask_len);
                                    has_buffer_mutation = 1;  // 标记为buffer mutation
                                    g_fuzz_stats.buffer_mutations++;
                                } else {
                                    RR_WARN("FLIP_BITS: Failed to write back to guest memory");
                                }
                            } else {
                                RR_WARN("FLIP_BITS: Failed to read from guest memory at 0x%lx", addr + offset);
                            }
                            g_free(buffer);
                        }
                    }
                }
                break;

            case FUZZ_CMD_INTERESTING_VALUES:
                /* 🔥 P0新增：特殊值/魔数注入 */
                {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0 && instr->data_len > 0) {
                        /* instr->data 包含：[offset(4字节)][interesting_value(剩余)] */
                        if (instr->data_len >= 4) {
                            uint32_t offset = *(uint32_t *)instr->data;
                            uint32_t value_len = instr->data_len - 4;
                            uint8_t *value = instr->data + 4;
                            
                            /* 直接写入特殊值到guest内存 */
                            if (cpu_memory_rw_debug(env_cpu(env), addr + offset, value, value_len, 1) == 0) {
                                RR_INFO("🔧 INTERESTING_VALUES: %s[%u] addr=0x%lx+%u, injected %u bytes",
                                       syscall_name ? syscall_name : "unknown",
                                       instr->arg_index, addr, offset, value_len);
                                has_buffer_mutation = 1;  // 标记为buffer mutation
                                g_fuzz_stats.buffer_mutations++;
                            } else {
                                RR_WARN("INTERESTING_VALUES: Failed to write to guest memory at 0x%lx", addr + offset);
                            }
                        }
                    }
                }
                break;

            case FUZZ_CMD_OVERWRITE_AT_OFFSET:
                /* ━━━━ Phase 2: 精确偏移覆写 ━━━━ */
                /* 
                 * 用于实现配方驱动的变异
                 * 从PathFinder生成的配方中获取精确的offset和size
                 * 在指定位置覆写数据
                 */
                {
                    fprintf(stderr, "[OVERWRITE] Entered FUZZ_CMD_OVERWRITE_AT_OFFSET branch\n");
                    fflush(stderr);
                    
                    target_ulong addr = args[instr->arg_index];
                    fprintf(stderr, "[OVERWRITE] addr=0x%lx (from args[%u])\n", addr, instr->arg_index);
                    fflush(stderr);
                    
                    if (addr == 0) {
                        fprintf(stderr, "[OVERWRITE] ERROR: NULL address for arg[%u]\n", instr->arg_index);
                        fflush(stderr);
                        RR_WARN("OVERWRITE_AT_OFFSET: NULL address for arg[%u]", instr->arg_index);
                        break;
                    }
                    
                    /* 验证offset和size的有效性 */
                    if (instr->size == 0 || instr->size > instr->data_len) {
                        RR_WARN("OVERWRITE_AT_OFFSET: Invalid size %u (data_len=%u)", 
                               instr->size, instr->data_len);
                        break;
                    }
                    
                    /* 计算目标地址 */
                    target_ulong target_addr = addr + instr->offset;
                    
                    /* 安全检查：防止溢出 */
                    if (target_addr < addr) {
                        RR_ERROR("OVERWRITE_AT_OFFSET: Address overflow detected (addr=0x%lx, offset=%u)",
                                addr, instr->offset);
                        break;
                    }
                    
                    /* 执行精确覆写 */
                    fprintf(stderr, "[OVERWRITE] Attempting to write %u bytes to 0x%lx\n", instr->size, target_addr);
                    fprintf(stderr, "[OVERWRITE] Data (first 20 bytes): ");
                    for (int k = 0; k < (instr->size < 20 ? instr->size : 20); k++) {
                        fprintf(stderr, "%02x ", instr->data[k]);
                    }
                    fprintf(stderr, "\n");
                    fprintf(stderr, "[OVERWRITE] Data (ASCII): %.*s\n", instr->size < 30 ? instr->size : 30, instr->data);
                    fflush(stderr);
                    
                    if (cpu_memory_rw_debug(env_cpu(env), target_addr, 
                                           instr->data, instr->size, 1) == 0) {
                        fprintf(stderr, "[OVERWRITE] ✅ Successfully wrote %u bytes\n", instr->size);
                        fflush(stderr);
                        
                        RR_INFO("🎯 OVERWRITE_AT_OFFSET: %s[%u] addr=0x%lx+%u, wrote %u bytes",
                               syscall_name ? syscall_name : "unknown",
                               instr->arg_index, addr, instr->offset, instr->size);
                        
                        has_buffer_mutation = 1;  // 标记为buffer mutation
                        g_fuzz_stats.buffer_mutations++;
                    } else {
                        fprintf(stderr, "[OVERWRITE] ❌ Failed to write!\n");
                        fflush(stderr);
                        RR_ERROR("OVERWRITE_AT_OFFSET: Failed to write %u bytes to guest memory at 0x%lx",
                                instr->size, target_addr);
                    }
                }
                break;

            default:
                RR_WARN("Unknown fuzz command: %d", instr->cmd);
                break;
        }

        g_fuzz_stats.total_mutations++;
    }
    
    return has_buffer_mutation;  // 返回是否应用了buffer mutation
}

/**
 * 在重放系统调用时应用变异
 * 这个函数被rr_replay_syscall调用
 * @return int >0表示应用了buffer mutation, 0表示无buffer mutation, <0表示错误
 */
int rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr)
{
    // 🔥 直接写stderr，绕过日志系统
    fprintf(stderr, "[DEBUG] rr_fuzz_mutate_syscall CALLED: syscall_index=%u, nr=%d\n", syscall_index, syscall_nr);
    fflush(stderr);
    
    if (!g_rr_framework) {
        fprintf(stderr, "[ERROR] g_rr_framework is NULL!\n");
        fflush(stderr);
        return 0;
    }
    
    fprintf(stderr, "[DEBUG] g_rr_framework OK, mode=%d, g_instruction_count=%zu\n", 
            g_rr_framework->mode, g_instruction_count);
    fflush(stderr);
    
    if (g_rr_framework->mode != RR_MODE_FUZZING) {
        fprintf(stderr, "[WARN] Not in fuzzing mode (mode=%d != %d)\n", 
                g_rr_framework->mode, RR_MODE_FUZZING);
        fflush(stderr);
        return 0;
    }

    fprintf(stderr, "[DEBUG] Calling apply_mutations_for_syscall...\n");
    fflush(stderr);
    int result = apply_mutations_for_syscall(env, syscall_index, args, syscall_nr);
    fprintf(stderr, "[DEBUG] apply_mutations_for_syscall DONE, result=%d\n", result);
    fflush(stderr);
    
    return result;  // 返回是否应用了buffer mutation
}

/**
 * 生成简单的变异指令
 * 这是一个辅助函数，用于生成基本的变异策略
 */
FuzzInstruction *rr_fuzz_generate_mutations(uint32_t target_syscall, int target_arg,
                                          const uint8_t *seed_data, size_t seed_len,
                                          size_t *out_count)
{
    if (!seed_data || seed_len == 0) {
        *out_count = 0;
        return NULL;
    }

    /* 生成3种基本变异：翻转bit、随机字节、边界值 */
    *out_count = 3;
    size_t total_size = 3 * (sizeof(FuzzInstruction) + seed_len);
    FuzzInstruction *mutations = g_malloc(total_size);

    uint8_t *ptr = (uint8_t *)mutations;

    /* 变异1: 翻转第一个字节的第一个bit */
    FuzzInstruction *mut1 = (FuzzInstruction *)ptr;
    mut1->cmd = FUZZ_CMD_REPLACE_BUFFER;
    mut1->syscall_index = target_syscall;
    mut1->arg_index = target_arg;
    mut1->data_len = seed_len;
    memcpy(mut1->data, seed_data, seed_len);
    if (seed_len > 0) {
        mut1->data[0] ^= 0x01; // 翻转第一个bit
    }
    ptr += sizeof(FuzzInstruction) + seed_len;

    /* 变异2: 随机修改第一个字节 */
    FuzzInstruction *mut2 = (FuzzInstruction *)ptr;
    mut2->cmd = FUZZ_CMD_REPLACE_BUFFER;
    mut2->syscall_index = target_syscall;
    mut2->arg_index = target_arg;
    mut2->data_len = seed_len;
    memcpy(mut2->data, seed_data, seed_len);
    if (seed_len > 0) {
        mut2->data[0] = 0xFF; // 边界值
    }
    ptr += sizeof(FuzzInstruction) + seed_len;

    /* 变异3: 参数值变异（如果是整数参数） */
    FuzzInstruction *mut3 = (FuzzInstruction *)ptr;
    mut3->cmd = FUZZ_CMD_MUTATE_ARG;
    mut3->syscall_index = target_syscall;
    mut3->arg_index = target_arg;
    mut3->data_len = sizeof(abi_long);
    *(abi_long *)mut3->data = -1; // 常见的错误值

    RR_LOG("Generated %zu mutations for syscall %u arg %d", *out_count, target_syscall, target_arg);
    return mutations;
}

/**
 * 获取Fuzz统计信息
 */
void rr_fuzz_get_stats(uint64_t *total, uint64_t *arg_mut, uint64_t *buf_mut, uint64_t *boundary)
{
    if (total) *total = g_fuzz_stats.total_mutations;
    if (arg_mut) *arg_mut = g_fuzz_stats.arg_mutations;
    if (buf_mut) *buf_mut = g_fuzz_stats.buffer_mutations;
    if (boundary) *boundary = g_fuzz_stats.boundary_tests;
}

/**
 * 打印Fuzz统计信息
 */
void rr_fuzz_print_stats(void)
{
    if (g_fuzz_stats.total_mutations == 0) {
        RR_INFO("No mutations applied");
        return;
    }

    RR_INFO("=== FUZZ ENGINE STATISTICS ===");
    RR_INFO("Total mutations: %lu", g_fuzz_stats.total_mutations);
    RR_INFO("  - Argument mutations: %lu", g_fuzz_stats.arg_mutations);
    RR_INFO("  - Buffer mutations: %lu", g_fuzz_stats.buffer_mutations);
    RR_INFO("  - Boundary tests: %lu", g_fuzz_stats.boundary_tests);
    RR_INFO("==============================");
}

/**
 * 清理Fuzzing引擎
 */
void rr_fuzz_cleanup(void)
{
    // 打印最终统计
    if (g_fuzz_stats.total_mutations > 0) {
        rr_fuzz_print_stats();
    }

    // 清理指令
    g_instruction_count = 0;
    memset(g_fuzz_instructions, 0, sizeof(g_fuzz_instructions));
    
    // 清理统计
    memset(&g_fuzz_stats, 0, sizeof(g_fuzz_stats));
    
    RR_VERBOSE("Fuzz engine cleanup completed");
}
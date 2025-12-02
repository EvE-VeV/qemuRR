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

/* ==================== 优化开关 ==================== */
// 🔥 Speed Optimization: 禁用debug日志减少I/O开销
// 设置为0可以提升10-15%的性能
#define FUZZ_ENABLE_DEBUG_LOG 0

#if FUZZ_ENABLE_DEBUG_LOG
#define FUZZ_DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__); fflush(stderr)
#else
#define FUZZ_DEBUG_LOG(...) do {} while(0)
#endif

/* ==================== 全局状态 ==================== */

// 当前生效的Fuzz指令集（从共享内存加载）
// ✅ Phase 1: 改为非 static，供 rr_fuzz_aux_mutations.c 使用
FuzzInstruction g_fuzz_instructions[FUZZ_MAX_INSTRUCTIONS];
size_t g_instruction_count = 0;

// ✅ 新增：IO返回值变异支持
bool g_has_retval_override = false;
abi_long g_retval_override = 0;

// ✅ 2025-11-17: Buffer Content Mutation支持 (配合retval override)
bool g_has_buffer_fill = false;           // 是否需要填充buffer
target_ulong g_buffer_fill_addr = 0;      // buffer地址
size_t g_buffer_fill_size = 0;            // 填充大小
uint8_t g_buffer_fill_pattern[1024];      // 填充内容 (最大1KB)
size_t g_buffer_fill_pattern_len = 0;     // 填充模式长度

// 变异统计
typedef struct {
    uint64_t total_mutations;       // 总变异次数
    uint64_t arg_mutations;         // 参数变异
    uint64_t buffer_mutations;      // 缓冲区变异
    uint64_t boundary_tests;        // 边界值测试
    uint64_t retval_mutations;      // 返回值变异 (新增)
} fuzz_stats_t;

/* ✅ 2025-11-17: Forward declaration */
static int get_input_io_buffer_arg_index(int syscall_nr);

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
    FUZZ_DEBUG_LOG("\n[APPLY] ========== START ==========\n");
    FUZZ_DEBUG_LOG("[APPLY] PID=%d, syscall_index=%u, nr=%d\n", getpid(), syscall_index, syscall_nr);
    FUZZ_DEBUG_LOG("[APPLY] g_instruction_count=%zu (address=%p, value_at_addr=%zu)\n",
            g_instruction_count, &g_instruction_count, *(size_t*)&g_instruction_count);
    if (g_instruction_count > 0) {
        FUZZ_DEBUG_LOG("[APPLY] First instruction: syscall_idx=%u, cmd=%d\n",
                g_fuzz_instructions[0].syscall_index, g_fuzz_instructions[0].cmd);
    }
    
    if (g_instruction_count == 0) {
        FUZZ_DEBUG_LOG("[APPLY] ERROR: g_instruction_count is 0!\n");
        FUZZ_DEBUG_LOG("[APPLY] This means instructions were cleared after reload!\n");
        return 0;  // 没有变异指令
    }

    // 获取系统调用的类型和重要性（用于智能变异）
    const char *syscall_name = rr_get_syscall_name_fast(syscall_nr);
    
    FUZZ_DEBUG_LOG("[APPLY] Searching for mutations: syscall_idx=%u, nr=%d (%s)\n",
            syscall_index, syscall_nr, syscall_name ? syscall_name : "unknown");

    /* 遍历所有指令，寻找匹配的系统调用索引 */
    for (size_t i = 0; i < g_instruction_count; i++) {
        FuzzInstruction *instr = &g_fuzz_instructions[i];
        
        FUZZ_DEBUG_LOG("[APPLY] Checking instr[%zu]: syscall_idx=%u vs target=%u, cmd=%d\n", 
                   i, instr->syscall_index, syscall_index, instr->cmd);

        // 跳过不匹配的系统调用
        if (instr->syscall_index != syscall_index) {
            FUZZ_DEBUG_LOG("[APPLY]   Skip: mismatch (%u != %u)\n", instr->syscall_index, syscall_index);
            continue;
        }
        
        FUZZ_DEBUG_LOG("[APPLY]   *** MATCH FOUND! cmd=%d ***\n", instr->cmd);

        // 检查参数索引有效性 (允许 0xFF 用于返回值变异)
        FUZZ_DEBUG_LOG("[APPLY] Checking arg_index: %u (0xFF=retval, else must be < 8)\n", instr->arg_index);

        if (instr->arg_index != 0xFF && instr->arg_index >= 8) {
            FUZZ_DEBUG_LOG("[APPLY] ERROR: Invalid arg_index %u for syscall %s\n",
                    instr->arg_index, syscall_name ? syscall_name : "unknown");
            RR_WARN("Invalid arg_index %u for syscall %s",
                    instr->arg_index, syscall_name ? syscall_name : "unknown");
            continue;
        }
        
        FUZZ_DEBUG_LOG("[APPLY] arg_index check passed, entering switch(cmd=%d)\n", instr->cmd);

        RR_VERBOSE("Applying mutation [%zu/%zu] to %s arg[%u]: cmd=%d",
                   i + 1, g_instruction_count,
                   syscall_name ? syscall_name : "unknown",
                   instr->arg_index, instr->cmd);

        switch (instr->cmd) {
            case FUZZ_CMD_MUTATE_ARG:
                // ✅ 特殊处理：arg_index == 0xFF 表示变异返回值
                if (instr->arg_index == 0xFF) {
                    if (instr->data_len >= sizeof(abi_long)) {
                        g_retval_override = *(abi_long *)instr->data;
                        g_has_retval_override = true;

                        RR_INFO("🎯 MUTATE_RETVAL: %s return value → %ld (syscall_idx=%u)",
                               syscall_name ? syscall_name : "unknown",
                               g_retval_override, syscall_index);

                        FUZZ_DEBUG_LOG("[APPLY] 🎯 IO RETVAL MUTATION: %s → %ld\n",
                                syscall_name ? syscall_name : "unknown", g_retval_override);

                        /* ✅ 2025-11-17: 泛化Buffer Fill - 如果是input IO syscall，自动设置buffer fill */
                        int buf_arg_idx = get_input_io_buffer_arg_index(syscall_nr);
                        if (buf_arg_idx >= 0 && g_retval_override > 0) {
                            target_ulong buf_addr = args[buf_arg_idx];
                            if (buf_addr != 0) {
                                /* 从指令中提取填充模式，或使用默认模式 */
                                const uint8_t *pattern = NULL;
                                size_t pattern_len = 0;

                                /* 如果指令包含额外数据（在retval之后），用作填充模式 */
                                if (instr->data_len > sizeof(abi_long)) {
                                    pattern = instr->data + sizeof(abi_long);
                                    pattern_len = instr->data_len - sizeof(abi_long);
                                }

                                rr_fuzz_set_buffer_fill(buf_addr, (size_t)g_retval_override,
                                                        pattern, pattern_len);

                                FUZZ_DEBUG_LOG("[APPLY] 🎨 AUTO BUFFER FILL: addr=0x%lx, size=%ld\n",
                                        buf_addr, g_retval_override);
                            }
                        }

                        g_fuzz_stats.retval_mutations++;
                    }
                    break;
                }

                // 正常的参数变异

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
                    FUZZ_DEBUG_LOG("[OVERWRITE] Entered FUZZ_CMD_OVERWRITE_AT_OFFSET branch\n");
                    
                    target_ulong addr = args[instr->arg_index];
                    FUZZ_DEBUG_LOG("[OVERWRITE] addr=0x%lx (from args[%u])\n", addr, instr->arg_index);
                    
                    if (addr == 0) {
                        FUZZ_DEBUG_LOG("[OVERWRITE] ERROR: NULL address for arg[%u]\n", instr->arg_index);
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
                    FUZZ_DEBUG_LOG("[OVERWRITE] Attempting to write %u bytes to 0x%lx\n", instr->size, target_addr);
                    FUZZ_DEBUG_LOG("[OVERWRITE] Data (first 20 bytes): ");
                    for (int k = 0; k < (instr->size < 20 ? instr->size : 20); k++) {
                        fprintf(stderr, "%02x ", instr->data[k]);
                    }
                    fprintf(stderr, "\n");
                    FUZZ_DEBUG_LOG("[OVERWRITE] Data (ASCII): %.*s\n", instr->size < 30 ? instr->size : 30, instr->data);
                    
                    if (cpu_memory_rw_debug(env_cpu(env), target_addr, 
                                           instr->data, instr->size, 1) == 0) {
                        FUZZ_DEBUG_LOG("[OVERWRITE] ✅ Successfully wrote %u bytes\n", instr->size);
                        
                        RR_INFO("🎯 OVERWRITE_AT_OFFSET: %s[%u] addr=0x%lx+%u, wrote %u bytes",
                               syscall_name ? syscall_name : "unknown",
                               instr->arg_index, addr, instr->offset, instr->size);
                        
                        has_buffer_mutation = 1;  // 标记为buffer mutation
                        g_fuzz_stats.buffer_mutations++;
                    } else {
                        FUZZ_DEBUG_LOG("[OVERWRITE] ❌ Failed to write!\n");
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
    FUZZ_DEBUG_LOG("[DEBUG] rr_fuzz_mutate_syscall CALLED: syscall_index=%u, nr=%d\n", syscall_index, syscall_nr);
    
    if (!g_rr_framework) {
        fprintf(stderr, "[ERROR] g_rr_framework is NULL!\n");
        return 0;
    }
    
    FUZZ_DEBUG_LOG("[DEBUG] g_rr_framework OK, mode=%d, g_instruction_count=%zu\n", 
            g_rr_framework->mode, g_instruction_count);
    
    if (g_rr_framework->mode != RR_MODE_FUZZING) {
        fprintf(stderr, "[WARN] Not in fuzzing mode (mode=%d != %d)\n", 
                g_rr_framework->mode, RR_MODE_FUZZING);
        return 0;
    }

    FUZZ_DEBUG_LOG("[DEBUG] Calling apply_mutations_for_syscall...\n");
    int result = apply_mutations_for_syscall(env, syscall_index, args, syscall_nr);
    FUZZ_DEBUG_LOG("[DEBUG] apply_mutations_for_syscall DONE, result=%d\n", result);
    
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
 * ✅ 新增：检查是否有返回值覆盖
 */
bool rr_fuzz_has_retval_override(void)
{
    return g_has_retval_override;
}

/**
 * ✅ 新增：获取返回值覆盖（并清除标志）
 */
abi_long rr_fuzz_get_retval_override(void)
{
    abi_long ret = g_retval_override;
    g_has_retval_override = false;  // 清除标志，避免影响后续syscalls
    return ret;
}

/**
 * ✅ 新增：清除返回值覆盖标志
 */
void rr_fuzz_clear_retval_override(void)
{
    g_has_retval_override = false;
    g_retval_override = 0;
}

/**
 * ✅ 2025-11-17: 泛化IO Syscall识别
 *
 * 识别input IO syscalls并返回buffer参数索引
 *
 * @param syscall_nr 系统调用号
 * @return buffer参数索引，-1表示不是input IO syscall
 */
static int get_input_io_buffer_arg_index(int syscall_nr)
{
    /* 通用规则：对于input IO syscalls，buffer通常在arg1 */
    switch (syscall_nr) {
        case TARGET_NR_read:        /* read(fd, buf, count) */
        case TARGET_NR_readv:       /* readv(fd, iov, iovcnt) */
        case TARGET_NR_pread64:     /* pread(fd, buf, count, offset) */
            return 1;  /* arg1 = buf */

#ifdef TARGET_NR_recv
        case TARGET_NR_recv:        /* recv(sockfd, buf, len, flags) */
#endif
#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:    /* recvfrom(sockfd, buf, len, flags, src_addr, addrlen) */
#endif
#ifdef TARGET_NR_recvmsg
        case TARGET_NR_recvmsg:     /* recvmsg(sockfd, msg, flags) */
#endif
            return 1;  /* arg1 = buf */

        default:
            return -1;  /* 不是input IO syscall */
    }
}

/**
 * ✅ 2025-11-17: 设置Buffer Fill参数
 *
 * 配合retval override，准备填充buffer内容
 *
 * @param buf_addr buffer地址
 * @param size 填充大小
 * @param pattern 填充模式数据
 * @param pattern_len 填充模式长度
 */
void rr_fuzz_set_buffer_fill(target_ulong buf_addr, size_t size,
                               const uint8_t *pattern, size_t pattern_len)
{
    if (size > sizeof(g_buffer_fill_pattern)) {
        RR_WARN("Buffer fill size %zu exceeds max %zu, truncating",
                size, sizeof(g_buffer_fill_pattern));
        size = sizeof(g_buffer_fill_pattern);
    }

    g_buffer_fill_addr = buf_addr;
    g_buffer_fill_size = size;
    g_buffer_fill_pattern_len = pattern_len;

    /* 复制填充模式并循环扩展到size大小 */
    if (pattern && pattern_len > 0) {
        for (size_t i = 0; i < size; i++) {
            g_buffer_fill_pattern[i] = pattern[i % pattern_len];
        }
    } else {
        /* 默认填充：递增模式 */
        for (size_t i = 0; i < size; i++) {
            g_buffer_fill_pattern[i] = (uint8_t)(i & 0xFF);
        }
    }

    g_has_buffer_fill = true;

    RR_INFO("🎨 Set buffer fill: addr=0x%lx, size=%zu, pattern_len=%zu",
            buf_addr, size, pattern_len);
}

/**
 * ✅ 2025-11-17: 检查是否需要填充buffer
 */
bool rr_fuzz_has_buffer_fill(void)
{
    return g_has_buffer_fill;
}

/**
 * ✅ 2025-11-17: 获取Buffer Fill参数
 *
 * @param out_addr 输出buffer地址
 * @param out_size 输出填充大小
 * @param out_pattern 输出填充模式
 * @return buffer fill大小，0表示无效
 */
size_t rr_fuzz_get_buffer_fill(target_ulong *out_addr, size_t *out_size,
                                 const uint8_t **out_pattern)
{
    if (!g_has_buffer_fill) {
        return 0;
    }

    if (out_addr) *out_addr = g_buffer_fill_addr;
    if (out_size) *out_size = g_buffer_fill_size;
    if (out_pattern) *out_pattern = g_buffer_fill_pattern;

    /* 清除标志，避免影响后续syscalls */
    g_has_buffer_fill = false;

    return g_buffer_fill_size;
}

/**
 * ✅ 2025-11-17: 清除buffer fill标志
 */
void rr_fuzz_clear_buffer_fill(void)
{
    g_has_buffer_fill = false;
    g_buffer_fill_addr = 0;
    g_buffer_fill_size = 0;
    g_buffer_fill_pattern_len = 0;
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
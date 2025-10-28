/**
 * RR-Fuzz变异引擎
 * 实现Fuzzing指令的应用和参数变异
 * 
 * 设计理念：
 * 1. 从共享内存读取Fuzz指令（由Conductor生成）
 * 2. 在系统调用重放时应用变异
 * 3. 支持多种变异策略（参数变异、缓冲区替换、边界值测试等）
 */

#include "../core/rr_framework.h"
#include "../utils/rr_syscall_dispatch.h"

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

    // 验证校验和（防止读到部分写入的数据）
    uint32_t expected_checksum = shm->magic ^ shm->sequence ^ shm->instruction_count;
    if (shm->checksum != expected_checksum) {
        RR_WARN("Shared memory checksum mismatch: got 0x%x, expected 0x%x (sequence=%u, count=%u)",
                shm->checksum, expected_checksum, shm->sequence, shm->instruction_count);
        RR_WARN("Possible incomplete write, skipping this round");
        g_instruction_count = 0;
        return -1;  // 返回错误，让调用方知道数据不完整
    }

    // 检查指令数量
    if (shm->instruction_count == 0) {
        RR_VERBOSE("No fuzz instructions in shared memory");
        g_instruction_count = 0;
        return 0;
    }

    if (shm->instruction_count > FUZZ_MAX_INSTRUCTIONS) {
        RR_ERROR("Too many instructions: %u (max %d)", 
                 shm->instruction_count, FUZZ_MAX_INSTRUCTIONS);
        return -1;
    }

    // 复制指令到本地缓冲区
    g_instruction_count = shm->instruction_count;
    memcpy(g_fuzz_instructions, shm->instructions, 
           sizeof(FuzzInstruction) * g_instruction_count);

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
 */
static void apply_mutations_for_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr)
{
    if (g_instruction_count == 0) {
        return;  // 没有变异指令
    }

    // 获取系统调用的类型和重要性（用于智能变异）
    const char *syscall_name = rr_get_syscall_name_fast(syscall_nr);

    /* 遍历所有指令，寻找匹配的系统调用索引 */
    for (size_t i = 0; i < g_instruction_count; i++) {
        FuzzInstruction *instr = &g_fuzz_instructions[i];

        // 跳过不匹配的系统调用
        if (instr->syscall_index != syscall_index) {
            continue;
        }

        // 检查参数索引有效性
        if (instr->arg_index >= 8) {
            RR_WARN("Invalid arg_index %u for syscall %s", 
                    instr->arg_index, syscall_name ? syscall_name : "unknown");
            continue;
        }

        RR_VERBOSE("Applying mutation [%zu/%zu] to %s arg[%u]: cmd=%d",
                   i + 1, g_instruction_count, 
                   syscall_name ? syscall_name : "unknown",
                   instr->arg_index, instr->cmd);

        switch (instr->cmd) {
            case FUZZ_CMD_MUTATE_ARG:
                /* 变异参数值 - 适用于整数参数 */
                if (instr->data_len >= sizeof(abi_long)) {
                    abi_long new_value = *(abi_long *)instr->data;
                    args[instr->arg_index] = new_value;
                    
                    RR_INFO("🔧 MUTATE_ARG: %s[%u] %ld → %ld (syscall_idx=%u)",
                           syscall_name ? syscall_name : "unknown",
                           instr->arg_index, args[instr->arg_index], new_value, syscall_index);
                    
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
                    abi_long xor_mask = *(abi_long *)instr->data;
                    args[instr->arg_index] ^= xor_mask;
                    
                    RR_INFO("🔧 MUTATE_FLAGS: %s[%u] 0x%lx → 0x%lx (XOR 0x%lx)",
                           syscall_name ? syscall_name : "unknown",
                           instr->arg_index, args[instr->arg_index], args[instr->arg_index], xor_mask);
                    
                    g_fuzz_stats.arg_mutations++;
                }
                break;

            case FUZZ_CMD_BOUNDARY_VALUE:
                /* 边界值测试 - 使用特殊值（0, -1, MAX等） */
                if (instr->data_len >= sizeof(abi_long)) {
                    abi_long old_value = args[instr->arg_index];
                    abi_long boundary = *(abi_long *)instr->data;
                    args[instr->arg_index] = boundary;
                    
                    RR_INFO("🔧 BOUNDARY_VALUE: %s[%u] %ld → %ld",
                           syscall_name ? syscall_name : "unknown",
                           instr->arg_index, old_value, boundary);
                    
                    g_fuzz_stats.boundary_tests++;
                }
                break;

            default:
                RR_WARN("Unknown fuzz command: %d", instr->cmd);
                break;
        }

        g_fuzz_stats.total_mutations++;
    }
}

/**
 * 在重放系统调用时应用变异
 * 这个函数被rr_replay_syscall调用
 */
void rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr)
{
    if (g_rr_framework->mode != RR_MODE_FUZZING) {
        return;
    }

    apply_mutations_for_syscall(env, syscall_index, args, syscall_nr);
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
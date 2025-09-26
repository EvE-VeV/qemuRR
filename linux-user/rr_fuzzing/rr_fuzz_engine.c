/**
 * RR-Fuzz变异引擎
 * 实现Fuzzing指令的应用和参数变异，对应design.md中的变异策略
 */

#include "rr_framework.h"

static FuzzInstruction *g_fuzz_instructions = NULL;
static size_t g_instruction_count = 0;

/**
 * 应用Fuzzing指令
 * 实现design.md中的参数变异机制
 */
int rr_fuzz_apply_instructions(const FuzzInstruction *instructions, size_t count)
{
    RR_VERBOSE("Applying fuzzing instructions: count=%zu", count);

    if (!instructions || count == 0) {
        RR_VERBOSE("No instructions to apply");
        return 0;
    }

    /* 清理旧指令 */
    if (g_fuzz_instructions) {
        RR_VERBOSE("Cleaning up previous instructions");
        g_free(g_fuzz_instructions);
    }

    /* 计算总大小并分配内存 */
    size_t total_size = 0;
    for (size_t i = 0; i < count; i++) {
        total_size += sizeof(FuzzInstruction) + instructions[i].data_len;
        RR_TRACE("Instruction %zu: cmd=%d, syscall_idx=%d, arg_idx=%d, data_len=%zu",
                 i, instructions[i].cmd, instructions[i].syscall_index,
                 instructions[i].arg_index, instructions[i].data_len);
    }

    RR_VERBOSE("Allocating %zu bytes for %zu instructions", total_size, count);
    g_fuzz_instructions = g_malloc(total_size);
    g_instruction_count = count;

    /* 复制指令数据 */
    uint8_t *ptr = (uint8_t *)g_fuzz_instructions;
    for (size_t i = 0; i < count; i++) {
        FuzzInstruction *dest = (FuzzInstruction *)ptr;
        dest->cmd = instructions[i].cmd;
        dest->syscall_index = instructions[i].syscall_index;
        dest->arg_index = instructions[i].arg_index;
        dest->data_len = instructions[i].data_len;

        if (instructions[i].data_len > 0) {
            memcpy(dest->data, instructions[i].data, instructions[i].data_len);
        }

        ptr += sizeof(FuzzInstruction) + instructions[i].data_len;
    }

    RR_INFO("Applied %zu fuzzing instructions", count);
    return 0;
}

/**
 * 检查并应用当前系统调用的变异
 */
static void apply_mutations_for_syscall(uint32_t syscall_index, abi_long *args, int syscall_nr)
{
    if (!g_fuzz_instructions) {
        return;
    }

    /* 遍历所有指令，寻找匹配的系统调用索引 */
    uint8_t *ptr = (uint8_t *)g_fuzz_instructions;
    for (size_t i = 0; i < g_instruction_count; i++) {
        FuzzInstruction *instr = (FuzzInstruction *)ptr;

        if (instr->syscall_index == (int)syscall_index) {
            switch (instr->cmd) {
                case FUZZ_CMD_MUTATE_ARG:
                    /* 变异参数值 */
                    if (instr->arg_index >= 0 && instr->arg_index < 8 && instr->data_len >= sizeof(abi_long)) {
                        abi_long new_value = *(abi_long *)instr->data;
                        RR_LOG("Mutating arg[%d] from %ld to %ld at syscall %u",
                               instr->arg_index, args[instr->arg_index], new_value, syscall_index);
                        args[instr->arg_index] = new_value;
                    }
                    break;

                case FUZZ_CMD_REPLACE_BUFFER:
                    /* 替换缓冲区内容 - 这需要在系统调用执行前修改内存 */
                    if (instr->arg_index >= 0 && instr->arg_index < 8 && instr->data_len > 0) {
                        target_ulong addr = args[instr->arg_index];
                        if (addr != 0) {
                            /* 写入变异数据到目标地址 */
                            // 注意：这里需要CPU环境，简化处理暂时记录日志
                            RR_LOG("Would replace buffer at arg[%d] (addr=0x%lx) with %zu bytes at syscall %u",
                                   instr->arg_index, addr, instr->data_len, syscall_index);
                        }
                    }
                    break;

                default:
                    break;
            }
        }

        ptr += sizeof(FuzzInstruction) + instr->data_len;
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

    apply_mutations_for_syscall(syscall_index, args, syscall_nr);
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
 * 清理Fuzzing引擎
 */
void rr_fuzz_cleanup(void)
{
    if (g_fuzz_instructions) {
        g_free(g_fuzz_instructions);
        g_fuzz_instructions = NULL;
        g_instruction_count = 0;
    }
}
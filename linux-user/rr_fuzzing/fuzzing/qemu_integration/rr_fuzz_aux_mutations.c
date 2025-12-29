/**
 * RR-Fuzz Phase 1: aux_data 变异引擎
 * 
 * 实现对 aux_data 的各种变异策略，用于 Pure Replay + Fuzzing 集成
 * 
 * 设计理念：
 * 1. 在 Pure Replay 成功后，对 aux_data 进行变异
 * 2. 变异后重新应用到 guest 内存，实现确定性 Fuzzing
 * 3. 支持多种变异策略，覆盖不同的测试场景
 */

#include "../../core/rr_framework.h"
#include "../../record/rr_aux_data.h"
#include "../../utils/rr_syscall_dispatch.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ==================== 外部变量 ==================== */

// Fuzz 指令（来自 rr_fuzz_engine.c）

// Fuzz 统计（来自 rr_fuzz_engine.c）
typedef struct {
    uint64_t total_mutations;
    uint64_t arg_mutations;
    uint64_t buffer_mutations;
    uint64_t boundary_tests;
} fuzz_stats_t;

extern fuzz_stats_t g_fuzz_stats;

/* ==================== 辅助函数 ==================== */

/**
 * 生成随机字节
 */
static uint8_t random_byte(void) {
    static bool initialized = false;
    if (!initialized) {
        srand(time(NULL));
        initialized = true;
    }
    return (uint8_t)(rand() % 256);
}

/**
 * 查找指定 arg_mask 的 aux_data
 * 
 * arg_mask 是参数索引的位掩码（例如 arg_mask=1 表示 arg[0]）
 */
static rr_aux_data_t *find_aux_data_by_arg_mask(rr_aux_data_t *head, uint8_t target_mask) {
    rr_aux_data_t *current = head;
    while (current) {
        if (current->arg_mask == target_mask) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

/* ==================== 变异策略实现 ==================== */

/**
 * 策略 1: 变异 aux_data 缓冲区
 * 
 * 直接替换 aux_data 中的数据
 */
static void mutate_aux_buffer(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data) {
        return;
    }
    
    // 限制变异长度，不超过 aux 的实际大小
    uint32_t copy_len = (instr->data_len < aux->size) ? instr->data_len : aux->size;
    
    // 复制变异数据
    memcpy(aux->data, instr->data, copy_len);
    
    RR_INFO("🔧 FUZZ_AUX: Mutated buffer, copied %u/%u bytes", copy_len, aux->size);
    g_fuzz_stats.buffer_mutations++;
}

/**
 * 策略 2: 位翻转
 * 
 * 随机翻转 aux_data 中的某些位
 */
static void flip_bits(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data || aux->size == 0) {
        return;
    }
    
    uint32_t flip_count = 0;
    
    // 从 instr->data[0] 读取翻转概率（0-100）
    uint32_t flip_prob = (instr->data_len > 0) ? instr->data[0] : 1;
    if (flip_prob == 0) flip_prob = 1;
    if (flip_prob > 100) flip_prob = 100;
    
    // 遍历每个字节
    for (uint32_t i = 0; i < aux->size; i++) {
        // 根据概率决定是否翻转
        if ((rand() % 100) < flip_prob) {
            // 随机选择一个位进行翻转
            int bit = rand() % 8;
            aux->data[i] ^= (1 << bit);
            flip_count++;
        }
    }
    
    RR_INFO("🔧 FUZZ_AUX: Flipped %u bits (prob=%u%%, size=%u)", 
            flip_count, flip_prob, aux->size);
    g_fuzz_stats.arg_mutations++;
}

/**
 * 策略 3: 截断数据
 * 
 * 减少 aux_data 的大小
 */
static void truncate_data(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data || aux->size == 0) {
        return;
    }
    
    __attribute__((unused)) uint32_t old_size = aux->size;
    
    // 从 instr->data[0] 读取截断比例（如果没有，默认减半）
    if (instr->data_len > 0 && instr->data[0] > 0 && instr->data[0] < 100) {
        // data[0] 表示保留的百分比
        aux->size = (aux->size * instr->data[0]) / 100;
    } else {
        // 默认减半
        aux->size = aux->size / 2;
    }
    
    // 至少保留 1 字节
    if (aux->size == 0) {
        aux->size = 1;
    }
    
    RR_INFO("🔧 FUZZ_AUX: Truncated %u → %u bytes", old_size, aux->size);
    g_fuzz_stats.boundary_tests++;
}

/**
 * 策略 4: 扩展数据
 * 
 * 增加 aux_data 的大小（填充随机数据或零）
 */
static void extend_data(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data) {
        return;
    }
    
    __attribute__((unused)) uint32_t old_size = aux->size;
    uint32_t new_size;
    
    // 🔥 修复：从 instr->data 读取绝对扩展字节数（不是倍数！）
    uint32_t extend_by;
    if (instr->data_len >= 4) {
        // Python端用struct.pack('I', extend_by)发送4字节的绝对值
        memcpy(&extend_by, instr->data, 4);
    } else {
        // 回退到默认值
        extend_by = 64;
    }

    new_size = aux->size + extend_by;

    // 🔥 提高最大大小限制以支持缓冲区溢出测试（1024 字节）
    if (new_size > 1024) {
        new_size = 1024;
    }
    
    // 如果没有增长，跳过
    if (new_size <= aux->size) {
        RR_VERBOSE("FUZZ_AUX: Extend skipped (already max size)");
        return;
    }
    
    // 重新分配内存
    uint8_t *new_data = g_malloc(new_size);
    memcpy(new_data, aux->data, old_size);
    
    // 填充方式：从 instr->data[1] 读取（0=零，1=随机）
    uint8_t fill_mode = (instr->data_len > 1) ? instr->data[1] : 0;
    if (fill_mode == 1) {
        // 填充随机数据
        for (uint32_t i = old_size; i < new_size; i++) {
            new_data[i] = random_byte();
        }
    } else {
        // 填充零
        memset(new_data + old_size, 0, new_size - old_size);
    }
    
    // 替换原数据
    g_free(aux->data);
    aux->data = new_data;
    aux->size = new_size;
    
    RR_INFO("🔧 FUZZ_AUX: Extended %u → %u bytes (fill_mode=%u)", 
            old_size, new_size, fill_mode);
    g_fuzz_stats.boundary_tests++;
}

/**
 * Phase 1 策略: 轻量级变异
 * 
 * 只翻转 1-2 个 bit，最小化破坏性
 * 适用于初期 Fuzzing，避免程序立即崩溃
 */
static void mutate_light(rr_aux_data_t *aux, const FuzzInstruction *instr) {
    if (!aux || !aux->data || aux->size == 0) {
        return;
    }
    
    // 默认只翻转 1 个 bit
    uint32_t flip_count = 1;
    
    // 如果指令提供了数据，第一个字节指定翻转数量（1-3）
    if (instr->data_len > 0 && instr->data[0] > 0) {
        flip_count = (instr->data[0] % 3) + 1;  // 1-3 bits
    }
    
    // 翻转指定数量的 bit
    for (uint32_t i = 0; i < flip_count; i++) {
        // 随机选择一个字节
        uint32_t byte_idx = rand() % aux->size;
        // 随机选择一个 bit
        uint8_t bit_idx = rand() % 8;
        // 翻转
        aux->data[byte_idx] ^= (1 << bit_idx);
    }
    
    RR_INFO("🔧 FUZZ_AUX: Light mutation - flipped %u bits in %u bytes", 
            flip_count, aux->size);
    g_fuzz_stats.arg_mutations++;
}

/**
 * 策略 5: 特殊值注入
 * 
 * 注入特定的"有趣"值，如边界值、魔数等
 */
/**
 * @brief 策略 5: 特殊值注入 (Vulnerability Patterns)
 * 
 * 根据系统调用的类型，智能注入已知漏洞模式的 Payload。
 * 这是发现特定类型漏洞（如格式化字符串、命令注入、缓冲区溢出）的关键策略。
 * 
 * **支持的模式**:
 * - `getrandom`: 全0/全1/重复模式 (测试弱随机数)
 * - `read/recv*`:
 *    - Format String: `%s%n`, `%p`
 *    - Buffer Overflow: 长字符串 ('A' * N)
 *    - Integer Overflow: MAX_INT, 0xFFFFFFFF
 *    - Command Injection: `$(id)`
 *    - Path Traversal: `../../etc/passwd`
 * 
 * @param aux 目标 aux_data
 * @param instr 变异指令
 * @param syscall_nr 系统调用号
 */
static void inject_interesting_values(rr_aux_data_t *aux, const FuzzInstruction *instr,
                                      int syscall_nr) {
    if (!aux || !aux->data || aux->size == 0) {
        return;
    }
    
    // 根据系统调用类型注入不同的特殊值
    switch (syscall_nr) {
        case TARGET_NR_getrandom: {
            /* 随机数特殊值：全零、全 1、重复模式 */
            if (instr->data_len > 0) {
                uint8_t pattern = instr->data[0];
                memset(aux->data, pattern, aux->size);
                RR_INFO("🔧 FUZZ_AUX: Injected pattern 0x%02x (getrandom)", pattern);
            } else {
                // 默认：全零
                memset(aux->data, 0x00, aux->size);
                RR_INFO("🔧 FUZZ_AUX: Injected all zeros (getrandom)");
            }
            break;
        }
        
        case TARGET_NR_read:
#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64:
#endif
#ifdef TARGET_NR_recv
        case TARGET_NR_recv:
#endif
#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
#endif
        {
            /* 🎯 增强：支持多种漏洞模式的特殊值注入 */
            if (instr->data_len > 0) {
                uint8_t pattern_type = instr->data[0] % 8;  // 8种模式

                switch (pattern_type) {
                    case 0: {
                        // 格式化字符串攻击
                        const char *fmt_patterns[] = {"%s%s%s%n", "%p%p%p", "%x%x%x"};
                        const char *pattern = fmt_patterns[instr->data[1] % 3];
                        size_t pattern_len = strlen(pattern);
                        size_t copy_len = (pattern_len < aux->size) ? pattern_len : aux->size;
                        memcpy(aux->data, pattern, copy_len);
                        RR_INFO("🔧 FUZZ_AUX: Injected format string pattern");
                        break;
                    }
                    case 1: {
                        // 缓冲区溢出模式 (重复字符)
                        uint8_t overflow_char = (instr->data_len > 1) ? instr->data[1] : 0x41;  // 'A'
                        memset(aux->data, overflow_char, aux->size);
                        RR_INFO("🔧 FUZZ_AUX: Injected overflow pattern (0x%02x)", overflow_char);
                        break;
                    }
                    case 2: {
                        // NULL字节注入
                        memset(aux->data, 0x00, aux->size);
                        RR_INFO("🔧 FUZZ_AUX: Injected NULL bytes");
                        break;
                    }
                    case 3: {
                        // 高位字节测试
                        memset(aux->data, 0xFF, aux->size);
                        RR_INFO("🔧 FUZZ_AUX: Injected high bytes (0xFF)");
                        break;
                    }
                    case 4: {
                        // 整数边界值
                        if (aux->size >= 4) {
                            uint32_t boundary_vals[] = {0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF};
                            uint32_t val = boundary_vals[(instr->data[1] % 5)];
                            memcpy(aux->data, &val, 4);
                            RR_INFO("🔧 FUZZ_AUX: Injected boundary value 0x%08x", val);
                        }
                        break;
                    }
                    case 5: {
                        // 路径遍历注入
                        const char *path_pattern = "/../../../etc/passwd";
                        size_t pattern_len = strlen(path_pattern);
                        size_t copy_len = (pattern_len < aux->size) ? pattern_len : aux->size;
                        memcpy(aux->data, path_pattern, copy_len);
                        RR_INFO("🔧 FUZZ_AUX: Injected path traversal");
                        break;
                    }
                    case 6: {
                        // 命令注入模式
                        const char *cmd_pattern = "$(id)";
                        size_t pattern_len = strlen(cmd_pattern);
                        size_t copy_len = (pattern_len < aux->size) ? pattern_len : aux->size;
                        memcpy(aux->data, cmd_pattern, copy_len);
                        RR_INFO("🔧 FUZZ_AUX: Injected command injection");
                        break;
                    }
                    default: {
                        // 通用魔数注入
                        if (instr->data_len >= 4) {
                            memcpy(aux->data, instr->data + 1, (instr->data_len - 1 < aux->size) ? instr->data_len - 1 : aux->size);
                            RR_INFO("🔧 FUZZ_AUX: Injected custom magic bytes");
                        } else {
                            memset(aux->data, 0xFF, aux->size);
                            RR_INFO("🔧 FUZZ_AUX: Injected default 0xFF pattern");
                        }
                        break;
                    }
                }
            } else {
                // 回退到原有逻辑
                memset(aux->data, 0xFF, aux->size);
                RR_INFO("🔧 FUZZ_AUX: Injected 0xFF pattern (fallback)");
            }
            break;
        }
        
        default:
            // 其他系统调用：注入 0xFF 模式
            memset(aux->data, 0xFF, aux->size);
            RR_INFO("🔧 FUZZ_AUX: Injected 0xFF pattern (default)");
            break;
    }
    
    g_fuzz_stats.arg_mutations++;
}

/* ==================== 主函数 ==================== */

/**
 * 变异 aux_data 中的数据
 * 
 * 此函数遍历所有 Fuzz 指令，对匹配的 aux_data 进行变异
 */
/**
 * @brief 执行 Aux Data 变异 (入口函数)
 * 
 * 在 Replay 过程中，当遇到带有 aux_data 的系统调用（如 read/getrandom）时被调用。
 * 遍历当前的 Fuzz 指令，如果找到针对该 syscall 的 aux 变异指令，则修改 aux_data 的内容。
 * 
 * **流程**:
 * 1. 检查是否在 Fuzzing 模式且有指令。
 * 2. 遍历指令集，匹配 syscall_index。
 * 3. 查找对应的 aux_data 节点 (基于 arg_index)。
 * 4. 调用具体的变异策略函数 (`mutate_aux_buffer`, `flip_bits`, `extend_data` 等)。
 * 
 * @param env CPU 环境
 * @param record syscall 记录
 * @param args 参数
 * @param syscall_nr 系统调用号
 */
void rr_fuzz_mutate_aux_data(CPUArchState *env, syscall_record_t *record,
                              abi_long *args, int syscall_nr) {
    // 检查前提条件
    if (!record || !record->aux_data) {
        RR_VERBOSE("FUZZ_AUX: No aux_data to mutate");
        return;
    }
    
    if (g_rr_framework->mode != RR_MODE_FUZZING) {
        RR_VERBOSE("FUZZ_AUX: Not in fuzzing mode");
        return;
    }
    
    if (g_instruction_count == 0) {
        RR_VERBOSE("FUZZ_AUX: No fuzz instructions");
        return;
    }
    
    RR_VERBOSE("FUZZ_AUX: Mutating aux_data for syscall %d (index=%u)", 
              syscall_nr, record->index);
    
    // 遍历所有 Fuzz 指令
    for (size_t i = 0; i < g_instruction_count; i++) {
        FuzzInstruction *instr = &g_fuzz_instructions[i];
        
        // 只处理匹配当前 syscall 索引的指令
        if (instr->syscall_index != record->index) {
            continue;
        }
        
        // 查找对应的 aux_data（将 arg_index 转为 arg_mask）
        uint8_t arg_mask = (1 << instr->arg_index);
        rr_aux_data_t *aux = find_aux_data_by_arg_mask(record->aux_data, arg_mask);
        if (!aux) {
            RR_VERBOSE("FUZZ_AUX: No aux_data for arg[%u] (mask=0x%02x)", 
                      instr->arg_index, arg_mask);
            continue;
        }
        
        RR_VERBOSE("FUZZ_AUX: Found aux_data for arg[%u] (mask=0x%02x), size=%u, kind=%d",
                  instr->arg_index, arg_mask, aux->size, aux->kind);
        
        // 根据命令类型执行变异
        switch (instr->cmd) {
            case FUZZ_CMD_MUTATE_AUX_BUFFER:
                mutate_aux_buffer(aux, instr);
                break;
                
            case FUZZ_CMD_FLIP_BITS:
                flip_bits(aux, instr);
                break;
                
            case FUZZ_CMD_TRUNCATE:
                truncate_data(aux, instr);
                break;
                
            case FUZZ_CMD_EXTEND:
                extend_data(aux, instr);
                break;
                
            case FUZZ_CMD_INTERESTING_VALUES:
                inject_interesting_values(aux, instr, syscall_nr);
                break;
            
            case FUZZ_CMD_LIGHT_MUTATION:
                mutate_light(aux, instr);
                break;
                
            default:
                RR_VERBOSE("FUZZ_AUX: Unknown command %d", instr->cmd);
                break;
        }
        
        g_fuzz_stats.total_mutations++;
    }
    
    RR_VERBOSE("FUZZ_AUX: Mutation complete");
}


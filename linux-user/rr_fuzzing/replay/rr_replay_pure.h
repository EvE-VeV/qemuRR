/**
 * RR-Fuzz 纯确定性重放模块头文件
 * Pure Deterministic Replay - EnvFuzz 风格
 */

#ifndef RR_REPLAY_PURE_H
#define RR_REPLAY_PURE_H

#include "qemu/osdep.h"
#include "user/abitypes.h"
#include "cpu.h"
#include "../core/rr_framework.h"

/**
 * 纯确定性重放单个系统调用
 * 
 * @param env CPU 环境
 * @param num 系统调用号
 * @param args 系统调用参数（未修改的原始参数）
 * @param record trace 记录
 * @return 成功返回 syscall 返回值，失败返回 -1（需要回退到 hybrid）
 */
abi_long rr_replay_syscall_pure(CPUArchState *env, int num, abi_long *args,
                                syscall_record_t *record);

/**
 * 检查系统调用是否支持纯重放
 * 
 * @param syscall_nr 系统调用号
 * @return 支持返回 true，否则返回 false
 */
bool rr_replay_pure_supported(int syscall_nr);

/**
 * 打印纯重放统计信息
 */
void rr_replay_pure_print_stats(void);

/* ━━━━ Phase 1: Pure Replay + Fuzzing 集成 ━━━━ */

/**
 * 重新应用 Pure Replay（在 aux_data 变异后）
 * 
 * 此函数在 aux_data 被 Fuzzing 变异后调用，
 * 将变异后的数据重新恢复到 guest 内存中
 * 
 * @param env CPU 环境
 * @param num 系统调用号
 * @param args 系统调用参数
 * @param record trace 记录（包含已变异的 aux_data）
 * @return 成功返回 syscall 返回值，失败返回 -1
 */
abi_long rr_replay_syscall_pure_reapply(CPUArchState *env, int num, 
                                        abi_long *args,
                                        syscall_record_t *record);

#endif /* RR_REPLAY_PURE_H */


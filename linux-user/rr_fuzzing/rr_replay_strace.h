/**
 * RR-Fuzz Strace重放模块头文件
 * 基于strace格式文件的智能重放接口
 */

#ifndef RR_REPLAY_STRACE_H
#define RR_REPLAY_STRACE_H

#include <stdint.h>
#include <stdbool.h>

/* Forward declarations for QEMU types */
#include "qemu/osdep.h"
#include "user/abitypes.h"
#include "cpu.h"

/* ==================== 核心API ==================== */

/**
 * 初始化strace重放模块
 * @param trace_file strace格式的trace文件路径
 * @return 成功返回0，失败返回-1
 */
int rr_strace_replay_init(const char *trace_file);

/**
 * 清理strace重放模块
 */
void rr_strace_replay_cleanup(void);

/**
 * 输出详细的重放统计信息
 */
void rr_strace_replay_print_stats(void);


/**
 * 将统计信息输出到文件
 */
void rr_strace_save_stats_to_file(const char *filename);

/**
 * 设置重放模式
 */
void rr_strace_set_pure_replay_mode(bool enabled);

/**
 * strace重放的主要系统调用处理函数
 * 这个函数可以替代原有的 rr_replay_syscall
 * @param env CPU架构状态
 * @param num 系统调用号
 * @param args 系统调用参数数组
 * @return 系统调用返回值，-1表示让系统执行原始调用
 */
abi_long rr_replay_syscall_strace(CPUArchState *env, int num, abi_long *args);

/**
 * 检查strace重放是否已启用
 * @return true表示已启用，false表示未启用
 */
bool rr_strace_replay_enabled(void);

/**
 * 系统调用执行后的hook（用于输出句柄映射）
 * @param env CPU架构状态
 * @param num 系统调用号
 * @param ret 系统调用返回值
 * @param args 系统调用参数数组
 */
void rr_strace_syscall_post_hook(CPUArchState *env, int num, abi_long ret, abi_long *args);

/**
 * 优化版系统调用执行后的hook（用于FD映射和返回值处理）
 * @param env CPU架构状态
 * @param num 系统调用号
 * @param ret 系统调用返回值
 * @param args 系统调用参数数组
 */
void rr_strace_syscall_post_hook_optimized(CPUArchState *env, int num, abi_long ret, abi_long *args);

/* ==================== 配置接口 ==================== */

/**
 * 设置strace重放模式
 * @param strict_mode 是否启用严格模式（精确匹配参数）
 * @param skip_unmatched 是否跳过不匹配的系统调用
 * @param max_lookahead 最大前瞻匹配数量
 */
void rr_strace_set_mode(bool strict_mode, bool skip_unmatched, int max_lookahead);

/* ==================== 统计和调试接口 ==================== */

/**
 * 获取strace重放统计信息
 * @param total 总系统调用数（可选，传NULL忽略）
 * @param matched 匹配的系统调用数（可选，传NULL忽略）
 * @param skipped 跳过的系统调用数（可选，传NULL忽略）
 * @param errors 错误的系统调用数（可选，传NULL忽略）
 */
void rr_strace_get_replay_stats(uint64_t *total, uint64_t *matched, 
                               uint64_t *skipped, uint64_t *errors);

/**
 * 打印当前strace重放状态（用于调试）
 */
void rr_strace_print_status(void);

/* ==================== 常量定义 ==================== */

/* strace重放模式常量 */
#define RR_STRACE_MODE_STRICT       1   /* 严格模式 */
#define RR_STRACE_MODE_LOOSE        0   /* 宽松模式 */
#define RR_STRACE_SKIP_UNMATCHED    1   /* 跳过不匹配 */
#define RR_STRACE_NO_SKIP           0   /* 不跳过 */
#define RR_STRACE_DEFAULT_LOOKAHEAD 5   /* 默认前瞻数量 */

#endif /* RR_REPLAY_STRACE_H */

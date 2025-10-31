/**
 * RR-Fuzz Coverage Tracking Module
 * 
 * 实现AFL风格的边覆盖率追踪
 * 
 * 核心设计：
 * 1. 使用共享内存存储coverage bitmap
 * 2. 在TCG中计算边哈希：(prev_pc >> 1) ^ cur_pc
 * 3. 更新bitmap计数器
 * 4. 支持Python端读取和分析
 * 
 * Phase 3: Coverage反馈与自我进化
 */

#ifndef RR_COVERAGE_H
#define RR_COVERAGE_H

#include "qemu/osdep.h"
#include <stdint.h>
#include <stdbool.h>

/* ================= 配置常量 ================= */

#define RR_COVERAGE_MAP_SIZE (64 * 1024)   // 64KB bitmap
#define RR_COVERAGE_SHM_NAME "rr_coverage" // 共享内存名称

/* ================= 数据结构 ================= */

/**
 * Coverage上下文
 */
typedef struct {
    bool enabled;                    // 是否启用coverage追踪
    uint8_t *coverage_map;          // Coverage bitmap (共享内存)
    int shm_fd;                     // 共享内存文件描述符
    uint64_t prev_pc;               // 前一个PC（用于计算边）
    
    /* 统计信息 */
    uint64_t total_edges;           // 总边数
    uint64_t unique_edges;          // 唯一边数
} rr_coverage_t;

/* ================= 全局变量 ================= */

extern rr_coverage_t *g_coverage;

/* ================= 核心函数 ================= */

/**
 * 初始化Coverage模块
 * 
 * @param shm_name 共享内存名称（如果为NULL则使用默认名称）
 * @return 0成功，-1失败
 */
int rr_coverage_init(const char *shm_name);

/**
 * 清理Coverage模块
 */
void rr_coverage_cleanup(void);

/**
 * 记录代码边执行
 * 
 * 这是核心函数，在每个TB执行时调用
 * 实现AFL风格的边哈希：(prev_pc >> 1) ^ cur_pc
 * 
 * @param cur_pc 当前程序计数器
 */
void rr_coverage_trace_edge(uint64_t cur_pc);

/**
 * 启用/禁用coverage追踪
 * 
 * @param enabled 是否启用
 */
void rr_coverage_set_enabled(bool enabled);

/**
 * 检查coverage追踪是否启用（内联版本）
 * 
 * @return true启用，false禁用
 */
static inline bool rr_coverage_is_enabled(void)
{
    return g_coverage && g_coverage->enabled && g_coverage->coverage_map;
}

/**
 * 检查coverage追踪是否启用（非内联版本，供外部使用）
 * 
 * @return true启用，false禁用
 */
bool rr_coverage_is_enabled_check(void);

/**
 * 重置coverage map
 * 
 * 用于开始新一轮fuzzing时清空之前的覆盖率数据
 */
void rr_coverage_reset(void);

/**
 * 获取coverage统计信息
 * 
 * @param total_edges 输出：总边数
 * @param unique_edges 输出：唯一边数
 */
void rr_coverage_get_stats(uint64_t *total_edges, uint64_t *unique_edges);

/**
 * 打印coverage统计信息
 */
void rr_coverage_print_stats(void);

/**
 * 检查是否发现新的覆盖率
 * 
 * @param baseline_map 基线bitmap（用于对比）
 * @return true如果有新边，false如果没有
 */
bool rr_coverage_has_new_edges(const uint8_t *baseline_map);

/**
 * 复制当前coverage map
 * 
 * @param dest 目标缓冲区（必须至少RR_COVERAGE_MAP_SIZE字节）
 */
void rr_coverage_copy_map(uint8_t *dest);

#endif /* RR_COVERAGE_H */

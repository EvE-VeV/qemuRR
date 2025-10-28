/**
 * RR-Fuzz Phase 3: Coverage Tracking
 * 
 * 覆盖率追踪接口，用于引导式 Fuzzing
 * 
 * 设计参考：
 * - AFL 的边覆盖（edge coverage）
 * - QEMU TCG 基本块执行追踪
 * 
 * TODO: 完整实现需要 hook 到 QEMU TCG 层
 */

#ifndef RR_COVERAGE_H
#define RR_COVERAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ==================== 配置参数 ==================== */

#define RR_COVERAGE_BITMAP_SIZE  (64 * 1024)  // 64KB bitmap (AFL standard)
#define RR_COVERAGE_HASH_SEED    0x12345678   // 边哈希种子

/* ==================== 数据结构 ==================== */

/**
 * 覆盖率追踪器
 */
typedef struct {
    uint8_t *edge_bitmap;       // 边覆盖 bitmap
    size_t bitmap_size;         // Bitmap 大小
    
    uint64_t total_edges;       // 总边数（累计）
    uint64_t unique_edges;      // 唯一边数
    
    uint64_t prev_pc;           // 上一个 PC（用于边计算）
    
    bool enabled;               // 是否启用
} rr_coverage_t;

/* ==================== 全局变量 ==================== */

extern rr_coverage_t *g_rr_coverage;

/* ==================== API 函数 ==================== */

/**
 * 初始化覆盖率追踪
 * 
 * Returns:
 *   0 on success, -1 on error
 */
int rr_coverage_init(void);

/**
 * 清理覆盖率追踪
 */
void rr_coverage_cleanup(void);

/**
 * 重置覆盖率数据（新的 Fuzzing 迭代）
 */
void rr_coverage_reset(void);

/**
 * 更新覆盖率（在基本块执行时调用）
 * 
 * 注意：此函数应由 QEMU TCG 层调用
 * 
 * Args:
 *   from_pc: 源基本块 PC
 *   to_pc:   目标基本块 PC
 */
void rr_coverage_update(uint64_t from_pc, uint64_t to_pc);

/**
 * 检查是否有新的覆盖率
 * 
 * Returns:
 *   true if new edges were discovered
 */
bool rr_coverage_is_new(void);

/**
 * 获取当前覆盖率统计
 * 
 * Args:
 *   total_out:  输出总边数
 *   unique_out: 输出唯一边数
 */
void rr_coverage_get_stats(uint64_t *total_out, uint64_t *unique_out);

/**
 * 保存覆盖率 bitmap 到文件（用于分析）
 * 
 * Args:
 *   filename: 输出文件名
 * 
 * Returns:
 *   0 on success, -1 on error
 */
int rr_coverage_save_bitmap(const char *filename);

#endif /* RR_COVERAGE_H */


/**
 * RR-Fuzz Phase 3: Coverage Tracking Implementation
 * 
 * 基础覆盖率追踪实现
 * 
 * 当前状态：框架就绪，等待 QEMU TCG 集成
 * 
 * TODO Phase 3 完整实现：
 * 1. Hook 到 QEMU TCG 的 gen_tb_start/end
 * 2. 在翻译块执行时调用 rr_coverage_update
 * 3. 集成到 fuzz_conductor.py 的反馈循环
 */

#include "rr_coverage.h"
#include "../core/rr_framework.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ==================== 全局变量 ==================== */

rr_coverage_t *g_rr_coverage = NULL;

/* ==================== 内部函数 ==================== */

/**
 * 计算边哈希
 */
static inline uint64_t edge_hash(uint64_t from_pc, uint64_t to_pc) {
    // AFL-style edge hash: (from_pc >> 1) ^ to_pc
    return ((from_pc >> 1) ^ to_pc) % RR_COVERAGE_BITMAP_SIZE;
}

/* ==================== API 实现 ==================== */

int rr_coverage_init(void) {
    if (g_rr_coverage) {
        RR_WARN("Coverage tracking already initialized");
        return 0;
    }
    
    g_rr_coverage = malloc(sizeof(rr_coverage_t));
    if (!g_rr_coverage) {
        RR_ERROR("Failed to allocate coverage tracker");
        return -1;
    }
    
    g_rr_coverage->bitmap_size = RR_COVERAGE_BITMAP_SIZE;
    g_rr_coverage->edge_bitmap = calloc(g_rr_coverage->bitmap_size, 1);
    
    if (!g_rr_coverage->edge_bitmap) {
        RR_ERROR("Failed to allocate coverage bitmap");
        free(g_rr_coverage);
        g_rr_coverage = NULL;
        return -1;
    }
    
    g_rr_coverage->total_edges = 0;
    g_rr_coverage->unique_edges = 0;
    g_rr_coverage->prev_pc = 0;
    g_rr_coverage->enabled = false;  // 默认禁用，Fuzzing 模式时启用
    
    RR_INFO("Coverage tracking initialized (bitmap_size=%zu bytes)", 
            g_rr_coverage->bitmap_size);
    
    return 0;
}

void rr_coverage_cleanup(void) {
    if (!g_rr_coverage) {
        return;
    }
    
    if (g_rr_coverage->edge_bitmap) {
        free(g_rr_coverage->edge_bitmap);
    }
    
    free(g_rr_coverage);
    g_rr_coverage = NULL;
    
    RR_INFO("Coverage tracking cleaned up");
}

void rr_coverage_reset(void) {
    if (!g_rr_coverage || !g_rr_coverage->edge_bitmap) {
        return;
    }
    
    // 清空 bitmap
    memset(g_rr_coverage->edge_bitmap, 0, g_rr_coverage->bitmap_size);
    
    g_rr_coverage->total_edges = 0;
    g_rr_coverage->unique_edges = 0;
    g_rr_coverage->prev_pc = 0;
    
    RR_VERBOSE("Coverage reset for new iteration");
}

void rr_coverage_update(uint64_t from_pc, uint64_t to_pc) {
    if (!g_rr_coverage || !g_rr_coverage->enabled) {
        return;
    }
    
    // 计算边索引
    uint64_t idx = edge_hash(from_pc, to_pc);
    
    // 更新 bitmap
    if (g_rr_coverage->edge_bitmap[idx] == 0) {
        // 新边
        g_rr_coverage->unique_edges++;
    }
    
    // 增加命中计数（饱和计数，最大 255）
    if (g_rr_coverage->edge_bitmap[idx] < 255) {
        g_rr_coverage->edge_bitmap[idx]++;
    }
    
    g_rr_coverage->total_edges++;
    g_rr_coverage->prev_pc = to_pc;
}

bool rr_coverage_is_new(void) {
    if (!g_rr_coverage) {
        return false;
    }
    
    // 简单实现：检查 unique_edges 是否增加
    // 更复杂的版本应该保存上一次的 snapshot 并比较
    static uint64_t last_unique = 0;
    
    if (g_rr_coverage->unique_edges > last_unique) {
        last_unique = g_rr_coverage->unique_edges;
        return true;
    }
    
    return false;
}

void rr_coverage_get_stats(uint64_t *total_out, uint64_t *unique_out) {
    if (!g_rr_coverage) {
        if (total_out) *total_out = 0;
        if (unique_out) *unique_out = 0;
        return;
    }
    
    if (total_out) *total_out = g_rr_coverage->total_edges;
    if (unique_out) *unique_out = g_rr_coverage->unique_edges;
}

int rr_coverage_save_bitmap(const char *filename) {
    if (!g_rr_coverage || !g_rr_coverage->edge_bitmap) {
        RR_ERROR("Coverage not initialized");
        return -1;
    }
    
    FILE *f = fopen(filename, "wb");
    if (!f) {
        RR_ERROR("Failed to open coverage file: %s", filename);
        return -1;
    }
    
    size_t written = fwrite(g_rr_coverage->edge_bitmap, 1, 
                           g_rr_coverage->bitmap_size, f);
    fclose(f);
    
    if (written != g_rr_coverage->bitmap_size) {
        RR_ERROR("Failed to write complete bitmap");
        return -1;
    }
    
    RR_INFO("Saved coverage bitmap to %s (%zu bytes, %lu unique edges)", 
            filename, written, g_rr_coverage->unique_edges);
    
    return 0;
}


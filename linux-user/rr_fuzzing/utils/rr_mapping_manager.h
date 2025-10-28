/**
 * 映射管理器 - 优化FD和地址映射的数据结构和算法
 */

#ifndef RR_MAPPING_MANAGER_H
#define RR_MAPPING_MANAGER_H

#include "../core/rr_framework.h"
#include <stdint.h>
#include <stdbool.h>

/* ==================== FD映射管理 ==================== */

typedef struct rr_fd_mapping {
    int recorded_fd;
    int actual_fd;
    uint64_t timestamp;  // 用于LRU淘汰
    struct rr_fd_mapping *next;
} rr_fd_mapping_t;

typedef struct {
    rr_fd_mapping_t **buckets;
    size_t bucket_count;
    size_t total_mappings;
    uint64_t access_counter;
} rr_fd_mapping_table_t;

/* ==================== 地址映射管理 ==================== */

typedef struct rr_addr_mapping {
    target_ulong recorded_addr;
    target_ulong actual_addr;
    size_t size;
    uint64_t timestamp;
    struct rr_addr_mapping *next;
} rr_addr_mapping_t;

typedef struct {
    rr_addr_mapping_t **buckets;
    size_t bucket_count;
    size_t total_mappings;
    uint64_t access_counter;
} rr_addr_mapping_table_t;

/* ==================== 统计信息 ==================== */

typedef struct {
    uint64_t fd_lookups;
    uint64_t fd_hits;
    uint64_t fd_misses;
    uint64_t addr_lookups;
    uint64_t addr_hits;
    uint64_t addr_misses;
    uint64_t collisions;
    double avg_chain_length;
} rr_mapping_stats_t;

/* ==================== 公共接口 ==================== */

/* 注意: 核心接口已在 rr_framework.h 中声明，此处仅声明扩展功能 */

/* 扩展FD映射操作 */
bool rr_fd_mapping_exists(int recorded_fd);

/* 扩展地址映射操作 */
bool rr_addr_mapping_exists(target_ulong recorded_addr);

/* 批量操作 */
int rr_fd_mapping_add_batch(const int *recorded_fds, const int *actual_fds, size_t count);
int rr_addr_mapping_add_batch(const target_ulong *recorded_addrs, 
                             const target_ulong *actual_addrs, 
                             const size_t *sizes, size_t count);

/* 统计和调试 */
void rr_mapping_get_stats(rr_mapping_stats_t *stats);
void rr_mapping_print_stats(void);
void rr_mapping_reset_stats(void);

/* 内存管理优化 */
void rr_mapping_gc(void);  // 垃圾回收
void rr_mapping_rehash(void);  // 重新哈希

#endif /* RR_MAPPING_MANAGER_H */

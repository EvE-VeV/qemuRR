/**
 * 映射管理器实现 - 高效的FD和地址映射管理
 */

#include "rr_mapping_manager.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ==================== 全局变量 ==================== */

static rr_fd_mapping_table_t *g_fd_table = NULL;
static rr_addr_mapping_table_t *g_addr_table = NULL;
static rr_mapping_stats_t g_stats = {0};
static bool g_initialized = false;

/* ==================== 哈希函数 ==================== */

static inline size_t hash_fd(int fd, size_t bucket_count) {
    // 使用简单但有效的哈希函数
    return ((unsigned int)fd * 2654435761U) % bucket_count;
}

static inline size_t hash_addr(target_ulong addr, size_t bucket_count) {
    // 对地址进行哈希，考虑页对齐
    return ((addr >> 12) * 2654435761U) % bucket_count;
}

/* ==================== FD映射实现 ==================== */

static rr_fd_mapping_t* create_fd_mapping(int recorded_fd, int actual_fd) {
    rr_fd_mapping_t *mapping = malloc(sizeof(rr_fd_mapping_t));
    if (!mapping) return NULL;
    
    mapping->recorded_fd = recorded_fd;
    mapping->actual_fd = actual_fd;
    mapping->timestamp = ++g_fd_table->access_counter;
    mapping->next = NULL;
    return mapping;
}

static void free_fd_mapping(rr_fd_mapping_t *mapping) {
    if (mapping) {
        free(mapping);
    }
}

/**
 * @brief 添加一个新的 FD 映射记录
 * 
 * 在 Replay/Fuzzing 模式下，当 guest 程序执行 open/dup/socket 等创建 FD 的系统调用后，
 * 实际获得的 FD (actual_fd) 可能与 trace 中记录的 FD (recorded_fd) 不同。
 * 该函数负责记录这种对应关系，供后续系统调用使用。
 * 
 * **使用场景**:
 * - open/openat: 记录 open 返回的新 FD
 * - dup/dup2/dup3: 记录复制后的 FD
 * - socket/accept: 记录网络 socket FD
 * 
 * @param recorded_fd Trace 中记录的 FD (record 阶段的值)
 * @param actual_fd Replay 阶段实际获得的 FD
 * 
 * @return int 
 *         - 0: 添加成功 (新建或更新)
 *         - -1: 添加失败 (内存分配错误或未初始化)
 * 
 * @note 如果映射已存在，会更新 actual_fd 和访问时间戳
 * @note 使用哈希表存储，查找复杂度为 O(1)
 * @note 这是一个高频调用函数，性能至关重要
 */
int rr_fd_mapping_add(int recorded_fd, int actual_fd) {
    if (!g_initialized || !g_fd_table) return -1;
    
    size_t bucket = hash_fd(recorded_fd, g_fd_table->bucket_count);
    
    // 检查是否已存在
    rr_fd_mapping_t *current = g_fd_table->buckets[bucket];
    while (current) {
        if (current->recorded_fd == recorded_fd) {
            // 更新现有映射
            current->actual_fd = actual_fd;
            current->timestamp = ++g_fd_table->access_counter;
            return 0;
        }
        current = current->next;
    }
    
    // 创建新映射
    rr_fd_mapping_t *new_mapping = create_fd_mapping(recorded_fd, actual_fd);
    if (!new_mapping) return -1;
    
    // 插入到链表头部
    new_mapping->next = g_fd_table->buckets[bucket];
    g_fd_table->buckets[bucket] = new_mapping;
    g_fd_table->total_mappings++;
    
    return 0;
}

/**
 * @brief 查找 FD 映射 - 获取当前实际的 FD
 * 
 * 当 guest 程序尝试使用一个 FD (如 read/write/close) 时，需要将 trace 中的
 * recorded_fd 转换为当前有效的 actual_fd。
 * 
 * @param recorded_fd Trace 中记录的 FD
 * 
 * @return int
 *         - 如果找到映射: 返回对应的 actual_fd
 *         - 如果未找到: 返回原 recorded_fd (假设一致)
 * 
 * @note 会更新统计信息 (lookups, hits, misses) 和访问时间戳 (LRU)
 * @note 如果未初始化，直接返回 recorded_fd
 * 
 * @warning 调用者应处理返回的 FD 可能无效的情况 (虽然在 replay 中通常是有效的)
 */
int rr_fd_mapping_get(int recorded_fd) {
    if (!g_initialized || !g_fd_table) return recorded_fd;
    
    g_stats.fd_lookups++;
    
    size_t bucket = hash_fd(recorded_fd, g_fd_table->bucket_count);
    rr_fd_mapping_t *current = g_fd_table->buckets[bucket];
    
    while (current) {
        if (current->recorded_fd == recorded_fd) {
            current->timestamp = ++g_fd_table->access_counter;
            g_stats.fd_hits++;
            return current->actual_fd;
        }
        current = current->next;
    }
    
    g_stats.fd_misses++;
    return recorded_fd;  // 未找到映射，返回原值
}

int rr_fd_mapping_remove(int recorded_fd) {
    if (!g_initialized || !g_fd_table) return -1;
    
    size_t bucket = hash_fd(recorded_fd, g_fd_table->bucket_count);
    rr_fd_mapping_t **current = &g_fd_table->buckets[bucket];
    
    while (*current) {
        if ((*current)->recorded_fd == recorded_fd) {
            rr_fd_mapping_t *to_remove = *current;
            *current = (*current)->next;
            free_fd_mapping(to_remove);
            g_fd_table->total_mappings--;
            return 0;
        }
        current = &(*current)->next;
    }
    
    return -1;  // 未找到
}

bool rr_fd_mapping_exists(int recorded_fd) {
    if (!g_initialized || !g_fd_table) return false;
    
    size_t bucket = hash_fd(recorded_fd, g_fd_table->bucket_count);
    rr_fd_mapping_t *current = g_fd_table->buckets[bucket];
    
    while (current) {
        if (current->recorded_fd == recorded_fd) {
            return true;
        }
        current = current->next;
    }
    
    return false;
}

/* ==================== 地址映射实现 ==================== */

static rr_addr_mapping_t* create_addr_mapping(target_ulong recorded_addr, 
                                             target_ulong actual_addr, size_t size) {
    rr_addr_mapping_t *mapping = malloc(sizeof(rr_addr_mapping_t));
    if (!mapping) return NULL;
    
    mapping->recorded_addr = recorded_addr;
    mapping->actual_addr = actual_addr;
    mapping->size = size;
    mapping->timestamp = ++g_addr_table->access_counter;
    mapping->next = NULL;
    return mapping;
}

static void free_addr_mapping(rr_addr_mapping_t *mapping) {
    if (mapping) {
        free(mapping);
    }
}

/**
 * @brief 添加一个新的地址映射记录
 * 
 * 类似于 FD 映射，由于 ASLR (地址空间布局随机化)，mmap/brk 等返回的内存地址
 * 在 Replay 阶段通常与 Record 阶段不同。该函数记录这种地址偏差。
 * 
 * @param recorded_addr Trace 中记录的内存地址
 * @param actual_addr Replay 阶段实际获得的内存地址
 * @param size 内存区域的大小 (字节)
 * 
 * @return int
 *         - 0: 添加成功
 *         - -1: 添加失败
 * 
 * @note 地址映射通常用于 mmap, mremap, shmat 等系统调用
 * @note 需要记录 size 以便支持范围查询 (Range Query)
 */
int rr_addr_mapping_add(target_ulong recorded_addr, target_ulong actual_addr, size_t size) {
    if (!g_initialized || !g_addr_table) return -1;
    
    size_t bucket = hash_addr(recorded_addr, g_addr_table->bucket_count);
    
    // 检查是否已存在
    rr_addr_mapping_t *current = g_addr_table->buckets[bucket];
    while (current) {
        if (current->recorded_addr == recorded_addr) {
            // 更新现有映射
            current->actual_addr = actual_addr;
            current->size = size;
            current->timestamp = ++g_addr_table->access_counter;
            return 0;
        }
        current = current->next;
    }
    
    // 创建新映射
    rr_addr_mapping_t *new_mapping = create_addr_mapping(recorded_addr, actual_addr, size);
    if (!new_mapping) return -1;
    
    // 插入到链表头部
    new_mapping->next = g_addr_table->buckets[bucket];
    g_addr_table->buckets[bucket] = new_mapping;
    g_addr_table->total_mappings++;
    
    return 0;
}

/**
 * @brief 查找地址映射 - 支持精确匹配和范围匹配
 * 
 * 将 trace 中的 recorded_addr 转换为 replay 阶段的 actual_addr。
 * 
 * **查询策略**:
 * 1. **精确匹配** (Fast Path): 哈希查找 O(1)。适用于 munmap(base_addr) 等操作。
 * 2. **范围匹配** (Slow Path): 遍历所有映射 O(N)。适用于 munmap(base + offset) 
 *    或指针算术操作访问映射内存内部的情况。
 * 
 * @param recorded_addr Trace 中记录的地址
 * 
 * @return target_ulong
 *         - 映射后的实际地址 (mapped_base + offset)
 *         - 如果未找到，返回原 recorded_addr
 * 
 * @note 范围匹配用于处理 "指向映射区域内部的指针"
 * @note 范围匹配有性能开销，应尽量优化或减少使用
 * @warning 范围匹配目前使用简单的线性遍历，映射数量多时可能会慢
 */
target_ulong rr_addr_mapping_get(target_ulong recorded_addr) {
    if (!g_initialized || !g_addr_table) return recorded_addr;
    
    g_stats.addr_lookups++;
    
    // 首先尝试精确匹配（快速路径）
    size_t bucket = hash_addr(recorded_addr, g_addr_table->bucket_count);
    rr_addr_mapping_t *current = g_addr_table->buckets[bucket];
    
    while (current) {
        if (current->recorded_addr == recorded_addr) {
            current->timestamp = ++g_addr_table->access_counter;
            g_stats.addr_hits++;
            return current->actual_addr;
        }
        current = current->next;
    }
    
    // 精确匹配失败，尝试范围查询（慢速路径）
    // 遍历所有bucket查找包含此地址的映射
    for (size_t i = 0; i < g_addr_table->bucket_count; i++) {
        current = g_addr_table->buckets[i];
        while (current) {
            target_ulong range_start = current->recorded_addr;
            target_ulong range_end = current->recorded_addr + current->size;
            
            if (recorded_addr >= range_start && recorded_addr < range_end) {
                // 找到包含此地址的映射，计算偏移
                target_ulong offset = recorded_addr - range_start;
                target_ulong mapped_addr = current->actual_addr + offset;
                
                current->timestamp = ++g_addr_table->access_counter;
                g_stats.addr_hits++;
                
                fprintf(stderr, "[ADDR-RANGE-MAPPING] addr=0x%lx in range [0x%lx-0x%lx], offset=0x%lx, mapped=0x%lx\n",
                        (unsigned long)recorded_addr,
                        (unsigned long)range_start, (unsigned long)range_end,
                        (unsigned long)offset, (unsigned long)mapped_addr);
                
                return mapped_addr;
            }
            current = current->next;
        }
    }
    
    g_stats.addr_misses++;
    return recorded_addr;  // 未找到映射，返回原值
}

int rr_addr_mapping_remove(target_ulong recorded_addr) {
    if (!g_initialized || !g_addr_table) return -1;
    
    size_t bucket = hash_addr(recorded_addr, g_addr_table->bucket_count);
    rr_addr_mapping_t **current = &g_addr_table->buckets[bucket];
    
    while (*current) {
        if ((*current)->recorded_addr == recorded_addr) {
            rr_addr_mapping_t *to_remove = *current;
            *current = (*current)->next;
            free_addr_mapping(to_remove);
            g_addr_table->total_mappings--;
            return 0;
        }
        current = &(*current)->next;
    }
    
    return -1;  // 未找到
}

bool rr_addr_mapping_exists(target_ulong recorded_addr) {
    if (!g_initialized || !g_addr_table) return false;
    
    size_t bucket = hash_addr(recorded_addr, g_addr_table->bucket_count);
    rr_addr_mapping_t *current = g_addr_table->buckets[bucket];
    
    while (current) {
        if (current->recorded_addr == recorded_addr) {
            return true;
        }
        current = current->next;
    }
    
    return false;
}

/* ==================== 批量操作 ==================== */

int rr_fd_mapping_add_batch(const int *recorded_fds, const int *actual_fds, size_t count) {
    if (!recorded_fds || !actual_fds || count == 0) return -1;
    
    int success_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (rr_fd_mapping_add(recorded_fds[i], actual_fds[i]) == 0) {
            success_count++;
        }
    }
    
    return success_count;
}

int rr_addr_mapping_add_batch(const target_ulong *recorded_addrs, 
                             const target_ulong *actual_addrs, 
                             const size_t *sizes, size_t count) {
    if (!recorded_addrs || !actual_addrs || !sizes || count == 0) return -1;
    
    int success_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (rr_addr_mapping_add(recorded_addrs[i], actual_addrs[i], sizes[i]) == 0) {
            success_count++;
        }
    }
    
    return success_count;
}

/* ==================== 初始化和清理 ==================== */

int rr_mapping_manager_init(size_t fd_buckets, size_t addr_buckets) {
    if (g_initialized) {
        return 0;  // 已经初始化
    }
    
    // 初始化FD映射表
    g_fd_table = malloc(sizeof(rr_fd_mapping_table_t));
    if (!g_fd_table) return -1;
    
    g_fd_table->bucket_count = fd_buckets > 0 ? fd_buckets : 256;
    g_fd_table->buckets = calloc(g_fd_table->bucket_count, sizeof(rr_fd_mapping_t*));
    if (!g_fd_table->buckets) {
        free(g_fd_table);
        return -1;
    }
    g_fd_table->total_mappings = 0;
    g_fd_table->access_counter = 0;
    
    // 初始化地址映射表
    g_addr_table = malloc(sizeof(rr_addr_mapping_table_t));
    if (!g_addr_table) {
        free(g_fd_table->buckets);
        free(g_fd_table);
        return -1;
    }
    
    g_addr_table->bucket_count = addr_buckets > 0 ? addr_buckets : 128;
    g_addr_table->buckets = calloc(g_addr_table->bucket_count, sizeof(rr_addr_mapping_t*));
    if (!g_addr_table->buckets) {
        free(g_fd_table->buckets);
        free(g_fd_table);
        free(g_addr_table);
        return -1;
    }
    g_addr_table->total_mappings = 0;
    g_addr_table->access_counter = 0;
    
    // 重置统计信息
    memset(&g_stats, 0, sizeof(g_stats));
    
    g_initialized = true;
    return 0;
}

void rr_mapping_manager_cleanup(void) {
    if (!g_initialized) return;
    
    // 清理FD映射表
    if (g_fd_table) {
        for (size_t i = 0; i < g_fd_table->bucket_count; i++) {
            rr_fd_mapping_t *current = g_fd_table->buckets[i];
            while (current) {
                rr_fd_mapping_t *next = current->next;
                free_fd_mapping(current);
                current = next;
            }
        }
        free(g_fd_table->buckets);
        free(g_fd_table);
        g_fd_table = NULL;
    }
    
    // 清理地址映射表
    if (g_addr_table) {
        for (size_t i = 0; i < g_addr_table->bucket_count; i++) {
            rr_addr_mapping_t *current = g_addr_table->buckets[i];
            while (current) {
                rr_addr_mapping_t *next = current->next;
                free_addr_mapping(current);
                current = next;
            }
        }
        free(g_addr_table->buckets);
        free(g_addr_table);
        g_addr_table = NULL;
    }
    
    g_initialized = false;
}

/* ==================== 统计和调试 ==================== */

void rr_mapping_get_stats(rr_mapping_stats_t *stats) {
    if (!stats) return;
    
    *stats = g_stats;
    
    // 计算平均链长度
    if (g_fd_table && g_addr_table) {
        size_t total_chains = 0;
        size_t total_length = 0;
        
        // FD表链长度
        for (size_t i = 0; i < g_fd_table->bucket_count; i++) {
            size_t chain_length = 0;
            rr_fd_mapping_t *current = g_fd_table->buckets[i];
            while (current) {
                chain_length++;
                current = current->next;
            }
            if (chain_length > 0) {
                total_chains++;
                total_length += chain_length;
            }
        }
        
        // 地址表链长度
        for (size_t i = 0; i < g_addr_table->bucket_count; i++) {
            size_t chain_length = 0;
            rr_addr_mapping_t *current = g_addr_table->buckets[i];
            while (current) {
                chain_length++;
                current = current->next;
            }
            if (chain_length > 0) {
                total_chains++;
                total_length += chain_length;
            }
        }
        
        stats->avg_chain_length = total_chains > 0 ? (double)total_length / total_chains : 0.0;
    }
}

void rr_mapping_print_stats(void) {
    rr_mapping_stats_t stats;
    rr_mapping_get_stats(&stats);
    
    printf("=== RR Mapping Manager Statistics ===\n");
    printf("FD Mappings:\n");
    printf("  Lookups: %lu, Hits: %lu, Misses: %lu\n", 
           stats.fd_lookups, stats.fd_hits, stats.fd_misses);
    printf("  Hit Rate: %.2f%%\n", 
           stats.fd_lookups > 0 ? (double)stats.fd_hits / stats.fd_lookups * 100.0 : 0.0);
    
    printf("Address Mappings:\n");
    printf("  Lookups: %lu, Hits: %lu, Misses: %lu\n", 
           stats.addr_lookups, stats.addr_hits, stats.addr_misses);
    printf("  Hit Rate: %.2f%%\n", 
           stats.addr_lookups > 0 ? (double)stats.addr_hits / stats.addr_lookups * 100.0 : 0.0);
    
    printf("Performance:\n");
    printf("  Average Chain Length: %.2f\n", stats.avg_chain_length);
    printf("  Total Mappings: FD=%zu, Addr=%zu\n", 
           g_fd_table ? g_fd_table->total_mappings : 0,
           g_addr_table ? g_addr_table->total_mappings : 0);
}

void rr_mapping_reset_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}

/* ==================== 内存管理优化 ==================== */

void rr_mapping_gc(void) {
    // TODO: 实现基于LRU的垃圾回收
    // 当映射数量过多时，清理最久未使用的映射
}

void rr_mapping_rehash(void) {
    // TODO: 实现动态重哈希
    // 当链长度过长时，增加桶数量并重新分布
}

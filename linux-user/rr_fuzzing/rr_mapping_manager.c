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

target_ulong rr_addr_mapping_get(target_ulong recorded_addr) {
    if (!g_initialized || !g_addr_table) return recorded_addr;
    
    g_stats.addr_lookups++;
    
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

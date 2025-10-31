/**
 * RR-Fuzz Coverage Tracking Module - Implementation
 * 
 * Phase 3: 实现AFL风格的覆盖率追踪
 */

#include "rr_coverage.h"
#include "../../core/rr_framework.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/* ================= 全局变量 ================= */

rr_coverage_t *g_coverage = NULL;

/* ================= 内部辅助函数 ================= */

/**
 * 创建共享内存
 */
static int create_shared_memory(const char *shm_name)
{
    char shm_path[256];
    snprintf(shm_path, sizeof(shm_path), "/dev/shm/%s_%d", shm_name, getpid());
    
    // 创建共享内存文件
    int fd = open(shm_path, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        RR_ERROR("Failed to create shared memory file '%s': %s (errno=%d)", 
                shm_path, strerror(errno), errno);
        return -1;
    }
    
    // 设置大小
    if (ftruncate(fd, RR_COVERAGE_MAP_SIZE) < 0) {
        RR_ERROR("Failed to resize shared memory: %s", strerror(errno));
        close(fd);
        unlink(shm_path);
        return -1;
    }
    
    // 映射到内存
    void *mem = mmap(NULL, RR_COVERAGE_MAP_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        RR_ERROR("Failed to mmap shared memory: %s", strerror(errno));
        close(fd);
        unlink(shm_path);
        return -1;
    }
    
    // 清零
    memset(mem, 0, RR_COVERAGE_MAP_SIZE);
    
    g_coverage->coverage_map = (uint8_t *)mem;
    g_coverage->shm_fd = fd;
    
    RR_INFO("Created coverage shared memory: %s (%d bytes)", 
            shm_path, RR_COVERAGE_MAP_SIZE);
    
    return 0;
}

/* ================= 核心函数实现 ================= */

int rr_coverage_init(const char *shm_name)
{
    if (g_coverage) {
        RR_WARN("Coverage already initialized");
        return 0;
    }
    
    // 分配上下文
    g_coverage = calloc(1, sizeof(rr_coverage_t));
    if (!g_coverage) {
        RR_ERROR("Failed to allocate coverage context");
        return -1;
    }
    
    // 使用默认名称
    if (!shm_name) {
        shm_name = RR_COVERAGE_SHM_NAME;
    }
    
    // 创建共享内存
    if (create_shared_memory(shm_name) < 0) {
        RR_ERROR("create_shared_memory() failed");
        free(g_coverage);
        g_coverage = NULL;
        return -1;
    }
    
    // 初始化状态
    g_coverage->enabled = true;
    g_coverage->prev_pc = 0;
    g_coverage->total_edges = 0;
    g_coverage->unique_edges = 0;
    
    RR_INFO("Coverage tracking initialized");
    
    return 0;
}

void rr_coverage_cleanup(void)
{
    if (!g_coverage) {
        return;
    }
    
    // 打印统计信息
    rr_coverage_print_stats();
    
    // 解除映射
    if (g_coverage->coverage_map) {
        munmap(g_coverage->coverage_map, RR_COVERAGE_MAP_SIZE);
        g_coverage->coverage_map = NULL;
    }
    
    // 关闭文件描述符
    if (g_coverage->shm_fd >= 0) {
        close(g_coverage->shm_fd);
        
        // 删除共享内存文件
        char shm_path[256];
        snprintf(shm_path, sizeof(shm_path), "/dev/shm/%s_%d", 
                RR_COVERAGE_SHM_NAME, getpid());
        unlink(shm_path);
    }
    
    free(g_coverage);
    g_coverage = NULL;
    
    RR_INFO("Coverage tracking cleanup completed");
}

void rr_coverage_trace_edge(uint64_t cur_pc)
{
    if (!rr_coverage_is_enabled()) {
        return;
    }
    
    // 计算AFL风格的边哈希
    // hash = (prev_pc >> 1) ^ cur_pc
    uint64_t edge_hash = (g_coverage->prev_pc >> 1) ^ cur_pc;
    
    // 映射到bitmap索引（取模）
    uint32_t idx = edge_hash % RR_COVERAGE_MAP_SIZE;
    
    // 获取当前计数
    uint8_t old_count = g_coverage->coverage_map[idx];
    
    // 更新计数（饱和加法，防止溢出）
    if (old_count < 255) {
        g_coverage->coverage_map[idx]++;
    }
    
    // 如果是新边，增加unique_edges计数
    if (old_count == 0) {
        g_coverage->unique_edges++;
    }
    
    // 更新总边数
    g_coverage->total_edges++;
    
    // 更新prev_pc为当前PC
    g_coverage->prev_pc = cur_pc;
}

void rr_coverage_set_enabled(bool enabled)
{
    if (g_coverage) {
        g_coverage->enabled = enabled;
        RR_INFO("Coverage tracking %s", enabled ? "enabled" : "disabled");
    }
}

void rr_coverage_reset(void)
{
    if (!g_coverage || !g_coverage->coverage_map) {
        return;
    }
    
    // 清零bitmap
    memset(g_coverage->coverage_map, 0, RR_COVERAGE_MAP_SIZE);
    
    // 重置统计
    g_coverage->prev_pc = 0;
    g_coverage->total_edges = 0;
    g_coverage->unique_edges = 0;
    
    RR_VERBOSE("Coverage map reset");
}

void rr_coverage_get_stats(uint64_t *total_edges, uint64_t *unique_edges)
{
    if (g_coverage) {
        if (total_edges) {
            *total_edges = g_coverage->total_edges;
        }
        if (unique_edges) {
            *unique_edges = g_coverage->unique_edges;
        }
    }
}

void rr_coverage_print_stats(void)
{
    if (!g_coverage) {
        return;
    }
    
    RR_INFO("=== Coverage Statistics ===");
    RR_INFO("  Total edges executed: %lu", g_coverage->total_edges);
    RR_INFO("  Unique edges found:   %lu", g_coverage->unique_edges);
    
    if (g_coverage->total_edges > 0) {
        RR_INFO("  Bitmap density:       %.2f%%", 
                (double)g_coverage->unique_edges * 100.0 / RR_COVERAGE_MAP_SIZE);
    }
}

bool rr_coverage_has_new_edges(const uint8_t *baseline_map)
{
    if (!g_coverage || !g_coverage->coverage_map || !baseline_map) {
        return false;
    }
    
    // 比较当前map和baseline
    for (size_t i = 0; i < RR_COVERAGE_MAP_SIZE; i++) {
        if (g_coverage->coverage_map[i] > 0 && baseline_map[i] == 0) {
            return true;  // 发现新边
        }
    }
    
    return false;
}

void rr_coverage_copy_map(uint8_t *dest)
{
    if (!g_coverage || !g_coverage->coverage_map || !dest) {
        return;
    }
    
    memcpy(dest, g_coverage->coverage_map, RR_COVERAGE_MAP_SIZE);
}

/* 非内联版本供cpu-exec.c使用 */
bool rr_coverage_is_enabled_check(void)
{
    return g_coverage && g_coverage->enabled && g_coverage->coverage_map;
}

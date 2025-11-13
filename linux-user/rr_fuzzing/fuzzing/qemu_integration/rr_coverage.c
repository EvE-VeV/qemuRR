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
 * 
 * 支持两种模式：
 * 1. AFL-style: 使用固定名称 (从环境变量RR_COVERAGE_SHM读取)
 * 2. Legacy: 使用PID后缀 (fallback)
 */
static int create_shared_memory(const char *shm_name)
{
    char shm_path[256];
    bool use_global_shm = false;
    bool file_backed = false;
    char file_backing_path[PATH_MAX] = {0};
    
    // ✅ NEW: Check for global shared memory name from environment
    const char *env_shm_name = getenv("RR_COVERAGE_SHM");
    if (env_shm_name && env_shm_name[0] != '\0') {
        if (strncmp(env_shm_name, "file:", 5) == 0) {
            file_backed = true;
            snprintf(file_backing_path, sizeof(file_backing_path), "%s", env_shm_name + 5);
            RR_INFO("Using file-backed coverage: %s", file_backing_path);
        } else {
            // AFL-style: Use fixed name without PID (shared across processes)
            snprintf(shm_path, sizeof(shm_path), "/dev/shm/%s", env_shm_name);
            use_global_shm = true;
            RR_INFO("Using global shared coverage: %s", shm_path);
        }
    } else {
        // Legacy: Use PID suffix (per-process)
        snprintf(shm_path, sizeof(shm_path), "/dev/shm/%s_%d", shm_name, getpid());
        RR_INFO("Using per-process coverage: %s", shm_path);
    }

    if (file_backed) {
        int fd = open(file_backing_path, O_CREAT | O_RDWR, 0666);
        if (fd < 0) {
            RR_ERROR("Failed to open file-backed coverage '%s': %s",
                    file_backing_path, strerror(errno));
            return -1;
        }
        
        if (ftruncate(fd, RR_COVERAGE_MAP_SIZE) < 0) {
            RR_ERROR("Failed to resize file-backed coverage '%s': %s",
                    file_backing_path, strerror(errno));
            close(fd);
            return -1;
        }
        
        void *mem = mmap(NULL, RR_COVERAGE_MAP_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
            RR_ERROR("Failed to mmap file-backed coverage '%s': %s",
                    file_backing_path, strerror(errno));
            close(fd);
            return -1;
        }
        
        memset(mem, 0, RR_COVERAGE_MAP_SIZE);
        g_coverage->coverage_map = (uint8_t *)mem;
        g_coverage->shm_fd = fd;
        g_coverage->file_backed = true;
        snprintf(g_coverage->backing_path, sizeof(g_coverage->backing_path),
                 "%s", file_backing_path);
        RR_INFO("✅ File-backed coverage ready: %s (%d bytes)",
                file_backing_path, RR_COVERAGE_MAP_SIZE);
        return 0;
    }
    
    // If global SHM, try to open existing first
    if (use_global_shm) {
        // Try to open existing shared memory
        int fd = open(shm_path, O_RDWR, 0666);
        if (fd >= 0) {
            // Existing shared memory found, just map it
            void *mem = mmap(NULL, RR_COVERAGE_MAP_SIZE, PROT_READ | PROT_WRITE,
                           MAP_SHARED, fd, 0);
            if (mem == MAP_FAILED) {
                RR_ERROR("Failed to mmap existing shared memory '%s': %s", 
                        shm_path, strerror(errno));
                close(fd);
                return -1;
            }
            
            g_coverage->coverage_map = (uint8_t *)mem;
            g_coverage->shm_fd = fd;
            
            RR_INFO("✅ Opened existing global coverage shared memory: %s (%d bytes)", 
                    shm_path, RR_COVERAGE_MAP_SIZE);
            return 0;
        }
        // If opening failed, we'll create it below
        RR_VERBOSE("Global shared memory doesn't exist yet, will create");
    }
    
    // Create new shared memory file
    int fd = open(shm_path, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        RR_ERROR("Failed to create shared memory file '%s': %s (errno=%d)", 
                shm_path, strerror(errno), errno);
        return -1;
    }
    
    // Set size
    if (ftruncate(fd, RR_COVERAGE_MAP_SIZE) < 0) {
        RR_ERROR("Failed to resize shared memory: %s", strerror(errno));
        close(fd);
        if (!use_global_shm) {
            unlink(shm_path);  // Only unlink per-process SHM
        }
        return -1;
    }
    
    // Map to memory
    void *mem = mmap(NULL, RR_COVERAGE_MAP_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        RR_ERROR("Failed to mmap shared memory: %s", strerror(errno));
        close(fd);
        if (!use_global_shm) {
            unlink(shm_path);  // Only unlink per-process SHM
        }
        return -1;
    }
    
    // Clear bitmap (only if we created it)
    memset(mem, 0, RR_COVERAGE_MAP_SIZE);
    
    g_coverage->coverage_map = (uint8_t *)mem;
    g_coverage->shm_fd = fd;
    
    RR_INFO("✅ Created coverage shared memory: %s (%d bytes)", 
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
        
        if (g_coverage->file_backed && g_coverage->backing_path[0] != '\0') {
            unlink(g_coverage->backing_path);
            RR_VERBOSE("Deleted file-backed coverage file: %s", g_coverage->backing_path);
        } else {
            // ✅ FIXED: Only delete per-process SHM files, NOT global shared memory
            const char *env_shm_name = getenv("RR_COVERAGE_SHM");
            if (!env_shm_name || env_shm_name[0] == '\0') {
                // Legacy per-process mode: delete the file
                char shm_path[256];
                snprintf(shm_path, sizeof(shm_path), "/dev/shm/%s_%d", 
                        RR_COVERAGE_SHM_NAME, getpid());
                unlink(shm_path);
                RR_VERBOSE("Deleted per-process coverage file: %s", shm_path);
            } else {
                // Global shared memory mode: DON'T delete (shared by all processes)
                RR_VERBOSE("Keeping global shared coverage (shared by all processes)");
            }
        }
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

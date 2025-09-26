/**
 * RR-Fuzz快照管理模块
 * 实现进程状态的保存和恢复，对应design.md中的状态树探索
 */

#include "rr_framework.h"
#include <sys/mman.h>

typedef struct rr_snapshot {
    uint32_t syscall_index;         // 快照保存时的系统调用索引
    size_t memory_size;             // 内存快照大小
    void *memory_data;              // 内存数据
    GHashTable *fd_map_snapshot;    // FD映射表快照
    struct rr_snapshot *next;       // 链表连接
} rr_snapshot_t;

static rr_snapshot_t *g_snapshots = NULL;
static rr_snapshot_t *g_current_snapshot = NULL;

/**
 * 创建FD映射表的快照
 */
static GHashTable *clone_fd_map(GHashTable *original)
{
    if (!original) {
        return NULL;
    }

    GHashTable *clone = g_hash_table_new(g_direct_hash, g_direct_equal);
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, original);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        g_hash_table_insert(clone, key, value);
    }

    return clone;
}

/**
 * 保存当前进程状态快照
 * 简化实现：只保存FD映射和基本状态
 */
int rr_snapshot_save(uint32_t syscall_index)
{
    RR_VERBOSE("Starting snapshot save at syscall index %u", syscall_index);

    if (!rr_framework_enabled()) {
        RR_ERROR("Cannot save snapshot: framework not enabled");
        return -1;
    }

    rr_snapshot_t *snapshot = g_malloc0(sizeof(rr_snapshot_t));
    snapshot->syscall_index = syscall_index;

    RR_VERBOSE("Cloning FD mapping table");
    /* 保存FD映射表快照 */
    snapshot->fd_map_snapshot = clone_fd_map(g_rr_framework->fd_map);
    if (snapshot->fd_map_snapshot) {
        RR_TRACE("FD map cloned: %d entries", g_hash_table_size(snapshot->fd_map_snapshot));
    }

    /* 简化的内存快照：在实际实现中，这里需要保存完整的进程内存状态
     * 但由于QEMU用户模式的复杂性，这里只做基本的状态保存 */
    snapshot->memory_size = 0;
    snapshot->memory_data = NULL;
    RR_TRACE("Memory snapshot: %zu bytes (simplified implementation)", snapshot->memory_size);

    /* 添加到快照链表 */
    snapshot->next = g_snapshots;
    g_snapshots = snapshot;

    RR_INFO("Snapshot saved at syscall index %u", syscall_index);
    return 0;
}

/**
 * 恢复到指定的快照状态
 */
int rr_snapshot_restore(uint32_t syscall_index)
{
    if (!rr_framework_enabled()) {
        return -1;
    }

    /* 查找匹配的快照 */
    rr_snapshot_t *snapshot = g_snapshots;
    while (snapshot) {
        if (snapshot->syscall_index == syscall_index) {
            break;
        }
        snapshot = snapshot->next;
    }

    if (!snapshot) {
        RR_LOG("Snapshot not found for syscall index %u", syscall_index);
        return -1;
    }

    /* 恢复FD映射表 */
    if (g_rr_framework->fd_map) {
        g_hash_table_destroy(g_rr_framework->fd_map);
    }
    g_rr_framework->fd_map = clone_fd_map(snapshot->fd_map_snapshot);

    /* 重置重放索引到快照点 */
    g_rr_framework->replay_index = syscall_index;

    g_current_snapshot = snapshot;

    RR_LOG("Snapshot restored to syscall index %u", syscall_index);
    return 0;
}

/**
 * 获取最近的快照点
 */
uint32_t rr_snapshot_get_latest(void)
{
    if (!g_snapshots) {
        return 0;
    }

    return g_snapshots->syscall_index;
}

/**
 * 列出所有可用的快照点
 */
int rr_snapshot_list(uint32_t *snapshots, size_t max_count)
{
    if (!snapshots || max_count == 0) {
        return 0;
    }

    int count = 0;
    rr_snapshot_t *snapshot = g_snapshots;

    while (snapshot && count < (int)max_count) {
        snapshots[count] = snapshot->syscall_index;
        count++;
        snapshot = snapshot->next;
    }

    return count;
}

/**
 * 智能快照策略
 * 在关键系统调用前自动保存快照
 */
bool rr_snapshot_should_save(int syscall_nr, uint32_t syscall_index)
{
    /* 在以下情况自动保存快照：
     * 1. 每隔一定数量的系统调用
     * 2. 关键系统调用前（如文件操作、网络操作）
     * 3. 可能产生分支的系统调用前
     */

    /* 每100个系统调用保存一次快照 */
    if (syscall_index % 100 == 0) {
        return true;
    }

    /* 在关键系统调用前保存快照 */
    switch (syscall_nr) {
#ifdef TARGET_NR_open
        case TARGET_NR_open:
#endif
        case TARGET_NR_openat:
        case TARGET_NR_socket:
#ifdef TARGET_NR_connect
        case TARGET_NR_connect:
#endif
#ifdef TARGET_NR_accept
        case TARGET_NR_accept:
#endif
        case TARGET_NR_execve:
#ifdef TARGET_NR_fork
        case TARGET_NR_fork:
#endif
#ifdef TARGET_NR_clone
        case TARGET_NR_clone:
#endif
            return true;
        default:
            break;
    }

    return false;
}

/**
 * 自动快照管理
 * 在重放过程中自动保存和管理快照
 */
void rr_snapshot_auto_manage(int syscall_nr, uint32_t syscall_index)
{
    if (g_rr_framework->mode != RR_MODE_FUZZING) {
        return;
    }

    if (rr_snapshot_should_save(syscall_nr, syscall_index)) {
        rr_snapshot_save(syscall_index);
    }

    /* 限制快照数量，删除过旧的快照 */
    const int MAX_SNAPSHOTS = 50;
    rr_snapshot_t *snapshot = g_snapshots;
    int count = 0;

    while (snapshot) {
        count++;
        if (count > MAX_SNAPSHOTS) {
            /* 删除过旧的快照 */
            rr_snapshot_t *to_delete = snapshot->next;
            while (to_delete) {
                rr_snapshot_t *next = to_delete->next;
                if (to_delete->fd_map_snapshot) {
                    g_hash_table_destroy(to_delete->fd_map_snapshot);
                }
                if (to_delete->memory_data) {
                    g_free(to_delete->memory_data);
                }
                g_free(to_delete);
                to_delete = next;
            }
            snapshot->next = NULL;
            break;
        }
        snapshot = snapshot->next;
    }
}

/**
 * 清理所有快照
 */
void rr_snapshot_cleanup(void)
{
    rr_snapshot_t *snapshot = g_snapshots;
    while (snapshot) {
        rr_snapshot_t *next = snapshot->next;

        if (snapshot->fd_map_snapshot) {
            g_hash_table_destroy(snapshot->fd_map_snapshot);
        }
        if (snapshot->memory_data) {
            g_free(snapshot->memory_data);
        }
        g_free(snapshot);

        snapshot = next;
    }

    g_snapshots = NULL;
    g_current_snapshot = NULL;
}
/**
 * RR Syscall Tree Builder - C Side Implementation
 *
 * High-performance syscall tree construction in C for zero IPC overhead.
 * Author: RR-Fuzz Team
 * Date: 2025-11-14
 */

#include "rr_syscall_tree.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

// 全局tree实例
RRSyscallTree g_syscall_tree = {0};

/**
 * 初始化syscall tree
 */
void rr_tree_init(void) {
    memset(&g_syscall_tree, 0, sizeof(RRSyscallTree));
    g_syscall_tree.enabled = true;
    g_syscall_tree.node_count = 0;
    g_syscall_tree.root_node_id = 0;
    g_syscall_tree.current_node_id = 0;
    g_syscall_tree.total_syscalls = 0;
    g_syscall_tree.total_forks = 0;

    // 初始化所有节点的parent_id为-1（无效值）
    for (uint32_t i = 0; i < MAX_TREE_NODES; i++) {
        g_syscall_tree.nodes[i].parent_id = (uint32_t)-1;
        g_syscall_tree.nodes[i].id = i;
    }
}

/**
 * 清理syscall tree
 */
void rr_tree_cleanup(void) {
    g_syscall_tree.enabled = false;
}

/**
 * 获取当前纳秒时间戳
 */
static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000UL + (uint64_t)ts.tv_nsec;
}

/**
 * 添加syscall节点到tree
 *
 * @return 新创建的节点ID
 */
uint32_t rr_tree_add_syscall_node(
    uint32_t pid,
    uint32_t syscall_index,
    uint32_t syscall_nr,
    const char *syscall_name,
    uint64_t *args,
    int64_t retval,
    uint64_t timestamp_enter,
    uint64_t timestamp_exit
) {
    if (!g_syscall_tree.enabled) {
        return 0;
    }

    // 检查节点池是否已满
    if (g_syscall_tree.node_count >= MAX_TREE_NODES) {
        fprintf(stderr, "[RR-Tree] ERROR: Tree node pool exhausted (max=%d)\n", MAX_TREE_NODES);
        return 0;
    }

    // 分配新节点
    uint32_t node_id = g_syscall_tree.node_count;
    TreeNode *node = &g_syscall_tree.nodes[node_id];

    // 基本信息
    node->id = node_id;
    node->pid = pid;
    node->syscall_index = syscall_index;
    node->syscall_nr = syscall_nr;
    strncpy(node->syscall_name, syscall_name ? syscall_name : "unknown", MAX_SYSCALL_NAME - 1);
    node->syscall_name[MAX_SYSCALL_NAME - 1] = '\0';

    // 参数和返回值
    if (args) {
        memcpy(node->args, args, sizeof(uint64_t) * 6);
    } else {
        memset(node->args, 0, sizeof(uint64_t) * 6);
    }
    node->retval = retval;

    // 时间戳
    node->timestamp_enter = timestamp_enter ? timestamp_enter : get_timestamp_ns();
    node->timestamp_exit = timestamp_exit ? timestamp_exit : node->timestamp_enter;

    // 树结构 - 链接到当前节点
    node->parent_id = g_syscall_tree.current_node_id;
    node->children_count = 0;
    node->is_fork_node = false;
    node->has_new_coverage = false;
    node->is_mutated = false;

    // 如果有父节点，添加到父节点的children列表
    if (node->parent_id != (uint32_t)-1 && node->parent_id < MAX_TREE_NODES) {
        TreeNode *parent = &g_syscall_tree.nodes[node->parent_id];
        if (parent->children_count < MAX_CHILDREN_PER_NODE) {
            parent->children_ids[parent->children_count++] = node_id;
        }
    }

    // 更新当前节点指针
    g_syscall_tree.current_node_id = node_id;
    g_syscall_tree.node_count++;
    g_syscall_tree.total_syscalls++;

    return node_id;
}

/**
 * 添加fork关系
 */
void rr_tree_add_fork_relation(
    uint32_t parent_node_id,
    uint32_t child_pid
) {
    if (!g_syscall_tree.enabled) {
        return;
    }

    if (parent_node_id >= g_syscall_tree.node_count) {
        fprintf(stderr, "[RR-Tree] ERROR: Invalid parent_node_id=%u\n", parent_node_id);
        return;
    }

    TreeNode *parent = &g_syscall_tree.nodes[parent_node_id];
    parent->is_fork_node = true;
    parent->fork_child_pid = child_pid;
    g_syscall_tree.total_forks++;
}

/**
 * 获取syscall名称（简化版本）
 */
const char* rr_tree_get_syscall_name(uint32_t syscall_nr) {
    // 常见x86-64 syscalls
    switch (syscall_nr) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 9: return "mmap";
        case 11: return "munmap";
        case 12: return "brk";
        case 56: return "clone";
        case 57: return "fork";
        case 58: return "vfork";
        case 59: return "execve";
        case 60: return "exit";
        case 231: return "exit_group";
        case 257: return "openat";
        case 262: return "newfstatat";
        case 318: return "getrandom";
        default: return "unknown";
    }
}

/**
 * 导出tree为JSON格式
 */
void rr_tree_export_json(const char *output_file) {
    if (!g_syscall_tree.enabled) {
        return;
    }

    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        fprintf(stderr, "[RR-Tree] ERROR: Failed to open %s for writing\n", output_file);
        return;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"metadata\": {\n");
    fprintf(fp, "    \"total_nodes\": %u,\n", g_syscall_tree.node_count);
    fprintf(fp, "    \"total_syscalls\": %u,\n", g_syscall_tree.total_syscalls);
    fprintf(fp, "    \"total_forks\": %u,\n", g_syscall_tree.total_forks);
    fprintf(fp, "    \"root_node_id\": %u\n", g_syscall_tree.root_node_id);
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"nodes\": [\n");

    for (uint32_t i = 0; i < g_syscall_tree.node_count; i++) {
        TreeNode *node = &g_syscall_tree.nodes[i];

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"id\": %u,\n", node->id);
        fprintf(fp, "      \"pid\": %u,\n", node->pid);
        fprintf(fp, "      \"syscall_index\": %u,\n", node->syscall_index);
        fprintf(fp, "      \"syscall_nr\": %u,\n", node->syscall_nr);
        fprintf(fp, "      \"syscall_name\": \"%s\",\n", node->syscall_name);
        fprintf(fp, "      \"retval\": %ld,\n", node->retval);
        fprintf(fp, "      \"timestamp_enter\": %lu,\n", node->timestamp_enter);
        fprintf(fp, "      \"timestamp_exit\": %lu,\n", node->timestamp_exit);
        fprintf(fp, "      \"parent_id\": %u,\n", node->parent_id);

        // Children IDs
        fprintf(fp, "      \"children_ids\": [");
        for (uint8_t j = 0; j < node->children_count; j++) {
            fprintf(fp, "%u", node->children_ids[j]);
            if (j < node->children_count - 1) {
                fprintf(fp, ", ");
            }
        }
        fprintf(fp, "],\n");

        fprintf(fp, "      \"is_fork_node\": %s,\n", node->is_fork_node ? "true" : "false");
        fprintf(fp, "      \"fork_child_pid\": %u,\n", node->fork_child_pid);
        fprintf(fp, "      \"has_new_coverage\": %s,\n", node->has_new_coverage ? "true" : "false");
        fprintf(fp, "      \"is_mutated\": %s\n", node->is_mutated ? "true" : "false");

        fprintf(fp, "    }");
        if (i < g_syscall_tree.node_count - 1) {
            fprintf(fp, ",");
        }
        fprintf(fp, "\n");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
    fprintf(stdout, "[RR-Tree] ✅ Exported %u nodes to %s\n", g_syscall_tree.node_count, output_file);
}

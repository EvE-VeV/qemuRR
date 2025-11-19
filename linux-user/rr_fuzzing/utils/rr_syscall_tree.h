#ifndef RR_SYSCALL_TREE_H
#define RR_SYSCALL_TREE_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_TREE_NODES 100000      // 最多10万个节点
#define MAX_CHILDREN_PER_NODE 16   // 每个节点最多16个子节点
#define MAX_SYSCALL_NAME 32

// TreeNode：表示一个syscall执行节点
typedef struct TreeNode {
    // 基本信息
    uint32_t id;                           // 节点ID（全局唯一）
    uint32_t pid;                          // 进程ID
    uint32_t syscall_index;                // 在trace中的索引
    uint32_t syscall_nr;                   // 系统调用号
    char syscall_name[MAX_SYSCALL_NAME];   // 系统调用名称

    // Syscall参数和返回值
    uint64_t args[6];                      // 最多6个参数
    int64_t retval;                        // 返回值

    // 时间信息
    uint64_t timestamp_enter;              // 进入时间戳（纳秒）
    uint64_t timestamp_exit;               // 退出时间戳（纳秒）

    // 树结构
    uint32_t parent_id;                    // 父节点ID
    uint32_t children_ids[MAX_CHILDREN_PER_NODE];  // 子节点IDs
    uint8_t children_count;                // 子节点数量

    // Fork信息
    bool is_fork_node;                     // 是否为fork节点
    uint32_t fork_child_pid;               // Fork产生的子进程PID

    // 覆盖率信息（可选）
    bool has_new_coverage;                 // 是否发现新覆盖
    uint32_t new_edges_count;              // 新edge数量

    // 变异信息（可选）
    bool is_mutated;                       // 是否被变异
    uint8_t mutation_cmd;                  // 变异命令类型

} TreeNode;

// Syscall Tree全局结构
typedef struct RRSyscallTree {
    // 节点池
    TreeNode nodes[MAX_TREE_NODES];
    uint32_t node_count;                   // 当前节点数量

    // 根节点
    uint32_t root_node_id;

    // 当前活跃节点（用于追踪execution）- 简化为单PID
    uint32_t current_node_id;

    // 统计信息
    uint32_t total_syscalls;
    uint32_t total_forks;

    // 启用标志
    bool enabled;

} RRSyscallTree;

// 全局tree实例
extern RRSyscallTree g_syscall_tree;

// API函数
void rr_tree_init(void);
void rr_tree_cleanup(void);

uint32_t rr_tree_add_syscall_node(
    uint32_t pid,
    uint32_t syscall_index,
    uint32_t syscall_nr,
    const char *syscall_name,
    uint64_t *args,
    int64_t retval,
    uint64_t timestamp_enter,
    uint64_t timestamp_exit
);

void rr_tree_add_fork_relation(
    uint32_t parent_node_id,
    uint32_t child_pid
);

void rr_tree_export_json(const char *output_file);

// 辅助函数
const char* rr_tree_get_syscall_name(uint32_t syscall_nr);

#endif /* RR_SYSCALL_TREE_H */

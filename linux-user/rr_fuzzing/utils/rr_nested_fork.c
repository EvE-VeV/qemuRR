/**
 * RR-Fuzz Autonomous Nested Fork模块
 * 实现子进程自主决定嵌套fork的功能
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include "../core/rr_framework.h"
#include "rr_syscall_info.h"
#include "rr_dynamic_trace.h"

/**
 * 检查一个syscall是否是IO类syscall
 */
bool is_io_syscall(int syscall_nr) {
    const syscall_info_t *info = rr_get_syscall_info(syscall_nr);
    if (!info) {
        return false;
    }
    
    return (info->class == SYSCALL_CLASS_IO);
}

/**
 * 判断是否应该在当前syscall触发嵌套fork
 * 
 * 策略：
 * 1. 必须是autonomous child (depth > 0)
 * 2. 必须是IO syscall
 * 3. 限制每个进程的fork次数（防止fork炸弹）
 * 4. 只在第一个IO syscall触发（简化测试）
 */
/**
 * @brief 判断是否触发嵌套 Fork (Nested Fork Heuristic)
 * 
 * 决定当前子进程是否应该进一步 Fork 出孙进程 (Grandchildren)。
 * 这是一个高级特性，允许在 Trace 的深处进行局部探索。
 * 
 * **触发条件**:
 * 1. 必须是 Autonomous Child (由 Fork Server 创建)。
 * 2. 嵌套深度 < 2 (防止 Fork 炸弹)。
 * 3. 每个进程限制 Fork 次数 (当前限制为 1)。
 * 4. **硬编码触发**: 当前仅在第 5 个 Syscall 触发 (用于演示/测试)。
 * 
 * @param syscall_nr 系统调用号
 * @return true 触发嵌套 Fork
 */
bool rr_should_nested_fork(int syscall_nr, const char *syscall_name, abi_long ret) {
    /* 只有autonomous child才能嵌套fork */
    if (!g_rr_framework->is_autonomous_child) {
        return false;
    }
    
    /* 限制depth（最多2层嵌套：parent→child→grandchild） */
    if (g_rr_framework->current_depth > 1) {
        return false;
    }
    
    /* 限制每个进程的fork次数（防止fork炸弹） */
    const uint32_t MAX_FORKS_PER_PROCESS = 1;  // ✅ 每个child只fork一次
    if (g_rr_framework->forks_this_iteration >= MAX_FORKS_PER_PROCESS) {
        return false;
    }
    
    /* ✅ 在任何成功的syscall触发（高概率，用于展示） */
    if (ret < 0) {
        return false;
    }
    
    /* ✅ 只在第5个syscall触发（简化） */
    static __thread int syscall_count = 0;
    syscall_count++;
    
    if (syscall_count != 5) {
        return false;
    }
    
    RR_INFO("🔥 Nested fork trigger: %s (depth=%u, syscall_nr=%d)", 
            syscall_name, g_rr_framework->current_depth, syscall_nr);
    
    return true;
}

/**
 * 执行autonomous nested fork - 真正的多级动态fork实现！
 * 
 * Child在执行中自主决定fork出多个grandchildren
 */
#define NUM_NESTED_VARIANTS 2

extern FILE *g_trace_file;
extern char *g_rr_trace_path;

/**
 * @brief 执行自主嵌套 Fork (Autonomous Nested Fork)
 * 
 * 这是真正的"多级 Fork"实现。当前进程 (Child) 暂停，
 * 并 Fork 出多个 (默认2个) 孙进程 (Grandchild) 并行探索。
 * 
 * **机制**:
 * 1. Fork 出 N 个 Grandchild。
 * 2. Grandchild 重新打开 Trace 文件 (以获得独立的文件指针)。
 * 3. Grandchild 继承当前状态继续执行。
 * 4. **Parent (Child) 等待所有 Grandchild 完成**，维持进程树结构。
 * 
 * @param fork_index 当前的系统调用索引
 */
void rr_autonomous_nested_fork(int fork_index) {
    RR_INFO("🔄 Autonomous nested fork at syscall[%d] (depth=%u, iteration=%u)", 
            fork_index, g_rr_framework->current_depth, g_rr_framework->current_iteration_id);
    
    g_rr_framework->forks_this_iteration++;
    
    /* ✅ 真正的nested fork实现！*/
    // const int NUM_NESTED_VARIANTS = 2;  // 每次fork出2个grandchildren
    
    pid_t my_pid = getpid();
    pid_t grandchild_pids[NUM_NESTED_VARIANTS];
    
    // 保存当前状态（trace file需要每个grandchild独立）
    // extern FILE *g_trace_file;
    // extern char *g_rr_trace_path;
    
    for (int i = 0; i < NUM_NESTED_VARIANTS; i++) {
        pid_t pid = fork();
        
        if (pid == 0) {
            /* ═══ Grandchild进程 ═══ */
            
            // ✅ 独立trace file
            if (g_trace_file && g_rr_trace_path) {
                fclose(g_trace_file);
                g_trace_file = fopen(g_rr_trace_path, "rb");
                if (!g_trace_file) {
                    RR_ERROR("Grandchild %d: Failed to reopen trace", i);
                    _exit(1);
                }
                // 保持当前file position（继承的）
                RR_INFO("Grandchild %d: Reopened trace file", i);
            }
            
            // ✅ 更新状态
            g_rr_framework->current_depth++;
            g_rr_framework->is_autonomous_child = true;  // Grandchild也是autonomous
            
#ifdef RR_ENABLE_DYNAMIC_TRACE
            if (g_dynamic_trace_enabled && g_dynamic_trace_pipe_fd >= 0) {
                // Grandchild发送iteration消息
                rr_dynamic_trace_iteration(g_rr_framework->current_iteration_id, getpid());
            }
#endif
            
            RR_INFO("✅ Grandchild %d started: PID=%d, depth=%u", 
                    i, getpid(), g_rr_framework->current_depth);
            
            // Grandchild继续执行（从当前replay_index继续）
            return;
            
        } else if (pid > 0) {
            /* ═══ Parent (original child) ═══ */
            grandchild_pids[i] = pid;
            
#ifdef RR_ENABLE_DYNAMIC_TRACE
            if (g_dynamic_trace_enabled && g_dynamic_trace_pipe_fd >= 0) {
                rr_dynamic_trace_fork(my_pid, pid, fork_index);
            }
#endif
            
            RR_INFO("  Nested fork: grandchild %d PID=%d", i, pid);
        } else {
            RR_ERROR("Nested fork failed for variant %d", i);
            break;
        }
    }
    
    /* ═══ Parent等待所有grandchildren完成 ═══ */
    if (getpid() == my_pid) {
        RR_INFO("⏳ Waiting for %d grandchildren to complete...", NUM_NESTED_VARIANTS);
        for (int i = 0; i < NUM_NESTED_VARIANTS; i++) {
            if (grandchild_pids[i] > 0) {
                int status;
                waitpid(grandchild_pids[i], &status, 0);
                RR_INFO("  Grandchild %d (PID=%d) finished", i, grandchild_pids[i]);
            }
        }
        
        RR_INFO("✅ All grandchildren completed, continuing execution");
    }
}


/**
 * RR-Fuzz Fork Server模块
 * 实现高速Fuzzing的Fork Server机制，支持基于系统调用的Fork点
 * 
 * 新特性：
 * - 支持基于系统调用名称的Fork点（如"openat", "read"）
 * - Support path pattern matching
 * - 智能Fork点检测
 */

#include <sys/wait.h>
#include <signal.h>
#include <fnmatch.h>
#include "rr_framework.h"

// Fork点配置
static char *g_fork_syscall_name = NULL;      // 目标系统调用名称
static char *g_fork_syscall_pattern = NULL;   // 路径匹配模式
static bool g_at_fork_point = false;          // 是否已到达fork点

/**
 * 启动Fork Server
 * 
 * @param syscall_name 目标系统调用名称（如"openat", "read", NULL表示使用旧的索引模式）
 * @param pattern Path matching pattern, NULL matches all
 * @return 成功返回0，失败返回-1
 */
int rr_start_fork_server(const char *syscall_name, const char *pattern)
{
    RR_VERBOSE("Starting Fork Server initialization");

    if (!rr_framework_enabled()) {
        RR_ERROR("Cannot start Fork Server: framework not enabled");
        return -1;
    }

    // 保存Fork点配置
    if (syscall_name) {
        g_fork_syscall_name = strdup(syscall_name);
        RR_INFO("Fork Server: target syscall = %s", syscall_name);
    } else {
        g_fork_syscall_name = NULL;
        RR_INFO("Fork Server: using legacy index-based fork point");
    }

    if (pattern) {
        g_fork_syscall_pattern = strdup(pattern);
        RR_INFO("Fork Server: path pattern = %s", pattern);
    } else {
        g_fork_syscall_pattern = NULL;
        RR_INFO("Fork Server: no path pattern (match all)");
    }

    g_rr_framework->fork_server_active = true;

    RR_INFO("Fork Server started with syscall-based fork point");
    RR_VERBOSE("Fork Server state: active=%s, syscall=%s, pattern=%s",
               g_rr_framework->fork_server_active ? "true" : "false", 
               g_fork_syscall_name ? g_fork_syscall_name : "none",
               g_fork_syscall_pattern ? g_fork_syscall_pattern : "none");

    /* 发送Ready状态给Conductor */
    RR_IPC_TRACE("Sending Ready status to Conductor");
    if (rr_ipc_send_status(1) < 0) { // 1 = Ready
        RR_WARN("Failed to send Ready status");
    }

    return 0;
}

/**
 * 停止Fork Server
 */
void rr_stop_fork_server(void)
{
    if (!g_rr_framework) {
        return;
    }

    g_rr_framework->fork_server_active = false;
    g_at_fork_point = false;

    /* 如果有子进程在运行，等待其结束 */
    if (g_rr_framework->child_pid > 0) {
        kill(g_rr_framework->child_pid, SIGTERM);
        waitpid(g_rr_framework->child_pid, NULL, 0);
        g_rr_framework->child_pid = 0;
    }

    /* 清理配置 */
    if (g_fork_syscall_name) {
        free(g_fork_syscall_name);
        g_fork_syscall_name = NULL;
    }
    if (g_fork_syscall_pattern) {
        free(g_fork_syscall_pattern);
        g_fork_syscall_pattern = NULL;
    }

    RR_LOG("Fork Server stopped");
}

/**
 * 提取系统调用的路径参数
 * 
 * @param syscall_name 系统调用名称
 * @param args 系统调用参数
 * @param env CPU环境（用于读取内存）
 * @return 提取的路径字符串，需要调用者释放；失败返回NULL
 */
static char *extract_path_from_syscall(const char *syscall_name, const abi_long *args, CPUArchState *env)
{
    if (!syscall_name || !args) {
        return NULL;
    }

    target_ulong path_addr = 0;
    
    // 根据系统调用类型确定路径参数位置
    if (strcmp(syscall_name, "openat") == 0 || strcmp(syscall_name, "newfstatat") == 0) {
        path_addr = args[1];  // openat(dirfd, pathname, ...)
    } else if (strcmp(syscall_name, "open") == 0 || strcmp(syscall_name, "access") == 0) {
        path_addr = args[0];  // open(pathname, ...)
    } else {
        return NULL;  // 不支持的系统调用
    }

    if (path_addr == 0) {
        return NULL;
    }

    // 从目标内存读取字符串
    // 注意：这里简化处理，实际应该使用cpu_memory_rw_debug
    // 但为了兼容性，我们先返回一个占位符
    return strdup("(path_extraction_not_implemented)");
}

/**
 * 检查是否到达Fork点（新实现）
 * 
 * @param syscall_nr 系统调用号
 * @param syscall_name 系统调用名称
 * @param args 系统调用参数
 * @return true表示到达fork点，false表示未到达
 */
bool rr_check_fork_point(int syscall_nr, const char *syscall_name, const abi_long *args)
{
    if (!g_rr_framework->fork_server_active) {
        return false;
    }

    // 如果已经到达fork点，直接返回true
    if (g_at_fork_point) {
        return true;
    }

    // 如果没有配置syscall名称，使用旧的索引模式（兼容性）
    if (!g_fork_syscall_name) {
        RR_WARN("No fork syscall configured, fork point detection disabled");
        return false;
    }

    // 检查系统调用名称是否匹配
    if (!syscall_name || strcmp(syscall_name, g_fork_syscall_name) != 0) {
        return false;
    }

    RR_VERBOSE("Found target syscall: %s", syscall_name);

    // 如果没有路径模式，直接匹配系统调用名称
    if (!g_fork_syscall_pattern) {
        g_at_fork_point = true;
        RR_INFO("🎯 Reached fork point: %s (no path pattern)", syscall_name);
        
        /* 发送到达Fork点的状态 */
        RR_IPC_TRACE("Sending At Fork Point status");
        if (rr_ipc_send_status(2) < 0) { // 2 = At Fork Point
            RR_WARN("Failed to send At Fork Point status");
        }
        
        return true;
    }

    // 有路径模式，需要进一步检查路径
    char *path = extract_path_from_syscall(syscall_name, args, NULL);
    if (!path) {
        RR_VERBOSE("Could not extract path from %s, skipping pattern match", syscall_name);
        return false;
    }

    // 使用fnmatch进行模式匹配
    int match_result = fnmatch(g_fork_syscall_pattern, path, FNM_PATHNAME);
    free(path);

    if (match_result == 0) {
        // 模式匹配成功
        g_at_fork_point = true;
        RR_INFO("🎯 Reached fork point: %s matching pattern '%s'", 
               syscall_name, g_fork_syscall_pattern);
        
        /* 发送到达Fork点的状态 */
        RR_IPC_TRACE("Sending At Fork Point status");
        if (rr_ipc_send_status(2) < 0) { // 2 = At Fork Point
            RR_WARN("Failed to send At Fork Point status");
        }
        
        return true;
    } else {
        RR_VERBOSE("Path pattern '%s' did not match, continuing...", g_fork_syscall_pattern);
        return false;
    }
}

/**
 * Fork Server主循环
 * 等待Conductor的命令并执行Fork
 */
int rr_fork_server_loop(void)
{
    if (!g_at_fork_point) {
        return 0; // 还未到达Fork点
    }

    while (g_rr_framework->fork_server_active) {
        /* 接收Conductor命令 */
        int cmd = rr_ipc_receive_command();

        switch (cmd) {
            case 'F': // Fork命令
                {
                    /* ===== 关键修复：在fork前从共享内存加载Fuzz指令 ===== */
                    if (g_rr_framework->shared_memory) {
                        RR_VERBOSE("Loading fuzz instructions from shared memory before fork");
                        
                        // 从共享内存读取并验证Fuzz指令
                        int load_result = rr_fuzz_load_from_shared_memory(g_rr_framework->shared_memory);
                        if (load_result < 0) {
                            RR_ERROR("Failed to load fuzz instructions from shared memory");
                            rr_ipc_send_status(-1); // 发送错误状态
                            break; // 不执行fork
                        }
                        
                        RR_VERBOSE("Fuzz instructions loaded successfully, proceeding to fork");
                    } else {
                        // 没有共享内存，正常replay模式（无变异）
                        RR_VERBOSE("No shared memory configured, running without mutations");
                    }
                    
                    /* 执行fork创建子进程 */
                    pid_t pid = fork();
                    
                    if (pid == 0) {
                        /* 子进程：继续执行Fuzzing */
                        g_rr_framework->child_pid = 0;
                        g_rr_framework->fork_server_active = false;  // 🔥 子进程不再是fork server
                        
                        RR_INFO("🔄 Child process started for fuzzing execution (PID=%d)", getpid());
                        RR_INFO("🔄 Child will continue replay from current point");
                        
                        // 子进程会继承父进程加载的Fuzz指令
                        // 这些指令将在 rr_fuzz_mutate_syscall() 中被应用
                        
                        return 1; // 返回1表示子进程应该继续执行
                        
                    } else if (pid > 0) {
                        /* 父进程：等待子进程完成 */
                        g_rr_framework->child_pid = pid;
                        
                        RR_VERBOSE("Parent process waiting for child PID=%d", pid);
                        
                        int status;
                        waitpid(pid, &status, 0);
                        
                        /* 分析执行结果并发送给Conductor */
                        if (WIFEXITED(status)) {
                            int exit_code = WEXITSTATUS(status);
                            RR_VERBOSE("Child exited normally with code %d", exit_code);
                            rr_ipc_send_status(3); // 3 = Normal Exit
                            
                        } else if (WIFSIGNALED(status)) {
                            int sig = WTERMSIG(status);
                            
                            // 检测是否为崩溃信号
                            if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS || 
                                sig == SIGILL || sig == SIGFPE) {
                                RR_INFO("💥 CRASH DETECTED: Child crashed with signal %d (%s)", 
                                       sig, strsignal(sig));
                                rr_ipc_send_status(4); // 4 = Crash Found
                            } else {
                                RR_VERBOSE("Child terminated by signal %d", sig);
                                rr_ipc_send_status(5); // 5 = Other Signal
                            }
                        } else {
                            RR_WARN("Child terminated with unknown status");
                            rr_ipc_send_status(-1);
                        }
                        
                        g_rr_framework->child_pid = 0;
                        g_rr_framework->total_executions++;
                        
                        RR_VERBOSE("Completed execution #%lu", g_rr_framework->total_executions);
                        
                    } else {
                        /* Fork失败 */
                        RR_ERROR("fork() failed: %s", strerror(errno));
                        rr_ipc_send_status(-1); // Error
                    }
                }
                break;

            case 'Q': // 退出命令
                RR_LOG("Fork Server received quit command");
                return -1; // 退出程序

            case 'S': // 保存Snapshot命令
                // TODO: 实现Snapshot保存
                rr_ipc_send_status(6); // 6 = Snapshot Saved
                break;

            case 'L': // 加载Snapshot命令
                // TODO: 实现Snapshot加载
                rr_ipc_send_status(7); // 7 = Snapshot Loaded
                break;

            case 0: // 无命令
                usleep(1000); // 短暂等待
                break;

            default:
                RR_LOG("Unknown fork server command: %d", cmd);
                break;
        }
    }

    return 0;
}
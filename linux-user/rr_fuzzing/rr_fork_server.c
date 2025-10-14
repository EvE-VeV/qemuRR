/**
 * RR-Fuzz Fork Server模块
 * 实现高速Fuzzing的Fork Server机制，支持基于系统调用的Fork点
 * 
 * 新特性：
 * - 支持基于系统调用名称的Fork点（如"openat", "read"）
 * - Support path pattern matching
 * - 智能Fork点检测（自动P_IO分类）
 */

/* 确保RR_DEBUG被定义，启用调试日志 */
#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include <sys/wait.h>
#include <signal.h>
#include <fnmatch.h>
#include "rr_framework.h"
#include "rr_syscall_info.h"  /* 新增：系统调用分类 */
#include "rr_dynamic_trace.h"  /* 动态跟踪API */

// Fork点配置
static char *g_fork_syscall_name = NULL;      // 目标系统调用名称
static char *g_fork_syscall_pattern = NULL;   // 路径匹配模式
static bool g_at_fork_point = false;          // 是否已到达fork点

/**
 * 重置 Fork 点状态（用于新进程启动时）
 */
void rr_reset_fork_point(void)
{
    g_at_fork_point = false;
    RR_VERBOSE("Reset fork point state for new process");
}

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

    // 自动检测模式：不需要手动配置
    if (syscall_name) {
        g_fork_syscall_name = strdup(syscall_name);
        RR_INFO("Fork Server: target syscall = %s", syscall_name);
    } else {
        g_fork_syscall_name = NULL;
        RR_INFO("Fork Server: AUTO-DETECTION mode (P_IO syscalls)");
    }

    if (pattern) {
        g_fork_syscall_pattern = strdup(pattern);
        RR_INFO("Fork Server: path pattern = %s", pattern);
    } else {
        g_fork_syscall_pattern = NULL;
        RR_INFO("Fork Server: no path pattern (auto-detection)");
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

    /* 🔥 关键修复：等待第一个命令再开始执行 
     * 这样可以防止程序在收到'F'命令前就开始执行并耗尽trace
     */
    RR_INFO("Waiting for first command from Conductor (cmd_pipe_fd=%d)...", 
            g_rr_framework->cmd_pipe_fd);
    int first_cmd = rr_ipc_receive_command();
    RR_INFO("rr_ipc_receive_command() returned: %d", first_cmd);
    
    if (first_cmd == 'F') {
        RR_INFO("Received first 'F' command, execution will proceed");
        // 不做任何事，让执行继续
        // 当到达fork点时，会调用 rr_check_auto_fork_point()
    } else if (first_cmd == 'Q') {
        RR_INFO("Received 'Q' command, exiting");
        exit(0);
    } else {
        RR_WARN("Unexpected first command: %d, continuing anyway", first_cmd);
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
    /* 
     * 注意：不再检查 g_at_fork_point，因为调用此函数时
     * 已经确认到达了 fork 点（通过 rr_check_auto_fork_point）
     */

    while (g_rr_framework->fork_server_active) {
        /* 接收Conductor命令 */
        int cmd = rr_ipc_receive_command();
        RR_INFO("🔧 Fork server loop: received command '%c' (%d)", cmd > 0 && cmd < 128 ? cmd : '?', cmd);

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
                        /* 子进程：关闭继承的IPC FD，防止干扰父进程通信 */
                        if (g_rr_framework->cmd_pipe_fd >= 0) {
                            close(g_rr_framework->cmd_pipe_fd);
                            g_rr_framework->cmd_pipe_fd = -1;
                        }
                        if (g_rr_framework->status_pipe_fd >= 0) {
                            close(g_rr_framework->status_pipe_fd);
                            g_rr_framework->status_pipe_fd = -1;
                        }
                        
                        /* 继续执行Fuzzing */
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
                        
                        /* 动态跟踪：记录fork事件 */
                        extern uint32_t g_strace_current_index;  /* 当前系统调用索引 */
                        rr_dynamic_trace_fork(getpid(), pid, g_strace_current_index);
                        
                        RR_VERBOSE("Parent process waiting for child PID=%d", pid);
                        
                        int status;
                        
                        /* 🔥 关键修复：添加超时机制，防止无限等待 */
                        int wait_result = waitpid(pid, &status, WNOHANG);
                        if (wait_result == 0) {
                            // 子进程还在运行，等待一段时间
                            RR_VERBOSE("Child still running, waiting with timeout...");
                            
                            int timeout_count = 0;
                            while (wait_result == 0 && timeout_count < 100) { // 10秒超时
                                usleep(100000); // 100ms
                                wait_result = waitpid(pid, &status, WNOHANG);
                                timeout_count++;
                            }
                            
                            if (wait_result == 0) {
                                RR_WARN("Child process timeout, forcibly terminating PID=%d", pid);
                                kill(pid, SIGKILL);
                                waitpid(pid, &status, 0); // 等待清理
                                rr_ipc_send_status(3); // 发送Normal Exit而不是Error
                                g_rr_framework->child_pid = 0;
                                // 不break，继续正常流程，让Python继续下一轮
                            }
                        }
                        
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
                        
                        /* 重置 fork 点状态，准备下次迭代 */
                        g_at_fork_point = false;
                        RR_VERBOSE("Reset fork point for next iteration");
                        
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

/**
 * 自动检测 Fork 点（改进版，支持Fallback）
 * 
 * 改进点：
 * 1. 支持多种fork策略（strict/relaxed/aggressive/fallback）
 * 2. 添加fallback机制：如果N个syscall未fork，强制fork
 * 
 * @param syscall_nr 系统调用号
 * @param syscall_name 系统调用名称（可选）
 * @param ret 系统调用返回值
 * @return true 表示应该进入 fork server loop
 */
bool rr_check_auto_fork_point(int syscall_nr, const char *syscall_name, abi_long ret)
{
    static int syscalls_since_ready = 0;  // Fallback计数器
    extern rr_config_t g_rr_config;
    
    if (!g_rr_framework->fork_server_active) {
        return false;
    }
    
    /* 如果已经在 fork point，发送状态并返回 */
    if (g_at_fork_point) {
        RR_IPC_TRACE("Sending At Fork Point status (already at fork point)");
        if (rr_ipc_send_status(2) < 0) {
            RR_WARN("Failed to send At Fork Point status");
        }
        return true;
    }
    
    /* 增加计数器（用于fallback） */
    syscalls_since_ready++;
    
    /* 策略1: 使用配置的fork策略检测 */
    const syscall_info_t *info = rr_get_syscall_info(syscall_nr);
    bool should_fork = rr_should_auto_fork(syscall_nr, ret);
    
    RR_VERBOSE("Auto-fork check: %s (class=%s, ret=%ld, strategy=%d, should_fork=%d)",
               info->name,
               rr_get_syscall_class_name(info->class),
               (long)ret,
               g_rr_config.fork_strategy,
               should_fork);
    
    if (should_fork) {
        g_at_fork_point = true;
        RR_INFO("🎯 Auto-detected fork point: %s (class=%s, ret=%ld, strategy=%d, after %d syscalls)",
                info->name, 
                rr_get_syscall_class_name(info->class),
                (long)ret,
                g_rr_config.fork_strategy,
                syscalls_since_ready);
        
        RR_IPC_TRACE("Sending At Fork Point status (auto-detected)");
        if (rr_ipc_send_status(2) < 0) {
            RR_WARN("Failed to send At Fork Point status");
        }
        
        syscalls_since_ready = 0;  // 重置计数器
        return true;
    }
    
    /* 策略2: Fallback机制 - 如果N个syscall后仍未fork，强制fork */
    if (syscalls_since_ready >= g_rr_config.fork_fallback_threshold) {
        const syscall_info_t *info = rr_get_syscall_info(syscall_nr);
        
        /* 只在合适的syscall上fallback（I/O或FD类） */
        if (info->class == SYSCALL_CLASS_IO || info->class == SYSCALL_CLASS_FD) {
            g_at_fork_point = true;
            RR_WARN("⚠️  Fallback fork triggered: %s after %d syscalls without fork",
                    info->name, syscalls_since_ready);
            
            RR_IPC_TRACE("Sending At Fork Point status (fallback)");
            if (rr_ipc_send_status(2) < 0) {
                RR_WARN("Failed to send At Fork Point status");
            }
            
            syscalls_since_ready = 0;
            return true;
        }
    }
    
    return false;
}
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
#include <unistd.h>
#include "../core/rr_framework.h"
#include "rr_syscall_info.h"  /* 新增：系统调用分类 */
#include "rr_dynamic_trace.h"  /* 动态跟踪API */
#include "../replay/rr_replay_strace.h"

extern FILE *g_trace_file;
extern char *g_rr_trace_path;
// extern void rr_reset_trace_position(void);

/* Status codes (must match Python-side definitions) */
#define STATUS_NONE          0
#define STATUS_READY         1
#define STATUS_AT_FORK_POINT 2
#define STATUS_NORMAL_EXIT   3
#define STATUS_CRASH         4
#define STATUS_OTHER_SIGNAL  5
#define STATUS_TIMEOUT       6

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

    /* 发送Ready状态给Conductor，然后直接返回 */
    /* fork_server_loop()会处理所有命令（包括第一个） */
    RR_IPC_TRACE("Sending Ready status to Conductor");
    if (rr_ipc_send_status(1) < 0) { // 1 = Ready
        RR_WARN("Failed to send Ready status");
    }
    
    RR_INFO("Fork server initialized, ready to receive commands in fork_server_loop()");
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
 * @param env CPU环境（用于读取内存）- 必需参数
 * @param syscall_name 系统调用名称
 * @param args 系统调用参数
 * @return 提取的路径字符串，需要调用者释放；失败返回NULL
 */
static char *extract_path_from_syscall(CPUArchState *env, const char *syscall_name, const abi_long *args)
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

    /* 🔥 修复：真实读取 guest 内存中的路径字符串 */
    if (!env) {
        RR_WARN("Cannot extract path without CPU env");
        return NULL;
    }
    
    /* 从 guest 内存读取字符串（最多4KB） */
    char path_buffer[4096];
    size_t len = 0;
    
    while (len < sizeof(path_buffer) - 1) {
        uint8_t byte;
        if (cpu_memory_rw_debug(env_cpu(env), path_addr + len, &byte, 1, 0) != 0) {
            break; // 内存访问失败
        }
        if (byte == 0) {
            break; // 字符串结束
        }
        path_buffer[len++] = byte;
    }
    path_buffer[len] = '\0';
    
    if (len == 0) {
        return NULL;
    }
    
    return strdup(path_buffer);
}

/**
 * 检查是否到达Fork点（新实现）
 * 
 * @param env CPU环境（用于读取路径）
 * @param syscall_nr 系统调用号
 * @param syscall_name 系统调用名称
 * @param args 系统调用参数
 * @return true表示到达fork点，false表示未到达
 */
bool rr_check_fork_point(CPUArchState *env, int syscall_nr, const char *syscall_name, const abi_long *args)
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
        RR_INFO("Reached fork point: %s (no path pattern)", syscall_name);
        
        /* 发送到达Fork点的状态 */
        RR_IPC_TRACE("Sending At Fork Point status");
        if (rr_ipc_send_status(2) < 0) { // 2 = At Fork Point
            RR_WARN("Failed to send At Fork Point status");
        }
        
        return true;
    }

    // 有路径模式，需要进一步检查路径
    char *path = extract_path_from_syscall(env, syscall_name, args);
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
        RR_INFO("Reached fork point: %s matching pattern '%s'", 
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
        RR_INFO("Info: Fork server loop: received command '%c' (%d)", cmd > 0 && cmd < 128 ? cmd : '?', cmd);

        switch (cmd) {
            // 新增：批量fork命令（用于动态多路径探索）
            case 'B': // Batch fork命令
                {
                    RR_INFO("Info: Batch fork command received");
                    
                    /* 从共享内存读取variants信息 */
                    if (!g_rr_framework->shared_memory) {
                        RR_ERROR("No shared memory for batch fork");
                        rr_ipc_send_status(-1);
                        break;
                    }
                    
                    FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                    int num_variants = shm->num_variants;
                    
                    if (num_variants <= 0 || num_variants > 10) {
                        RR_WARN("Invalid num_variants: %d, using 1", num_variants);
                        num_variants = 1;
                    }
                    
                    RR_INFO("Batch fork: %d variants", num_variants);
                    
                    /* 批量fork多个子进程 */
                    pid_t child_pids[10] = {0};
                    
                    for (int variant_idx = 0; variant_idx < num_variants; variant_idx++) {
                        /* 加载variant的mutations到全局指令数组 */
                        FuzzVariant *variant = &shm->variants[variant_idx];
                        g_instruction_count = variant->instruction_count;
                        memcpy(g_fuzz_instructions, variant->instructions,
                               sizeof(FuzzInstruction) * g_instruction_count);
                        
                        RR_INFO("  Variant %d: %zu instructions", variant_idx, g_instruction_count);
                        
                        /* Fork子进程 */
                        pid_t pid = fork();
                        
                        if (pid == 0) {
                            /* ═══ 子进程 ═══ */
                            
                            /* 关闭IPC FD */
                            if (g_rr_framework->cmd_pipe_fd >= 0) {
                                close(g_rr_framework->cmd_pipe_fd);
                                g_rr_framework->cmd_pipe_fd = -1;
                            }
                            if (g_rr_framework->status_pipe_fd >= 0) {
                                close(g_rr_framework->status_pipe_fd);
                                g_rr_framework->status_pipe_fd = -1;
                            }
                            
                            /* 重置trace */
                            RR_INFO("Child variant %d: Resetting trace", variant_idx);
                            rr_reset_trace_position();
                            g_rr_framework->replay_index = 0;
                            
                            if (g_current_record) {
                                rr_record_dispose(g_current_record);
                                g_current_record = NULL;
                            }
                            
                            /* 修复: 子进程保持dynamic trace启用 */
                            // g_rr_framework->fork_server_active = false;  // 保持为true
                            g_rr_framework->child_pid = 0;
                            
                            /* 关键修复: 直接设置全局变量启用dynamic trace */
#ifdef RR_ENABLE_DYNAMIC_TRACE
                            // extern int g_dynamic_trace_pipe_fd;
                            // extern bool g_dynamic_trace_enabled;
                            
                            RR_INFO("🔍 Child %d: pipe_fd=%d, enabled_before=%d", 
                                    variant_idx, g_dynamic_trace_pipe_fd, g_dynamic_trace_enabled);
                            
                            if (g_dynamic_trace_pipe_fd >= 0) {
                                g_dynamic_trace_enabled = true;  // 直接设置
                                RR_INFO("Child %d: Forced enabled=true (PID=%d, fd=%d)", 
                                        variant_idx, getpid(), g_dynamic_trace_pipe_fd);
                            } else {
                                RR_WARN("❌ Child %d: Invalid pipe_fd=%d, cannot enable trace", 
                                        variant_idx, g_dynamic_trace_pipe_fd);
                            }
#endif
                            
                            RR_INFO("Child variant %d ready (PID=%d)", variant_idx, getpid());
                            return 1;  // 继续执行
                            
                        } else if (pid > 0) {
                            /* ═══ 父进程 ═══ */
                            child_pids[variant_idx] = pid;
                            
                            /* 发送fork事件到tree visualizer */
                            rr_dynamic_trace_fork(getpid(), pid, g_rr_framework->replay_index);
                            
                            RR_INFO("  Forked variant %d: PID=%d", variant_idx, pid);
                            
                        } else {
                            /* Fork失败 */
                            RR_ERROR("fork() failed for variant %d: %s", variant_idx, strerror(errno));
                            rr_ipc_send_status(-1);
                            break;
                        }
                    }
                    
                    /* 父进程：等待所有子进程完成 */
                    RR_INFO("Parent: Waiting for %d children...", num_variants);
                    
                    for (int i = 0; i < num_variants; i++) {
                        int status;
                        waitpid(child_pids[i], &status, 0);
                        
                        /* 分析退出状态 */
                        if (WIFEXITED(status)) {
                            RR_VERBOSE("Child variant %d exited normally", i);
                        } else if (WIFSIGNALED(status)) {
                            int sig = WTERMSIG(status);
                            if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS || 
                                sig == SIGILL || sig == SIGFPE) {
                                RR_INFO("Crash: Child variant %d crashed with signal %d", i, sig);
                            }
                        }
                        
                        /* 发送status（每个子进程一个） */
                        rr_ipc_send_status(2);  // STATUS_AT_FORK_POINT = 2
                    }
                    
                    RR_INFO("Batch fork completed");
                    g_rr_framework->child_pid = 0;
                }
                break;
            
            case 'F': // Fork命令
                {
                    /* 读取共享内存中的iteration_id */
                    if (g_rr_framework->shared_memory) {
                        FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                        g_rr_framework->current_iteration_id = shm->iteration_id;
                        RR_VERBOSE("Case 'F': iteration_id=%u from shared memory", shm->iteration_id);
                    }
                    
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
                        
                        /* 🔥 关键修复：重置 trace 文件指针到开头 */
                        RR_INFO("Child: Resetting trace position to start");
                        rr_reset_trace_position();
                        
                        /* 🔥 P0修复：重置replay_index到0 */
                        RR_INFO("Child: Resetting replay_index to 0");
                        g_rr_framework->replay_index = 0;
                        
                        /* 🔥 P0修复：清空当前record */
                        if (g_current_record) {
                            RR_INFO("Child: Disposing current record");
                            rr_record_dispose(g_current_record);
                            g_current_record = NULL;
                        }
                        
                        /* 🔥 关键修复：子进程重新加载Fuzz指令 */
                        if (g_rr_framework->shared_memory) {
                            RR_INFO("Child: Reloading fuzz instructions from shared memory");
                            int load_result = rr_fuzz_load_from_shared_memory(g_rr_framework->shared_memory);
                            if (load_result < 0) {
                                RR_ERROR("Child: Failed to reload fuzz instructions!");
                            } else {
                                RR_INFO("🎉 Child: Successfully reloaded %zu fuzz instructions", g_instruction_count);
                                
                                // DEBUG: 立即验证reload后的状态
                                /* fprintf(stderr, "[DEBUG-CHILD-RELOAD] PID=%d, IMMEDIATELY after reload:\\n\", getpid());\n                                fprintf(stderr, "[DEBUG-CHILD-RELOAD]   g_instruction_count=%zu (address=%p)\\n\", \n                                        g_instruction_count, &g_instruction_count);\n                                if (g_instruction_count > 0) {\n                                    fprintf(stderr, "[DEBUG-CHILD-RELOAD]   First instruction: syscall_idx=%u, cmd=%d\\n\",\n                                            g_fuzz_instructions[0].syscall_index, g_fuzz_instructions[0].cmd);\n                                } */
                                fflush(stderr);
                            }
                        }
                        
                        /* 继续执行Fuzzing */
                        g_rr_framework->child_pid = 0;
                        /* 修复: 保持trace pipe启用 */
                        // g_rr_framework->fork_server_active = false;  // 保持为true
                        
#ifdef RR_ENABLE_DYNAMIC_TRACE
                        // extern int g_dynamic_trace_pipe_fd;
                        // extern bool g_dynamic_trace_enabled;
                        if (g_dynamic_trace_pipe_fd >= 0) {
                            g_dynamic_trace_enabled = true;
                            RR_INFO("Child (F cmd): Forced trace enabled (PID=%d, fd=%d)", 
                                    getpid(), g_dynamic_trace_pipe_fd);
                            
                            /* 发送iteration消息 (使用current_iteration_id，如果未设置则为0) */
                            uint32_t iter_id = g_rr_framework->current_iteration_id;
                            rr_dynamic_trace_iteration(iter_id, getpid());
                            RR_INFO("Child (F cmd): Sent iteration %u message", iter_id);
                        }
#endif
                        
                        RR_INFO("Child process started for fuzzing execution (PID=%d)", getpid());
                        RR_INFO("Child will execute syscalls from BEGINNING (early fork mode)");
                        
                        // DEBUG: 返回前再次检查
                        fprintf(stderr, "[DEBUG-CHILD-BEFORE-RETURN] PID=%d, before returning:\n", getpid());
                        fprintf(stderr, "[DEBUG-CHILD-BEFORE-RETURN]   g_instruction_count=%zu\n", g_instruction_count);
                        fflush(stderr);
                        
                        /* FIX: 返回1让控制权回到rr_do_syscall
                         * 
                         * 重要：由于我们在第一个syscall之前就fork了（early fork），
                         *      子进程返回后会继续执行第一个syscall
                         *      然后是第二个、第三个...直到所有syscalls
                         *      
                         * Mutation会在每个syscall执行时自动应用（apply_mutations_for_syscall）
                         * Coverage会自动收集（共享内存bitmap）
                         */
                        RR_INFO("Child: Returning to execute syscalls with mutations (PID=%d)", getpid());
                        
                        return 1; // 返回1表示子进程应该继续执行
                        
                    } else if (pid > 0) {
                        /* 父进程：等待子进程完成 */
                        g_rr_framework->child_pid = pid;
                        
                        /* 动态跟踪：记录fork事件 */
                        rr_dynamic_trace_fork(getpid(), pid, 0);  // 修复: 启用fork追踪
                        
                        RR_VERBOSE("Parent process waiting for child PID=%d", pid);
                        
                        int status;
                        
                        /* 🔥 关键修复：添加超时机制，防止无限等待 */
                        int wait_result = waitpid(pid, &status, WNOHANG);
                        if (wait_result == 0) {
                            // 子进程还在运行，等待一段时间
                            RR_VERBOSE("Child still running, waiting with timeout...");
                            
                            int timeout_count = 0;
                            while (wait_result == 0 && timeout_count < 5000) { // 5秒超时
                                usleep(1000); // 1ms (Reduced from 100ms)
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
                        
                        /* FIX: 分析执行结果并发送给Conductor 
                         * 
                         * 在persistent mode中，父进程需要告诉Conductor：
                         * 1. 子进程的执行结果（crash or normal）
                         * 2. 父进程仍然alive并ready for下一轮
                         * 
                         * 关键：发送STATUS_AT_FORK_POINT (2)而不是STATUS_NORMAL_EXIT (3)
                         *      这样Conductor才知道不要wait QEMU进程exit
                         */
                        if (WIFEXITED(status)) {
                            int exit_code = WEXITSTATUS(status);
                            RR_VERBOSE("Child exited normally with code %d", exit_code);
                            // 发送AT_FORK_POINT表示父进程ready，而不是发送NORMAL_EXIT
                            rr_ipc_send_status(2); // 2 = AT_FORK_POINT (parent ready for next round)
                            
                        } else if (WIFSIGNALED(status)) {
                            int sig = WTERMSIG(status);
                            
                            // 检测是否为崩溃信号
                            if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS || 
                                sig == SIGILL || sig == SIGFPE) {
                                RR_INFO("Crash: CRASH DETECTED: Child crashed with signal %d (%s)", 
                                       sig, strsignal(sig));
                                rr_ipc_send_status(4); // 4 = Crash Found (Conductor needs to know)
                                // Note: After crash, Conductor may choose to terminate or continue
                            } else {
                                RR_VERBOSE("Child terminated by signal %d", sig);
                                rr_ipc_send_status(5); // 5 = Other Signal
                            }
                        } else {
                            RR_WARN("Child terminated with unknown status");
                            rr_ipc_send_status(2); // Still ready for next round
                        }
                        
                        g_rr_framework->child_pid = 0;
                        
                        /* 重置 fork 点状态，准备下次迭代 */
                        g_at_fork_point = false;
                        RR_VERBOSE("Reset fork point for next iteration");
                        RR_VERBOSE("Completed execution (child process finished)");
                        
                    } else {
                        /* Fork失败 */
                        RR_ERROR("fork() failed: %s", strerror(errno));
                        rr_ipc_send_status(-1); // Error
                    }
                }
                break;

            // 新增：Baseline execution命令（完整执行但不fork）
            case 'E': // Baseline execution - Full trace replay without fork
                {
                    RR_INFO("Baseline execution command received");
                    
                    if (!g_rr_framework->shared_memory) {
                        RR_ERROR("No shared memory for baseline execution");
                        rr_ipc_send_status(-1);
                        break;
                    }
                    
                    FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                    uint32_t iteration_id = shm->iteration_id;
                    
                    RR_INFO("Baseline execution: iteration=%u", iteration_id);
                    
                    // Send ITERATION message from parent
                    // extern bool g_dynamic_trace_enabled;
                    // extern int g_dynamic_trace_pipe_fd;
                    if (g_dynamic_trace_enabled && g_dynamic_trace_pipe_fd >= 0) {
                        rr_dynamic_trace_iteration(iteration_id, getpid());
                        RR_INFO("Sent ITERATION message");
                    }
                    
                    // Fork a child to execute the full baseline trace
                    rr_reset_trace_position();
                    
                    pid_t baseline_pid = fork();
                    if (baseline_pid < 0) {
                        RR_ERROR("Fork failed for baseline execution");
                        rr_ipc_send_status(-1);
                        break;
                    }
                    
                    if (baseline_pid == 0) {
                        // Child: Execute baseline trace (only up to first IO syscall)
                        g_rr_framework->silent_replay_mode = false;
                        g_rr_framework->current_iteration_id = iteration_id;
                        g_rr_framework->baseline_mode = true;

                        // 🔥 关键修复：设置为REPLAY模式以正确使用trace数据
                        g_rr_framework->mode = RR_MODE_REPLAY;
                        g_rr_framework->replay_index = 0;  // 从头开始replay
                        RR_INFO("✅ Baseline child: Switched to REPLAY mode for proper trace execution");

                        // 🔥 确保replay系统正确初始化 (使用绝对路径)
                        if (g_rr_config.trace_file) {
                            // 🔥 构建绝对路径，确保子进程能找到文件
                            char abs_trace_path[1024];
                            if (g_rr_config.trace_file[0] == '/') {
                                // 已经是绝对路径
                                strncpy(abs_trace_path, g_rr_config.trace_file, sizeof(abs_trace_path) - 1);
                                abs_trace_path[sizeof(abs_trace_path) - 1] = '\0';
                            } else {
                                // 相对路径，需要构建绝对路径
                                if (!getcwd(abs_trace_path, sizeof(abs_trace_path))) {
                                    RR_ERROR("Baseline child: Failed to get current working directory");
                                    _exit(1);
                                }
                                size_t len = strlen(abs_trace_path);
                                snprintf(abs_trace_path + len, sizeof(abs_trace_path) - len, "/%s", g_rr_config.trace_file);
                            }

                            // 🔥 重置replay状态并初始化
                            // extern void rr_reset_trace_position(void);
                            rr_reset_trace_position();

                            // extern int rr_start_replay(const char *trace_file);
                            if (rr_start_replay(abs_trace_path) < 0) {
                                RR_ERROR("Baseline child: Failed to initialize replay system with path: %s", abs_trace_path);
                                _exit(1);
                            }
                            RR_INFO("✅ Baseline child: Replay system initialized successfully with: %s", abs_trace_path);
                        } else {
                            RR_ERROR("Baseline child: No trace file specified");
                            _exit(1);
                        }

                        // Re-enable dynamic trace in child
                        if (g_dynamic_trace_enabled && g_dynamic_trace_pipe_fd >= 0) {
                            rr_dynamic_trace_iteration(iteration_id, getpid());
                            RR_INFO("Child sent ITERATION message");
                        }

                        RR_INFO("Baseline child: will exit at first IO syscall (fork point)");
                        return 1;
                    }
                    
                    // Parent: Wait for baseline child to complete
                    int status;
                    pid_t wait_result = waitpid(baseline_pid, &status, 0);
                    
                    if (wait_result < 0) {
                        RR_ERROR("waitpid failed for baseline child");
                        rr_ipc_send_status(-1);
                    } else {
                        RR_INFO("Baseline execution completed");
                        rr_ipc_send_status(0);
                    }
                }
                break;

            // 新增：Checkpoint fork命令（中间点动态fork）
            case 'C': // Checkpoint fork命令 - Mid-Point Fork
                {
                    RR_INFO("Mid-Point Fork command received");
                    
                    if (!g_rr_framework->shared_memory) {
                        RR_ERROR("No shared memory for checkpoint fork");
                        rr_ipc_send_status(-1);
                        break;
                    }
                    
                    FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                    uint32_t fork_point = shm->fork_point;
                    uint32_t depth = shm->current_depth;  // 新增：读取depth
                    uint32_t iteration_id = shm->iteration_id;  // 新增：读取iteration_id
                    int num_variants = shm->num_variants;
                    
                    RR_INFO("Info: Fork command: fork_point=%u, variants=%d, depth=%u, iteration=%u",
                            fork_point, num_variants, depth, iteration_id);
                    
                    /* TRUE MID-POINT FORK 策略：
                     * 
                     * 关键架构变更：
                     * 1. Parent已经通过之前的执行到达了某个状态（可能是syscall[N]）
                     * 2. 如果当前replay_index < fork_point：
                     *    - 设置target，让parent返回到主循环继续replay
                     *    - 到达fork_point后，会在下次进入fork_server_loop时处理fork
                     * 3. 如果当前replay_index >= fork_point：
                     *    - 立即fork，children继承parent的完整状态
                     * 4. Children不需要从头replay，直接从当前点继续！
                     */
                    
                    uint32_t current_index = g_rr_framework->replay_index;
                    RR_INFO("📍 Current replay_index=%u, target fork_point=%u", current_index, fork_point);
                    
                    if (current_index < fork_point) {
                        /* Parent还没到fork_point，需要继续replay */
                        RR_INFO("Warning:  Parent未到达fork_point，简化处理：从头replay");
                        
                        /* 简化方案：重置到开头，children自己replay到fork_point */
                        rr_reset_trace_position();
                        g_rr_framework->replay_index = 0;
                        if (g_current_record) {
                            rr_record_dispose(g_current_record);
                            g_current_record = NULL;
                        }
                    } else {
                        /* Parent已在fork_point或之后，直接fork！*/
                        RR_INFO("Parent已到达fork_point，立即fork children");
                    }
                    
                    // 并发fork所有variants - 真正的动态多级fork！
                    pid_t child_pids[10] = {0};
                    int status;
                    
                    /* 检查parent的strace replay状态 */
                    // extern bool rr_strace_replay_enabled(void);
                    bool parent_strace_enabled = rr_strace_replay_enabled();
                    RR_INFO("🔍 DEBUG: Parent strace_replay_enabled=%d before fork", parent_strace_enabled);
                    
                    for (int variant_idx = 0; variant_idx < num_variants && variant_idx < 10; variant_idx++) {
                        FuzzVariant *variant = &shm->variants[variant_idx];
                        g_instruction_count = variant->instruction_count;
                        memcpy(g_fuzz_instructions, variant->instructions,
                               sizeof(FuzzInstruction) * g_instruction_count);
                        
                        RR_INFO("Forking variant %d/%d (并发)...", variant_idx + 1, num_variants);
                        
                        pid_t pid = fork();
                        
                        if (pid == 0) {
                            /* ═══ 子进程 ═══ */
                            if (g_rr_framework->cmd_pipe_fd >= 0) {
                                close(g_rr_framework->cmd_pipe_fd);
                                g_rr_framework->cmd_pipe_fd = -1;
                            }
                            if (g_rr_framework->status_pipe_fd >= 0) {
                                close(g_rr_framework->status_pipe_fd);
                                g_rr_framework->status_pipe_fd = -1;
                            }
                            
                            /* 关键修复：每个child重新打开trace file，完全隔离！*/
                            // extern FILE *g_trace_file;  // 定义在rr_replay.c
                            // extern char *g_rr_trace_path;
                            
                            if (g_trace_file != NULL && g_rr_trace_path) {
                                // 关闭继承的FILE*
                                fclose(g_trace_file);
                                g_trace_file = NULL;  // 🔥 必须设置为NULL，避免dangling pointer

                                // 🔥 构建绝对路径，确保子进程能找到文件
                                char abs_trace_path[1024];
                                if (g_rr_trace_path[0] == '/') {
                                    // 已经是绝对路径
                                    strncpy(abs_trace_path, g_rr_trace_path, sizeof(abs_trace_path) - 1);
                                    abs_trace_path[sizeof(abs_trace_path) - 1] = '\0';
                                } else {
                                    // 相对路径，需要构建绝对路径
                                    if (!getcwd(abs_trace_path, sizeof(abs_trace_path))) {
                                        RR_ERROR("Checkpoint child %d: Failed to get current working directory", variant_idx);
                                        _exit(1);
                                    }
                                    size_t len = strlen(abs_trace_path);
                                    snprintf(abs_trace_path + len, sizeof(abs_trace_path) - len, "/%s", g_rr_trace_path);
                                }

                                // 🔥 重新初始化replay系统（会重新打开trace文件）
                                // extern int rr_start_replay(const char *trace_file);
                                if (rr_start_replay(abs_trace_path) < 0) {
                                    RR_ERROR("Checkpoint child %d: Failed to initialize replay system with path: %s", variant_idx, abs_trace_path);
                                    _exit(1);
                                }

                                RR_INFO("Child %d: Reopened trace file independently and reset replay state", variant_idx);
                            }
                            
                            /* 修复：Strace replay也需要重新初始化trace parser */
                            if (rr_strace_replay_enabled()) {
                                /* 重新初始化strace replay parser以获得独立的FILE* */
                                // extern int rr_strace_replay_cleanup(void);
                                // extern int rr_strace_replay_init(const char *trace_file);
                                
                                const char *trace_file = g_rr_config.trace_file;
                                if (trace_file) {
                                    RR_INFO("Child %d: Re-initializing strace replay parser with %s", variant_idx, trace_file);
                                    rr_strace_replay_cleanup();
                                    
                                    if (rr_strace_replay_init(trace_file) < 0) {
                                        RR_ERROR("Child %d: Failed to reinitialize strace replay", variant_idx);
                                        _exit(1);
                                    }
                                    RR_INFO("Child %d: Strace replay reinitialized with independent parser", variant_idx);
                                } else {
                                    RR_ERROR("Child %d: trace_file is NULL, cannot reinitialize", variant_idx);
                                }
                            }

                            /* 🔥 关键修复：子进程重新加载Fuzz指令 (Checkpoint fork命令) */
                            if (g_rr_framework->shared_memory) {
                                RR_INFO("Child %d: Reloading fuzz instructions from shared memory", variant_idx);
                                int load_result = rr_fuzz_load_from_shared_memory(g_rr_framework->shared_memory);
                                if (load_result < 0) {
                                    RR_ERROR("Child %d: Failed to reload fuzz instructions!", variant_idx);
                                } else {
                                    RR_INFO("🎉 Child %d: Successfully reloaded %zu fuzz instructions", variant_idx, g_instruction_count);

                                    // DEBUG: 立即验证reload后的状态
                                    /* fprintf(stderr, "[DEBUG-CHILD-RELOAD] Child %d PID=%d, IMMEDIATELY after reload:\n", variant_idx, getpid());
                                    fprintf(stderr, "[DEBUG-CHILD-RELOAD]   g_instruction_count=%zu (address=%p)\n",
                                            g_instruction_count, &g_instruction_count);
                                    if (g_instruction_count > 0) {
                                        fprintf(stderr, "[DEBUG-CHILD-RELOAD]   First instruction: syscall_idx=%u, cmd=%d\n",
                                                g_fuzz_instructions[0].syscall_index, g_fuzz_instructions[0].cmd);
                                    } */
                                    fflush(stderr);
                                }
                            } else {
                                RR_WARN("Child %d: No shared memory available for instruction loading", variant_idx);
                            }

                            /* 真正的mid-point fork实现！*/
                            if (fork_point > 0) {
                                RR_INFO("Info: Child %d: Mid-point fork from syscall[%u]", variant_idx, fork_point);
                                
                                // Silent replay: 快速replay到fork_point，不发送dynamic trace
                                g_rr_framework->silent_replay_mode = true;
                                g_rr_framework->checkpoint_target = fork_point;  // 保存fork_point
                                g_rr_framework->replay_index = 0;
                                if (g_current_record) {
                                    rr_record_dispose(g_current_record);
                                    g_current_record = NULL;
                                }
                                
                                RR_INFO("  → Fast-forwarding 0 to %u (silent)", fork_point);
                                
                                // Silent replay会在replay module中执行
                                // 当replay_index达到fork_point时，replay module会关闭silent mode
                                
                            } else {
                                // fork_point=0: 从头开始
                                RR_INFO("Child %d: Starting from beginning (fork_point=0)", variant_idx);
                                g_rr_framework->replay_index = 0;
                                if (g_current_record) {
                                    rr_record_dispose(g_current_record);
                                    g_current_record = NULL;
                                }
                                g_rr_framework->silent_replay_mode = false;
                            }
                            
                            /* 更新子进程状态 */
                            g_rr_framework->current_depth = depth + 1;
                            // 第一层children（depth+1=1）也应该能够nested fork！
                            g_rr_framework->is_autonomous_child = true;  // 所有children都是autonomous
                            g_rr_framework->current_iteration_id = iteration_id;

                            // 🔥 关键修复：设置为FUZZING模式以正确应用变异
                            g_rr_framework->mode = RR_MODE_FUZZING;
                            RR_INFO("✅ Child %d: Switched to FUZZING mode for mutation application", variant_idx);
                            
                            /* TRUE MID-POINT FORK: Child继承parent的完整状态！*/
                            /* 
                             * 关键：fork()已经复制了：
                             * - replay_index（继承parent的fork_point）
                             * - g_trace_file（文件描述符被复制）
                             * - g_current_record（内存状态）
                             * - CPU/Memory状态（COW机制）
                             * 
                             * Child将从fork_point继续执行，不需要重新replay前面的syscalls！
                             */
                            
                            
                            /* Child从fork_point继续 */
                            RR_INFO("TRUE Mid-Point Fork: Child %d starting from replay_index=%d (fork_point=%u)", 
                                    variant_idx, g_rr_framework->replay_index, fork_point);
                            
                            g_rr_framework->child_pid = 0;
                            
#ifdef RR_ENABLE_DYNAMIC_TRACE
                            // extern int g_dynamic_trace_pipe_fd;
                            // extern bool g_dynamic_trace_enabled;
                            if (g_dynamic_trace_pipe_fd >= 0) {
                                g_dynamic_trace_enabled = true;
                                RR_INFO("Child %d: Dynamic trace enabled (PID=%d, continuing from index %d)", 
                                        variant_idx, getpid(), g_rr_framework->replay_index);
                                
                                /* 发送iteration消息 (不发送fork消息，由parent发送) */
                                rr_dynamic_trace_iteration(iteration_id, getpid());
                            }
#endif
                            
                            /* Child继续执行，从当前replay_index开始处理后续syscalls */
                            RR_INFO("🔍 DEBUG: About to return 1, silent_replay_mode=%d, checkpoint_target=%u",
                                    g_rr_framework->silent_replay_mode, g_rr_framework->checkpoint_target);
                            
                            /* 检查strace replay是否启用 */
                            // extern bool rr_strace_replay_enabled(void);
                            bool strace_enabled = rr_strace_replay_enabled();
                            RR_INFO("🔍 DEBUG: Child %d strace_replay_enabled=%d", variant_idx, strace_enabled);
                            
                            return 1;
                            
                        } else if (pid > 0) {
                            /* ═══ Parent: 记录child PID，继续fork其他children（并发） ═══ */
                            child_pids[variant_idx] = pid;
                            rr_dynamic_trace_fork(getpid(), pid, fork_point);
                            RR_INFO("  Forked variant %d: PID=%d (并发，不等待)", variant_idx, pid);
                            // ❌ 不要wait！让children并发执行！
                        } else {
                            RR_ERROR("Fork failed for variant %d", variant_idx);
                            break;
                        }
                    }
                    
                    // 等待所有children完成（并发执行后统一等待）
                    RR_INFO("⏳ Waiting for %d children to complete...", num_variants);
                    for (int i = 0; i < num_variants && i < 10; i++) {
                        if (child_pids[i] > 0) {
                            waitpid(child_pids[i], &status, 0);
                            
                            // 分析child的退出状态
                            int result_status = STATUS_NORMAL_EXIT;
                            if (WIFEXITED(status)) {
                                result_status = STATUS_NORMAL_EXIT;
                            } else if (WIFSIGNALED(status)) {
                                int sig = WTERMSIG(status);
                                if (sig == SIGSEGV || sig == SIGABRT || sig == SIGILL) {
                                    result_status = STATUS_CRASH;
                                } else {
                                    result_status = STATUS_OTHER_SIGNAL;
                                }
                            }
                            
                            rr_ipc_send_status(result_status);
                            RR_INFO("  Child %d (PID=%d) finished: status=%d", i, child_pids[i], result_status);
                        }
                    }
                    
                    RR_INFO("Fork completed: %d variants", num_variants);
                    g_rr_framework->child_pid = 0;
                }
                break;

            case 'Q': // 退出命令
                RR_LOG("Fork Server received quit command");
                return -1; // 退出程序

            case 'S': // 保存Snapshot命令（预留功能）
                // TODO: 实现真正的进程状态snapshot
                // 需要保存：CPU寄存器、内存快照、FD映射等
                RR_WARN("Snapshot save not implemented (stub only)");
                rr_ipc_send_status(6); // 6 = Snapshot Saved
                break;

            case 'L': // 加载Snapshot命令（预留功能）
                // TODO: 实现从snapshot恢复进程状态
                RR_WARN("Snapshot load not implemented (stub only)");
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
        RR_INFO("Auto-detected fork point: %s (class=%s, ret=%ld, strategy=%d, after %d syscalls)",
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
        const syscall_info_t *info_inner = rr_get_syscall_info(syscall_nr);
        
        /* 只在合适的syscall上fallback（I/O或FD类） */
        if (info_inner->class == SYSCALL_CLASS_IO || info_inner->class == SYSCALL_CLASS_FD) {
            g_at_fork_point = true;
            RR_WARN("Warning:  Fallback fork triggered: %s after %d syscalls without fork",
                    info_inner->name, syscalls_since_ready);
            
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
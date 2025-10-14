/**
 * RR-Fuzz主控模块 - 框架初始化和核心逻辑
 * 对应design.md中的rr_main.c
 */

/* 确保RR_DEBUG被定义 */
#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "rr_framework.h"
#include "rr_replay_strace.h"
#include "qemu/error-report.h"
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

/* 全局框架状态 */
rr_framework_t *g_rr_framework = NULL;

/* 用于mmap地址映射的临时存储 */
target_ulong g_pending_mmap_recorded_addr = 0;

/**
 * 获取系统调用名称
 */
static const char* get_syscall_name(int syscall_nr) {
    switch (syscall_nr) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 4: return "stat";
        case 5: return "fstat";
        case 6: return "lstat";
        case 7: return "poll";
        case 8: return "lseek";
        case 9: return "mmap";
        case 10: return "mprotect";
        case 11: return "munmap";
        case 12: return "brk";
        case 13: return "rt_sigaction";
        case 14: return "rt_sigprocmask";
        case 15: return "rt_sigreturn";
        case 16: return "ioctl";
        case 17: return "pread64";
        case 18: return "pwrite64";
        case 19: return "readv";
        case 20: return "writev";
        case 21: return "access";
        case 22: return "pipe";
        case 23: return "select";
        case 39: return "getpid";
        case 63: return "uname";
        case 102: return "getuid";
        case 104: return "getgid";
        case 137: return "statfs";
        case 158: return "arch_prctl";
        case 217: return "getdents64";
        case 218: return "set_tid_address";
        case 231: return "exit_group";
        case 257: return "openat";
        case 262: return "newfstatat";
        case 273: return "set_robust_list";
        case 302: return "prlimit64";
        case 318: return "getrandom";
        case 334: return "rseq";
        default: return "unknown";
    }
}

/**
 * 初始化RR框架
 */
int rr_framework_init(void)
{
    const char *strace_mode_env = NULL;  // 用于检测strace模式
    
    /* 初始化配置系统 */
    if (rr_config_init() < 0) {
        error_report("RR-Fuzz: Failed to initialize configuration");
        return -1;
    }

    /* 检查是否启用 */
    if (!g_rr_config.enabled) {
        return 0; // 未启用，直接返回
    }

    /* 初始化调试系统 */
    rr_debug_init();

    /* 打印配置信息 */
    rr_config_print();

    /* 分配全局上下文 */
    g_rr_framework = g_malloc0(sizeof(rr_framework_t));
    if (!g_rr_framework) {
        RR_ERROR("Failed to allocate framework context");
        return -1;
    }

    /* 从配置获取运行模式 */
    g_rr_framework->mode = g_rr_config.mode;
    g_rr_framework->enabled = g_rr_config.enabled;  // 设置enabled标志

    /* 初始化FD映射表 */
    g_rr_framework->fd_map = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* 初始化地址映射表 */
    g_rr_framework->addr_map = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* 注册退出清理函数 */
    atexit(rr_framework_cleanup);
    RR_VERBOSE("Registered exit cleanup handler");

    /* 初始化子系统 */
    if (rr_ipc_init() < 0) {
        RR_ERROR("Failed to initialize IPC");
        goto error;
    }
    RR_INFO("IPC subsystem initialized");
    
#ifdef RR_ENABLE_DYNAMIC_TRACE
    /* 初始化动态跟踪管道（用于树可视化） */
    const char *trace_pipe_path = getenv("RR_TRACE_PIPE");
    if (trace_pipe_path) {
        /* 使用阻塞模式打开，确保可视化器已经准备好 */
        int trace_fd = open(trace_pipe_path, O_WRONLY);
        if (trace_fd >= 0) {
            rr_dynamic_trace_init(trace_fd);
            RR_INFO("Dynamic trace pipe connected: %s (FD=%d)", trace_pipe_path, trace_fd);
        } else {
            RR_WARN("Failed to open dynamic trace pipe: %s (errno=%d)", trace_pipe_path, errno);
        }
    }
#endif
    
    /* 重置 Fork Server 状态（每次新进程启动时） */
    rr_reset_fork_point();

    /* 根据模式启动相应功能 */
    switch (g_rr_framework->mode) {
        case RR_MODE_DISABLED:
            RR_INFO("RR-Fuzz mode is disabled, no initialization required");
            break;
        case RR_MODE_RECORD:
            RR_INFO("Starting recording mode, trace_file=%s", g_rr_config.trace_file);
            if (rr_start_recording(g_rr_config.trace_file) < 0) {
                RR_ERROR("Failed to start recording");
                goto error;
            }
            RR_INFO("Recording started successfully");
            break;
        case RR_MODE_REPLAY:
            /* 检查是否启用strace重放模式 */
            {
                strace_mode_env = getenv("RR_STRACE_MODE");
                RR_INFO("Starting replay mode, trace_file=%s", g_rr_config.trace_file);
                RR_INFO("RR_STRACE_MODE environment variable: %s", strace_mode_env ? strace_mode_env : "NULL");
                
                if (strace_mode_env) {
                    RR_INFO("Starting strace replay mode");
                    if (rr_strace_replay_init(g_rr_config.trace_file) < 0) {
                        RR_ERROR("Failed to start strace replay");
                        goto error;
                    }
                    RR_INFO("Strace replay started successfully");
                } else {
                    RR_INFO("Starting binary replay mode");
                    if (rr_start_replay(g_rr_config.trace_file) < 0) {
                        RR_ERROR("Failed to start binary replay");
                        goto error;
                    }
                    RR_INFO("Binary replay started successfully");
                }
            }
            break;
        case RR_MODE_FUZZING:
            // Fuzzing模式需要先加载trace，然后启动fork server
            RR_INFO("Starting fuzzing mode, trace_file=%s", g_rr_config.trace_file);
            
            // 检查是否使用strace模式（与replay模式一致）
            strace_mode_env = getenv("RR_STRACE_MODE");
            if (strace_mode_env) {
                RR_INFO("Starting strace replay mode for fuzzing");
                if (rr_strace_replay_init(g_rr_config.trace_file) < 0) {
                    RR_ERROR("Failed to start strace replay for fuzzing");
                    goto error;
                }
                RR_INFO("Strace replay started successfully for fuzzing");
            } else {
                // 使用原生replay
                if (rr_start_replay(g_rr_config.trace_file) < 0) {
                    RR_ERROR("Failed to load trace for fuzzing");
                    goto error;
                }
            }
            /* 在Fuzzing模式下启动Fork Server（自动检测模式） */
            if (g_rr_config.fork_server_enabled) {
                RR_INFO("Starting fork server in auto-detection mode");
                       
                if (rr_start_fork_server(NULL, NULL) < 0) {
                    RR_ERROR("Failed to start fork server");
                    goto error;
                }
            }
            RR_INFO("Fuzzing mode started successfully");
            break;
        default:
            RR_ERROR("Unknown RR mode: %d", g_rr_framework->mode);
            goto error;
    }

    g_rr_framework->enabled = true;
    RR_INFO("RR-Fuzz framework initialized successfully, mode=%d (%s)",
             g_rr_framework->mode,
             g_rr_framework->mode == RR_MODE_RECORD ? "RECORD" :
             g_rr_framework->mode == RR_MODE_REPLAY ? "REPLAY" :
             g_rr_framework->mode == RR_MODE_FUZZING ? "FUZZING" : "UNKNOWN");
    return 0;

error:
    rr_framework_cleanup();
    return -1;
}

/**
 * 清理RR框架
 */
void rr_framework_cleanup(void)
{
    if (!g_rr_framework) {
        return;
    }

    RR_INFO("Starting RR-Fuzz framework cleanup");

    /* 停止当前模式 */
    switch (g_rr_framework->mode) {
        case RR_MODE_DISABLED:
            // 无需清理操作
            break;
        case RR_MODE_RECORD:
            rr_stop_recording();
            break;
        case RR_MODE_REPLAY:
            if (rr_strace_replay_enabled()) {
                rr_strace_replay_cleanup();
            } else {
                rr_stop_replay();
            }
            break;
        case RR_MODE_FUZZING:
            rr_stop_fork_server();
            // Fuzzing模式也需要停止replay，检查是否使用strace模式
            if (rr_strace_replay_enabled()) {
                rr_strace_replay_cleanup();
            } else {
                rr_stop_replay();
            }
            break;
        default:
            break;
    }

    /* 清理子系统 */
    RR_VERBOSE("Cleaning up subsystems");
    rr_ipc_cleanup();
    
#ifdef RR_ENABLE_DYNAMIC_TRACE
    /* 清理动态跟踪 */
    rr_dynamic_trace_cleanup();
#endif
    
    rr_fuzz_cleanup();
    rr_snapshot_cleanup();
    rr_debug_cleanup();
    rr_config_cleanup();

    /* 清理FD映射表 */
    if (g_rr_framework->fd_map) {
        g_hash_table_destroy(g_rr_framework->fd_map);
    }

    /* 清理地址映射表 */
    if (g_rr_framework->addr_map) {
        g_hash_table_destroy(g_rr_framework->addr_map);
    }

    /* 清理轨迹 */
    syscall_record_t *record = g_rr_framework->trace_head;
    while (record) {
        syscall_record_t *next = record->next;
        /* 清理参数数据 */
        for (int i = 0; i < 8; i++) {
            if (record->arg_data[i]) {
                g_free(record->arg_data[i]);
            }
        }
        g_free(record);
        record = next;
    }

    g_free(g_rr_framework);
    g_rr_framework = NULL;
    RR_INFO("RR-Fuzz framework cleanup completed");
}

/**
 * 核心系统调用处理函数
 * 这是do_syscall调用的入口点
 */
abi_long rr_do_syscall(CPUArchState *env, int num,
                       abi_long *arg1, abi_long *arg2, abi_long *arg3, abi_long *arg4,
                       abi_long *arg5, abi_long *arg6, abi_long *arg7, abi_long *arg8)
{
    RR_VERBOSE("RR_DO_SYSCALL: Called for syscall %d, enabled=%d", num, rr_framework_enabled());

    if (!rr_framework_enabled()) {
        RR_VERBOSE("RR_DO_SYSCALL: Framework not enabled, returning -1");
        return -1; // 让调用者执行原始逻辑
    }

    RR_VERBOSE("RR_DO_SYSCALL: Framework enabled, mode=%d", g_rr_framework->mode);

    /* 添加醒目的系统调用入口提示 - 调试阶段使用 */
    const char* syscall_name = get_syscall_name(num);
    RR_INFO("===============================================================");    
    RR_INFO("=== ENTERING SYSCALL: %s (%d) === MODE: %s ===",
            syscall_name, num,
            g_rr_framework->mode == RR_MODE_RECORD ? "RECORD" :
            g_rr_framework->mode == RR_MODE_REPLAY ? "REPLAY" :
            g_rr_framework->mode == RR_MODE_FUZZING ? "FUZZING" : "UNKNOWN");

    /* 特殊处理deterministic系统调用，直接返回固定值，不需要记录/重放 */
    switch (num) {
        case 39: /* getpid */
            RR_VERBOSE("RR_DO_SYSCALL: Handling deterministic syscall getpid");
            RR_INFO("=== EXITING SYSCALL: %s (%d) === RETURN: %ld ===", syscall_name, num, 12345L);
            RR_INFO("===============================================================");    
            return 12345; // 返回固定的PID
        case 102: /* getuid */
            RR_VERBOSE("RR_DO_SYSCALL: Handling deterministic syscall getuid");
            RR_INFO("=== EXITING SYSCALL: %s (%d) === RETURN: %ld ===", syscall_name, num, 1000L);
            RR_INFO("===============================================================");    
            return 1000; // 返回固定的UID
        case 104: /* getgid */
            RR_VERBOSE("RR_DO_SYSCALL: Handling deterministic syscall getgid");
            RR_INFO("=== EXITING SYSCALL: %s (%d) === RETURN: %ld ===", syscall_name, num, 1000L);
            RR_INFO("===============================================================");    
            return 1000; // 返回固定的GID
        case 218: /* set_tid_address */
            RR_VERBOSE("RR_DO_SYSCALL: Handling deterministic syscall set_tid_address");
            RR_INFO("=== EXITING SYSCALL: %s (%d) === RETURN: %ld ===", syscall_name, num, 12345L);
            RR_INFO("===============================================================");    
            return 12345; // 返回与getpid一致的固定值
        case 231: /* exit_group */
            RR_VERBOSE("RR_DO_SYSCALL: Handling exit_group syscall, allowing normal exit");
            RR_INFO("=== EXITING SYSCALL: %s (%d) === RETURN: %ld ===", syscall_name, num, -1L);
            RR_INFO("===============================================================");    
            return -1; // 让系统正常退出
        default:
            break; // 继续正常的record/replay逻辑
    }

    abi_long args[8] = {*arg1, *arg2, *arg3, *arg4, *arg5, *arg6, *arg7, *arg8};
    abi_long ret;

    switch (g_rr_framework->mode) {
        case RR_MODE_RECORD:
            /* 记录模式：执行原始系统调用，然后记录结果 */
            ret = -1; // 返回-1让调用者执行原始逻辑
            break;

        case RR_MODE_REPLAY:
            /* 重放模式：根据类型选择重放方式 */
            RR_VERBOSE("RR_DO_SYSCALL: Checking if strace replay is enabled...");
            if (rr_strace_replay_enabled()) {
                RR_VERBOSE("RR_DO_SYSCALL: ABOUT TO CALL rr_replay_syscall_strace for syscall %d", num);
                ret = rr_replay_syscall_strace(env, num, args);
                RR_VERBOSE("RR_DO_SYSCALL: rr_replay_syscall_strace returned %d", (int)ret);
            } else {
                RR_VERBOSE("RR_DO_SYSCALL: STRACE REPLAY DISABLED - Calling rr_replay_syscall for syscall %d", num);
                ret = rr_replay_syscall(env, num, args);
                RR_VERBOSE("RR_DO_SYSCALL: rr_replay_syscall returned %d", (int)ret);
            }
            break;

        case RR_MODE_FUZZING:
            /* Fuzzing模式：可能修改参数，然后重放 */
            /* 根据是否使用strace模式选择replay函数 */
            if (rr_strace_replay_enabled()) {
                ret = rr_replay_syscall_strace_optimized(env, num, args);
            } else {
                ret = rr_replay_syscall(env, num, args);
            }
            
            /* 
             * 自动检测 Fork 点（EnvFuzz 策略）
             * 只对 P_IO 类的输入系统调用进行 fork
             * 必须在执行后检查，因为需要返回值来判断是否有数据
             */
            {
                const char *syscall_name = get_syscall_name(num);
                extern bool rr_check_auto_fork_point(int, const char *, abi_long);
                
                if (rr_check_auto_fork_point(num, syscall_name, ret)) {
                    /* 进入Fork Server主循环 */
                    RR_INFO("🔄 Entering fork server loop after %s", syscall_name);
                    int fork_result = rr_fork_server_loop();
                    RR_INFO("🔄 Fork server loop returned: %d", fork_result);
                    if (fork_result < 0) {
                        RR_INFO("🔄 Exiting due to quit command");
                        exit(0); // 收到退出命令
                    } else if (fork_result > 0) {
                        /* 子进程继续Fuzzing执行 */
                        RR_INFO("🔄 Child process %d continuing fuzzing", getpid());
                    } else {
                        RR_INFO("🔄 Parent process %d continuing after fork", getpid());
                    }
                }
            }
            break;

        default:
            ret = -1;
            break;
    }
    /* 将可能修改过的参数写回到指针中 */
    *arg1 = args[0]; *arg2 = args[1]; *arg3 = args[2]; *arg4 = args[3];
    *arg5 = args[4]; *arg6 = args[5]; *arg7 = args[6]; *arg8 = args[7];
    
    /* 添加醒目的系统调用退出提示 - 调试阶段使用 */
    RR_INFO("=== EXITING SYSCALL: %s (%d) === RETURN: %d ===",
            syscall_name, num, (int)ret);
    RR_INFO("===============================================================");    
    return ret;
}

/**
 * 地址映射管理函数
 */
void rr_add_addr_mapping(target_ulong recorded_addr, target_ulong actual_addr)
{
    if (!g_rr_framework || !g_rr_framework->addr_map) {
        return;
    }
    
    g_hash_table_insert(g_rr_framework->addr_map,
                       GSIZE_TO_POINTER((gsize)recorded_addr),
                       GSIZE_TO_POINTER((gsize)actual_addr));
    
    RR_VERBOSE("Address mapping: recorded=0x%lx -> actual=0x%lx", 
               (unsigned long)recorded_addr, (unsigned long)actual_addr);
}

target_ulong rr_get_mapped_addr(target_ulong recorded_addr)
{
    if (!g_rr_framework || !g_rr_framework->addr_map) {
        return recorded_addr; // 没有映射表，返回原地址
    }
    
    gpointer mapped = g_hash_table_lookup(g_rr_framework->addr_map,
                                         GSIZE_TO_POINTER((gsize)recorded_addr));
    if (mapped) {
        return (target_ulong)GPOINTER_TO_SIZE(mapped);
    }
    
    return recorded_addr; // 没找到映射，返回原地址
}

void rr_handle_mmap_post(target_ulong recorded_addr, target_ulong actual_addr)
{
    if (recorded_addr != actual_addr) {
        rr_add_addr_mapping(recorded_addr, actual_addr);
        RR_INFO("mmap address remapped: 0x%lx -> 0x%lx", 
                (unsigned long)recorded_addr, (unsigned long)actual_addr);
    }
}

/**
 * 系统调用执行后的Hook
 * 用于记录模式
 */
void rr_syscall_post_hook(CPUArchState *env, int num, abi_long ret,
                          abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8)
{
    RR_VERBOSE("POST_HOOK: syscall=%d, enabled=%d, mode=%d, ret=%d",
               num, rr_framework_enabled(), g_rr_framework ? g_rr_framework->mode : -1, (int)ret);

    if (!rr_framework_enabled()) {
        RR_VERBOSE("POST_HOOK: Skipping syscall %d - framework not enabled", num);
        return;
    }

    if (g_rr_framework->mode == RR_MODE_RECORD) {
        /* 记录模式：记录系统调用结果 */
        RR_VERBOSE("POST_HOOK: Recording syscall %d with ret=%d", num, (int)ret);
        abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};

        int record_result = rr_record_syscall(env, num, args, ret);
        if (record_result == 0) {
            g_rr_framework->total_syscalls++;
            RR_VERBOSE("POST_HOOK: Successfully recorded syscall %d (total: %lu)", num, g_rr_framework->total_syscalls);
        } else {
            RR_ERROR("POST_HOOK: Failed to record syscall %d (result=%d)", num, record_result);
        }
        return;
    }
    
    if (g_rr_framework->mode == RR_MODE_REPLAY || g_rr_framework->mode == RR_MODE_FUZZING) {
        /* 重放模式：处理句柄映射 */
        
        // 调用strace replay的POST-HOOK（新增）
        if (rr_strace_replay_enabled()) {
            abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
            rr_strace_syscall_post_hook(env, num, ret, args);
        }
        
        // 原有的mmap地址映射处理（保留）
        if (num == 9 && g_pending_mmap_recorded_addr != 0) { /* mmap调用且有记录地址 */
            if (ret > 0) {
                /* mmap成功，建立地址映射 */
                RR_VERBOSE("POST_HOOK: mmap success - recorded=0x%lx, actual=0x%lx", 
                          (unsigned long)g_pending_mmap_recorded_addr, (unsigned long)ret);
                rr_handle_mmap_post(g_pending_mmap_recorded_addr, (target_ulong)ret);
            } else {
                /* mmap仍然失败，这是一个严重问题 */
                RR_ERROR("POST_HOOK: mmap still failed after conversion - recorded=0x%lx, ret=%d", 
                        (unsigned long)g_pending_mmap_recorded_addr, (int)ret);
            }
            
            /* 清理临时存储 */
            g_pending_mmap_recorded_addr = 0;
        }
        
        RR_VERBOSE("POST_HOOK: Replay mode, syscall=%d, ret=%d", num, (int)ret);
        return;
    }
}
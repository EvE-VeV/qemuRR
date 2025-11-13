/**
 * RR-Fuzz主控模块 - 框架初始化和核心逻辑
 * 对应design.md中的rr_main.c
 */

/* 确保RR_DEBUG被定义 */
#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "rr_framework.h"
#include "../replay/rr_replay_strace.h"
#include "../record/rr_aux_data.h"
#include "../utils/rr_dynamic_trace.h"
#include "../fuzzing/qemu_integration/rr_coverage.h"
#include "rr_constants.h"
#include "qemu/error-report.h"
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

/* 全局框架状态 */
rr_framework_t *g_rr_framework = NULL;

/* 用于mmap地址映射的临时存储 */
target_ulong g_pending_mmap_recorded_addr = 0;
target_ulong g_pending_mmap_length = 0;

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
 * 判断某个 syscall 的返回值偏离是否为预期行为
 * 
 * @param syscall_nr syscall 编号
 * @param recorded 记录的返回值
 * @param actual 实际返回值
 * @return true 如果偏离是预期的 (如 ASLR 导致的地址偏离)
 */
static bool is_expected_deviation(int syscall_nr, abi_long recorded, abi_long actual) {
    /* mmap 地址偏离是预期的 (ASLR) */
#ifdef TARGET_NR_mmap
    if (syscall_nr == TARGET_NR_mmap) {
        return true;
    }
#endif
#ifdef TARGET_NR_mmap2
    if (syscall_nr == TARGET_NR_mmap2) {
        return true;
    }
#endif
    
    /* brk 地址偏离也是预期的 */
    if (syscall_nr == TARGET_NR_brk) {
        return true;
    }
    
    /* mremap 地址偏离也是预期的 */
#ifdef TARGET_NR_mremap
    if (syscall_nr == TARGET_NR_mremap) {
        return true;
    }
#endif
    
    /* set_tid_address 返回线程ID,每次运行都会不同 */
#ifdef TARGET_NR_set_tid_address
    if (syscall_nr == TARGET_NR_set_tid_address) {
        return true;
    }
#endif
    
    /* readlink 返回值可能因为路径长度变化 */
#ifdef TARGET_NR_readlink
    if (syscall_nr == TARGET_NR_readlink) {
        return true;
    }
#endif
#ifdef TARGET_NR_readlinkat
    if (syscall_nr == TARGET_NR_readlinkat) {
        return true;
    }
#endif
    
    /* gettid 返回线程ID */
#ifdef TARGET_NR_gettid
    if (syscall_nr == TARGET_NR_gettid) {
        return true;
    }
#endif
    
    /* getpid/getppid 可能会变化 */
    // 处理架构差异：某些架构使用不同的syscall名称
#ifdef TARGET_NR_getpid
    if (syscall_nr == TARGET_NR_getpid) return true;
#endif
#ifdef TARGET_NR_getxpid  // alpha架构
    if (syscall_nr == TARGET_NR_getxpid) return true;
#endif
#ifdef TARGET_NR_getppid
    if (syscall_nr == TARGET_NR_getppid) return true;
#endif
    
    return false;
}

/**
 * FD 环境对齐 (任务3)
 * 在 replay 模式下,尽量让 guest 程序的 FD 分配与 record 时一致
 */
static int align_fd_state(void) {
    if (g_rr_config.mode != RR_MODE_REPLAY && g_rr_config.mode != RR_MODE_FUZZING) {
        return 0;
    }
    
    RR_INFO("Aligning FD state for replay/fuzzing mode...");
    
    /* 获取 IPC FD，确保不会关闭它们 */
    int ipc_cmd_fd = -1, ipc_status_fd = -1;
    const char *cmd_fd_str = getenv("RR_CMD_PIPE");
    const char *status_fd_str = getenv("RR_STATUS_PIPE");
    if (cmd_fd_str) {
        ipc_cmd_fd = atoi(cmd_fd_str);
        RR_VERBOSE("Protecting IPC command FD %d from alignment", ipc_cmd_fd);
    }
    if (status_fd_str) {
        ipc_status_fd = atoi(status_fd_str);
        RR_VERBOSE("Protecting IPC status FD %d from alignment", ipc_status_fd);
    }
    
    /* 1. 查找最小的可用 FD (跳过 0,1,2 标准流) */
    int min_available_fd = -1;
    for (int fd = RR_FIRST_USER_FD; fd < RR_MAX_CHECKED_FD; fd++) {
        if (fcntl(fd, F_GETFD) == -1) {
            /* FD 不存在,这是第一个可用的 */
            min_available_fd = fd;
            break;
        }
    }
    
    if (min_available_fd == -1) {
        RR_WARN("No available FD found in range %d-%d, cannot align",
                RR_FIRST_USER_FD, RR_MAX_CHECKED_FD);
        return 0; /* 不阻塞初始化 */
    }
    
    RR_INFO("First available FD: %d", min_available_fd);
    
    /* 2. 如果第一个可用 FD > 3,说明有 FD 被 qemu 占用 */
    /*    尝试关闭非关键的 FD (但要小心,避免关闭重要的 FD) */
    if (min_available_fd > 3) {
        int closed_count = 0;
        for (int fd = 3; fd < min_available_fd; fd++) {
            /* 尝试检查 FD 是否可关闭 */
            /* 注意: 我们无法直接访问 g_trace_file (它在其他模块中) */
            /*       所以采用保守策略: 只关闭可以确认不重要的 FD */
            
            /* 尝试获取 FD 状态 */
            int flags = fcntl(fd, F_GETFL);
            if (flags == -1) {
                continue; /* FD 已经不存在 */
            }
            
            /* 跳过 IPC FD - 这些是fuzzing模式必需的 */
            if (fd == ipc_cmd_fd || fd == ipc_status_fd) {
                RR_VERBOSE("Keeping FD %d (IPC pipe)", fd);
                continue;
            }
            
            /* 保守策略: 只关闭以读模式打开的 FD (更安全) */
            /* 因为 trace 文件通常是写模式 */
            if ((flags & O_ACCMODE) == O_RDONLY) {
                if (close(fd) == 0) {
                    closed_count++;
                    RR_VERBOSE("Closed read-only FD %d for alignment", fd);
                }
            } else {
                RR_VERBOSE("Keeping FD %d (write/rdwr mode)", fd);
            }
        }
        
        if (closed_count > 0) {
            RR_INFO("Closed %d FDs for environment alignment", closed_count);
        } else {
            RR_WARN("Could not close any FDs - alignment may be incomplete");
        }
    }
    
    /* 3. 重新检查第一个可用 FD */
    for (int fd = RR_FIRST_USER_FD; fd < RR_MAX_CHECKED_FD; fd++) {
        if (fcntl(fd, F_GETFD) == -1) {
            RR_INFO("After alignment, first available FD: %d", fd);
            
            /* 如果还不是 fd=3,打开 dummy FDs */
            if (fd > 3) {
                RR_WARN("Cannot fully align FDs, guest's first open() will return fd=%d", fd);
                /* 注意: 这会导致 FD 映射,但至少现在有映射机制来处理 */
            }
            return 0;
        }
    }
    
    return 0;
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

    /* 初始化映射管理器（FD/地址映射） */
    if (rr_mapping_manager_init(RR_FD_MAPPING_BUCKETS, RR_ADDR_MAPPING_BUCKETS) < 0) {
        RR_ERROR("Failed to initialize mapping manager");
        goto error;
    }

    /* 任务3: FD 环境对齐 - 在 replay/fuzzing 模式下对齐 FD 状态 */
    if (align_fd_state() < 0) {
        RR_ERROR("Failed to align FD state");
        goto error;
    }

    /* 注册退出清理函数 */
    atexit(rr_framework_cleanup);
    RR_VERBOSE("Registered exit cleanup handler");

    /* 初始化子系统 */
    if (rr_ipc_init() < 0) {
        RR_ERROR("Failed to initialize IPC");
        goto error;
    }
    RR_INFO("IPC subsystem initialized");
    
    /* 初始化Coverage模块 (始终初始化，用于所有模式) */
    RR_VERBOSE("Attempting to initialize coverage tracking...");
    int cov_ret = rr_coverage_init(NULL);
    RR_VERBOSE("rr_coverage_init() returned: %d", cov_ret);
    if (cov_ret < 0) {
        RR_WARN("Failed to initialize coverage tracking (non-fatal), return=%d", cov_ret);
    } else {
        RR_INFO("Coverage tracking initialized successfully");
    }
    
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
    
    /* 清理Coverage模块 */
    rr_coverage_cleanup();
    RR_VERBOSE("Coverage tracking cleaned up");
    
    rr_ipc_cleanup();
    
#ifdef RR_ENABLE_DYNAMIC_TRACE
    /* 清理动态跟踪 */
    rr_dynamic_trace_cleanup();
#endif
    
    rr_fuzz_cleanup();
    rr_snapshot_cleanup();
    rr_debug_cleanup();
    rr_config_cleanup();

    /* 清理映射管理器 */
    rr_mapping_manager_cleanup();

    /* 清理轨迹 */
    syscall_record_t *record = g_rr_framework->trace_head;
    while (record) {
        syscall_record_t *next = record->next;
        /* 清理参数数据 */
        for (int i = 0; i < RR_MAX_SYSCALL_ARGS; i++) {
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

    /* ✅ FIX: 在第一个syscall之前进入fork server (方案B)
     * 
     * 策略：在target程序执行第一个syscall之前进入fork server loop
     *      这样fork出的子进程会从main()开始自然执行
     *      
     * 优点：子进程自动replay整个trace，mutation自动应用
     */
    static bool fork_server_entered = false;
    if (!fork_server_entered && g_rr_framework->mode == RR_MODE_FUZZING && 
        g_rr_framework->fork_server_active) {
        
        fork_server_entered = true;
        RR_INFO("🚀 [EARLY FORK] Entering fork server BEFORE first syscall");
        RR_INFO("🚀 [EARLY FORK] This ensures child processes replay from main()");
        
        int fork_result = rr_fork_server_loop();
        
        if (fork_result < 0) {
            RR_INFO("🔄 Fork server received quit command, exiting");
            exit(0);
        } else if (fork_result > 0) {
            RR_INFO("🔄 Child process %d will now execute syscalls from the beginning", getpid());
        } else {
            RR_INFO("🔄 Parent process %d continuing in fork server loop", getpid());
        }
    }

    /* 添加醒目的系统调用入口提示 - 调试阶段使用 */
    const char* syscall_name = get_syscall_name(num);
    RR_INFO("===============================================================");    
    RR_INFO("=== ENTERING SYSCALL: %s (%d) === MODE: %s ===",
            syscall_name, num,
            g_rr_framework->mode == RR_MODE_RECORD ? "RECORD" :
            g_rr_framework->mode == RR_MODE_REPLAY ? "REPLAY" :
            g_rr_framework->mode == RR_MODE_FUZZING ? "FUZZING" : "UNKNOWN");

    /* 退出系统调用需要记录结果，但仍交由宿主执行 */
    if (num == 231 || num == 60) {
        RR_INFO("=== EXIT SYSCALL DETECTED: %s (%d) ===", syscall_name, num);
        if (g_rr_framework->mode == RR_MODE_RECORD) {
            abi_long args[8] = {
                *arg1, *arg2, *arg3, *arg4,
                *arg5, *arg6, *arg7, *arg8
            };
            rr_record_syscall(env, num, args, *arg1);
        }
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
            
            // Baseline mode: exit after first IO syscall (fork point)
            if (g_rr_framework->baseline_mode && is_io_syscall(num)) {
                RR_INFO("Baseline mode: reached first IO syscall %s at index %u, exiting",
                        get_syscall_name(num), g_rr_framework->replay_index);
                exit(0);
            }
            
            /* 
             * ✅ FIX: 禁用旧的auto fork point检查
             * 
             * 原因：我们已经在第一个syscall之前进入fork server了（EARLY FORK）
             *      不需要在syscall执行后再次fork
             *      
             * 保留代码作为参考，但添加条件永远为false
             */
            {
                const char *syscall_name_auto = get_syscall_name(num);
                
                // ✅ 禁用：fork_server_entered总是true，所以永远不会进入
                if (false && !fork_server_entered && rr_check_auto_fork_point(num, syscall_name_auto, ret)) {
                    /* 进入Fork Server主循环 */
                    RR_INFO("🔄 Entering fork server loop after %s", syscall_name_auto);
                    int fork_result = rr_fork_server_loop();
                    RR_INFO("🔄 Fork server loop returned: %d", fork_result);
                    
                    // ✅ DEBUG: 检查fork server返回后的状态
                    fprintf(stderr, "[DEBUG-AFTER-FORK] PID=%d, fork_result=%d\n", getpid(), fork_result);
                    fprintf(stderr, "[DEBUG-AFTER-FORK]   g_instruction_count=%zu\n", g_instruction_count);
                    fflush(stderr);
                    
                    if (fork_result < 0) {
                        RR_INFO("🔄 Exiting due to quit command");
                        exit(0); // 收到退出命令
                    } else if (fork_result > 0) {
                        /* 子进程继续Fuzzing执行 */
                        RR_INFO("🔄 Child process %d continuing fuzzing", getpid());
                        fprintf(stderr, "[DEBUG-CHILD-CONTINUE] PID=%d will execute syscalls now\n", getpid());
                        fprintf(stderr, "[DEBUG-CHILD-CONTINUE]   g_instruction_count=%zu at this point\n", g_instruction_count);
                        fflush(stderr);
                    } else {
                        RR_INFO("🔄 Parent process %d continuing after fork", getpid());
                    }
                }
                
                /* ✅ 新增：Autonomous nested fork检查
                 * 
                 * 如果是autonomous child（depth > 0），在IO syscalls上检查是否应该嵌套fork
                 */
                if (g_rr_framework->is_autonomous_child && 
                    rr_should_nested_fork(num, syscall_name_auto, ret)) {
                    uint32_t fork_index = g_rr_framework->replay_index;
                    rr_autonomous_nested_fork(fork_index);
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
void rr_handle_mmap_post(target_ulong recorded_addr, target_ulong actual_addr)
{
    if (recorded_addr != actual_addr) {
        /* 检查是否已存在映射 (可能是重复使用record导致的bug) */
        target_ulong existing = rr_addr_mapping_get(recorded_addr);
        if (existing != recorded_addr && existing != actual_addr) {
            RR_WARN("⚠️  Overwriting existing mmap mapping: 0x%lx -> 0x%lx (old) with 0x%lx -> 0x%lx (new), size=%lu",
                    (unsigned long)recorded_addr, (unsigned long)existing,
                    (unsigned long)recorded_addr, (unsigned long)actual_addr,
                    (unsigned long)g_pending_mmap_length);
        }
        
        rr_addr_mapping_add(recorded_addr, actual_addr, g_pending_mmap_length);
        RR_INFO("mmap address remapped: 0x%lx -> 0x%lx, size=%lu", 
                (unsigned long)recorded_addr, (unsigned long)actual_addr,
                (unsigned long)g_pending_mmap_length);
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
        
        /* 🔥 修复：先让 strace post_hook 运行，再检查标志 */
        if (rr_strace_replay_enabled()) {
            abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
            rr_strace_syscall_post_hook(env, num, ret, args);
        }
        
        /* 检查：如果这个系统调用已经在 rr_replay_syscall 中被消费（读取记录并递增索引），
         * 就不要再做记录处理，避免重复 */
        if (g_syscall_already_consumed) {
            syscall_record_t *record = g_pending_post_record;
            g_syscall_already_consumed = false;
            g_pending_post_record = NULL;

            if (record) {
                /* 🔥 P0: 偏离检测 - 验证返回值是否与 trace 一致 */
                if (record->retval != ret) {
                    if (is_expected_deviation(num, record->retval, ret)) {
                        /* 预期的偏离 (如 ASLR),只在 VERBOSE 级别输出 */
                        RR_VERBOSE("Expected deviation: syscall=%d (%s), recorded=0x%lx, actual=0x%lx",
                                   num, get_syscall_name(num), 
                                   (unsigned long)record->retval, (unsigned long)ret);
                    } else {
                        /* 非预期的偏离,需要警告 */
                        RR_WARN("⚠️  UNEXPECTED DEVIATION: syscall=%d (%s), recorded_ret=%ld, actual_ret=%ld (diff=%ld)",
                                num, get_syscall_name(num), record->retval, ret, ret - record->retval);
                        g_rr_framework->deviation_count++;
                    }
                }

                switch (num) {
#ifdef TARGET_NR_open
                case TARGET_NR_open:
#endif
                case TARGET_NR_openat:
#ifdef TARGET_NR_creat
                case TARGET_NR_creat:
#endif
                case TARGET_NR_dup:
#ifdef TARGET_NR_dup2
                case TARGET_NR_dup2:
#endif
#ifdef TARGET_NR_dup3
                case TARGET_NR_dup3:
#endif
#ifdef TARGET_NR_socket
                case TARGET_NR_socket:
#endif
#ifdef TARGET_NR_accept
                case TARGET_NR_accept:
#endif
#ifdef TARGET_NR_accept4
                case TARGET_NR_accept4:
#endif
                    if (ret >= 0) {
                        RR_INFO("🔗 FD_MAPPING: Adding mapping recorded_fd=%d -> actual_fd=%d",
                                (int)record->retval, (int)ret);
                        rr_fd_mapping_add(record->retval, (int)ret);
                    }
                    break;

                case TARGET_NR_close:
                    if (ret == 0) {
                        rr_fd_mapping_remove((int)record->args[0]);
                    }
                    break;

#ifdef TARGET_NR_pipe
                case TARGET_NR_pipe:
#endif
#ifdef TARGET_NR_pipe2
                case TARGET_NR_pipe2:
#endif
                    if (ret == 0 && record->arg_data[0]) {
                        int recorded_fds[2];
                        memcpy(recorded_fds, record->arg_data[0], sizeof(recorded_fds));
                        int actual_fds[2];
                        target_ulong guest_ptr = (target_ulong)record->args[0];
                        if (cpu_memory_rw_debug(env_cpu(env), guest_ptr, (uint8_t *)actual_fds,
                                                sizeof(actual_fds), 0) == 0) {
                            rr_fd_mapping_add(recorded_fds[0], actual_fds[0]);
                            rr_fd_mapping_add(recorded_fds[1], actual_fds[1]);
                        }
                    }
                    break;

#ifdef TARGET_NR_mmap
                case TARGET_NR_mmap:
#endif
#ifdef TARGET_NR_mmap2
                case TARGET_NR_mmap2:
#endif
                    if (g_pending_mmap_recorded_addr != 0) {
                        if (ret > 0) {
                            rr_handle_mmap_post(g_pending_mmap_recorded_addr, (target_ulong)ret);
                        } else {
                            RR_ERROR("POST_HOOK: mmap failed, recorded=0x%lx, ret=%ld",
                                     (unsigned long)g_pending_mmap_recorded_addr, (long)ret);
                        }
                        g_pending_mmap_recorded_addr = 0;
                        g_pending_mmap_length = 0;
                    }
                    break;

                case TARGET_NR_munmap:
                    if (ret == 0) {
                        rr_addr_mapping_remove((target_ulong)record->args[0]);
                    }
                    break;

                case TARGET_NR_mremap:
#ifdef TARGET_NR_mremap
                    if (ret != (abi_long)-1) {
                        rr_addr_mapping_remove((target_ulong)record->args[0]);
                        rr_handle_mmap_post((target_ulong)record->args[0], (target_ulong)ret);
                    }
                    break;
#endif

                case TARGET_NR_brk:
                    if (ret != (abi_long)-1 && record->has_aux_data) {
                        rr_aux_data_t *aux = rr_aux_find(record->aux_data, 0);
                        if (aux && aux->size == sizeof(abi_long)) {
                            abi_long recorded_brk;
                            memcpy(&recorded_brk, aux->data, sizeof(recorded_brk));
                            rr_addr_mapping_add((target_ulong)recorded_brk, (target_ulong)ret, 0);
                        }
                    }
                    break;

                default:
                    break;
                }

                /* 动态跟踪：系统调用退出（Hybrid 路径） */
#ifdef RR_ENABLE_DYNAMIC_TRACE
                rr_dynamic_trace_syscall_exit(env, num, (uint64_t*)&arg1, ret,
                                                g_rr_framework->replay_index - 1, 0);
#endif

                rr_record_dispose(record);
            }
            return;
        }

        if (
#ifdef TARGET_NR_mmap
            num == TARGET_NR_mmap
#ifdef TARGET_NR_mmap2
            ||
#endif
#endif
#ifdef TARGET_NR_mmap2
            num == TARGET_NR_mmap2
#endif
        ) {
            if (g_pending_mmap_recorded_addr != 0 && ret > 0) {
                rr_handle_mmap_post(g_pending_mmap_recorded_addr, (target_ulong)ret);
            }
            g_pending_mmap_recorded_addr = 0;
            g_pending_mmap_length = 0;
        }

        /* ✅ 修复：真实执行的syscall也要发送dynamic trace exit */
        if (!g_rr_framework->silent_replay_mode) {
            abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
            rr_dynamic_trace_syscall_exit(env, num, (uint64_t*)args, ret,
                                           g_rr_framework->replay_index - 1, false);  // -1因为已递增
        }
        
        RR_VERBOSE("POST_HOOK: Replay mode, syscall=%d, ret=%d", num, (int)ret);
        return;
    }
}
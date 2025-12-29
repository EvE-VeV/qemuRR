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
#include "../utils/rr_syscall_tree.h"  // ✅ C-Tree-P2: syscall tree tracking
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
 * @brief 将系统调用编号转换为可读的名称字符串
 * 
 * 该函数提供系统调用号到名称的映射，主要用于日志和调试输出。
 * 对于已知的常用系统调用，返回其标准名称（如 "read", "write"）。
 * 对于未识别的系统调用，返回 "unknown"。
 * 
 * @param syscall_nr 系统调用编号（如 TARGET_NR_read, TARGET_NR_write）
 * @return 系统调用名称的常量字符串指针。
 *         - 对于已知调用：返回标准名称字符串（如 "read", "mmap"）
 *         - 对于未知调用：返回 "unknown"
 * 
 * @note 当前实现仅包含约 30 个常用系统调用的映射，未覆盖所有系统调用。
 * @note 返回的字符串指针指向静态常量区域，调用者无需释放内存。
 * @warning 对于未映射的系统调用返回 "unknown"，调用者应注意处理。
 * 
 * @see rr_syscall_post_hook() 主要使用该函数进行日志输出
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
 * @brief 判断系统调用返回值的偏离是否属于预期范围
 * 
 * 在确定性重放 (deterministic replay) 过程中，某些系统调用的返回值会因为
 * 操作系统的 ASLR (地址空间布局随机化)、PID 分配等机制而在 record 和 replay
 * 阶段产生差异。此函数用于判断这种偏离是否在预期范围内（即是否为已知的
 * 不确定性来源），从而决定是否应该触发不一致警告。
 * 
 * @param syscall_nr 系统调用编号（如 TARGET_NR_mmap, TARGET_NR_brk）
 * @param recorded 记录 (record) 阶段该系统调用的返回值
 * @param actual 重放 (replay) 阶段该系统调用的实际返回值
 * @return bool
 *         - true: 偏离属于预期范围（如地址类系统调用、PID/TID 相关调用）
 *         - false: 偏离异常，可能需要进一步检查或警告
 * 
 * @note 当前支持的预期偏离场景包括：
 *       - 内存管理: mmap, mmap2, brk, mremap (返回的地址受 ASLR 影响)
 *       - 进程标识: set_tid_address, gettid, getpid, getppid
 *       - 路径操作: readlink, readlinkat (路径长度可能变化)
 * 
 * @warning 对于未列出的系统调用，该函数会返回 false，表示不接受任何偏离。
 *          在添加新的预期偏离场景时，需要仔细评估其合理性。
 * 
 * @see rr_do_syscall() 在检测到返回值不一致时会调用此函数
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
 * @brief 在重放模式下对齐文件描述符 (FD) 环境
 * 
 * 为了确保确定性重放，guest 程序在 replay 阶段的 FD 分配应尽可能与
 * record 阶段保持一致。该函数在 replay/fuzzing 模式启动时被调用，
 * 尝试关闭一些由 QEMU 占用的 FD，使得 guest 程序的第一个 open() 调用
 * 能够获得与 record 阶段相同的 FD 编号（通常是 FD=3）。
 * 
 * @return int
 *         - 0: 对齐操作完成（无论是否成功）
 *         - 负值: 保留用于未来错误处理扩展
 * 
 * @note FD 对齐策略:
 *       1. 跳过标准流 (stdin=0, stdout=1, stderr=2)
 *       2. 保护 IPC 通信管道 FD (fuzzing 模式必需)
 *       3. 仅关闭以只读模式打开的 FD，避免误关闭 trace 文件
 * 
 * @note 如果无法完全对齐（如 QEMU 占用了多个 FD），系统会启用 FD 映射机制
 *       来处理 record 和 replay 之间的 FD 差异。
 * 
 * @warning 在 multi-threaded 环境下可能存在竞态条件（当前 QEMU user-mode 是单线程）
 * 
 * @see rr_fd_mapping_add() FD 映射机制的实现
 * @see rr_framework_init() 在框架初始化时调用
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
 * @brief 初始化 RR-Fuzz 框架的所有子系统
 * 
 * 这是 RR-Fuzz 框架的主初始化函数，负责根据配置（record/replay/fuzzing 模式）
 * 启动相应的子系统。该函数通常在 QEMU 启动 guest 程序之前被调用一次。
 * 
 * 初始化流程:
 * 1. 加载并验证配置 (rr_config_init)
 * 2. 初始化调试日志系统
 * 3. 分配全局框架上下文 (g_rr_framework)
 * 4. 初始化 FD/地址映射管理器
 * 5. 执行 FD 环境对齐 (replay/fuzzing 模式)
 * 6. 初始化 IPC 通信管道 (fuzzing 模式)
 * 7. 初始化覆盖率追踪模块
 * 8. 初始化 Syscall Tree Builder
 * 9. 根据运行模式启动 record/replay/fuzzing 子系统
 * 
 * @return int
 *         - 0: 初始化成功
 *         - -1: 初始化失败（会打印错误日志）
 * 
 * @note 该函数应仅被调用一次。重复调用会导致资源泄漏。
 * @note 会自动注册 atexit 清理函数 rr_framework_cleanup()
 * 
 * @warning 如果初始化失败，部分子系统可能已经初始化完成。调用者应确保
 *          正确处理错误情况并退出程序，或调用 rr_framework_cleanup() 清理。
 * 
 * @see rr_framework_cleanup() 对应的清理函数
 * @see g_rr_config 全局配置对象
 * @see g_rr_framework 全局框架上下文
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

    /* ✅ C-Tree-P2: 初始化Syscall Tree Builder */
    rr_tree_init();
    RR_INFO("Syscall tree builder initialized");
    
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
 * @brief 清理 RR-Fuzz 框架并释放所有资源
 * 
 * 该函数负责停止所有运行中的子系统并释放框架占用的内存资源。
 * 通常在程序退出时通过 atexit 机制自动调用，也可以手动调用。
 * 
 * 清理流程:
 * 1. 根据当前模式停止相应子系统 (recording/replay/fork-server)
 * 2. 导出 Syscall Tree 到 JSON 文件 (默认 /tmp/syscall_tree.json)
 * 3. 清理覆盖率追踪模块
 * 4. 清理 IPC 通信管道
 * 5. 清理动态跟踪管道 (如果启用)
 * 6. 清理 fuzzing、snapshot、调试、配置等子系统
 * 7. 清理 FD/地址映射管理器
 * 8. 释放 trace 记录链表
 * 9. 释放全局框架上下文
 * 
 * @note 该函数可以安全地被多次调用（会检查 g_rr_framework 是否为 NULL）
 * @note 清理顺序很重要：先停止业务逻辑，再清理底层资源
 * 
 * @warning 调用此函数后，g_rr_framework 会被设置为 NULL，后续不应再使用框架功能
 * 
 * @see rr_framework_init() 对应的初始化函数
 * @see g_rr_framework 全局框架上下文
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

    /* ✅ C-Tree-P2: 导出Syscall Tree为JSON（仅在记录模式下） */
    if (g_rr_framework->mode == RR_MODE_RECORD) {
        const char *tree_output = getenv("RR_TREE_OUTPUT");
        if (tree_output) {
            rr_tree_export_json(tree_output);
        } else {
            /* 默认输出到 /tmp/syscall_tree.json */
            rr_tree_export_json("/tmp/syscall_tree.json");
        }
    }
    rr_tree_cleanup();
    RR_VERBOSE("Syscall tree cleaned up");

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
 * @brief RR-Fuzz 框架的核心系统调用拦截处理函数
 * 
 * 该函数是 RR-Fuzz 框架与 QEMU 的主要接入点，由 `linux-user/syscall.c` 中的
 * `do_syscall()` 在系统调用执行**之前**调用。根据当前运行模式 (record/replay/fuzzing),
 * 决定是记录、重放还是以修改的方式执行系统调用。
 * 
 * **工作流程**:
 * - **Record 模式**: 返回 -1，让 QEMU 执行原始系统调用，结果在 post-hook 中记录
 * - **Replay 模式**: 调用 `rr_replay_syscall()` 或 `rr_replay_syscall_strace()`，
 *   根据 trace 文件确定性反现系统调用结果
 * - **Fuzzing 模式**: 类似 replay，但会应用 mutation 并支持 fork-server 机制
 * 
 * **Fork-Server 机制** (✅ Early Fork):
 * 在 fuzzing 模式下，该函数在**第一个系统调用之前**就会进入 fork-server 循环，
 * 确保 fork 出的子进程从 `main()` 开始执行，自然完成整个 trace 的 replay。
 * 
 * @param env CPU 架构状态指针 (CPUArchState)
 * @param num 系统调用编号 (syscall number)
 * @param arg1-arg8 系统调用的 8 个参数指针 (注意是指针，可被修改)
 * 
 * @return abi_long
 *         - 非 -1: 由 RR-Fuzz 框架处理的系统调用返回值，QEMU 直接使用，不再执行原始 syscall
 *         - -1: RR-Fuzz 未处理，让 QEMU 执行原始系统调用 (record 模式或未启用时)
 * 
 * @note 这是 pre-hook，在系统调用执行**之前**被调用
 * @note Fuzzing 模式下，fork-server 只会被初始化一次 (static bool fork_server_entered)
 * @note 退出相关的系统调用 (exit/exit_group) 在 record 模式下会被特殊处理
 * 
 * @warning 此函数会直接修改参数指针 (arg1-arg8) 的值，在 fuzzing 模式下用于应用 mutation
 * @warning Fork-server 逻辑会导致进程 fork，调用者需考虑多进程场景
 * 
 * @see do_syscall() QEMU 中调用此函数的入口
 * @see rr_syscall_post_hook() 对应的 post-hook (系统调用执行之后)
 * @see rr_replay_syscall() Binary trace replay 实现
 * @see rr_replay_syscall_strace() Strace replay 实现
 * @see rr_fork_server_loop() Fork-server 循环实现
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
    /* RR_INFO("===============================================================");    
    RR_INFO("=== ENTERING SYSCALL: %s (%d) === MODE: %s ===",
            syscall_name, num,
            g_rr_framework->mode == RR_MODE_RECORD ? "RECORD" :
            g_rr_framework->mode == RR_MODE_REPLAY ? "REPLAY" :
            g_rr_framework->mode == RR_MODE_FUZZING ? "FUZZING" : "UNKNOWN"); */

    /* 退出系统调用需要记录结果，但仍交由宿主执行 */
    if (num == 231 || num == 60) {
        /* RR_INFO("=== EXIT SYSCALL DETECTED: %s (%d) ===", syscall_name, num); */
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

    /* ✅ 2025-11-17: IO Mutation 返回值覆盖已在 rr_replay_syscall() 中处理 */
    /* 注意: ret 已经是覆盖后的值，由 rr_replay.c:655-664 处理 */

    /* 添加醒目的系统调用退出提示 - 调试阶段使用 */
    RR_INFO("=== EXITING SYSCALL: %s (%d) === RETURN: %d ===",
            syscall_name, num, (int)ret);
    RR_INFO("===============================================================");
    return ret;
}

/**
 * @brief 处理 mmap 系统调用执行后的地址映射
 * 
 * 在 replay/fuzzing 模式下，由于 ASLR (Address Space Layout Randomization)，
 * mmap 返回的地址会与 record 阶段不同。该函数负责建立 record 地址到
 * replay 地址的映射关系，供后续内存相关系统调用 (munmap, mprotect 等) 使用。
 * 
 * @param recorded_addr mmap 在 record 阶段返回的地址 (从 trace 文件读取)
 * @param actual_addr mmap 在 replay 阶段实际返回的地址
 * 
 * @note 该函数在 post-hook 中被调用，确保 mmap 已经实际执行完成
 * @note 地址映射信息存储在全局映射管理器中
 * 
 * @warning 必须在 mmap 执行后立即调用，否则后续操作可能找不到正确的映射
 * 
 * @see rr_addr_mapping_add() 地址映射管理器的添加函数
 * @see rr_syscall_post_hook() 调用此函数的 post-hook
 * @see g_pending_mmap_recorded_addr 保存 recorded_addr 的全局变量
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
 * @brief 系统调用执行后的通用 Hook 函数
 * 
 * 该函数在 QEMU 执行完系统调用之后被调用，负责处理系统调用的
 * 各种副作用，包括：
 * - **Record 模式**: 记录系统调用的返回值和输出数据到 trace 文件
 * - **FD 管理**: 更新 FD 映射表 (open/close/dup 等调用)
 * - **地址映射**: 处理 mmap/munmap/mremap 的地址映射
 * - **Fuzzing 统计**: 更新 fuzzing 模式下的执行统计信息
 * 
 * **处理的主要系统调用类型**:
 * - 文件操作: open, openat, close, dup, dup2, dup3
 * - 内存管理: mmap, mmap2, munmap, mremap, mprotect
 * - 网络: socket, accept, accept4
 * - 进程管理: fork, vfork, clone
 * 
 * @param env CPU 架构状态指针
 * @param num 系统调用编号
 * @param ret 系统调用的返回值
 * @param arg1-arg8 系统调用的 8 个参数值 (注意不是指针)
 * 
 * @note 这是 post-hook，在系统调用执行**之后**被调用
 * @note 与 `rr_do_syscall` 不同，这里的 arg1-arg8 是值而不是指针
 * @note 包含一个大型 switch-case 结构 (L800-L900+)，处理各种系统调用
 * 
 * @warning 该函数自身没有返回值，无法阻止 QEMU 的后续处理
 * @warning 包含大量 switch-case 逻辑，与 `rr_syscall_dispatch.c` 存在功能重复
 * 
 * @see rr_do_syscall() 对应的 pre-hook
 * @see rr_syscall_dispatch.c 更模块化的 syscall 处理方式
 * @see rr_record_syscall() Record 模式下记录系统调用
 * @see rr_fd_mapping_add() FD 映射管理
 */
void rr_syscall_post_hook(CPUArchState *env, int num, abi_long ret,
                          abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8)
{
    RR_VERBOSE("POST_HOOK: syscall=%d, ret=%ld", num, (long)ret);
    if (!rr_framework_enabled()) {
        RR_VERBOSE("POST_HOOK: Skipping syscall %d - framework not enabled", num);
        return;
    }

    /* ✅ C-Tree-P2: 记录syscall节点到树结构 */
    if (g_rr_framework) {
        uint64_t args_arr[6] = {
            (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
            (uint64_t)arg4, (uint64_t)arg5, (uint64_t)arg6
        };
        uint32_t current_idx = (g_rr_framework->mode == RR_MODE_RECORD) ? 
                               g_rr_framework->trace_length : g_rr_framework->replay_index;
        
        uint32_t node_id = rr_tree_add_syscall_node(
            getpid(),                               // PID
            current_idx,                            // syscall_index
            num,                                     // syscall_nr
            get_syscall_name(num),                  // syscall_name
            args_arr,                                // args
            ret,                                     // retval
            0,                                       // timestamp_enter (auto)
            0                                        // timestamp_exit (auto)
        );

        /* ✅ C-Tree-P2: 检测fork系统调用并记录fork关系 */
        if ((num == 56 || num == 57 || num == 58) && ret > 0) {  // clone/fork/vfork
            rr_tree_add_fork_relation(node_id, (uint32_t)ret);
            RR_VERBOSE("Recorded fork relation: parent_node=%u, child_pid=%u", node_id, (uint32_t)ret);
        }
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
                                num, get_syscall_name(num), (long)record->retval, (long)ret, (long)(ret - record->retval));
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

        /* 🔥 修复：始终发送EXIT消息以保证tree visualization完整性
         * Silent mode的目的是性能优化，不应该影响消息完整性
         * 即使在silent replay期间，tree visualizer也需要接收完整的syscall消息
         */
        abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
        rr_dynamic_trace_syscall_exit(env, num, (uint64_t*)args, ret,
                                       g_rr_framework->replay_index - 1, false);  // -1因为已递增
        
        RR_VERBOSE("POST_HOOK: Replay mode, syscall=%d, ret=%d", num, (int)ret);
        return;
    }
}
/**
 * RR-Fuzz主控模块 - 框架初始化和核心逻辑
 * 对应design.md中的rr_main.c
 */

/* 确保RR_DEBUG被定义 */
#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "rr_framework.h"
#include "qemu/error-report.h"
#include <stdlib.h>

/* 全局框架状态 */
rr_framework_t *g_rr_framework = NULL;

/**
 * 初始化RR框架
 */
int rr_framework_init(void)
{
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

    /* 初始化FD映射表 */
    g_rr_framework->fd_map = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* 注册退出清理函数 */
    atexit(rr_framework_cleanup);
    RR_VERBOSE("Registered exit cleanup handler");

    /* 初始化子系统 */
    if (rr_ipc_init() < 0) {
        RR_ERROR("Failed to initialize IPC");
        goto error;
    }
    RR_INFO("IPC subsystem initialized");

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
            RR_INFO("Starting replay mode, trace_file=%s", g_rr_config.trace_file);
            if (rr_start_replay(g_rr_config.trace_file) < 0) {
                RR_ERROR("Failed to start replay");
                goto error;
            }
            RR_INFO("Replay started successfully");
            break;
        case RR_MODE_FUZZING:
            // Fuzzing模式需要先加载trace，然后启动fork server
            RR_INFO("Starting fuzzing mode, trace_file=%s", g_rr_config.trace_file);
            if (rr_start_replay(g_rr_config.trace_file) < 0) {
                RR_ERROR("Failed to load trace for fuzzing");
                goto error;
            }
            /* 在Fuzzing模式下启动Fork Server（如果配置启用） */
            if (g_rr_config.fork_server_enabled) {
                RR_INFO("Starting fork server at point %u", g_rr_config.fork_point);
                if (rr_start_fork_server(g_rr_config.fork_point) < 0) {
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
            rr_stop_replay();
            break;
        case RR_MODE_FUZZING:
            rr_stop_fork_server();
            rr_stop_replay(); // Fuzzing模式也需要停止replay
            break;
        default:
            break;
    }

    /* 清理子系统 */
    RR_VERBOSE("Cleaning up subsystems");
    rr_ipc_cleanup();
    rr_fuzz_cleanup();
    rr_snapshot_cleanup();
    rr_debug_cleanup();
    rr_config_cleanup();

    /* 清理FD映射表 */
    if (g_rr_framework->fd_map) {
        g_hash_table_destroy(g_rr_framework->fd_map);
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
                       abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                       abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8)
{
    RR_VERBOSE("RR_DO_SYSCALL: Called for syscall %d, enabled=%d", num, rr_framework_enabled());

    if (!rr_framework_enabled()) {
        RR_VERBOSE("RR_DO_SYSCALL: Framework not enabled, returning -1");
        return -1; // 让调用者执行原始逻辑
    }

    RR_VERBOSE("RR_DO_SYSCALL: Framework enabled, mode=%d", g_rr_framework->mode);

    abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
    abi_long ret;

    switch (g_rr_framework->mode) {
        case RR_MODE_RECORD:
            /* 记录模式：执行原始系统调用，然后记录结果 */
            ret = -1; // 返回-1让调用者执行原始逻辑
            break;

        case RR_MODE_REPLAY:
            /* 重放模式：从轨迹中获取结果 */
            RR_VERBOSE("RR_DO_SYSCALL: Calling rr_replay_syscall for syscall %d", num);
            ret = rr_replay_syscall(env, num, args);
            RR_VERBOSE("RR_DO_SYSCALL: rr_replay_syscall returned %ld", ret);
            break;

        case RR_MODE_FUZZING:
            /* 检查是否到达Fork点 */
            if (rr_check_fork_point()) {
                /* 进入Fork Server主循环 */
                int fork_result = rr_fork_server_loop();
                if (fork_result < 0) {
                    exit(0); // 收到退出命令
                } else if (fork_result > 0) {
                    /* 子进程继续Fuzzing执行 */
                }
            }
            /* Fuzzing模式：可能修改参数，然后重放 */
            ret = rr_replay_syscall(env, num, args);
            break;

        default:
            ret = -1;
            break;
    }

    return ret;
}

/**
 * 系统调用执行后的Hook
 * 用于记录模式
 */
void rr_syscall_post_hook(CPUArchState *env, int num, abi_long ret,
                          abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8)
{
    RR_VERBOSE("POST_HOOK: syscall=%d, enabled=%d, mode=%d, ret=%ld",
               num, rr_framework_enabled(), g_rr_framework ? g_rr_framework->mode : -1, ret);

    if (!rr_framework_enabled()) {
        RR_VERBOSE("POST_HOOK: Skipping syscall %d - framework not enabled", num);
        return;
    }

    if (g_rr_framework->mode != RR_MODE_RECORD) {
        RR_VERBOSE("POST_HOOK: Skipping syscall %d - mode not RECORD (mode=%d)", num, g_rr_framework->mode);
        return;
    }

    RR_VERBOSE("POST_HOOK: Recording syscall %d with ret=%ld", num, ret);
    abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};

    int record_result = rr_record_syscall(env, num, args, ret);
    if (record_result == 0) {
        g_rr_framework->total_syscalls++;
        RR_VERBOSE("POST_HOOK: Successfully recorded syscall %d (total: %u)", num, g_rr_framework->total_syscalls);
    } else {
        RR_ERROR("POST_HOOK: Failed to record syscall %d (result=%d)", num, record_result);
    }
}
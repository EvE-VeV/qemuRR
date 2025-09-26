/**
 * RR-Fuzz IPC通信模块
 * 实现Conductor与QEMU之间的管道和共享内存通信
 * 对应design.md中的rr_ipc.c
 */

#include "rr_framework.h"
#include <sys/mman.h>
#include <sys/stat.h>

/**
 * 初始化IPC系统
 * 使用统一配置系统
 */
int rr_ipc_init(void)
{
    RR_IPC_TRACE("Initializing IPC system");

    /* 从配置获取管道路径，这里使用管道路径作为FD或路径 */
    if (g_rr_config.cmd_pipe_path) {
        /* 尝试将路径作为FD数字解析 */
        char *endptr;
        long fd = strtol(g_rr_config.cmd_pipe_path, &endptr, 10);
        if (*endptr == '\0' && fd >= 0) {
            /* 是数字，作为FD使用 */
            g_rr_framework->cmd_pipe_fd = (int)fd;
            RR_IPC_TRACE("Using command pipe FD: %d", g_rr_framework->cmd_pipe_fd);
        } else {
            /* 不是数字，暂时设为-1（未来可以扩展为路径） */
            g_rr_framework->cmd_pipe_fd = -1;
            RR_WARN("Command pipe path not numeric: %s", g_rr_config.cmd_pipe_path);
        }
    } else {
        g_rr_framework->cmd_pipe_fd = -1;
        RR_IPC_TRACE("No command pipe configured");
    }

    if (g_rr_config.status_pipe_path) {
        /* 尝试将路径作为FD数字解析 */
        char *endptr;
        long fd = strtol(g_rr_config.status_pipe_path, &endptr, 10);
        if (*endptr == '\0' && fd >= 0) {
            /* 是数字，作为FD使用 */
            g_rr_framework->status_pipe_fd = (int)fd;
            RR_IPC_TRACE("Using status pipe FD: %d", g_rr_framework->status_pipe_fd);
        } else {
            /* 不是数字，暂时设为-1 */
            g_rr_framework->status_pipe_fd = -1;
            RR_WARN("Status pipe path not numeric: %s", g_rr_config.status_pipe_path);
        }
    } else {
        g_rr_framework->status_pipe_fd = -1;
        RR_IPC_TRACE("No status pipe configured");
    }

    /* 初始化共享内存 */
    if (g_rr_config.shared_memory_name) {
        int shm_fd = shm_open(g_rr_config.shared_memory_name, O_RDWR, 0666);
        if (shm_fd >= 0) {
            g_rr_framework->shared_memory = mmap(NULL, g_rr_config.shared_memory_size,
                                               PROT_READ | PROT_WRITE,
                                               MAP_SHARED, shm_fd, 0);
            if (g_rr_framework->shared_memory != MAP_FAILED) {
                RR_IPC_TRACE("Mapped shared memory: %s (%zu bytes)",
                            g_rr_config.shared_memory_name, g_rr_config.shared_memory_size);
            } else {
                RR_WARN("Failed to map shared memory: %s", g_rr_config.shared_memory_name);
                g_rr_framework->shared_memory = NULL;
            }
            close(shm_fd);
        } else {
            RR_WARN("Failed to open shared memory: %s", g_rr_config.shared_memory_name);
        }
    } else {
        RR_IPC_TRACE("No shared memory configured");
    }

    RR_INFO("IPC system initialized");
    return 0;
}

/**
 * 清理IPC系统
 */
void rr_ipc_cleanup(void)
{
    RR_IPC_TRACE("Cleaning up IPC system");

    if (g_rr_framework->shared_memory) {
        munmap(g_rr_framework->shared_memory, g_rr_config.shared_memory_size);
        g_rr_framework->shared_memory = NULL;
        RR_IPC_TRACE("Unmapped shared memory");
    }

    if (g_rr_framework->cmd_pipe_fd >= 0) {
        close(g_rr_framework->cmd_pipe_fd);
        g_rr_framework->cmd_pipe_fd = -1;
        RR_IPC_TRACE("Closed command pipe");
    }

    if (g_rr_framework->status_pipe_fd >= 0) {
        close(g_rr_framework->status_pipe_fd);
        g_rr_framework->status_pipe_fd = -1;
        RR_IPC_TRACE("Closed status pipe");
    }
}

/**
 * 发送状态消息
 * 实现design.md中的状态管道协议
 */
int rr_ipc_send_status(int status)
{
    if (g_rr_framework->status_pipe_fd < 0) {
        return 0; // 如果没有状态管道，直接返回成功
    }

    if (write(g_rr_framework->status_pipe_fd, &status, sizeof(status)) != sizeof(status)) {
        RR_LOG("Failed to send status: %d", status);
        return -1;
    }

    RR_LOG("Sent status: %d", status);
    return 0;
}

/**
 * 接收命令
 * 实现design.md中的控制管道协议
 */
int rr_ipc_receive_command(void)
{
    if (g_rr_framework->cmd_pipe_fd < 0) {
        return 0; // 如果没有命令管道，返回无命令
    }

    char cmd;
    ssize_t n = read(g_rr_framework->cmd_pipe_fd, &cmd, 1);
    if (n != 1) {
        return 0; // 无数据或错误
    }

    RR_LOG("Received command: %c", cmd);

    switch (cmd) {
        case 'F': // Fork命令
            return 'F';
        case 'Q': // 退出命令
            return 'Q';
        case 'S': // 保存Snapshot命令
            return 'S';
        case 'L': // 加载Snapshot命令
            return 'L';
        default:
            RR_LOG("Unknown command: %c", cmd);
            return 0;
    }
}
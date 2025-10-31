/**
 * RR-Fuzz IPC通信模块
 * 实现Conductor与QEMU之间的管道和共享内存通信
 * 对应design.md中的rr_ipc.c
 */

#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "../core/rr_framework.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/**
 * 初始化IPC系统
 * 使用统一配置系统
 */
int rr_ipc_init(void)
{
    RR_IPC_TRACE("Initializing IPC system");

    /* 从配置获取管道路径，支持FD数字或文件路径 */
    if (g_rr_config.cmd_pipe_path) {
        /* 尝试将路径作为FD数字解析 */
        char *endptr;
        long fd = strtol(g_rr_config.cmd_pipe_path, &endptr, 10);
        if (*endptr == '\0' && fd >= 0) {
            /* 是数字，作为已打开的FD使用 */
            g_rr_framework->cmd_pipe_fd = (int)fd;
            RR_IPC_TRACE("Using command pipe FD: %d", g_rr_framework->cmd_pipe_fd);
        } else {
            /* 不是数字，作为文件路径打开（QEMU读取命令） */
            g_rr_framework->cmd_pipe_fd = open(g_rr_config.cmd_pipe_path, O_RDONLY | O_NONBLOCK);
            if (g_rr_framework->cmd_pipe_fd < 0) {
                RR_WARN("Failed to open command pipe: %s (errno=%d)", g_rr_config.cmd_pipe_path, errno);
            } else {
                RR_IPC_TRACE("Opened command pipe: %s -> FD %d", 
                             g_rr_config.cmd_pipe_path, g_rr_framework->cmd_pipe_fd);
            }
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
            /* 是数字，作为已打开的FD使用 */
            g_rr_framework->status_pipe_fd = (int)fd;
            RR_IPC_TRACE("Using status pipe FD: %d", g_rr_framework->status_pipe_fd);
        } else {
            /* 不是数字，作为文件路径打开（QEMU写入状态） */
            g_rr_framework->status_pipe_fd = open(g_rr_config.status_pipe_path, O_WRONLY | O_NONBLOCK);
            if (g_rr_framework->status_pipe_fd < 0) {
                RR_WARN("Failed to open status pipe: %s (errno=%d)", g_rr_config.status_pipe_path, errno);
            } else {
                RR_IPC_TRACE("Opened status pipe: %s -> FD %d", 
                             g_rr_config.status_pipe_path, g_rr_framework->status_pipe_fd);
            }
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
        RR_WARN("Cannot send status %d: status_pipe_fd is invalid", status);
        return 0; // 如果没有状态管道，直接返回成功
    }

    RR_INFO("📤 Sending status: %d (fd=%d, pid=%d)", status, g_rr_framework->status_pipe_fd, getpid());
    
    /* 🔥 修复：添加重试机制，处理非阻塞写入 */
    int retry_count = 0;
    const int max_retries = 3;
    ssize_t written;
    
    while (retry_count < max_retries) {
        written = write(g_rr_framework->status_pipe_fd, &status, sizeof(status));
        if (written == sizeof(status)) {
            RR_INFO("✅ Status %d sent successfully", status);
            return 0;
        }
        
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* 管道缓冲区满，短暂等待后重试 */
            retry_count++;
            RR_WARN("Status pipe full, retrying (%d/%d)...", retry_count, max_retries);
            usleep(10000); // 10ms
            continue;
        }
        
        /* 其他错误 */
        break;
    }
    
    RR_ERROR("Failed to send status %d after %d retries: written=%zd, errno=%d (%s)", 
             status, retry_count, written, errno, strerror(errno));
    return -1;
}

/**
 * 接收命令
 * 实现design.md中的控制管道协议
 */
int rr_ipc_receive_command(void)
{
    if (g_rr_framework->cmd_pipe_fd < 0) {
        RR_WARN("cmd_pipe_fd is invalid (<0), returning 0");
        return 0; // 如果没有命令管道，返回无命令
    }

    char cmd;
    RR_VERBOSE("Calling read() on cmd_pipe_fd=%d...", g_rr_framework->cmd_pipe_fd);
    ssize_t n = read(g_rr_framework->cmd_pipe_fd, &cmd, 1);
    RR_INFO("📥 IPC read: fd=%d, n=%zd, cmd='%c' (%d)", g_rr_framework->cmd_pipe_fd, n, 
            (n == 1 && cmd > 0) ? cmd : '?', (int)(unsigned char)cmd);
    
    if (n != 1) {
        if (n < 0) {
            RR_WARN("read() failed with errno=%d (%s)", errno, strerror(errno));
            return 0;
        } else if (n == 0) {
            /* 🔥 修复：管道关闭（EOF），应返回退出命令 */
            RR_WARN("Command pipe closed (EOF), conductor disconnected");
            return 'Q'; // 返回退出命令，让 fork server 安全停机
        } else {
            RR_VERBOSE("read() returned %zd (partial read)", n);
            return 0;
        }
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
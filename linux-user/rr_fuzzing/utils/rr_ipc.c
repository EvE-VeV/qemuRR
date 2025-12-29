/**
 * RR-Fuzz IPC通信模块
 * 实现Conductor与QEMU之间的管道和共享内存通信
 */

#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "../core/rr_framework.h"
#include "../core/rr_constants.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static void *rr_map_shared_memory(const char *identifier);

int rr_ipc_init(void)
{
    RR_IPC_TRACE("Initializing IPC system");

    if (g_rr_config.cmd_pipe_path) {
        char *endptr;
        long fd = strtol(g_rr_config.cmd_pipe_path, &endptr, 10);
        if (*endptr == '\0' && fd >= 0) {
            g_rr_framework->cmd_pipe_fd = (int)fd;
            RR_IPC_TRACE("Using command pipe FD: %d", g_rr_framework->cmd_pipe_fd);
        } else {
            g_rr_framework->cmd_pipe_fd = open(g_rr_config.cmd_pipe_path, O_RDONLY | O_NONBLOCK);
            if (g_rr_framework->cmd_pipe_fd < 0) {
                RR_WARN("Failed to open command pipe: %s", g_rr_config.cmd_pipe_path);
            }
        }
    } else {
        g_rr_framework->cmd_pipe_fd = -1;
    }

    if (g_rr_config.status_pipe_path) {
        char *endptr;
        long fd = strtol(g_rr_config.status_pipe_path, &endptr, 10);
        if (*endptr == '\0' && fd >= 0) {
            g_rr_framework->status_pipe_fd = (int)fd;
            RR_IPC_TRACE("Using status pipe FD: %d", g_rr_framework->status_pipe_fd);
        } else {
            g_rr_framework->status_pipe_fd = open(g_rr_config.status_pipe_path, O_WRONLY | O_NONBLOCK);
            if (g_rr_framework->status_pipe_fd < 0) {
                RR_WARN("Failed to open status pipe: %s", g_rr_config.status_pipe_path);
            }
        }
    } else {
        g_rr_framework->status_pipe_fd = -1;
    }

    if (g_rr_config.shared_memory_name) {
        g_rr_framework->shared_memory = rr_map_shared_memory(g_rr_config.shared_memory_name);
    }

    RR_INFO("IPC system initialized");
    return 0;
}

void rr_ipc_cleanup(void)
{
    RR_IPC_TRACE("Cleaning up IPC system");
    if (g_rr_framework->shared_memory) {
        munmap(g_rr_framework->shared_memory, g_rr_config.shared_memory_size);
        g_rr_framework->shared_memory = NULL;
    }
    if (g_rr_framework->cmd_pipe_fd >= 0) {
        close(g_rr_framework->cmd_pipe_fd);
        g_rr_framework->cmd_pipe_fd = -1;
    }
    if (g_rr_framework->status_pipe_fd >= 0) {
        close(g_rr_framework->status_pipe_fd);
        g_rr_framework->status_pipe_fd = -1;
    }
}

int rr_ipc_send_status(int status)
{
    if (g_rr_framework->status_pipe_fd < 0) return 0;
    ssize_t written = write(g_rr_framework->status_pipe_fd, &status, sizeof(status));
    if (written == sizeof(status)) return 0;
    return -1;
}

/**
 * Send crash status with additional details (exit code and signal)
 * 
 * When a crash is detected, this function sends 3 integers:
 * 1. status (STATUS_CRASH = 4)
 * 2. exit_code (e.g., 134 for SIGABRT, 139 for SIGSEGV)
 * 3. signal_number (e.g., 6 for SIGABRT, 11 for SIGSEGV)
 * 
 * Python side reads these 3 ints to populate ExecutionResult fully.
 */
int rr_ipc_send_crash_status(int status, int exit_code, int signal_number)
{
    if (g_rr_framework->status_pipe_fd < 0) return 0;
    
    // Send 3 integers: [status, exit_code, signal_number]
    int buffer[3] = {status, exit_code, signal_number};
    ssize_t written = write(g_rr_framework->status_pipe_fd, buffer, sizeof(buffer));
    
    if (written == sizeof(buffer)) {
        RR_VERBOSE("Sent crash status: status=%d, exit_code=%d, signal=%d", 
                   status, exit_code, signal_number);
        return 0;
    }
    
    RR_WARN("Failed to send full crash status (wrote %zd of %zu bytes)", 
            written, sizeof(buffer));
    return -1;
}

int rr_ipc_receive_command(void)
{
    if (g_rr_framework->cmd_pipe_fd < 0) return 0;
    char cmd;
    ssize_t n = read(g_rr_framework->cmd_pipe_fd, &cmd, 1);
    if (n == 1) return (unsigned char)cmd;
    if (n == 0) return 'Q';
    return 0;
}

static void *rr_map_posix_shared_memory(const char *name)
{
    int shm_fd = shm_open(name, O_RDWR, 0666);
    if (shm_fd < 0) return NULL;
    void *addr = mmap(NULL, g_rr_config.shared_memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    close(shm_fd);
    return addr == MAP_FAILED ? NULL : addr;
}

static void *rr_map_file_backed_memory(const char *path)
{
    int fd = open(path, O_RDWR, 0);
    if (fd < 0) return NULL;
    void *addr = mmap(NULL, g_rr_config.shared_memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    return addr == MAP_FAILED ? NULL : addr;
}

static void *rr_map_shared_memory(const char *identifier)
{
    if (!identifier) return NULL;
    if (strncmp(identifier, "file:", 5) == 0) return rr_map_file_backed_memory(identifier + 5);
    return rr_map_posix_shared_memory(identifier);
}

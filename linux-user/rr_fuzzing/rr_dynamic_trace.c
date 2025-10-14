/*
 * RR-Fuzz 动态跟踪实现
 * 实时向Python发送系统调用和Fork事件用于树可视化
 */

/* 必须在include之前定义RR_DEBUG */
#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "qemu/osdep.h"  // 必须首先include
#include "rr_dynamic_trace.h"
#include "rr_framework.h"
#include "rr_syscall_dispatch.h"  /* for rr_get_syscall_name_fast */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* 全局跟踪管道 */
static int g_dynamic_trace_pipe_fd = -1;
static bool g_dynamic_trace_enabled = false;

void rr_dynamic_trace_init(int write_fd) {
    RR_INFO("=== Dynamic Trace Init START ===");
    RR_INFO("  write_fd = %d", write_fd);
    
    g_dynamic_trace_pipe_fd = write_fd;
    g_dynamic_trace_enabled = (write_fd >= 0);
    
    RR_INFO("  g_dynamic_trace_enabled = %d", g_dynamic_trace_enabled);
    
    if (g_dynamic_trace_enabled) {
        /* 发送初始化消息 */
        rr_dynamic_trace_msg_t msg = {
            .type = RR_DYN_MSG_INIT,
            .pid = getpid(),
            .parent_pid = 0
        };
        
        RR_INFO("  Attempting to write INIT message (%zu bytes)", sizeof(msg));
        errno = 0;
        ssize_t written = write(g_dynamic_trace_pipe_fd, &msg, sizeof(msg));
        
        RR_INFO("  write() returned: %zd", written);
        if (written < 0) {
            RR_WARN("  errno = %d (%s)", errno, strerror(errno));
            RR_WARN("  ❌ INIT message send FAILED - disabling dynamic trace");
            g_dynamic_trace_enabled = false;
        } else if (written != sizeof(msg)) {
            RR_WARN("  ⚠️  Partial write: %zd/%zu bytes", written, sizeof(msg));
            g_dynamic_trace_enabled = false;
        } else {
            RR_INFO("  ✅ INIT message sent successfully (%zd bytes)", written);
        }
    }
    
    RR_INFO("=== Dynamic Trace Init END (enabled=%d) ===", g_dynamic_trace_enabled);
}

void rr_dynamic_trace_cleanup(void) {
    if (!g_dynamic_trace_enabled) return;
    
    /* 发送清理消息 */
    rr_dynamic_trace_msg_t msg = {
        .type = RR_DYN_MSG_CLEANUP,
        .pid = getpid(),
        .parent_pid = 0
    };
    write(g_dynamic_trace_pipe_fd, &msg, sizeof(msg));
    
    if (g_dynamic_trace_pipe_fd >= 0) {
        close(g_dynamic_trace_pipe_fd);
        g_dynamic_trace_pipe_fd = -1;
    }
    g_dynamic_trace_enabled = false;
    
    RR_INFO("Dynamic trace cleanup completed");
}

static inline void send_trace_msg(rr_dynamic_trace_msg_t *msg) {
    if (!g_dynamic_trace_enabled || g_dynamic_trace_pipe_fd < 0) {
        RR_VERBOSE("send_trace_msg: skipped (enabled=%d, fd=%d)", g_dynamic_trace_enabled, g_dynamic_trace_pipe_fd);
        return;
    }
    
    errno = 0;
    ssize_t written = write(g_dynamic_trace_pipe_fd, msg, sizeof(rr_dynamic_trace_msg_t));
    if (written != sizeof(rr_dynamic_trace_msg_t)) {
        /* 写入失败时禁用跟踪 */
        RR_WARN("Dynamic trace pipe write failed: written=%zd, expected=%zu, errno=%d (%s)", 
                written, sizeof(rr_dynamic_trace_msg_t), errno, strerror(errno));
        g_dynamic_trace_enabled = false;
        RR_WARN("Dynamic trace DISABLED due to write failure");
    } else {
        RR_VERBOSE("send_trace_msg: wrote %zd bytes (type=%u)", written, msg->type);
    }
}

void rr_dynamic_trace_syscall_enter(CPUArchState *env, int num, uint64_t *args,
                                     uint32_t trace_index, uint8_t is_fuzzed) {
    if (!g_dynamic_trace_enabled) {
        RR_VERBOSE("Dynamic trace syscall_enter skipped: not enabled");
        return;
    }
    
    RR_VERBOSE("Dynamic trace syscall_enter: num=%d, index=%u", num, trace_index);
    
    /* 显式初始化整个结构为0 */
    rr_dynamic_trace_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    
    msg.type = RR_DYN_MSG_SYSCALL_ENTER;
    msg.pid = getpid();
    msg.parent_pid = 0;
    
    msg.syscall_info.index = trace_index;
    msg.syscall_info.syscall_nr = num;
    msg.syscall_info.is_fuzzed = is_fuzzed;
    msg.syscall_info.is_entry = 1;
    msg.syscall_info.pid = getpid();
    
    /* 复制参数 */
    if (args) {
        for (int i = 0; i < 8; i++) {
            msg.syscall_info.args[i] = args[i];
        }
    }
    
    /* 获取系统调用名 */
    const char *name = rr_get_syscall_name_fast(num);
    if (name) {
        strncpy(msg.syscall_info.name, name, sizeof(msg.syscall_info.name) - 1);
        msg.syscall_info.name[sizeof(msg.syscall_info.name) - 1] = '\0';
    } else {
        snprintf(msg.syscall_info.name, sizeof(msg.syscall_info.name), "syscall_%d", num);
    }
    
    /* Debug: 验证消息数据 */
    RR_INFO("ENTER msg: type=%u, pid=%u, index=%u, nr=%d, name='%s'",
            msg.type, msg.pid, msg.syscall_info.index, msg.syscall_info.syscall_nr, msg.syscall_info.name);
    
    send_trace_msg(&msg);
}

void rr_dynamic_trace_syscall_exit(CPUArchState *env, int num, uint64_t *args,
                                    int32_t ret, uint32_t trace_index, uint8_t is_fuzzed) {
    if (!g_dynamic_trace_enabled) return;
    
    /* 显式初始化整个结构为0 */
    rr_dynamic_trace_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    
    msg.type = RR_DYN_MSG_SYSCALL_EXIT;
    msg.pid = getpid();
    msg.parent_pid = 0;
    
    msg.syscall_info.index = trace_index;
    msg.syscall_info.syscall_nr = num;
    msg.syscall_info.retval = ret;
    msg.syscall_info.is_fuzzed = is_fuzzed;
    msg.syscall_info.is_entry = 0;
    msg.syscall_info.pid = getpid();
    
    /* 复制参数 */
    if (args) {
        for (int i = 0; i < 8; i++) {
            msg.syscall_info.args[i] = args[i];
        }
    }
    
    /* 获取系统调用名 */
    const char *name = rr_get_syscall_name_fast(num);
    if (name) {
        strncpy(msg.syscall_info.name, name, sizeof(msg.syscall_info.name) - 1);
        msg.syscall_info.name[sizeof(msg.syscall_info.name) - 1] = '\0';
    } else {
        snprintf(msg.syscall_info.name, sizeof(msg.syscall_info.name), "syscall_%d", num);
    }
    
    send_trace_msg(&msg);
}

void rr_dynamic_trace_fork(uint32_t parent_pid, uint32_t child_pid, uint32_t fork_syscall_index) {
    if (!g_dynamic_trace_enabled) return;
    
    rr_dynamic_trace_msg_t msg = {
        .type = RR_DYN_MSG_FORK,
        .pid = child_pid,
        .parent_pid = parent_pid
    };
    
    msg.syscall_info.index = fork_syscall_index;
    
    send_trace_msg(&msg);
    
    RR_VERBOSE("Dynamic trace: fork %u -> %u @ syscall[%u]", parent_pid, child_pid, fork_syscall_index);
}

void rr_dynamic_trace_exec(uint32_t pid) {
    if (!g_dynamic_trace_enabled) return;
    
    rr_dynamic_trace_msg_t msg = {
        .type = RR_DYN_MSG_EXEC,
        .pid = pid,
        .parent_pid = 0
    };
    
    send_trace_msg(&msg);
}

void rr_dynamic_trace_exit(uint32_t pid, int exit_code) {
    if (!g_dynamic_trace_enabled) return;
    
    rr_dynamic_trace_msg_t msg = {
        .type = RR_DYN_MSG_EXIT,
        .pid = pid,
        .parent_pid = 0
    };
    
    msg.syscall_info.retval = exit_code;
    
    send_trace_msg(&msg);
}

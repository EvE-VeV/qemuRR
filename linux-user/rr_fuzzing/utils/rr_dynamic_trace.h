/*
 * RR-Fuzz 动态跟踪 - 实时树可视化
 * 向Python发送系统调用和Fork事件
 */

#ifndef RR_DYNAMIC_TRACE_H
#define RR_DYNAMIC_TRACE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/* 前向声明 - 避免循环依赖 */
typedef struct CPUArchState CPUArchState;

/* 消息类型 */
typedef enum {
    RR_DYN_MSG_SYSCALL_ENTER = 0,
    RR_DYN_MSG_SYSCALL_EXIT = 1,
    RR_DYN_MSG_FORK = 2,
    RR_DYN_MSG_EXEC = 3,
    RR_DYN_MSG_EXIT = 4,
    RR_DYN_MSG_INIT = 5,
    RR_DYN_MSG_CLEANUP = 6,
    RR_DYN_MSG_ITERATION = 7    /* ✅ 新增：iteration开始事件 */
} rr_dynamic_msg_type_t;

/* 系统调用信息 */
typedef struct {
    uint32_t index;         /* trace索引 */
    int32_t syscall_nr;     /* 系统调用号 */
    uint64_t args[8];       /* 参数 */
    int32_t retval;         /* 返回值 */
    uint32_t pid;           /* 进程ID */
    uint32_t parent_pid;    /* 父进程ID */
    uint8_t is_fuzzed;      /* 是否被fuzz */
    uint8_t is_entry;       /* 进入/退出 */
    char name[64];          /* 系统调用名 */
} rr_dynamic_syscall_info_t;

/* 完整消息 */
typedef struct {
    rr_dynamic_msg_type_t type;
    uint32_t pid;
    uint32_t parent_pid;
    rr_dynamic_syscall_info_t syscall_info;
} rr_dynamic_trace_msg_t;

/* API函数 */
#ifdef __cplusplus
extern "C" {
#endif

/* API函数声明 - 总是声明，实现在.c文件或编译器优化掉 */
void rr_dynamic_trace_init(int write_fd);
void rr_dynamic_trace_cleanup(void);
void rr_dynamic_trace_syscall_enter(CPUArchState *env, int num, uint64_t *args, 
                                     uint32_t trace_index, uint8_t is_fuzzed);
void rr_dynamic_trace_syscall_exit(CPUArchState *env, int num, uint64_t *args, 
                                    int32_t ret, uint32_t trace_index, uint8_t is_fuzzed);
void rr_dynamic_trace_fork(uint32_t parent_pid, uint32_t child_pid, uint32_t fork_syscall_index);
void rr_dynamic_trace_iteration(uint32_t iteration_id, uint32_t pid);  /* ✅ 新增 */
void rr_dynamic_trace_exec(uint32_t pid);
void rr_dynamic_trace_exit(uint32_t pid, int exit_code);
void rr_dynamic_trace_enable_in_child(void);  /* 在fork子进程中重新启用trace */

/* 全局变量声明 - 允许直接访问 */
extern int g_dynamic_trace_pipe_fd;
extern bool g_dynamic_trace_enabled;

#ifdef __cplusplus
}
#endif

#endif /* RR_DYNAMIC_TRACE_H */

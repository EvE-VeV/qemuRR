/**
 * 系统调用分发优化模块
 * 使用函数指针表和ID映射替代大量字符串比较
 */

#ifndef RR_SYSCALL_DISPATCH_H
#define RR_SYSCALL_DISPATCH_H

#include "../core/rr_framework.h"
#include "rr_syscallparser.h"

/* 系统调用类型枚举 */
typedef enum {
    SYSCALL_TYPE_UNKNOWN = 0,
    SYSCALL_TYPE_FILE_IO,
    SYSCALL_TYPE_NETWORK,
    SYSCALL_TYPE_PROCESS,
    SYSCALL_TYPE_MEMORY,
    SYSCALL_TYPE_TIME,
    SYSCALL_TYPE_SIGNAL,
    SYSCALL_TYPE_SYSTEM_INFO,
    SYSCALL_TYPE_MAX
} syscall_type_t;

/* 系统调用重要性级别 */
typedef enum {
    SYSCALL_IMPORTANCE_CRITICAL = 0,
    SYSCALL_IMPORTANCE_IMPORTANT,
    SYSCALL_IMPORTANCE_OPTIONAL,
    SYSCALL_IMPORTANCE_ENVIRONMENT,
    SYSCALL_IMPORTANCE_MAX
} syscall_importance_t;

/* 系统调用处理函数类型 */
typedef struct rr_syscall_handler {
    const char *name;
    int syscall_nr;
    syscall_type_t type;
    syscall_importance_t importance;
    
    /* 处理函数指针 */
    void (*apply_args)(rr_strace_record_t *record, abi_long *args);
    void (*apply_fd_mapping)(const char *syscall_name, abi_long *args);
    void (*post_hook)(rr_strace_record_t *record, abi_long ret, abi_long *args);
    
    /* 标志位 */
    bool needs_fd_mapping;
    bool needs_addr_mapping;
    bool is_fd_syscall;
} rr_syscall_handler_t;

/* 快速查找结构 */
typedef struct {
    int syscall_nr;
    rr_syscall_handler_t *handler;
} syscall_lookup_entry_t;

/* 公共接口 */
int rr_syscall_dispatch_init(void);
void rr_syscall_dispatch_cleanup(void);

rr_syscall_handler_t* rr_get_syscall_handler(int syscall_nr);
rr_syscall_handler_t* rr_get_syscall_handler_by_name(const char *name);

const char* rr_get_syscall_name_fast(int syscall_nr);
syscall_type_t rr_get_syscall_type(int syscall_nr);
syscall_importance_t rr_get_syscall_importance(int syscall_nr);

/* 优化的处理函数 */
void rr_apply_syscall_args_optimized(rr_strace_record_t *record, abi_long *args);
void rr_apply_fd_mapping_optimized(int syscall_nr, abi_long *args);
void rr_syscall_post_hook_optimized(int syscall_nr, rr_strace_record_t *record, 
                                    abi_long ret, abi_long *args);

#endif /* RR_SYSCALL_DISPATCH_H */

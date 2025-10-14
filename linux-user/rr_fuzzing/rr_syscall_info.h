/**
 * RR-Fuzz 系统调用分类信息
 * 
 * 基于 EnvFuzz 的 P_IO 分类策略
 * 只对数据传输类系统调用进行 fuzzing
 */

#ifndef RR_SYSCALL_INFO_H
#define RR_SYSCALL_INFO_H

#include <stdint.h>
#include <stdbool.h>

/* 系统调用分类（参考 EnvFuzz） */
typedef enum {
    SYSCALL_CLASS_MISC = 0,    /* 杂项 */
    SYSCALL_CLASS_FD   = 1,    /* 文件描述符管理（open, close, socket...） */
    SYSCALL_CLASS_IO   = 2,    /* I/O 数据传输 - fuzzing 目标！ */
    SYSCALL_CLASS_INFO = 3,    /* 信息查询（stat, getpid...） */
    SYSCALL_CLASS_MEM  = 4,    /* 内存管理（mmap, brk...） */
    SYSCALL_CLASS_SIG  = 5,    /* 信号处理 */
    SYSCALL_CLASS_THR  = 6,    /* 线程管理 */
    SYSCALL_CLASS_PROC = 7,    /* 进程管理（fork, execve...） */
} syscall_class_t;

/* 系统调用信息 */
typedef struct {
    int nr;                    /* 系统调用号 */
    const char *name;          /* 名称 */
    syscall_class_t class;     /* 分类 */
    bool is_input;             /* 是否为输入方向（read: true, write: false） */
} syscall_info_t;

/* ===== 核心函数 ===== */

/**
 * 获取系统调用信息
 * @param syscall_nr 系统调用号
 * @return 系统调用信息，如果未找到返回默认信息
 */
const syscall_info_t *rr_get_syscall_info(int syscall_nr);

/**
 * 判断是否应该自动 fork（EnvFuzz 策略）
 * 
 * 充要条件:
 * 1. 是 P_IO 类（数据传输）
 * 2. inbound 方向（输入，如 read）
 * 3. 返回值 > 0（有数据）
 * 
 * @param syscall_nr 系统调用号
 * @param ret 系统调用返回值
 * @return true 表示应该 fork
 */
bool rr_should_auto_fork(int syscall_nr, abi_long ret);

/**
 * 获取系统调用分类名称（用于日志）
 */
const char *rr_get_syscall_class_name(syscall_class_t class);

#endif /* RR_SYSCALL_INFO_H */


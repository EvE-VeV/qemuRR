/**
 * RR-Fuzz 系统调用分类信息实现
 */

#include "../core/rr_framework.h"
#include "rr_syscall_info.h"

/* 系统调用号定义 */
#ifndef __NR_read
#include <sys/syscall.h>
#endif

/* ===== 系统调用分类表 ===== */
/**
 * @brief 系统调用分类表 (P0 Key Data Structure)
 * 
 * 定义了所有受支持的系统调用的分类信息。
 * 
 * **分类 (Class)**:
 * - `SYSCALL_CLASS_IO`:   读写数据 (fuzzing 重点)
 * - `SYSCALL_CLASS_FD`:   管理 FD (open, close, socket)
 * - `SYSCALL_CLASS_MEM`:  内存管理 (mmap)
 * - `SYSCALL_CLASS_PROC`: 进程控制 (fork, exec)
 * 
 * **属性**:
 * - `is_input`: 标记该 syscall 是否为输入源 (如 read 是, write 不是)。
 *               这对于 Auto Fork 策略至关重要。
 */
static const syscall_info_t g_syscall_table[] = {
    /* ===== P_IO 类（18个）- fuzzing 目标 ===== */
    /* 这些系统调用传输数据，是 fuzzing 的主要目标 */
    
    /* 文件 I/O */
    {__NR_read,          "read",          SYSCALL_CLASS_IO, true},
    {__NR_write,         "write",         SYSCALL_CLASS_IO, false},
#ifdef __NR_pread64
    {__NR_pread64,       "pread64",       SYSCALL_CLASS_IO, true},
#endif
#ifdef __NR_pwrite64
    {__NR_pwrite64,      "pwrite64",      SYSCALL_CLASS_IO, false},
#endif
    {__NR_readv,         "readv",         SYSCALL_CLASS_IO, true},
    {__NR_writev,        "writev",        SYSCALL_CLASS_IO, false},
#ifdef __NR_preadv
    {__NR_preadv,        "preadv",        SYSCALL_CLASS_IO, true},
#endif
#ifdef __NR_pwritev
    {__NR_pwritev,       "pwritev",       SYSCALL_CLASS_IO, false},
#endif
    
    /* 网络 I/O */
    {__NR_sendto,        "sendto",        SYSCALL_CLASS_IO, false},
    {__NR_recvfrom,      "recvfrom",      SYSCALL_CLASS_IO, true},
    {__NR_sendmsg,       "sendmsg",       SYSCALL_CLASS_IO, false},
    {__NR_recvmsg,       "recvmsg",       SYSCALL_CLASS_IO, true},
#ifdef __NR_sendmmsg
    {__NR_sendmmsg,      "sendmmsg",      SYSCALL_CLASS_IO, false},
#endif
#ifdef __NR_recvmmsg
    {__NR_recvmmsg,      "recvmmsg",      SYSCALL_CLASS_IO, true},
#endif
    
    /* 设备和目录 I/O */
    {__NR_ioctl,         "ioctl",         SYSCALL_CLASS_IO, true},
    {__NR_getdents,      "getdents",      SYSCALL_CLASS_IO, true},
#ifdef __NR_getdents64
    {__NR_getdents64,    "getdents64",    SYSCALL_CLASS_IO, true},
#endif
    
    /* ===== P_FD 类 - 文件描述符管理 ===== */
    /* 这些系统调用管理文件描述符，不传输数据 */
    {__NR_open,          "open",          SYSCALL_CLASS_FD, false},
    {__NR_openat,        "openat",        SYSCALL_CLASS_FD, false},
    {__NR_close,         "close",         SYSCALL_CLASS_FD, false},
    {__NR_socket,        "socket",        SYSCALL_CLASS_FD, false},
    {__NR_accept,        "accept",        SYSCALL_CLASS_FD, false},
#ifdef __NR_accept4
    {__NR_accept4,       "accept4",       SYSCALL_CLASS_FD, false},
#endif
    {__NR_connect,       "connect",       SYSCALL_CLASS_FD, false},
    {__NR_bind,          "bind",          SYSCALL_CLASS_FD, false},
    {__NR_listen,        "listen",        SYSCALL_CLASS_FD, false},
    {__NR_dup,           "dup",           SYSCALL_CLASS_FD, false},
    {__NR_dup2,          "dup2",          SYSCALL_CLASS_FD, false},
#ifdef __NR_dup3
    {__NR_dup3,          "dup3",          SYSCALL_CLASS_FD, false},
#endif
    {__NR_pipe,          "pipe",          SYSCALL_CLASS_FD, false},
#ifdef __NR_pipe2
    {__NR_pipe2,         "pipe2",         SYSCALL_CLASS_FD, false},
#endif
    
    /* ===== PMEM 类 - 内存管理 ===== */
    {__NR_mmap,          "mmap",          SYSCALL_CLASS_MEM, false},
    {__NR_munmap,        "munmap",        SYSCALL_CLASS_MEM, false},
    {__NR_mprotect,      "mprotect",      SYSCALL_CLASS_MEM, false},
    {__NR_brk,           "brk",           SYSCALL_CLASS_MEM, false},
#ifdef __NR_mremap
    {__NR_mremap,        "mremap",        SYSCALL_CLASS_MEM, false},
#endif
    {__NR_madvise,       "madvise",       SYSCALL_CLASS_MEM, false},
    
    /* ===== PINF 类 - 信息查询 ===== */
    {__NR_stat,          "stat",          SYSCALL_CLASS_INFO, false},
    {__NR_fstat,         "fstat",         SYSCALL_CLASS_INFO, false},
    {__NR_lstat,         "lstat",         SYSCALL_CLASS_INFO, false},
#ifdef __NR_newfstatat
    {__NR_newfstatat,    "newfstatat",    SYSCALL_CLASS_INFO, false},
#endif
    {__NR_getpid,        "getpid",        SYSCALL_CLASS_INFO, false},
    {__NR_getuid,        "getuid",        SYSCALL_CLASS_INFO, false},
    {__NR_geteuid,       "geteuid",       SYSCALL_CLASS_INFO, false},
    {__NR_getgid,        "getgid",        SYSCALL_CLASS_INFO, false},
    {__NR_getegid,       "getegid",       SYSCALL_CLASS_INFO, false},
    {__NR_uname,         "uname",         SYSCALL_CLASS_INFO, false},
    {__NR_getcwd,        "getcwd",        SYSCALL_CLASS_INFO, false},
    {__NR_getdents,      "getdents",      SYSCALL_CLASS_INFO, false},
    
    /* ===== PROC 类 - 进程管理 ===== */
    {__NR_fork,          "fork",          SYSCALL_CLASS_PROC, false},
#ifdef __NR_vfork
    {__NR_vfork,         "vfork",         SYSCALL_CLASS_PROC, false},
#endif
    {__NR_execve,        "execve",        SYSCALL_CLASS_PROC, false},
#ifdef __NR_execveat
    {__NR_execveat,      "execveat",      SYSCALL_CLASS_PROC, false},
#endif
    {__NR_wait4,         "wait4",         SYSCALL_CLASS_PROC, false},
#ifdef __NR_waitid
    {__NR_waitid,        "waitid",        SYSCALL_CLASS_PROC, false},
#endif
    {__NR_exit,          "exit",          SYSCALL_CLASS_PROC, false},
    {__NR_exit_group,    "exit_group",    SYSCALL_CLASS_PROC, false},
    
    /* ===== PSIG 类 - 信号处理 ===== */
    {__NR_rt_sigaction,  "rt_sigaction",  SYSCALL_CLASS_SIG, false},
    {__NR_rt_sigprocmask, "rt_sigprocmask", SYSCALL_CLASS_SIG, false},
#ifdef __NR_rt_sigreturn
    {__NR_rt_sigreturn,  "rt_sigreturn",  SYSCALL_CLASS_SIG, false},
#endif
    {__NR_kill,          "kill",          SYSCALL_CLASS_SIG, false},
#ifdef __NR_tkill
    {__NR_tkill,         "tkill",         SYSCALL_CLASS_SIG, false},
#endif
    
    /* ===== PTHR 类 - 线程管理 ===== */
    {__NR_clone,         "clone",         SYSCALL_CLASS_THR, false},
#ifdef __NR_sched_yield
    {__NR_sched_yield,   "sched_yield",   SYSCALL_CLASS_THR, false},
#endif
    {__NR_futex,         "futex",         SYSCALL_CLASS_THR, false},
    
    /* 结束标记 */
    {-1, NULL, SYSCALL_CLASS_MISC, false}
};

/* ===== 实现函数 ===== */

const syscall_info_t *rr_get_syscall_info(int syscall_nr)
{
    /* 线性查找（表不大，性能足够） */
    for (int i = 0; g_syscall_table[i].nr != -1; i++) {
        if (g_syscall_table[i].nr == syscall_nr) {
            return &g_syscall_table[i];
        }
    }
    
    /* 未找到，返回默认信息 */
    static const syscall_info_t default_info = {
        -1, "unknown", SYSCALL_CLASS_MISC, false
    };
    return &default_info;
}

/**
 * @brief 判断是否应该自动 Fork (Auto Fork Heuristic)
 * 
 * Fork Server 的核心决策函数。在 `rr_check_auto_fork_point` 中被调用。
 * 决定当前系统调用执行完毕后，是否应该作为一个新的 Fork 点。
 * 
 * **策略 (Strategy)**:
 * - `STRICT`: 仅当成功读取且被标记为 input 时 fork (保守)。
 * - `RELAXED`: 允许部分错误 (如 ENOENT)。
 * - `AGGRESSIVE`: 只要是 IO 类 syscall 就 fork (覆盖率最大化)。
 * - `FALLBACK`: 留给上层逻辑决定。
 * 
 * @param syscall_nr 系统调用号
 * @param ret 返回值
 * @return true 应该 fork, false 不 fork
 */
bool rr_should_auto_fork(int syscall_nr, abi_long ret)
{
    const syscall_info_t *info = rr_get_syscall_info(syscall_nr);
    
    /*
     * 改进的 Fork 策略（支持多种模式）
     * 
     * 模式说明：
     * - STRICT: EnvFuzz原始策略（ret>0 && is_input && class==IO）
     * - RELAXED: 允许探测性错误（ENOENT, EACCES）
     * - AGGRESSIVE: 任何I/O类syscall都fork（当前最实用）
     * - FALLBACK: 会在rr_check_auto_fork_point()中处理
     */
    
    /* 基本过滤：必须是I/O类或FD类（因为open/openat返回fd后会有read/write） */
    if (info->class != SYSCALL_CLASS_IO && info->class != SYSCALL_CLASS_FD) {
        return false;  
    }
    
    /* 根据策略选择不同的判断逻辑 */
    switch (g_rr_config.fork_strategy) {
        case RR_FORK_STRATEGY_STRICT:
            /* 严格模式：EnvFuzz原始策略 */
            if (!info->is_input) return false;
            if (ret <= 0) return false;
            return true;
            
        case RR_FORK_STRATEGY_RELAXED:
            /* 宽松模式：允许ENOENT/EACCES等探测性错误 */
            if (!info->is_input) return false;
            if (ret > 0) return true;  // 成功
            // 允许特定的探测性错误
            if (ret == -2 || ret == -13) return true;  // ENOENT or EACCES
            return false;
            
        case RR_FORK_STRATEGY_AGGRESSIVE:
            /* 激进模式：任何I/O类syscall都fork（推荐用于测试） */
            // 不检查方向，不检查返回值
            return true;
            
        case RR_FORK_STRATEGY_FALLBACK:
            /* Fallback模式：在check_auto_fork_point中处理 */
            if (!info->is_input) return false;
            if (ret > 0) return true;  // 成功的优先
            return false;  // 失败的等fallback处理
            
        default:
            /* 默认使用AGGRESSIVE */
            return true;
    }
}

const char *rr_get_syscall_class_name(syscall_class_t class)
{
    switch (class) {
        case SYSCALL_CLASS_MISC: return "MISC";
        case SYSCALL_CLASS_FD:   return "FD";
        case SYSCALL_CLASS_IO:   return "IO";
        case SYSCALL_CLASS_INFO: return "INFO";
        case SYSCALL_CLASS_MEM:  return "MEM";
        case SYSCALL_CLASS_SIG:  return "SIG";
        case SYSCALL_CLASS_THR:  return "THR";
        case SYSCALL_CLASS_PROC: return "PROC";
        default: return "UNKNOWN";
    }
}


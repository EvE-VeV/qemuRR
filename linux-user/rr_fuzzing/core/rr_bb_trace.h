/**
 * RR-Fuzz Basic Block Trace Module
 * 
 * 用于记录程序执行时的基本块(BB)轨迹
 * 
 * 设计目标：
 * 1. 高效记录每个翻译块(TB)的PC地址
 * 2. 与syscall trace关联，提供精确的执行序列
 * 3. 支持离线静态分析（angr CFG匹配）
 */

#ifndef RR_BB_TRACE_H
#define RR_BB_TRACE_H

#include "qemu/osdep.h"
#include "user/abitypes.h"

/* ================= 配置常量 ================= */

#define RR_BB_TRACE_BUFFER_SIZE (1024 * 1024)  // 1MB缓冲区
#define RR_BB_TRACE_SUFFIX ".bbl"              // BB trace文件后缀

/* ================= 数据结构 ================= */

/**
 * BB Trace记录项
 * 每个TB执行时记录一条
 */
typedef struct {
    uint64_t pc;           // 程序计数器（TB起始地址）
    uint32_t syscall_idx;  // 关联的syscall索引（0表示syscall前，N表示第N个syscall后）
    uint32_t flags;        // 保留标志位
} rr_bb_entry_t;

/**
 * BB Trace上下文
 */
typedef struct {
    bool enabled;                          // 是否启用BB跟踪
    char *trace_file;                      // BB trace文件路径
    int fd;                                // 文件描述符
    
    /* 缓冲区 */
    rr_bb_entry_t *buffer;                 // 内存缓冲区
    size_t buffer_size;                    // 缓冲区大小（条目数）
    size_t buffer_pos;                     // 当前缓冲区位置
    
    /* 统计信息 */
    uint64_t total_bbs;                    // 总BB数
    uint64_t total_flushes;                // 总刷新次数
    uint32_t current_syscall_idx;          // 当前syscall索引
} rr_bb_trace_t;

/* ================= 全局变量 ================= */

extern rr_bb_trace_t *g_bb_trace;

/* ================= 核心函数 ================= */

/**
 * 初始化BB trace模块
 * 
 * @param trace_file syscall trace文件路径（将自动添加.bbl后缀）
 * @return 0成功，-1失败
 */
int rr_bb_trace_init(const char *trace_file);

/**
 * 清理BB trace模块
 */
void rr_bb_trace_cleanup(void);

/**
 * 记录一个基本块执行
 * 
 * 这是最核心的函数，会在每个TB执行时被调用
 * 
 * @param pc 程序计数器（TB起始地址）
 */
void rr_bb_trace_log(uint64_t pc);

/**
 * 刷新缓冲区到磁盘
 */
void rr_bb_trace_flush(void);

/**
 * 更新当前syscall索引
 * 
 * 每当一个syscall被记录时，rr_record模块应调用此函数
 * 
 * @param syscall_idx syscall索引
 */
void rr_bb_trace_update_syscall_idx(uint32_t syscall_idx);

/**
 * 启用/禁用BB跟踪
 * 
 * @param enabled 是否启用
 */
void rr_bb_trace_set_enabled(bool enabled);

/**
 * 检查BB跟踪是否启用（内联版本）
 * 
 * @return true启用，false禁用
 */
static inline bool rr_bb_trace_is_enabled(void)
{
    return g_bb_trace && g_bb_trace->enabled;
}

/**
 * 检查BB跟踪是否启用（非内联版本，供cpu-exec.c使用）
 * 
 * @return true启用，false禁用
 */
bool rr_bb_trace_is_enabled_check(void);

/**
 * 获取BB trace统计信息
 * 
 * @param total_bbs 输出：总BB数
 * @param total_flushes 输出：总刷新次数
 */
void rr_bb_trace_get_stats(uint64_t *total_bbs, uint64_t *total_flushes);

/**
 * 打印BB trace统计信息
 */
void rr_bb_trace_print_stats(void);

#endif /* RR_BB_TRACE_H */


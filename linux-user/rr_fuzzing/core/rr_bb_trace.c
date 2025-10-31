/**
 * RR-Fuzz Basic Block Trace Module - Implementation
 */

#include "rr_bb_trace.h"
#include "rr_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* ================= 全局变量 ================= */

rr_bb_trace_t *g_bb_trace = NULL;

/* ================= 内部辅助函数 ================= */

/**
 * 构造BB trace文件路径
 */
static char *construct_bb_trace_path(const char *trace_file)
{
    if (!trace_file) {
        return NULL;
    }
    
    size_t len = strlen(trace_file) + strlen(RR_BB_TRACE_SUFFIX) + 1;
    char *bb_path = malloc(len);
    if (!bb_path) {
        RR_ERROR("Failed to allocate memory for BB trace path");
        return NULL;
    }
    
    snprintf(bb_path, len, "%s%s", trace_file, RR_BB_TRACE_SUFFIX);
    return bb_path;
}

/* ================= 核心函数实现 ================= */

int rr_bb_trace_init(const char *trace_file)
{
    if (!trace_file) {
        RR_ERROR("BB trace: trace_file is NULL");
        return -1;
    }
    
    /* 分配上下文 */
    g_bb_trace = calloc(1, sizeof(rr_bb_trace_t));
    if (!g_bb_trace) {
        RR_ERROR("Failed to allocate BB trace context");
        return -1;
    }
    
    /* 构造BB trace文件路径 */
    g_bb_trace->trace_file = construct_bb_trace_path(trace_file);
    if (!g_bb_trace->trace_file) {
        free(g_bb_trace);
        g_bb_trace = NULL;
        return -1;
    }
    
    /* 打开文件 */
    g_bb_trace->fd = open(g_bb_trace->trace_file, 
                          O_WRONLY | O_CREAT | O_TRUNC, 
                          0644);
    if (g_bb_trace->fd < 0) {
        RR_ERROR("Failed to open BB trace file '%s': %s",
                g_bb_trace->trace_file, strerror(errno));
        free(g_bb_trace->trace_file);
        free(g_bb_trace);
        g_bb_trace = NULL;
        return -1;
    }
    
    /* 分配缓冲区 */
    g_bb_trace->buffer_size = RR_BB_TRACE_BUFFER_SIZE / sizeof(rr_bb_entry_t);
    g_bb_trace->buffer = malloc(RR_BB_TRACE_BUFFER_SIZE);
    if (!g_bb_trace->buffer) {
        RR_ERROR("Failed to allocate BB trace buffer");
        close(g_bb_trace->fd);
        free(g_bb_trace->trace_file);
        free(g_bb_trace);
        g_bb_trace = NULL;
        return -1;
    }
    
    /* 初始化状态 */
    g_bb_trace->buffer_pos = 0;
    g_bb_trace->total_bbs = 0;
    g_bb_trace->total_flushes = 0;
    g_bb_trace->current_syscall_idx = 0;
    g_bb_trace->enabled = true;
    
    RR_INFO("BB trace initialized: %s (buffer: %zu entries)",
            g_bb_trace->trace_file, g_bb_trace->buffer_size);
    
    return 0;
}

void rr_bb_trace_cleanup(void)
{
    if (!g_bb_trace) {
        return;
    }
    
    /* 刷新剩余数据 */
    if (g_bb_trace->buffer_pos > 0) {
        rr_bb_trace_flush();
    }
    
    /* 打印统计信息 */
    rr_bb_trace_print_stats();
    
    /* 关闭文件 */
    if (g_bb_trace->fd >= 0) {
        close(g_bb_trace->fd);
    }
    
    /* 释放资源 */
    if (g_bb_trace->buffer) {
        free(g_bb_trace->buffer);
    }
    if (g_bb_trace->trace_file) {
        free(g_bb_trace->trace_file);
    }
    
    free(g_bb_trace);
    g_bb_trace = NULL;
    
    RR_INFO("BB trace cleanup completed");
}

void rr_bb_trace_log(uint64_t pc)
{
    if (!rr_bb_trace_is_enabled()) {
        return;
    }
    
    /* 检查缓冲区是否已满 */
    if (g_bb_trace->buffer_pos >= g_bb_trace->buffer_size) {
        rr_bb_trace_flush();
    }
    
    /* 记录BB */
    rr_bb_entry_t *entry = &g_bb_trace->buffer[g_bb_trace->buffer_pos];
    entry->pc = pc;
    entry->syscall_idx = g_bb_trace->current_syscall_idx;
    entry->flags = 0;
    
    g_bb_trace->buffer_pos++;
    g_bb_trace->total_bbs++;
}

void rr_bb_trace_flush(void)
{
    if (!g_bb_trace || g_bb_trace->buffer_pos == 0) {
        return;
    }
    
    size_t bytes_to_write = g_bb_trace->buffer_pos * sizeof(rr_bb_entry_t);
    ssize_t written = write(g_bb_trace->fd, g_bb_trace->buffer, bytes_to_write);
    
    if (written != (ssize_t)bytes_to_write) {
        RR_ERROR("Failed to write BB trace: expected %zu bytes, wrote %zd",
                bytes_to_write, written);
        return;
    }
    
    g_bb_trace->total_flushes++;
    g_bb_trace->buffer_pos = 0;
    
    RR_TRACE("BB trace flushed: %zu entries", 
            bytes_to_write / sizeof(rr_bb_entry_t));
}

void rr_bb_trace_update_syscall_idx(uint32_t syscall_idx)
{
    if (g_bb_trace) {
        g_bb_trace->current_syscall_idx = syscall_idx;
        RR_TRACE("BB trace syscall index updated to %u", syscall_idx);
    }
}

void rr_bb_trace_set_enabled(bool enabled)
{
    if (g_bb_trace) {
        g_bb_trace->enabled = enabled;
        RR_INFO("BB trace %s", enabled ? "enabled" : "disabled");
    }
}

/* 非内联版本供cpu-exec.c使用 */
bool rr_bb_trace_is_enabled_check(void)
{
    return g_bb_trace && g_bb_trace->enabled;
}

void rr_bb_trace_get_stats(uint64_t *total_bbs, uint64_t *total_flushes)
{
    if (g_bb_trace) {
        if (total_bbs) {
            *total_bbs = g_bb_trace->total_bbs;
        }
        if (total_flushes) {
            *total_flushes = g_bb_trace->total_flushes;
        }
    }
}

void rr_bb_trace_print_stats(void)
{
    if (!g_bb_trace) {
        return;
    }
    
    RR_INFO("=== BB Trace Statistics ===");
    RR_INFO("  Total BBs recorded: %lu", g_bb_trace->total_bbs);
    RR_INFO("  Total flushes: %lu", g_bb_trace->total_flushes);
    RR_INFO("  Buffer size: %zu entries", g_bb_trace->buffer_size);
    RR_INFO("  Current syscall idx: %u", g_bb_trace->current_syscall_idx);
    
    if (g_bb_trace->total_flushes > 0) {
        RR_INFO("  Avg BBs per flush: %.2f", 
                (double)g_bb_trace->total_bbs / (double)g_bb_trace->total_flushes);
    }
}


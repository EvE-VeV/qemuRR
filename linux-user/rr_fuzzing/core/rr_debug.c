/**
 * RR-Fuzz分级调试系统实现
 */

#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "rr_framework.h"
#include <string.h>
#include <stdlib.h>

/* 全局调试配置 */
rr_debug_config_t g_rr_debug = {
    .level = RR_DEBUG_INFO,          // 默认级别：基本信息
    .log_file = NULL                 // 默认输出到stderr
};

/**
 * 调试级别名称映射
 */
static const char *debug_level_names[] = {
    [RR_DEBUG_OFF] = "OFF",
    [RR_DEBUG_ERROR] = "ERROR",
    [RR_DEBUG_WARN] = "WARN",
    [RR_DEBUG_INFO] = "INFO",
    [RR_DEBUG_VERBOSE] = "VERBOSE",
    [RR_DEBUG_TRACE] = "TRACE"
};

/**
 * 获取调试级别名称
 */
const char *rr_debug_level_name(rr_debug_level_t level)
{
    if (level >= 0 && level < G_N_ELEMENTS(debug_level_names)) {
        return debug_level_names[level];
    }
    return "UNKNOWN";
}

/**
 * 解析调试级别字符串
 */
static rr_debug_level_t parse_debug_level(const char *level_str)
{
    if (!level_str) {
        return RR_DEBUG_INFO;
    }

    if (strcmp(level_str, "0") == 0 || strcasecmp(level_str, "off") == 0) {
        return RR_DEBUG_OFF;
    } else if (strcmp(level_str, "1") == 0 || strcasecmp(level_str, "error") == 0) {
        return RR_DEBUG_ERROR;
    } else if (strcmp(level_str, "2") == 0 || strcasecmp(level_str, "warn") == 0) {
        return RR_DEBUG_WARN;
    } else if (strcmp(level_str, "3") == 0 || strcasecmp(level_str, "info") == 0) {
        return RR_DEBUG_INFO;
    } else if (strcmp(level_str, "4") == 0 || strcasecmp(level_str, "verbose") == 0) {
        return RR_DEBUG_VERBOSE;
    } else if (strcmp(level_str, "5") == 0 || strcasecmp(level_str, "trace") == 0) {
        return RR_DEBUG_TRACE;
    }

    return RR_DEBUG_INFO; // 默认级别
}

/**
 * 解析布尔值字符串
 */
__attribute__((unused))
static bool parse_bool(const char *str, bool default_val)
{
    if (!str) {
        return default_val;
    }

    if (strcmp(str, "1") == 0 || strcasecmp(str, "true") == 0 ||
        strcasecmp(str, "yes") == 0 || strcasecmp(str, "on") == 0) {
        return true;
    } else if (strcmp(str, "0") == 0 || strcasecmp(str, "false") == 0 ||
               strcasecmp(str, "no") == 0 || strcasecmp(str, "off") == 0) {
        return false;
    }

    return default_val;
}

/**
 * 初始化调试系统
 */
void rr_debug_init(void)
{
    /* 从环境变量读取调试配置 */
    const char *debug_level = getenv("RR_DEBUG_LEVEL");
    const char *debug_file = getenv("RR_DEBUG_FILE");

    /* 设置调试级别 */
    g_rr_debug.level = parse_debug_level(debug_level);

    /* 设置日志文件 */
    if (debug_file && strcmp(debug_file, "stderr") != 0 && strcmp(debug_file, "") != 0) {
        FILE *log_file = fopen(debug_file, "a");
        if (log_file) {
            g_rr_debug.log_file = log_file;
            fprintf(log_file, "\n=== RR-Fuzz Debug Session Started ===\n");
            fflush(log_file);
        } else {
            fprintf(stderr, "[RR-ERROR] Failed to open debug log file: %s\n", debug_file);
        }
    }

    /* 输出初始化信息 */
    fprintf(stderr, "[RR-INFO] Debug system initialized:\n");
    fprintf(stderr, "  Level: %s (%d)\n", rr_debug_level_name(g_rr_debug.level), g_rr_debug.level);
    fprintf(stderr, "  Log file: %s\n", g_rr_debug.log_file ? debug_file : "stderr");
    fflush(stderr);
}

/**
 * 设置调试级别
 */
void rr_debug_set_level(rr_debug_level_t level)
{
    if (level >= RR_DEBUG_OFF && level <= RR_DEBUG_TRACE) {
        g_rr_debug.level = level;
        RR_INFO("Debug level set to %s (%d)", rr_debug_level_name(level), level);
    } else {
        RR_ERROR("Invalid debug level: %d", level);
    }
}

/**
 * 设置日志输出文件
 */
void rr_debug_set_output(FILE *file)
{
    if (g_rr_debug.log_file && g_rr_debug.log_file != stderr) {
        fclose(g_rr_debug.log_file);
    }
    g_rr_debug.log_file = file;
    RR_INFO("Debug output redirected");
}

/**
 * 清理调试系统
 */
void rr_debug_cleanup(void)
{
    if (g_rr_debug.log_file && g_rr_debug.log_file != stderr) {
        fprintf(g_rr_debug.log_file, "\n=== RR-Fuzz Debug Session Ended ===\n");
        fclose(g_rr_debug.log_file);
        g_rr_debug.log_file = NULL;
    }
}
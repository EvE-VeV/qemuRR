/**
 * RR-Fuzz统一配置管理系统
 * 替换分散的getenv()调用，提供统一的配置接口
 */

#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "rr_framework.h"
#include <string.h>
#include <stdlib.h>

/* 全局配置实例 */
rr_config_t g_rr_config = {0};

/**
 * 默认配置值
 */
static const rr_config_t DEFAULT_CONFIG = {
    .enabled = false,
    .mode = RR_MODE_DISABLED,

    /* 文件路径 - 默认为NULL，需要时动态分配 */
    .trace_file = NULL,
    .shared_memory_name = NULL,
    .cmd_pipe_path = NULL,
    .status_pipe_path = NULL,
    .config_file = NULL,

    /* Fork Server配置 */
    .fork_server_enabled = false,
    .fork_point = 0,

    /* IPC配置 */
    .shared_memory_size = 4096,           // 4KB
    .ipc_timeout = 1000                   // 1秒
};

/**
 * 解析模式字符串
 */
static rr_mode_t parse_mode(const char *mode_str)
{
    if (!mode_str) {
        return RR_MODE_RECORD; // 默认记录模式
    }

    if (strcmp(mode_str, "record") == 0) {
        return RR_MODE_RECORD;
    } else if (strcmp(mode_str, "replay") == 0) {
        return RR_MODE_REPLAY;
    } else if (strcmp(mode_str, "fuzzing") == 0) {
        return RR_MODE_FUZZING;
    } else if (strcmp(mode_str, "disabled") == 0) {
        return RR_MODE_DISABLED;
    }

    RR_WARN("Unknown mode '%s', defaulting to 'record'", mode_str);
    return RR_MODE_RECORD;
}

/**
 * 解析布尔值
 */
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
 * 解析整数值
 */
static int parse_int(const char *str, int default_val)
{
    if (!str) {
        return default_val;
    }

    char *endptr;
    int val = (int)strtol(str, &endptr, 10);
    if (*endptr != '\0') {
        RR_WARN("Invalid integer '%s', using default %d", str, default_val);
        return default_val;
    }

    return val;
}

/**
 * 解析大小值(支持K、M、G后缀)
 */
static size_t parse_size(const char *str, size_t default_val)
{
    if (!str) {
        return default_val;
    }

    char *endptr;
    unsigned long val = strtoul(str, &endptr, 10);

    if (endptr != str) {
        switch (*endptr) {
            case 'K':
            case 'k':
                val *= 1024;
                break;
            case 'M':
            case 'm':
                val *= 1024 * 1024;
                break;
            case 'G':
            case 'g':
                val *= 1024 * 1024 * 1024;
                break;
            case '\0':
                // 纯数字，不需要处理
                break;
            default:
                RR_WARN("Invalid size suffix in '%s', using default %zu", str, default_val);
                return default_val;
        }
    } else {
        RR_WARN("Invalid size format '%s', using default %zu", str, default_val);
        return default_val;
    }

    return (size_t)val;
}


/**
 * 从配置文件读取配置
 */
static int load_config_file(const char *config_file)
{
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        RR_WARN("Cannot open config file: %s", config_file);
        return -1;
    }

    RR_INFO("Loading config from file: %s", config_file);

    char line[256];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* 跳过注释和空行 */
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (*trimmed == '#' || *trimmed == '\n' || *trimmed == '\0') {
            continue;
        }

        /* 解析key=value格式 */
        char *equals = strchr(trimmed, '=');
        if (!equals) {
            RR_WARN("Invalid config line %d: %s", line_num, line);
            continue;
        }

        *equals = '\0';
        char *key = trimmed;
        char *value = equals + 1;

        /* 去除末尾的换行符和空格 */
        char *end = value + strlen(value) - 1;
        while (end > value && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        /* 解析配置项 */
        if (strcmp(key, "enabled") == 0) {
            g_rr_config.enabled = parse_bool(value, false);
        } else if (strcmp(key, "mode") == 0) {
            g_rr_config.mode = parse_mode(value);
        } else if (strcmp(key, "trace_file") == 0) {
            g_free(g_rr_config.trace_file);
            g_rr_config.trace_file = g_strdup(value);
        } else if (strcmp(key, "shared_memory_name") == 0) {
            g_free(g_rr_config.shared_memory_name);
            g_rr_config.shared_memory_name = g_strdup(value);
        } else if (strcmp(key, "cmd_pipe_path") == 0) {
            g_free(g_rr_config.cmd_pipe_path);
            g_rr_config.cmd_pipe_path = g_strdup(value);
        } else if (strcmp(key, "status_pipe_path") == 0) {
            g_free(g_rr_config.status_pipe_path);
            g_rr_config.status_pipe_path = g_strdup(value);
        } else if (strcmp(key, "fork_point") == 0) {
            g_rr_config.fork_point = (uint32_t)parse_int(value, 0);
            g_rr_config.fork_server_enabled = (g_rr_config.fork_point > 0);
        } else if (strcmp(key, "shared_memory_size") == 0) {
            g_rr_config.shared_memory_size = parse_size(value, DEFAULT_CONFIG.shared_memory_size);
        } else if (strcmp(key, "ipc_timeout") == 0) {
            g_rr_config.ipc_timeout = parse_int(value, DEFAULT_CONFIG.ipc_timeout);
        } else if (strcmp(key, "debug_level") == 0) {
            /* 调试级别将在rr_debug_init中处理 */
            setenv("RR_DEBUG_LEVEL", value, 1);
        } else if (strcmp(key, "debug_syscall") == 0) {
            setenv("RR_DEBUG_SYSCALL", value, 1);
        } else if (strcmp(key, "debug_fd") == 0) {
            setenv("RR_DEBUG_FD", value, 1);
        } else if (strcmp(key, "debug_mem") == 0) {
            setenv("RR_DEBUG_MEM", value, 1);
        } else if (strcmp(key, "debug_ipc") == 0) {
            setenv("RR_DEBUG_IPC", value, 1);
        } else if (strcmp(key, "debug_perf") == 0) {
            setenv("RR_DEBUG_PERF", value, 1);
        } else if (strcmp(key, "debug_file") == 0) {
            setenv("RR_DEBUG_FILE", value, 1);
        } else {
            RR_WARN("Unknown config key '%s' at line %d", key, line_num);
        }
    }

    fclose(fp);
    RR_INFO("Config file loaded successfully");
    return 0;
}

/**
 * 初始化配置系统
 */
int rr_config_init(void)
{
    /* 强制输出以验证函数被调用 */
    fprintf(stderr, "RR_CONFIG_INIT: Starting configuration initialization\n");
    fflush(stderr);

    RR_VERBOSE("Initializing RR-Fuzz configuration system");

    /* 使用默认配置初始化 */
    g_rr_config = DEFAULT_CONFIG;

    /* 优先从配置文件读取 */
    const char *config_file = getenv("RR_CONFIG_FILE");
    if (config_file) {
        g_rr_config.config_file = g_strdup(config_file);
        load_config_file(config_file);
    }

    /* 环境变量可以覆盖配置文件 */
    const char *rr_enabled = getenv("RR_FUZZING_ENABLED");
    if (rr_enabled) {
        g_rr_config.enabled = parse_bool(rr_enabled, g_rr_config.enabled);
    }

    if (!g_rr_config.enabled) {
        RR_INFO("RR-Fuzz disabled via configuration");
        return 0;
    }

    /* 环境变量覆盖其他配置 */
    const char *mode_str = getenv("RR_MODE");
    if (mode_str) {
        g_rr_config.mode = parse_mode(mode_str);
    }

    const char *trace_file = getenv("RR_TRACE_FILE");
    if (trace_file) {
        g_free(g_rr_config.trace_file);
        g_rr_config.trace_file = g_strdup(trace_file);
    }

    const char *shared_memory = getenv("RR_SHARED_MEMORY");
    if (shared_memory) {
        g_free(g_rr_config.shared_memory_name);
        g_rr_config.shared_memory_name = g_strdup(shared_memory);
    }

    const char *cmd_pipe = getenv("RR_CMD_PIPE");
    if (cmd_pipe) {
        g_free(g_rr_config.cmd_pipe_path);
        g_rr_config.cmd_pipe_path = g_strdup(cmd_pipe);
    }

    const char *status_pipe = getenv("RR_STATUS_PIPE");
    if (status_pipe) {
        g_free(g_rr_config.status_pipe_path);
        g_rr_config.status_pipe_path = g_strdup(status_pipe);
    }

    const char *fork_point_str = getenv("RR_FORK_POINT");
    if (fork_point_str) {
        g_rr_config.fork_point = (uint32_t)parse_int(fork_point_str, 0);
        g_rr_config.fork_server_enabled = (g_rr_config.fork_point > 0);
    }
    
    /* 如果设置了RR_FORK_SYSCALL，也启用Fork Server */
    const char *fork_syscall = getenv("RR_FORK_SYSCALL");
    if (fork_syscall) {
        g_rr_config.fork_server_enabled = true;
    }

    const char *shm_size = getenv("RR_SHARED_MEMORY_SIZE");
    if (shm_size) {
        g_rr_config.shared_memory_size = parse_size(shm_size, DEFAULT_CONFIG.shared_memory_size);
    }

    const char *ipc_timeout = getenv("RR_IPC_TIMEOUT");
    if (ipc_timeout) {
        g_rr_config.ipc_timeout = parse_int(ipc_timeout, DEFAULT_CONFIG.ipc_timeout);
    }

    /* 设置默认路径 */
    if (!g_rr_config.trace_file) {
        g_rr_config.trace_file = g_strdup("/tmp/rr_trace.dat");
    }
    if (!g_rr_config.shared_memory_name) {
        g_rr_config.shared_memory_name = g_strdup("rr_fuzzing_shm");
    }
    if (!g_rr_config.cmd_pipe_path) {
        g_rr_config.cmd_pipe_path = g_strdup("/tmp/rr_cmd_pipe");
    }
    if (!g_rr_config.status_pipe_path) {
        g_rr_config.status_pipe_path = g_strdup("/tmp/rr_status_pipe");
    }

    RR_INFO("Configuration loaded successfully");
    return 0;
}

/**
 * 获取模式名称
 */
const char *rr_config_get_mode_name(rr_mode_t mode)
{
    switch (mode) {
        case RR_MODE_DISABLED: return "DISABLED";
        case RR_MODE_RECORD:   return "RECORD";
        case RR_MODE_REPLAY:   return "REPLAY";
        case RR_MODE_FUZZING:  return "FUZZING";
        default:               return "UNKNOWN";
    }
}

/**
 * 打印配置信息
 */
void rr_config_print(void)
{
    if (!g_rr_config.enabled) {
        RR_INFO("RR-Fuzz: DISABLED");
        return;
    }

    RR_INFO("=== RR-Fuzz Configuration ===");
    RR_INFO("Core:");
    RR_INFO("  Enabled: %s", g_rr_config.enabled ? "YES" : "NO");
    RR_INFO("  Mode: %s (%d)", rr_config_get_mode_name(g_rr_config.mode), g_rr_config.mode);
    if (g_rr_config.config_file) {
        RR_INFO("  Config file: %s", g_rr_config.config_file);
    }

    RR_INFO("Files:");
    RR_INFO("  Trace file: %s", g_rr_config.trace_file);
    RR_INFO("  Shared memory: %s", g_rr_config.shared_memory_name);
    RR_INFO("  Command pipe: %s", g_rr_config.cmd_pipe_path);
    RR_INFO("  Status pipe: %s", g_rr_config.status_pipe_path);

    RR_INFO("Fork Server:");
    RR_INFO("  Enabled: %s", g_rr_config.fork_server_enabled ? "YES" : "NO");
    if (g_rr_config.fork_server_enabled) {
        RR_INFO("  Fork point: %u", g_rr_config.fork_point);
    }

    RR_INFO("IPC:");
    RR_INFO("  Shared memory size: %zu bytes", g_rr_config.shared_memory_size);
    RR_INFO("  IPC timeout: %d milliseconds", g_rr_config.ipc_timeout);
    RR_INFO("=============================");
}

/**
 * 清理配置系统
 */
void rr_config_cleanup(void)
{
    RR_VERBOSE("Cleaning up RR-Fuzz configuration");

    g_free(g_rr_config.trace_file);
    g_free(g_rr_config.shared_memory_name);
    g_free(g_rr_config.cmd_pipe_path);
    g_free(g_rr_config.status_pipe_path);
    g_free(g_rr_config.config_file);

    memset(&g_rr_config, 0, sizeof(g_rr_config));
}
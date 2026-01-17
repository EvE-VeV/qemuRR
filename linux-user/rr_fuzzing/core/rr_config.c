/**
 * RR-Fuzz Unified Configuration Management System
 * Replaces scattered getenv() calls with a unified configuration interface.
 */

#ifndef RR_DEBUG
#define RR_DEBUG 1
#endif

#include "rr_framework.h"
#include <string.h>
#include <stdlib.h>

/* Global configuration instance */
rr_config_t g_rr_config = {0};

/**
 * Default Configuration Values (Fallback Defaults)
 * 
 * Used if no values are provided via environment variables or configuration files.
 * 
 * Key Defaults:
 * - mode: DISABLED (Must be explicitly enabled)
 * - fork_strategy: AGGRESSIVE (Maximize coverage)
 * - shared_memory_size: 64KB (Fits standard fuzzing payloads)
 * - use_legacy_capture: false (Avoid double-capture bugs)
 */
static const rr_config_t DEFAULT_CONFIG = {
    .enabled = false,
    .mode = RR_MODE_DISABLED,

    /* File paths - NULL defaults, allocated as needed */
    .trace_file = NULL,
    .shared_memory_name = NULL,
    .cmd_pipe_path = NULL,
    .status_pipe_path = NULL,
    .config_file = NULL,

    /* Fork Server configuration */
    .fork_server_enabled = false,
    .fork_point = 0,
    .fork_strategy = RR_FORK_STRATEGY_AGGRESSIVE,  // Default: Aggressive mode (most practical currently)
    .fork_fallback_threshold = 20,                  // Fallback threshold: 20 syscalls

    /* IPC configuration */
    .shared_memory_size = 128 * 1024,      // 128KB (fits 10 variants)
    .ipc_timeout = 1000,                  // 1 second
    
    /* Advanced configuration */
    .use_legacy_capture = false           // Default to using only aux_data to avoid double-capture
};

/**
 * Parses the mode string.
 */
static rr_mode_t parse_mode(const char *mode_str)
{
    if (!mode_str) {
        return RR_MODE_RECORD; // Default to record mode
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
 * Parses a boolean value.
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
 * Parses an integer value.
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
 * Parses a size value (supports K, M, G suffixes).
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
                // Pure number, no suffix to process
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
 * Load configuration from a file
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

        /* Skip comments and empty lines */
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (*trimmed == '#' || *trimmed == '\n' || *trimmed == '\0') {
            continue;
        }

        /* Parse key=value format */
        char *equals = strchr(trimmed, '=');
        if (!equals) {
            RR_WARN("Invalid config line %d: %s", line_num, line);
            continue;
        }

        *equals = '\0';
        char *key = trimmed;
        char *value = equals + 1;

        /* Trim trailing newline and spaces */
        char *end = value + strlen(value) - 1;
        while (end > value && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        /* Parse configuration key-value pairs */
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
            /* Debug level handled in rr_debug_init */
            setenv("RR_DEBUG_LEVEL", value, 1);
        } else if (strcmp(key, "debug_file") == 0) {
            setenv("RR_DEBUG_FILE", value, 1);
        } else if (strcmp(key, "fork_strategy") == 0) {
            g_rr_config.fork_strategy = parse_int(value, DEFAULT_CONFIG.fork_strategy);
        } else if (strcmp(key, "fork_threshold") == 0) {
            g_rr_config.fork_fallback_threshold = parse_int(value, DEFAULT_CONFIG.fork_fallback_threshold);
        } else if (strcmp(key, "use_legacy_capture") == 0) {
            g_rr_config.use_legacy_capture = parse_bool(value, DEFAULT_CONFIG.use_legacy_capture);
        } else {
            RR_WARN("Unknown config key '%s' at line %d", key, line_num);
        }
    }

    fclose(fp);
    RR_INFO("Config file loaded successfully");
    return 0;
}

/**
 * @brief Initialize configuration system (Global Config Init)
 * 
 * Loading order (priority from low to high):
 * 1. Default values (`DEFAULT_CONFIG`)
 * 2. Configuration file (specified by `RR_CONFIG_FILE`)
 * 3. Environment variables (e.g., `RR_MODE`, `RR_TRACE_FILE`)
 * 
 * **Side effects**:
 * - Initialize global variable `g_rr_config`.
 * - May modify some environment variables (e.g., `RR_DEBUG_LEVEL`) to adapt to underlying libraries.
 * 
 * @return int 0 for success
 */
int rr_config_init(void)
{
    /* Preserve configuration if already initialized */
    static bool initialized = false;
    if (initialized) {
        RR_VERBOSE("rr_config_init() already called, skipping re-initialization");
        return 0;
    }
    initialized = true;
    
    /* fprintf(stderr, "RR_CONFIG_INIT: Starting configuration initialization\n");
    fflush(stderr); */

    RR_VERBOSE("Initializing RR-Fuzz configuration system");

    /* Initialize with default configuration */
    g_rr_config = DEFAULT_CONFIG;

    /* Read from config file with priority */
    const char *config_file = getenv("RR_CONFIG_FILE");
    if (config_file) {
        g_rr_config.config_file = g_strdup(config_file);
        load_config_file(config_file);
    }

    /* Auto-enable RR-Fuzz if RR_MODE is set */
    const char *mode_str = getenv("RR_MODE");
    if (mode_str) {
        g_rr_config.mode = parse_mode(mode_str);
        /* Auto-enable RR-Fuzz if mode is set */
        if (g_rr_config.mode != RR_MODE_DISABLED) {
            g_rr_config.enabled = true;
        }
    }
    
    /* Environment variables can override config file and auto-enablement */
    const char *rr_enabled = getenv("RR_FUZZING_ENABLED");
    if (rr_enabled) {
        g_rr_config.enabled = parse_bool(rr_enabled, g_rr_config.enabled);
    }

    if (!g_rr_config.enabled) {
        RR_INFO("RR-Fuzz disabled via configuration");
        return 0;
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
    
    /* Auto-enable Fork Server in Fuzzing mode (new auto-detection mode) */
    if (g_rr_config.mode == RR_MODE_FUZZING) {
        if (!getenv("RR_DISABLE_FORK_SERVER")) {
            g_rr_config.fork_server_enabled = true;
            RR_INFO("Auto-enabled Fork Server for fuzzing mode");
        } else {
            RR_INFO("Fork Server manually disabled via RR_DISABLE_FORK_SERVER");
        }
    }

    const char *shm_size = getenv("RR_SHARED_MEMORY_SIZE");
    if (shm_size) {
        g_rr_config.shared_memory_size = parse_size(shm_size, DEFAULT_CONFIG.shared_memory_size);
    }

    const char *ipc_timeout = getenv("RR_IPC_TIMEOUT");
    if (ipc_timeout) {
        g_rr_config.ipc_timeout = parse_int(ipc_timeout, DEFAULT_CONFIG.ipc_timeout);
    }

    /* Fork Server advanced configuration */
    const char *fork_strategy = getenv("RR_FORK_STRATEGY");
    if (fork_strategy) {
        g_rr_config.fork_strategy = parse_int(fork_strategy, DEFAULT_CONFIG.fork_strategy);
    }

    const char *fork_threshold = getenv("RR_FORK_THRESHOLD");
    if (fork_threshold) {
        g_rr_config.fork_fallback_threshold = parse_int(fork_threshold, DEFAULT_CONFIG.fork_fallback_threshold);
    }

    /* Advanced configuration */
    const char *use_legacy_capture = getenv("RR_USE_LEGACY_CAPTURE");
    if (use_legacy_capture) {
        g_rr_config.use_legacy_capture = parse_bool(use_legacy_capture, DEFAULT_CONFIG.use_legacy_capture);
    }

    /* Set default paths */
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
 * Get mode name
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
 * Print configuration information
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
 * Clean up configuration system
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
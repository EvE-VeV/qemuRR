/**
 * 系统调用分发优化实现
 * 使用函数指针表和哈希表优化系统调用处理性能
 */

#include "rr_syscall_dispatch.h"
#include "rr_mapping_manager.h"
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

/* ==================== 具体的处理函数实现 ==================== */

/* 文件I/O类系统调用处理 */
static void apply_file_io_args(rr_strace_record_t *record, abi_long *args) {
    if (!record || !record->syscall_name) return;
    
    if (strcmp(record->syscall_name, "openat") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // flags
        if (record->arg_count > 3) args[3] = record->args[3].value; // mode
    } else if (strcmp(record->syscall_name, "read") == 0 || 
               strcmp(record->syscall_name, "write") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // count
    } else if (strcmp(record->syscall_name, "pread64") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // count
        if (record->arg_count > 3) args[3] = record->args[3].value; // offset
    } else if (strcmp(record->syscall_name, "writev") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // iovcnt
    } else if (strcmp(record->syscall_name, "ioctl") == 0) {
        if (record->arg_count > 1) args[1] = record->args[1].value; // request
    } else if (strcmp(record->syscall_name, "getdents64") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // count
    } else if (strcmp(record->syscall_name, "newfstatat") == 0) {
        if (record->arg_count > 3) args[3] = record->args[3].value; // flags
    }
}

static void apply_file_io_fd_mapping(const char *syscall_name, abi_long *args) {
    if (strcmp(syscall_name, "read") == 0 || 
        strcmp(syscall_name, "write") == 0 ||
        strcmp(syscall_name, "pread64") == 0 ||
        strcmp(syscall_name, "writev") == 0 ||
        strcmp(syscall_name, "close") == 0 ||
        strcmp(syscall_name, "fstat") == 0 ||
        strcmp(syscall_name, "ioctl") == 0 ||
        strcmp(syscall_name, "getdents64") == 0) {
        args[0] = rr_fd_mapping_get(args[0]);
    } else if (strcmp(syscall_name, "openat") == 0 ||
               strcmp(syscall_name, "newfstatat") == 0) {
        if (args[0] != -100) { // AT_FDCWD
            args[0] = rr_fd_mapping_get(args[0]);
        }
    }
}

static void file_io_post_hook(rr_strace_record_t *record, abi_long ret, abi_long *args) {
    if (!record) return;
    
    // openat/open 成功后，建立FD映射: recorded_fd → actual_fd
    if ((strcmp(record->syscall_name, "openat") == 0 || 
         strcmp(record->syscall_name, "open") == 0) && ret >= 0) {
        
        abi_long recorded_fd = record->ret_value;  // trace中的FD值
        abi_long actual_fd = ret;                   // 真实返回的FD值
        
        // ✅ 建立映射: recorded_fd → actual_fd
        rr_fd_mapping_add(recorded_fd, actual_fd);
        
        fprintf(stderr, "[FD-MAPPING] %s: recorded_fd=%ld -> actual_fd=%ld\n", 
                record->syscall_name, (long)recorded_fd, (long)actual_fd);
    } 
    // dup/dup2 也需要处理
    else if (strcmp(record->syscall_name, "dup") == 0 && ret >= 0) {
        abi_long recorded_fd = record->ret_value;
        abi_long actual_fd = ret;
        rr_fd_mapping_add(recorded_fd, actual_fd);
        fprintf(stderr, "[FD-MAPPING] dup: recorded_fd=%ld -> actual_fd=%ld\n", 
                (long)recorded_fd, (long)actual_fd);
    }
    // close 时移除映射
    else if (strcmp(record->syscall_name, "close") == 0 && ret == 0) {
        abi_long recorded_fd = record->args[0].value;
        rr_fd_mapping_remove((int)recorded_fd);
        fprintf(stderr, "[FD-MAPPING] close: removed mapping for fd=%ld\n", (long)recorded_fd);
    }
}

/* 内存管理类系统调用处理 */
static void apply_memory_args(rr_strace_record_t *record, abi_long *args) {
    if (!record || !record->syscall_name) return;
    
    if (strcmp(record->syscall_name, "mmap") == 0) {
        if (record->arg_count > 0) args[0] = record->args[0].value; // addr
        if (record->arg_count > 4) args[4] = record->args[4].value; // fd (将在apply_memory_fd_mapping中映射)
    } else if (strcmp(record->syscall_name, "mprotect") == 0) {
        if (record->arg_count > 1) args[1] = record->args[1].value; // len
        if (record->arg_count > 2) args[2] = record->args[2].value; // prot
    }
}

static void apply_memory_fd_mapping(const char *syscall_name, abi_long *args) {
    if (strcmp(syscall_name, "mmap") == 0) {
        // mmap的参数4是FD (-1表示匿名映射)
        if (args[4] != (abi_long)-1) {
            abi_long recorded_fd = args[4];  // trace中记录的FD
            
            // ✅ 查询映射表: recorded_fd → actual_fd
            abi_long actual_fd = rr_fd_mapping_get(recorded_fd);
            
            if (actual_fd != -1) {
                args[4] = actual_fd;  // 使用实际的FD
                fprintf(stderr, "[FD-MAPPING] mmap: recorded_fd=%ld -> actual_fd=%ld\n", 
                        (long)recorded_fd, (long)actual_fd);
            } else {
                fprintf(stderr, "[FD-MAPPING-WARN] mmap: No mapping for recorded_fd=%ld, using as-is\n", 
                        (long)recorded_fd);
                // 保持原值，让syscall尝试执行
            }
        }
    }
}

static void memory_post_hook(rr_strace_record_t *record, abi_long ret, abi_long *args) {
    if (!record) return;
    
    if (strcmp(record->syscall_name, "mmap") == 0) {
        if (ret != (abi_long)MAP_FAILED && record->ret_value != (target_ulong)MAP_FAILED) {
            target_ulong recorded_addr = (target_ulong)record->ret_value;
            target_ulong actual_addr = (target_ulong)ret;
            size_t size = (size_t)record->args[1].value;
            rr_addr_mapping_add(recorded_addr, actual_addr, size);
        }
    } else if (strcmp(record->syscall_name, "munmap") == 0) {
        if (ret == 0 && record->ret_value == 0) {
            target_ulong recorded_addr = (target_ulong)record->args[0].value;
            rr_addr_mapping_remove(recorded_addr);
        }
    }
}

/* 网络类系统调用处理 */
static void apply_network_args(rr_strace_record_t *record, abi_long *args) {
    if (!record || !record->syscall_name) return;
    
    if (strcmp(record->syscall_name, "socket") == 0) {
        // 所有参数都是数值，使用记录值
        for (int i = 0; i < record->arg_count && i < 3; i++) {
            args[i] = record->args[i].value;
        }
    } else if (strcmp(record->syscall_name, "bind") == 0 ||
               strcmp(record->syscall_name, "connect") == 0) {
        if (record->arg_count > 2) args[2] = record->args[2].value; // addrlen
    }
}

static void network_post_hook(rr_strace_record_t *record, abi_long ret, abi_long *args) {
    if (!record) return;
    
    if (strcmp(record->syscall_name, "socket") == 0 ||
        strcmp(record->syscall_name, "accept") == 0 ||
        strcmp(record->syscall_name, "accept4") == 0) {
        if (ret >= 0 && record->ret_value >= 0) {
            rr_fd_mapping_add(record->ret_value, ret);
        }
    }
}

/* 通用处理函数 */
static void apply_generic_args(rr_strace_record_t *record, abi_long *args) {
    if (!record) return;
    
    // 特殊处理：某些系统调用不应该修改参数
    // 这些调用的参数高度依赖于当前执行环境
    if (record->syscall_name) {
        if (strcmp(record->syscall_name, "arch_prctl") == 0 ||
            strcmp(record->syscall_name, "brk") == 0 ||
            strcmp(record->syscall_name, "set_tid_address") == 0 ||
            strcmp(record->syscall_name, "set_robust_list") == 0) {
            // 这些系统调用的参数不应该被重放
            // 它们需要使用当前进程的实际地址
            return;
        }
    }
    
    // 通用策略：对于数值参数使用记录值，对于指针参数保持原值
    for (int i = 0; i < record->arg_count && i < 8; i++) {
        if (record->args[i].type == RR_STRACE_ARG_TYPE_INT) {
            args[i] = record->args[i].value;
        }
    }
}

static void generic_post_hook(rr_strace_record_t *record, abi_long ret, abi_long *args) {
    // 默认不做特殊处理
    (void)record;
    (void)ret;
    (void)args;
}

/* ==================== 系统调用处理表定义 ==================== */

static rr_syscall_handler_t syscall_handlers[] = {
    /* 文件I/O类 */
    {"read", 0, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_CRITICAL, 
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"write", 1, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"open", 2, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_CRITICAL,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"close", 3, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_CRITICAL,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"ioctl", 16, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"pread64", 17, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"openat", 257, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"writev", 20, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_CRITICAL,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"getdents64", 217, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"newfstatat", 262, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    
    /* 内存管理类 */
    {"mmap", 9, SYSCALL_TYPE_MEMORY, SYSCALL_IMPORTANCE_CRITICAL,
     apply_memory_args, apply_memory_fd_mapping, memory_post_hook, true, true, true},
    {"munmap", 11, SYSCALL_TYPE_MEMORY, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_memory_args, NULL, memory_post_hook, false, true, false},
    {"mprotect", 10, SYSCALL_TYPE_MEMORY, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_memory_args, NULL, memory_post_hook, false, true, false},
    {"brk", 12, SYSCALL_TYPE_MEMORY, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_memory_args, NULL, memory_post_hook, false, true, false},
    
    /* 网络类 */
    {"socket", 41, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
    {"bind", 49, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
    {"connect", 42, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
    {"accept", 43, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
    {"accept4", 288, SYSCALL_TYPE_NETWORK, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_network_args, apply_file_io_fd_mapping, network_post_hook, true, false, true},
    
    /* 系统信息类 */
    {"getpid", 39, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"getuid", 102, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"getgid", 104, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"uname", 63, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"statfs", 137, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"prlimit64", 302, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"getrandom", 318, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"set_robust_list", 273, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"rseq", 334, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_OPTIONAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    
    /* 进程管理类 */
    {"clone", 56, SYSCALL_TYPE_PROCESS, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"fork", 57, SYSCALL_TYPE_PROCESS, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"exit_group", 231, SYSCALL_TYPE_PROCESS, SYSCALL_IMPORTANCE_CRITICAL,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    
    /* 其他常用系统调用 */
    {"access", 21, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_ENVIRONMENT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    {"newfstatat", 262, SYSCALL_TYPE_FILE_IO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_file_io_args, apply_file_io_fd_mapping, file_io_post_hook, true, false, true},
    {"arch_prctl", 158, SYSCALL_TYPE_SYSTEM_INFO, SYSCALL_IMPORTANCE_IMPORTANT,
     apply_generic_args, NULL, generic_post_hook, false, false, false},
    
    /* 结束标记 */
    {NULL, -1, SYSCALL_TYPE_UNKNOWN, SYSCALL_IMPORTANCE_ENVIRONMENT, NULL, NULL, NULL, false, false, false}
};

/* ==================== 快速查找表 ==================== */

#define MAX_SYSCALL_NR 512
static rr_syscall_handler_t* syscall_lookup_table[MAX_SYSCALL_NR];
static bool dispatch_initialized = false;

/* ==================== 公共接口实现 ==================== */

int rr_syscall_dispatch_init(void) {
    if (dispatch_initialized) {
        return 0;
    }
    
    // 初始化查找表
    memset(syscall_lookup_table, 0, sizeof(syscall_lookup_table));
    
    // 填充查找表
    for (int i = 0; syscall_handlers[i].name != NULL; i++) {
        int nr = syscall_handlers[i].syscall_nr;
        if (nr >= 0 && nr < MAX_SYSCALL_NR) {
            syscall_lookup_table[nr] = &syscall_handlers[i];
        }
    }
    
    dispatch_initialized = true;
    return 0;
}

void rr_syscall_dispatch_cleanup(void) {
    dispatch_initialized = false;
    memset(syscall_lookup_table, 0, sizeof(syscall_lookup_table));
}

rr_syscall_handler_t* rr_get_syscall_handler(int syscall_nr) {
    if (!dispatch_initialized) {
        rr_syscall_dispatch_init();
    }
    
    if (syscall_nr >= 0 && syscall_nr < MAX_SYSCALL_NR) {
        return syscall_lookup_table[syscall_nr];
    }
    return NULL;
}

rr_syscall_handler_t* rr_get_syscall_handler_by_name(const char *name) {
    if (!name || !dispatch_initialized) {
        return NULL;
    }
    
    for (int i = 0; syscall_handlers[i].name != NULL; i++) {
        if (strcmp(syscall_handlers[i].name, name) == 0) {
            return &syscall_handlers[i];
        }
    }
    return NULL;
}

const char* rr_get_syscall_name_fast(int syscall_nr) {
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    return handler ? handler->name : NULL;
}

syscall_type_t rr_get_syscall_type(int syscall_nr) {
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    return handler ? handler->type : SYSCALL_TYPE_UNKNOWN;
}

syscall_importance_t rr_get_syscall_importance(int syscall_nr) {
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    return handler ? handler->importance : SYSCALL_IMPORTANCE_ENVIRONMENT;
}

/* ==================== 优化的处理函数 ==================== */

void rr_apply_syscall_args_optimized(rr_strace_record_t *record, abi_long *args) {
    if (!record || !args) return;
    
    rr_syscall_handler_t *handler = rr_get_syscall_handler_by_name(record->syscall_name);
    if (handler && handler->apply_args) {
        handler->apply_args(record, args);
    } else {
        // 回退到通用处理
        apply_generic_args(record, args);
    }
}

void rr_apply_fd_mapping_optimized(int syscall_nr, abi_long *args) {
    if (!args) return;
    
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    if (handler && handler->needs_fd_mapping && handler->apply_fd_mapping) {
        handler->apply_fd_mapping(handler->name, args);
    }
}

void rr_syscall_post_hook_optimized(int syscall_nr, rr_strace_record_t *record, 
                                   abi_long ret, abi_long *args) {
    if (!record || !args) return;
    
    rr_syscall_handler_t *handler = rr_get_syscall_handler(syscall_nr);
    if (handler && handler->post_hook) {
        handler->post_hook(record, ret, args);
    }
}

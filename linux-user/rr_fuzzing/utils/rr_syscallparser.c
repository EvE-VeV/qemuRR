/**
 * RR-Fuzz Strace Parser Module Implementation
 * Provides functionality for parsing syscall records in strace format.
 */

#include "rr_syscallparser.h"
#include <sys/ioctl.h>
#include <termios.h>

/* strdup function implementation if not available */
#ifndef _GNU_SOURCE
static char *strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *p = malloc(len);
    if (p) {
        memcpy(p, s, len);
    }
    return p;
}
#endif

/* ==================== Syscall Name to Number Mapping Table ==================== */

typedef struct {
    const char *name;
    int number;
} syscall_mapping_t;

static const syscall_mapping_t g_syscall_map[] = {
    {"read", 0},
    {"write", 1},
    {"open", 2},
    {"close", 3},
    {"stat", 4},
    {"fstat", 5},
    {"lstat", 6},
    {"poll", 7},
    {"lseek", 8},
    {"mmap", 9},
    {"mprotect", 10},
    {"munmap", 11},
    {"brk", 12},
    {"rt_sigaction", 13},
    {"rt_sigprocmask", 14},
    {"rt_sigreturn", 15},
    {"ioctl", 16},
    {"pread64", 17},
    {"pwrite64", 18},
    {"readv", 19},
    {"writev", 20},
    {"access", 21},
    {"pipe", 22},
    {"select", 23},
    {"sched_yield", 24},
    {"mremap", 25},
    {"msync", 26},
    {"mincore", 27},
    {"madvise", 28},
    {"shmget", 29},
    {"shmat", 30},
    {"shmctl", 31},
    {"dup", 32},
    {"dup2", 33},
    {"pause", 34},
    {"nanosleep", 35},
    {"getitimer", 36},
    {"alarm", 37},
    {"setitimer", 38},
    {"getpid", 39},
    {"sendfile", 40},
    {"socket", 41},
    {"connect", 42},
    {"accept", 43},
    {"sendto", 44},
    {"recvfrom", 45},
    {"sendmsg", 46},
    {"recvmsg", 47},
    {"shutdown", 48},
    {"bind", 49},
    {"listen", 50},
    {"getsockname", 51},
    {"getpeername", 52},
    {"socketpair", 53},
    {"setsockopt", 54},
    {"getsockopt", 55},
    {"clone", 56},
    {"fork", 57},
    {"vfork", 58},
    {"execve", 59},
    {"exit", 60},
    {"wait4", 61},
    {"kill", 62},
    {"uname", 63},
    {"semget", 64},
    {"semop", 65},
    {"semctl", 66},
    {"shmdt", 67},
    {"msgget", 68},
    {"msgsnd", 69},
    {"msgrcv", 70},
    {"msgctl", 71},
    {"fcntl", 72},
    {"flock", 73},
    {"fsync", 74},
    {"fdatasync", 75},
    {"truncate", 76},
    {"ftruncate", 77},
    {"getdents", 78},
    {"getcwd", 79},
    {"chdir", 80},
    {"fchdir", 81},
    {"rename", 82},
    {"mkdir", 83},
    {"rmdir", 84},
    {"creat", 85},
    {"link", 86},
    {"unlink", 87},
    {"symlink", 88},
    {"readlink", 89},
    {"chmod", 90},
    {"fchmod", 91},
    {"chown", 92},
    {"fchown", 93},
    {"lchown", 94},
    {"umask", 95},
    {"gettimeofday", 96},
    {"getrlimit", 97},
    {"getrusage", 98},
    {"sysinfo", 99},
    {"times", 100},
    {"ptrace", 101},
    {"getuid", 102},
    {"syslog", 103},
    {"getgid", 104},
    {"setuid", 105},
    {"setgid", 106},
    {"geteuid", 107},
    {"getegid", 108},
    {"setpgid", 109},
    {"getppid", 110},
    {"getpgrp", 111},
    {"setsid", 112},
    {"setreuid", 113},
    {"setregid", 114},
    {"getgroups", 115},
    {"setgroups", 116},
    {"setresuid", 117},
    {"getresuid", 118},
    {"setresgid", 119},
    {"getresgid", 120},
    {"getpgid", 121},
    {"setfsuid", 122},
    {"setfsgid", 123},
    {"getsid", 124},
    {"capget", 125},
    {"capset", 126},
    {"rt_sigpending", 127},
    {"rt_sigtimedwait", 128},
    {"rt_sigqueueinfo", 129},
    {"rt_sigsuspend", 130},
    {"sigaltstack", 131},
    {"utime", 132},
    {"mknod", 133},
    {"uselib", 134},
    {"personality", 135},
    {"ustat", 136},
    {"statfs", 137},
    {"fstatfs", 138},
    {"sysfs", 139},
    {"getpriority", 140},
    {"setpriority", 141},
    {"sched_setparam", 142},
    {"sched_getparam", 143},
    {"sched_setscheduler", 144},
    {"sched_getscheduler", 145},
    {"sched_get_priority_max", 146},
    {"sched_get_priority_min", 147},
    {"sched_rr_get_interval", 148},
    {"mlock", 149},
    {"munlock", 150},
    {"mlockall", 151},
    {"munlockall", 152},
    {"vhangup", 153},
    {"modify_ldt", 154},
    {"pivot_root", 155},
    {"_sysctl", 156},
    {"prctl", 157},
    {"arch_prctl", 158},
    {"adjtimex", 159},
    {"setrlimit", 160},
    {"chroot", 161},
    {"sync", 162},
    {"acct", 163},
    {"settimeofday", 164},
    {"mount", 165},
    {"umount2", 166},
    {"swapon", 167},
    {"swapoff", 168},
    {"reboot", 169},
    {"sethostname", 170},
    {"setdomainname", 171},
    {"iopl", 172},
    {"ioperm", 173},
    {"create_module", 174},
    {"init_module", 175},
    {"delete_module", 176},
    {"get_kernel_syms", 177},
    {"query_module", 178},
    {"quotactl", 179},
    {"nfsservctl", 180},
    {"getpmsg", 181},
    {"putpmsg", 182},
    {"afs_syscall", 183},
    {"tuxcall", 184},
    {"security", 185},
    {"gettid", 186},
    {"readahead", 187},
    {"setxattr", 188},
    {"lsetxattr", 189},
    {"fsetxattr", 190},
    {"getxattr", 191},
    {"lgetxattr", 192},
    {"fgetxattr", 193},
    {"listxattr", 194},
    {"llistxattr", 195},
    {"flistxattr", 196},
    {"removexattr", 197},
    {"lremovexattr", 198},
    {"fremovexattr", 199},
    {"tkill", 200},
    {"time", 201},
    {"futex", 202},
    {"sched_setaffinity", 203},
    {"sched_getaffinity", 204},
    {"set_thread_area", 205},
    {"io_setup", 206},
    {"io_destroy", 207},
    {"io_getevents", 208},
    {"io_submit", 209},
    {"io_cancel", 210},
    {"get_thread_area", 211},
    {"lookup_dcookie", 212},
    {"epoll_create", 213},
    {"epoll_ctl_old", 214},
    {"epoll_wait_old", 215},
    {"remap_file_pages", 216},
    {"getdents64", 217},
    {"set_tid_address", 218},
    {"restart_syscall", 219},
    {"semtimedop", 220},
    {"fadvise64", 221},
    {"timer_create", 222},
    {"timer_settime", 223},
    {"timer_gettime", 224},
    {"timer_getoverrun", 225},
    {"timer_delete", 226},
    {"clock_settime", 227},
    {"clock_gettime", 228},
    {"clock_getres", 229},
    {"clock_nanosleep", 230},
    {"exit_group", 231},
    {"epoll_wait", 232},
    {"epoll_ctl", 233},
    {"tgkill", 234},
    {"utimes", 235},
    {"vserver", 236},
    {"mbind", 237},
    {"set_mempolicy", 238},
    {"get_mempolicy", 239},
    {"mq_open", 240},
    {"mq_unlink", 241},
    {"mq_timedsend", 242},
    {"mq_timedreceive", 243},
    {"mq_notify", 244},
    {"mq_getsetattr", 245},
    {"kexec_load", 246},
    {"waitid", 247},
    {"add_key", 248},
    {"request_key", 249},
    {"keyctl", 250},
    {"ioprio_set", 251},
    {"ioprio_get", 252},
    {"inotify_init", 253},
    {"inotify_add_watch", 254},
    {"inotify_rm_watch", 255},
    {"migrate_pages", 256},
    {"openat", 257},
    {"mkdirat", 258},
    {"mknodat", 259},
    {"fchownat", 260},
    {"futimesat", 261},
    {"newfstatat", 262},
    {"unlinkat", 263},
    {"renameat", 264},
    {"linkat", 265},
    {"symlinkat", 266},
    {"readlinkat", 267},
    {"fchmodat", 268},
    {"faccessat", 269},
    {"pselect6", 270},
    {"ppoll", 271},
    {"unshare", 272},
    {"set_robust_list", 273},
    {"get_robust_list", 274},
    {"splice", 275},
    {"tee", 276},
    {"sync_file_range", 277},
    {"vmsplice", 278},
    {"move_pages", 279},
    {"utimensat", 280},
    {"epoll_pwait", 281},
    {"signalfd", 282},
    {"timerfd_create", 283},
    {"eventfd", 284},
    {"fallocate", 285},
    {"timerfd_settime", 286},
    {"timerfd_gettime", 287},
    {"accept4", 288},
    {"signalfd4", 289},
    {"eventfd2", 290},
    {"epoll_create1", 291},
    {"dup3", 292},
    {"pipe2", 293},
    {"inotify_init1", 294},
    {"preadv", 295},
    {"pwritev", 296},
    {"rt_tgsigqueueinfo", 297},
    {"perf_event_open", 298},
    {"recvmmsg", 299},
    {"fanotify_init", 300},
    {"fanotify_mark", 301},
    {"prlimit64", 302},
    {"name_to_handle_at", 303},
    {"open_by_handle_at", 304},
    {"clock_adjtime", 305},
    {"syncfs", 306},
    {"sendmmsg", 307},
    {"setns", 308},
    {"getcpu", 309},
    {"process_vm_readv", 310},
    {"process_vm_writev", 311},
    {"kcmp", 312},
    {"finit_module", 313},
    {"sched_setattr", 314},
    {"sched_getattr", 315},
    {"renameat2", 316},
    {"seccomp", 317},
    {"getrandom", 318},
    {"memfd_create", 319},
    {"kexec_file_load", 320},
    {"bpf", 321},
    {"execveat", 322},
    {"userfaultfd", 323},
    {"membarrier", 324},
    {"mlock2", 325},
    {"copy_file_range", 326},
    {"preadv2", 327},
    {"pwritev2", 328},
    {NULL, -1}  /* End marker */
};

/* ==================== Flag Mapping Functions ==================== */

/* Memory protection flags mapping */
static int map_prot_flag(const char *flag_str) {
    if (strcmp(flag_str, "PROT_NONE") == 0) return PROT_NONE;
    if (strcmp(flag_str, "PROT_READ") == 0) return PROT_READ;
    if (strcmp(flag_str, "PROT_WRITE") == 0) return PROT_WRITE;
    if (strcmp(flag_str, "PROT_EXEC") == 0) return PROT_EXEC;
    return 0;
}

/* Memory mapping flags mapping */
static int map_mmap_flag(const char *flag_str) {
    if (strcmp(flag_str, "MAP_SHARED") == 0) return MAP_SHARED;
    if (strcmp(flag_str, "MAP_PRIVATE") == 0) return MAP_PRIVATE;
    if (strcmp(flag_str, "MAP_FIXED") == 0) return MAP_FIXED;
    if (strcmp(flag_str, "MAP_ANONYMOUS") == 0) return MAP_ANONYMOUS;
#ifdef MAP_ANON
    if (strcmp(flag_str, "MAP_ANON") == 0) return MAP_ANON;
#endif
#ifdef MAP_32BIT
    if (strcmp(flag_str, "MAP_32BIT") == 0) return MAP_32BIT;
#endif
#ifdef MAP_GROWSDOWN
    if (strcmp(flag_str, "MAP_GROWSDOWN") == 0) return MAP_GROWSDOWN;
#endif
#ifdef MAP_DENYWRITE
    if (strcmp(flag_str, "MAP_DENYWRITE") == 0) return MAP_DENYWRITE;
#endif
#ifdef MAP_EXECUTABLE
    if (strcmp(flag_str, "MAP_EXECUTABLE") == 0) return MAP_EXECUTABLE;
#endif
#ifdef MAP_LOCKED
    if (strcmp(flag_str, "MAP_LOCKED") == 0) return MAP_LOCKED;
#endif
#ifdef MAP_NORESERVE
    if (strcmp(flag_str, "MAP_NORESERVE") == 0) return MAP_NORESERVE;
#endif
#ifdef MAP_POPULATE
    if (strcmp(flag_str, "MAP_POPULATE") == 0) return MAP_POPULATE;
#endif
#ifdef MAP_NONBLOCK
    if (strcmp(flag_str, "MAP_NONBLOCK") == 0) return MAP_NONBLOCK;
#endif
#ifdef MAP_STACK
    if (strcmp(flag_str, "MAP_STACK") == 0) return MAP_STACK;
#endif
#ifdef MAP_HUGETLB
    if (strcmp(flag_str, "MAP_HUGETLB") == 0) return MAP_HUGETLB;
#endif
    return 0;
}

/* File open flags mapping */
static int map_open_flag(const char *flag_str) {
    if (strcmp(flag_str, "O_RDONLY") == 0) return O_RDONLY;
    if (strcmp(flag_str, "O_WRONLY") == 0) return O_WRONLY;
    if (strcmp(flag_str, "O_RDWR") == 0) return O_RDWR;
    if (strcmp(flag_str, "O_CREAT") == 0) return O_CREAT;
    if (strcmp(flag_str, "O_EXCL") == 0) return O_EXCL;
    if (strcmp(flag_str, "O_NOCTTY") == 0) return O_NOCTTY;
    if (strcmp(flag_str, "O_TRUNC") == 0) return O_TRUNC;
    if (strcmp(flag_str, "O_APPEND") == 0) return O_APPEND;
    if (strcmp(flag_str, "O_NONBLOCK") == 0) return O_NONBLOCK;
    if (strcmp(flag_str, "O_SYNC") == 0) return O_SYNC;
#ifdef O_CLOEXEC
    if (strcmp(flag_str, "O_CLOEXEC") == 0) return O_CLOEXEC;
#endif
    return 0;
}

/* Access mode flags mapping */
static int map_access_flag(const char *flag_str) {
    if (strcmp(flag_str, "F_OK") == 0) return F_OK;
    if (strcmp(flag_str, "R_OK") == 0) return R_OK;
    if (strcmp(flag_str, "W_OK") == 0) return W_OK;
    if (strcmp(flag_str, "X_OK") == 0) return X_OK;
    return 0;
}

/* ==================== Helper Functions Implementation ==================== */

/**
 * Parse a hexadecimal or decimal numeric string into a long integer.
 */
long rr_strace_parse_number(const char *str) {
    if (!str) return 0;
    
    if (strncmp(str, "0x", 2) == 0) {
        return strtol(str, NULL, 16);
    }
    return strtol(str, NULL, 10);
}

/**
 * Identify parameter type.
 */
rr_strace_arg_type_t rr_strace_identify_arg_type(const char *arg_str) {
    if (!arg_str) return RR_STRACE_ARG_TYPE_INT;
    
    if (arg_str[0] == '\"') {
        return RR_STRACE_ARG_TYPE_STR;
    } else if (strncmp(arg_str, "0x", 2) == 0 || 
              (arg_str[0] >= '0' && arg_str[0] <= '9') ||
              (arg_str[0] == '-' && arg_str[1] >= '0' && arg_str[1] <= '9') ||
              strcmp(arg_str, "NULL") == 0) {
        return RR_STRACE_ARG_TYPE_INT;
    } else {
        return RR_STRACE_ARG_TYPE_PTR;
    }
}

/**
 * Parse combined flags string.
 */
static int parse_combined_flags(const char *flag_str, int (*map_flag)(const char*)) {
    if (!flag_str || !map_flag) {
        return 0;
    }
    
    /* If it is purely numeric, return directly */
    char *endptr;
    long value = strtol(flag_str, &endptr, 0);
    if (*flag_str != '\0' && *endptr == '\0') {
        return (int)value;
    }
    
    /* Copy string to allow modification */
    char flag_copy[256];
    strncpy(flag_copy, flag_str, sizeof(flag_copy) - 1);
    flag_copy[sizeof(flag_copy) - 1] = '\0';
    
    /* Parse flags separated by '|' */
    int result = 0;
    char *token = strtok(flag_copy, "|");
    while (token) {
        /* Trim leading/trailing whitespace */
        while (*token && isspace(*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace(*end)) *end-- = '\0';
        
        /* Look up flag value */
        result |= map_flag(token);
        
        token = strtok(NULL, "|");
    }
    
    return result;
}

/**
 * Parse flags.
 */
int rr_strace_parse_flags(const char *flag_str, const char *syscall_name, int arg_index) {
    if (!flag_str || !syscall_name) return 0;
    
    /* mmap syscall */
    if (strcmp(syscall_name, "mmap") == 0) {
        if (arg_index == 2) {  /* prot parameter */
            return parse_combined_flags(flag_str, map_prot_flag);
        } else if (arg_index == 3) {  /* flags parameter */
            return parse_combined_flags(flag_str, map_mmap_flag);
        }
    }
    /* mprotect syscall */
    else if (strcmp(syscall_name, "mprotect") == 0) {
        if (arg_index == 2) { /* prot parameter */
            return parse_combined_flags(flag_str, map_prot_flag);
        }
    }
    /* open/openat syscall */
    else if (strcmp(syscall_name, "open") == 0) {
        if (arg_index == 1) {  /* flags parameter */
            return parse_combined_flags(flag_str, map_open_flag);
        }
    }
    else if (strcmp(syscall_name, "openat") == 0) {
        if (arg_index == 2) {  /* flags parameter */
            return parse_combined_flags(flag_str, map_open_flag);
        }
    }
    /* access/faccessat syscall */
    else if (strcmp(syscall_name, "access") == 0 || 
             strcmp(syscall_name, "faccessat") == 0) {
        if (arg_index == 1 || arg_index == 2) {  /* mode parameter */
            return parse_combined_flags(flag_str, map_access_flag);
        }
    }
    
    /* Default try parsing as number */
    char *endptr;
    long value = strtol(flag_str, &endptr, 0);
    if (*flag_str != '\0' && *endptr == '\0') {
        return (int)value;
    }
    
    return 0;
}

/* ==================== Core API Functions Implementation ==================== */

/**
 * Get syscall number.
 */
int rr_strace_get_syscall_number(const char *syscall_name) {
    if (!syscall_name) return -1;
    
    for (int i = 0; g_syscall_map[i].name != NULL; i++) {
        if (strcmp(g_syscall_map[i].name, syscall_name) == 0) {
            return g_syscall_map[i].number;
        }
    }
    
    return -1;
}

/**
 * Parse a single line strace record.
 */
/**
 * @brief Parse a single strace line
 * 
 * Parses a single line of text strace output into a structured `rr_strace_record_t`.
 * 
 * **Steps**:
 * 1. Extract PID (if present).
 * 2. Extract syscall name.
 * 3. Extract argument list (content between parentheses).
 * 4. Identify and parse each argument (Int/String/Flag/Ptr).
 * 5. Extract return value and error code (errno).
 * 
 * @param line Input text line (modified in-place by strtok/trim).
 * @param record Output record structure.
 * @return int 1 on success, 0 on failure.
 */
int rr_strace_parse_line(char *line, rr_strace_record_t *record) {
    if (!line || !record) return 0;
    
    memset(record, 0, sizeof(rr_strace_record_t));
    
    char *current = line;
    char *next;
    
    /* Skip leading whitespace */
    while (*current && isspace(*current)) current++;
    if (!*current) return 0;
    
    /* Parse PID */
    record->pid = strtol(current, &next, 10);
    if (current == next) return 0;
    current = next;
    
    /* Skip whitespace */
    while (*current && isspace(*current)) current++;
    if (!*current) return 0;
    
    /* Find end of syscall name */
    next = strchr(current, '(');
    if (!next) return 0;
    
    /* Copy syscall name */
    /* 复制系统调用名称 */
    size_t name_len = next - current;
    if (name_len >= sizeof(record->syscall_name)) name_len = sizeof(record->syscall_name) - 1;
    memcpy(record->syscall_name, current, name_len);
    record->syscall_name[name_len] = '\0';
    
    /* Remove trailing whitespace from name */
    char *trim_end = record->syscall_name + name_len - 1;
    while (trim_end >= record->syscall_name && isspace(*trim_end)) {
        *trim_end = '\0';
        trim_end--;
    }
    
    /* Move to argument start */
    current = next + 1;  /* Skip '(' */
    
    /* Find end of argument list */
    next = strchr(current, ')');
    if (!next) return 0;
    
    /* Copy argument string for processing */
    char args_buffer[1024] = {0};
    size_t args_len = next - current;
    if (args_len >= sizeof(args_buffer)) args_len = sizeof(args_buffer) - 1;
    memcpy(args_buffer, current, args_len);
    args_buffer[args_len] = '\0';
    
    /* Parse arguments */
    record->arg_count = 0;
    char *arg_str = args_buffer;
    char *arg_end;
    
    while (*arg_str && record->arg_count < RR_STRACE_MAX_ARGS) {
        /* Skip leading whitespace */
        while (*arg_str && isspace(*arg_str)) arg_str++;
        if (!*arg_str) break;
        
        /* Find argument end */
        if (*arg_str == '"') {
            /* String argument */
            arg_end = strchr(arg_str + 1, '"');
            if (arg_end) arg_end = strchr(arg_end, ',');
        } else {
            /* Non-string argument */
            arg_end = strchr(arg_str, ',');
        }
        
        /* If no more commas, the remaining part is the last argument */
        if (!arg_end) arg_end = arg_str + strlen(arg_str);
        
        /* Temporarily null-terminate for processing */
        char saved_char = *arg_end;
        *arg_end = '\0';
        
        /* Process argument */
        rr_strace_arg_t *arg = &record->args[record->arg_count];
        arg->type = rr_strace_identify_arg_type(arg_str);
        
        if (arg->type == RR_STRACE_ARG_TYPE_STR) {
            /* Process string argument (remove quotes) */
            char *str_start = strchr(arg_str, '"');
            char *str_end = strrchr(arg_str, '"');
            if (str_start && str_end && str_start != str_end) {
                size_t str_len = str_end - str_start - 1;
                if (str_len >= RR_STRACE_MAX_STRING_LENGTH) str_len = RR_STRACE_MAX_STRING_LENGTH - 1;
                memcpy(arg->str, str_start + 1, str_len);
                arg->str[str_len] = '\0';
            } else {
                snprintf(arg->str, RR_STRACE_MAX_STRING_LENGTH, "%s", arg_str);
                arg->value = 0;
            }
        } else if (arg->type == RR_STRACE_ARG_TYPE_PTR) {
            /* Process flags, etc. */
            snprintf(arg->str, RR_STRACE_MAX_STRING_LENGTH, "%s", arg_str);
            arg->value = rr_strace_parse_flags(arg_str, record->syscall_name, record->arg_count);
        } else {
            /* Process numeric argument */
            if (strcmp(arg_str, "NULL") == 0) {
                arg->value = 0;
            } else {
                arg->value = rr_strace_parse_number(arg_str);
            }
        }
        
        record->arg_count++;
        
        /* Restore character */
        *arg_end = saved_char;
        
        /* Move to start of next argument if any */
        if (*arg_end == ',') {
            arg_str = arg_end + 1;
        } else {
            break;
        }
    }
    
    /* Parse return value after '=' */
    current = next + 1;  /* Skip ')' */
    
    /* Find '=' */
    next = strchr(current, '=');
    if (!next) {
        /* Some syscalls (e.g., exit_group) have no return value; this is valid */
        /* Skip trailing whitespace and check for end of line */
        while (*current && isspace(*current)) current++;
        if (*current == '\0') {
            /* Valid syscall with no return value, use default */
            record->ret_value = 0;
            record->has_error = 0;
            return 1;
        }
        return 0;  /* Format error */
    }
    
    current = next + 1;  /* Skip '=' */
    
    /* Skip whitespace */
    while (*current && isspace(*current)) current++;
    if (!*current) return 0;
    
    /* Parse return value */
    record->ret_value = strtol(current, &next, 0);
    current = next;
    
    /* Check for error info */
    next = strstr(current, "errno=");
    if (next) {
        record->has_error = 1;
        current = next + 6;  /* Skip "errno=" */
        record->error_code = strtol(current, &next, 10);
        current = next;
        
        /* Find error description (usually in parentheses) */
        next = strchr(current, '(');
        if (next) {
            current = next + 1;
            next = strchr(current, ')');
            if (next) {
                size_t err_len = next - current;
                if (err_len >= sizeof(record->error_msg)) err_len = sizeof(record->error_msg) - 1;
                memcpy(record->error_msg, current, err_len);
                record->error_msg[err_len] = '\0';
            }
        }
    }
    
    return 1;
}

/**
 * Initialize strace parser.
 */
rr_strace_parser_t *rr_strace_parser_init(const char *filename) {
    if (!filename) return NULL;
    
    rr_strace_parser_t *parser = malloc(sizeof(rr_strace_parser_t));
    if (!parser) return NULL;
    
    memset(parser, 0, sizeof(rr_strace_parser_t));
    
    parser->filename = strdup(filename);
    if (!parser->filename) {
        free(parser);
        return NULL;
    }
    
    return parser;
}

/**
 * Load and parse strace file.
 */
/**
 * @brief Load and parse a complete Strace file
 * 
 * Reads the specified file and parses syscall records line by line.
 * 
 * **Note**: 
 * - Memory-intensive operation; all records are loaded into memory (`parser->records`).
 * - Parsed records are used to drive Replay.
 * 
 * @param parser Parser context (filename must be initialized).
 * @return int 0 on success, -1 on failure.
 */
int rr_strace_parser_load(rr_strace_parser_t *parser) {
    fprintf(stderr, "[FORCE_DEBUG] rr_strace_parser_load called with filename: %s\n", 
            parser ? (parser->filename ? parser->filename : "NULL") : "parser is NULL");
    fflush(stderr);
    
    if (!parser || !parser->filename) return -1;
    
    FILE *file = fopen(parser->filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", parser->filename);
        return -1;
    }
    
    /* Count records first */
    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        count++;
    }
    
    if (count == 0) {
        fclose(file);
        return -1;
    }
    
    /* Allocate records array */
    parser->records = malloc(count * sizeof(rr_strace_record_t));
    if (!parser->records) {
        fclose(file);
        return -1;
    }
    
    /* Rewind file to beginning */
    rewind(file);
    
    /* Read and parse each line */
    int i = 0;
    int skip_execve = 1;  /* Skip first execve call */
    while (fgets(line, sizeof(line), file) && i < count) {
        /* Remove newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        /* Skip execve call, as QEMU user mode does not re-execute execve during replay */
        if (skip_execve && strstr(line, "execve(") != NULL) {
            fprintf(stderr, "[FORCE_DEBUG] Skipping execve record: %s\n", line);
            fflush(stderr);
            skip_execve = 0;  /* Only skip first execve */
            continue;
        }
        
        /* Parse current line */
        if (rr_strace_parse_line(line, &parser->records[i])) {
            i++;
        }
    }
    
    fclose(file);
    parser->record_count = i;
    parser->current_index = 0;
    parser->loaded = 1;
    
    fprintf(stderr, "[FORCE_DEBUG] rr_strace_parser_load completed successfully: loaded %d records\n", i);
    fflush(stderr);
    
    return 0;
}

/**
 * Get next syscall record.
 */
rr_strace_record_t *rr_strace_parser_get_next(rr_strace_parser_t *parser) {
    if (!parser || !parser->loaded || parser->current_index >= parser->record_count) {
        return NULL;
    }
    
    return &parser->records[parser->current_index++];
}

/**
 * Reset parser to beginning.
 */
void rr_strace_parser_reset(rr_strace_parser_t *parser) {
    if (parser) {
        parser->current_index = 0;
    }
}

/**
 * Get parser statistics.
 */
void rr_strace_get_stats(rr_strace_parser_t *parser, size_t *total_records, size_t *current_index) {
    if (parser && total_records && current_index) {
        *total_records = parser->record_count;
        *current_index = parser->current_index;
    }
}

/**
 * Clean up parser resources.
 */
void rr_strace_parser_cleanup(rr_strace_parser_t *parser) {
    if (!parser) return;
    
    if (parser->records) {
        free(parser->records);
    }
    
    if (parser->filename) {
        free(parser->filename);
    }
    
    free(parser);
}

/**
 * Print syscall record (for debugging).
 */
void rr_strace_print_record(const rr_strace_record_t *record) {
    if (!record) return;
    
    printf("PID: %d, Syscall: %s\n", record->pid, record->syscall_name);
    printf("Arguments (%d):\n", record->arg_count);
    for (int i = 0; i < record->arg_count; i++) {
        const rr_strace_arg_t *arg = &record->args[i];
        switch (arg->type) {
            case RR_STRACE_ARG_TYPE_INT:
                printf("  [%d] INT: %ld (0x%lx)\n", i, arg->value, arg->value);
                break;
            case RR_STRACE_ARG_TYPE_PTR:
                printf("  [%d] PTR: %s (%ld)\n", i, arg->str, arg->value);
                break;
            case RR_STRACE_ARG_TYPE_STR:
                printf("  [%d] STR: \"%s\"\n", i, arg->str);
                break;
        }
    }
    
    printf("Return value: %ld (0x%lx)\n", record->ret_value, record->ret_value);
    if (record->has_error) {
        printf("Error: %d (%s)\n", record->error_code, record->error_msg);
    }
    printf("\n");
}

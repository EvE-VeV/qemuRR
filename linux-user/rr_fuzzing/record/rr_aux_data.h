/*
 * RR-Fuzz Auxiliary Data System
 * 
 * Inspired by EnvFuzz's AUX system for recording buffer contents,
 * structures, and other data associated with syscall arguments.
 * 
 * This enables Pure Deterministic Replay by capturing actual data
 * instead of just pointers.
 */

#ifndef RR_AUX_DATA_H
#define RR_AUX_DATA_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

/* Data kinds - matches EnvFuzz categories */
typedef enum {
    AUX_NONE = 0,
    AUX_BUFFER,         /* Raw buffer (ABUF) */
    AUX_STRING,         /* String (ASTR) */
    AUX_IOV,            /* iovec array (AIOV) */
    AUX_MSG,            /* msghdr (AMSG) */
    AUX_STAT,           /* stat structure (ASTB) */
    AUX_TIMEVAL,        /* timeval (A_TV) */
    AUX_TIMESPEC,       /* timespec (A_TS) */
    AUX_POLLFD,         /* pollfd array (APFD) */
    AUX_FDSET,          /* fd_set (ASET) */
    AUX_MMAP_CONTENT,   /* mmap file content */
    AUX_SCALAR,         /* simple scalar value */
    AUX_STRUCT,         /* generic structured data */
    AUX_IOCTL_OUTPUT,   /* ioctl output buffer (task2) */
} rr_aux_kind_t;

typedef struct {
    uint64_t addr;
    uint64_t length;
    int64_t prot;
    int64_t flags;
    int64_t fd;
    uint64_t offset;
} rr_aux_mmap_info_t;

typedef struct {
    uint64_t addr;
    uint64_t len;
    int64_t extra1;
    int64_t extra2;
} rr_aux_mm_params_t;

/* Single auxiliary data entry */
typedef struct rr_aux_data {
    struct rr_aux_data *next;   /* Linked list for multiple aux entries */
    
    rr_aux_kind_t kind;         /* Data type */
    uint8_t arg_mask;           /* Which argument (bit mask) */
    uint32_t size;              /* Data size in bytes */
    uint8_t *data;              /* Actual data content */
    
    /* Optional metadata */
    char *external_file;        /* Path to external data file (if large) */
    bool is_external;           /* Data stored externally? */
} rr_aux_data_t;

/* Configuration */
#define AUX_MAX_INLINE_SIZE  (4 * 1024)       /* 4KB inline threshold */
#define AUX_MAX_RECORD_SIZE  (64 * 1024)      /* 64KB total threshold */

/* API Functions */

/**
 * Create a new auxiliary data entry
 */
/**
 * @brief 创建一个新的辅助数据 (aux_data) 节点
 * 
 * 分配并初始化一个 `rr_aux_data_t` 结构体，用于存储系统调用的额外信息
 * (如 read 读入的缓冲区内容、mmap 的参数结构等)。
 * 
 * @param kind 数据类型 (AUX_BUFFER, AUX_STRUCT, AUX_SCALAR 等)
 * @param arg_mask 参数掩码，表示该数据关联的是第几个参数 (1 << arg_index)
 * @param data 源数据指针，将被**深拷贝**到新分配的缓冲区中
 * @param size 数据大小
 * 
 * @return rr_aux_data_t* 
 *         - 指向新创建节点的指针
 *         - NULL: 如果参数无效或内存分配失败
 * 
 * @note 该函数会执行内存复制，如果数据较大 (>64KB)，考虑后续优化为引用或外部文件
 * @note 统计信息 (g_aux_stats) 会自动更新
 */
rr_aux_data_t *rr_aux_create(rr_aux_kind_t kind, uint8_t arg_mask, 
                             const void *data, uint32_t size);

/**
 * Add aux data to a list (chain multiple entries)
 */
void rr_aux_append(rr_aux_data_t **list, rr_aux_data_t *entry);

/**
 * Find aux data for specific argument
 */
/**
 * @brief 在辅助数据链表中查找特定参数的数据
 * 
 * 根据 arg_mask 查找关联的 aux_data。
 * 
 * @param list 链表头指针
 * @param arg_mask 要查找的参数掩码
 * 
 * @return rr_aux_data_t* 
 *         - 找到的节点指针
 *         - NULL: 未找到
 * 
 * @note 对于每个参数索引，链表中应该只有一个对应的 aux_data (除非设计变更)
 */
rr_aux_data_t *rr_aux_find(rr_aux_data_t *list, uint8_t arg_mask);

/**
 * Free aux data list
 */
void rr_aux_free(rr_aux_data_t *list);

/**
 * Check if data should be recorded (size heuristic)
 */
/**
 * @brief 判断是否应该记录辅助数据 (智能记录策略)
 * 
 * 这是一个启发式函数，用于决定是否记录某些数据。避免 trace 文件无限膨胀。
 * 
 * **决策策略**:
 * 1. **小数据 (<= 4KB)**: 总是记录 (Rule 1)
 * 2. **中等数据 (4KB - 64KB)**: 选择性记录 (Rule 2)
 *    - 标准流 (stdin/stdout/stderr): 记录
 *    - 关键 Syscall (read/write/getrandom): 记录
 *    - 网络 I/O: 记录
 *    - 其他: 仅在 <= 16KB 时记录
 * 3. **大数据 (> 64KB)**: 跳过 (Rule 3)
 *    - 避免性能问题和过大的 trace 文件
 * 
 * @param size 数据大小
 * @param fd 关联的文件描述符 (如果有关)
 * @param syscall_nr 系统调用编号
 * 
 * @return true: 应该记录
 * @return false: 跳过记录 (replay 时需要回退到 hybrid 模式或重新执行)
 * 
 * @note 即使返回 false，对于 getrandom 等关键非确定性调用，可能会被调用者强制记录
 * @warning 跳过数据意味着 replay 必须依赖环境 (Hybrid 模式)，降低了确定性
 * @todo 考虑实现外部大文件存储支持 (External Storage) 以支持记录大数据
 */
bool rr_aux_should_record(uint32_t size, int fd, int syscall_nr);

/**
 * Serialize aux data to external file (for large data)
 */
int rr_aux_save_external(rr_aux_data_t *aux, const char *base_path, int record_id);

/**
 * Load aux data from external file
 */
int rr_aux_load_external(rr_aux_data_t *aux);

/**
 * Serialize aux data to trace line
 * Format: "  AUX[arg]: kind=BUFFER, size=832, data=<base64>"
 */
void rr_aux_serialize_to_trace(rr_aux_data_t *aux, FILE *trace_file);

/**
 * Parse aux data from trace line
 */
rr_aux_data_t *rr_aux_parse_from_trace(const char *line);

/* Statistics */
typedef struct {
    uint64_t total_aux_entries;
    uint64_t total_bytes_inline;
    uint64_t total_bytes_external;
    uint64_t buffers_recorded;
    uint64_t buffers_skipped;
} rr_aux_stats_t;

extern rr_aux_stats_t g_aux_stats;

void rr_aux_print_stats(void);

#endif /* RR_AUX_DATA_H */


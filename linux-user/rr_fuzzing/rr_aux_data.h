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
} rr_aux_kind_t;

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
rr_aux_data_t *rr_aux_create(rr_aux_kind_t kind, uint8_t arg_mask, 
                             const void *data, uint32_t size);

/**
 * Add aux data to a list (chain multiple entries)
 */
void rr_aux_append(rr_aux_data_t **list, rr_aux_data_t *entry);

/**
 * Find aux data for specific argument
 */
rr_aux_data_t *rr_aux_find(rr_aux_data_t *list, uint8_t arg_mask);

/**
 * Free aux data list
 */
void rr_aux_free(rr_aux_data_t *list);

/**
 * Check if data should be recorded (size heuristic)
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


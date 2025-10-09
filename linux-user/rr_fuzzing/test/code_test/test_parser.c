/**
 * RR-Fuzz Strace解析器测试程序
 */

#include "rr_syscallparser.h"

int main(int argc, char *argv[]) {
    const char *trace_file = "/home/webfuzz/Downloads/strace_final_trace.dat";
    
    if (argc > 1) {
        trace_file = argv[1];
    }
    
    printf("=== RR-Fuzz Strace Parser Test ===\n");
    printf("Testing with file: %s\n\n", trace_file);
    
    /* 初始化解析器 */
    rr_strace_parser_t *parser = rr_strace_parser_init(trace_file);
    if (!parser) {
        fprintf(stderr, "Failed to initialize parser\n");
        return 1;
    }
    
    /* 加载文件 */
    if (rr_strace_parser_load(parser) != 0) {
        fprintf(stderr, "Failed to load trace file\n");
        rr_strace_parser_cleanup(parser);
        return 1;
    }
    
    /* 获取统计信息 */
    size_t total_records, current_index;
    rr_strace_get_stats(parser, &total_records, &current_index);
    printf("Loaded %zu records from trace file\n\n", total_records);
    
    /* 解析前几条记录进行测试 */
    int test_count = 10;
    if (total_records < test_count) test_count = total_records;
    
    printf("=== Testing first %d records ===\n", test_count);
    
    for (int i = 0; i < test_count; i++) {
        rr_strace_record_t *record = rr_strace_parser_get_next(parser);
        if (!record) {
            printf("No more records available\n");
            break;
        }
        
        printf("--- Record %d ---\n", i + 1);
        rr_strace_print_record(record);
        
        /* 测试系统调用编号映射 */
        int syscall_nr = rr_strace_get_syscall_number(record->syscall_name);
        printf("Syscall number: %d\n", syscall_nr);
        printf("========================================\n\n");
    }
    
    /* 重置并测试特定系统调用 */
    printf("=== Testing syscall filtering ===\n");
    rr_strace_parser_reset(parser);
    
    int mmap_count = 0;
    int openat_count = 0;
    int total_processed = 0;
    
    rr_strace_record_t *record;
    while ((record = rr_strace_parser_get_next(parser)) != NULL) {
        total_processed++;
        
        if (strcmp(record->syscall_name, "mmap") == 0) {
            mmap_count++;
            if (mmap_count <= 3) {  /* 只显示前3个mmap调用 */
                printf("MMAP #%d:\n", mmap_count);
                rr_strace_print_record(record);
            }
        } else if (strcmp(record->syscall_name, "openat") == 0) {
            openat_count++;
            if (openat_count <= 3) {  /* 只显示前3个openat调用 */
                printf("OPENAT #%d:\n", openat_count);
                rr_strace_print_record(record);
            }
        }
    }
    
    printf("\n=== Summary ===\n");
    printf("Total records processed: %d\n", total_processed);
    printf("mmap calls found: %d\n", mmap_count);
    printf("openat calls found: %d\n", openat_count);
    
    /* 清理资源 */
    rr_strace_parser_cleanup(parser);
    
    printf("\n=== Test completed successfully ===\n");
    return 0;
}

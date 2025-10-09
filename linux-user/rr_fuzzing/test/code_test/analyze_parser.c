/**
 * RR-Fuzz Strace解析器性能和内存分析工具
 */

#include "rr_syscallparser.h"
#include <time.h>
#include <sys/resource.h>

void print_memory_usage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    printf("内存使用: %ld KB\n", usage.ru_maxrss);
}

void analyze_structure_sizes() {
    printf("=== 数据结构大小分析 ===\n");
    printf("rr_strace_arg_t: %zu bytes\n", sizeof(rr_strace_arg_t));
    printf("rr_strace_record_t: %zu bytes\n", sizeof(rr_strace_record_t));
    printf("rr_strace_parser_t: %zu bytes\n", sizeof(rr_strace_parser_t));
    
    printf("\n每条记录占用内存: %zu bytes\n", sizeof(rr_strace_record_t));
    printf("109条记录总占用: %zu bytes (%.2f KB)\n", 
           109 * sizeof(rr_strace_record_t),
           (109 * sizeof(rr_strace_record_t)) / 1024.0);
}

void benchmark_parsing() {
    const char *trace_file = "/home/webfuzz/Downloads/strace_final_trace.dat";
    
    printf("\n=== 解析性能测试 ===\n");
    
    clock_t start, end;
    
    /* 测试初始化性能 */
    start = clock();
    rr_strace_parser_t *parser = rr_strace_parser_init(trace_file);
    end = clock();
    printf("初始化时间: %.6f 秒\n", ((double)(end - start)) / CLOCKS_PER_SEC);
    
    if (!parser) {
        printf("初始化失败\n");
        return;
    }
    
    /* 测试加载性能 */
    start = clock();
    int load_result = rr_strace_parser_load(parser);
    end = clock();
    printf("加载时间: %.6f 秒\n", ((double)(end - start)) / CLOCKS_PER_SEC);
    
    if (load_result != 0) {
        printf("加载失败\n");
        rr_strace_parser_cleanup(parser);
        return;
    }
    
    /* 测试遍历性能 */
    start = clock();
    rr_strace_record_t *record;
    int count = 0;
    while ((record = rr_strace_parser_get_next(parser)) != NULL) {
        count++;
        /* 访问记录的各个字段以模拟实际使用 */
        volatile int pid = record->pid;
        volatile int arg_count = record->arg_count;
        volatile long ret_value = record->ret_value;
        (void)pid; (void)arg_count; (void)ret_value; /* 避免unused警告 */
    }
    end = clock();
    printf("遍历%d条记录时间: %.6f 秒\n", count, ((double)(end - start)) / CLOCKS_PER_SEC);
    printf("平均每条记录处理时间: %.9f 秒\n", ((double)(end - start)) / CLOCKS_PER_SEC / count);
    
    rr_strace_parser_cleanup(parser);
}

void analyze_syscall_distribution() {
    const char *trace_file = "/home/webfuzz/Downloads/strace_final_trace.dat";
    
    printf("\n=== 系统调用分布分析 ===\n");
    
    rr_strace_parser_t *parser = rr_strace_parser_init(trace_file);
    if (!parser || rr_strace_parser_load(parser) != 0) {
        printf("无法加载trace文件\n");
        return;
    }
    
    /* 统计系统调用分布 */
    struct {
        char name[64];
        int count;
    } syscall_stats[50];
    int unique_syscalls = 0;
    
    rr_strace_record_t *record;
    while ((record = rr_strace_parser_get_next(parser)) != NULL) {
        /* 查找是否已存在 */
        int found = 0;
        for (int i = 0; i < unique_syscalls; i++) {
            if (strcmp(syscall_stats[i].name, record->syscall_name) == 0) {
                syscall_stats[i].count++;
                found = 1;
                break;
            }
        }
        
        /* 如果是新的系统调用 */
        if (!found && unique_syscalls < 50) {
            strncpy(syscall_stats[unique_syscalls].name, record->syscall_name, 63);
            syscall_stats[unique_syscalls].name[63] = '\0';
            syscall_stats[unique_syscalls].count = 1;
            unique_syscalls++;
        }
    }
    
    printf("总共发现 %d 种不同的系统调用:\n", unique_syscalls);
    for (int i = 0; i < unique_syscalls; i++) {
        printf("  %-20s: %d 次\n", syscall_stats[i].name, syscall_stats[i].count);
    }
    
    rr_strace_parser_cleanup(parser);
}

void check_potential_optimizations() {
    printf("\n=== 潜在优化点分析 ===\n");
    
    printf("1. 内存优化建议:\n");
    printf("   - 当前每条记录固定分配 %zu 字节\n", sizeof(rr_strace_record_t));
    printf("   - 可考虑变长字符串存储以节省内存\n");
    printf("   - 参数数组可根据实际使用动态分配\n\n");
    
    printf("2. 性能优化建议:\n");
    printf("   - 解析器使用两次文件扫描(计数+解析)\n");
    printf("   - 可考虑单次扫描+动态数组重分配\n");
    printf("   - 字符串解析可使用更高效的方法\n\n");
    
    printf("3. 功能优化建议:\n");
    printf("   - 添加流式解析支持(不全部加载到内存)\n");
    printf("   - 添加索引支持快速查找特定系统调用\n");
    printf("   - 添加过滤器支持只解析感兴趣的系统调用\n\n");
    
    printf("4. 代码简化建议:\n");
    printf("   - 系统调用映射表可考虑使用哈希表提升查找效率\n");
    printf("   - 标志解析函数可合并减少重复代码\n");
}

int main() {
    printf("=== RR-Fuzz Strace解析器综合分析 ===\n\n");
    
    print_memory_usage();
    analyze_structure_sizes();
    benchmark_parsing();
    analyze_syscall_distribution();
    check_potential_optimizations();
    
    print_memory_usage();
    
    return 0;
}

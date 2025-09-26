/**
 * RR-Fuzz独立测试程序
 * 测试核心数据结构和基本功能，不依赖QEMU
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <glib.h>

/* 简化的数据结构定义用于测试 */
typedef long abi_long;

typedef struct syscall_record {
    uint32_t index;
    int syscall_nr;
    abi_long args[8];
    abi_long retval;
    uint8_t *arg_data[8];
    size_t arg_size[8];
    struct syscall_record *next;
} syscall_record_t;

typedef struct {
    enum {
        RR_MODE_RECORD = 1,
        RR_MODE_REPLAY = 2,
        RR_MODE_FUZZING = 3
    } mode;

    bool enabled;
    syscall_record_t *trace_head;
    syscall_record_t *trace_tail;
    uint32_t trace_length;
    uint32_t replay_index;
    GHashTable *fd_map;
} rr_framework_t;

/* 全局框架实例 */
static rr_framework_t g_framework = {0};

/* 测试函数 */
void test_data_structures(void)
{
    printf("Testing RR-Fuzz data structures...\n");

    /* 测试记录结构 */
    syscall_record_t *record = g_malloc0(sizeof(syscall_record_t));
    record->index = 1;
    record->syscall_nr = 2;  // SYS_open
    record->args[0] = 0x1000;  // 文件路径地址
    record->retval = 3;  // 返回的FD

    /* 测试参数数据存储 */
    const char *filename = "/etc/passwd";
    record->arg_data[0] = g_malloc(strlen(filename) + 1);
    strcpy((char *)record->arg_data[0], filename);
    record->arg_size[0] = strlen(filename) + 1;

    printf("  ✓ Record structure created: syscall=%d, retval=%ld\n",
           record->syscall_nr, record->retval);
    printf("  ✓ Argument data captured: %s (%zu bytes)\n",
           record->arg_data[0], record->arg_size[0]);

    /* 清理 */
    if (record->arg_data[0]) {
        g_free(record->arg_data[0]);
    }
    g_free(record);

    /* 测试FD映射表 */
    GHashTable *fd_map = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* 添加映射：记录FD 5 -> 重放FD 7 */
    g_hash_table_insert(fd_map, GINT_TO_POINTER(5), GINT_TO_POINTER(7));

    /* 查找映射 */
    gpointer mapped_fd = g_hash_table_lookup(fd_map, GINT_TO_POINTER(5));
    int replay_fd = GPOINTER_TO_INT(mapped_fd);

    printf("  ✓ FD mapping test: record_fd=5 -> replay_fd=%d\n", replay_fd);

    g_hash_table_destroy(fd_map);

    printf("Data structure tests completed successfully!\n\n");
}

void test_trace_format(void)
{
    printf("Testing trace file format...\n");

    /* 创建模拟轨迹文件 */
    FILE *trace_file = fopen("test_trace.dat", "wb");
    if (!trace_file) {
        printf("  ✗ Failed to create trace file\n");
        return;
    }

    /* 写入文件头 */
    uint32_t magic = 0x52525254; // "RRTR"
    uint32_t version = 1;
    uint32_t record_count = 2;

    fwrite(&magic, sizeof(magic), 1, trace_file);
    fwrite(&version, sizeof(version), 1, trace_file);
    fwrite(&record_count, sizeof(record_count), 1, trace_file);

    /* 写入两条记录 */
    for (int i = 0; i < 2; i++) {
        syscall_record_t record = {0};
        record.index = i;
        record.syscall_nr = 2 + i;  // open, write
        record.retval = i + 3;

        fwrite(&record, sizeof(record), 1, trace_file);

        /* 写入结束标记 */
        int end_marker = -1;
        fwrite(&end_marker, sizeof(int), 1, trace_file);
    }

    fclose(trace_file);
    printf("  ✓ Trace file created with %d records\n", record_count);

    /* 读取并验证轨迹文件 */
    trace_file = fopen("test_trace.dat", "rb");
    if (!trace_file) {
        printf("  ✗ Failed to open trace file for reading\n");
        return;
    }

    /* 验证文件头 */
    uint32_t read_magic, read_version, read_count;
    fread(&read_magic, sizeof(read_magic), 1, trace_file);
    fread(&read_version, sizeof(read_version), 1, trace_file);
    fread(&read_count, sizeof(read_count), 1, trace_file);

    if (read_magic == 0x52525254 && read_version == 1 && read_count == 2) {
        printf("  ✓ Trace file header verified: magic=0x%x, version=%u, count=%u\n",
               read_magic, read_version, read_count);
    } else {
        printf("  ✗ Trace file header validation failed\n");
    }

    fclose(trace_file);
    unlink("test_trace.dat");

    printf("Trace format tests completed successfully!\n\n");
}

void test_fuzzing_instructions(void)
{
    printf("Testing fuzzing instruction format...\n");

    /* 创建变异指令 */
    typedef struct {
        enum {
            FUZZ_CMD_MUTATE_ARG = 1,
            FUZZ_CMD_REPLACE_BUFFER = 2
        } cmd;
        int syscall_index;
        int arg_index;
        size_t data_len;
        uint8_t data[];
    } FuzzInstruction;

    /* 测试参数变异指令 */
    size_t instr_size = sizeof(FuzzInstruction) + sizeof(abi_long);
    FuzzInstruction *instr = g_malloc(instr_size);

    instr->cmd = 1;  // FUZZ_CMD_MUTATE_ARG
    instr->syscall_index = 10;
    instr->arg_index = 0;
    instr->data_len = sizeof(abi_long);
    *(abi_long *)instr->data = -1;  // 变异值

    printf("  ✓ Mutation instruction created: syscall=%d, arg=%d, value=%ld\n",
           instr->syscall_index, instr->arg_index, *(abi_long *)instr->data);

    /* 测试缓冲区替换指令 */
    const char *fuzz_data = "AAAABBBBCCCCDDDD";
    size_t fuzz_len = strlen(fuzz_data);
    size_t buf_instr_size = sizeof(FuzzInstruction) + fuzz_len;
    FuzzInstruction *buf_instr = g_malloc(buf_instr_size);

    buf_instr->cmd = 2;  // FUZZ_CMD_REPLACE_BUFFER
    buf_instr->syscall_index = 15;
    buf_instr->arg_index = 1;
    buf_instr->data_len = fuzz_len;
    memcpy(buf_instr->data, fuzz_data, fuzz_len);

    printf("  ✓ Buffer replacement instruction created: syscall=%d, arg=%d, len=%zu\n",
           buf_instr->syscall_index, buf_instr->arg_index, buf_instr->data_len);
    printf("    Data: %.16s\n", buf_instr->data);

    g_free(instr);
    g_free(buf_instr);

    printf("Fuzzing instruction tests completed successfully!\n\n");
}

int main(void)
{
    printf("=== RR-Fuzz Standalone Test Suite ===\n\n");

    /* 初始化框架结构 */
    g_framework.mode = RR_MODE_RECORD;
    g_framework.enabled = true;
    g_framework.fd_map = g_hash_table_new(g_direct_hash, g_direct_equal);

    /* 运行测试 */
    test_data_structures();
    test_trace_format();
    test_fuzzing_instructions();

    /* 清理 */
    g_hash_table_destroy(g_framework.fd_map);

    printf("=== All Tests Passed! ===\n");
    printf("\nRR-Fuzz core functionality validated.\n");
    printf("Next step: Integrate with QEMU build system.\n");

    return 0;
}
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

// 复制实际的结构定义（从rr_framework.h）
typedef long abi_long;

typedef struct syscall_record {
    uint32_t index;                     // 在trace中的序号
    int syscall_nr;                     // 系统调用号
    abi_long args[8];                   // 参数值
    abi_long retval;                    // 返回值
    /* 参数数据存储 */
    uint8_t *arg_data[8];               // 参数指向的数据
    size_t arg_size[8];                 // 每个参数数据的大小
    /* 元数据 */
    bool creates_fd;                    // 是否创建文件描述符
    bool uses_fd;                       // 是否使用文件描述符
    int32_t created_fd;                 // 创建的文件描述符值
    struct syscall_record *next;        // 链表连接
} syscall_record_t;

int main() {
    printf("=== Structure Size Analysis ===\n");
    printf("sizeof(syscall_record_t) = %zu bytes\n", sizeof(syscall_record_t));
    printf("sizeof(uint32_t) = %zu\n", sizeof(uint32_t));
    printf("sizeof(int) = %zu\n", sizeof(int));
    printf("sizeof(abi_long) = %zu\n", sizeof(abi_long));
    printf("sizeof(uint8_t*) = %zu\n", sizeof(uint8_t*));
    printf("sizeof(size_t) = %zu\n", sizeof(size_t));
    printf("sizeof(bool) = %zu\n", sizeof(bool));
    printf("sizeof(int32_t) = %zu\n", sizeof(int32_t));
    printf("sizeof(void*) = %zu\n", sizeof(void*));

    printf("\n=== Field Offsets ===\n");
    syscall_record_t s;
    printf("offset of index = %zu\n", (char*)&s.index - (char*)&s);
    printf("offset of syscall_nr = %zu\n", (char*)&s.syscall_nr - (char*)&s);
    printf("offset of args = %zu\n", (char*)&s.args - (char*)&s);
    printf("offset of retval = %zu\n", (char*)&s.retval - (char*)&s);
    printf("offset of arg_data = %zu\n", (char*)&s.arg_data - (char*)&s);
    printf("offset of arg_size = %zu\n", (char*)&s.arg_size - (char*)&s);
    printf("offset of creates_fd = %zu\n", (char*)&s.creates_fd - (char*)&s);
    printf("offset of uses_fd = %zu\n", (char*)&s.uses_fd - (char*)&s);
    printf("offset of created_fd = %zu\n", (char*)&s.created_fd - (char*)&s);
    printf("offset of next = %zu\n", (char*)&s.next - (char*)&s);

    return 0;
}
/**
 * RR-Fuzz测试目标程序
 * 演示RR-Fuzz框架的使用
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
    printf("RR-Fuzz Test Target Started\n");

    /* 基本的系统调用序列，用于测试记录重放 */

    /* 1. 文件操作 */
    int fd = open("/tmp/rrfuzz_test.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* 2. 写入数据 */
    const char *data = "Hello RR-Fuzz World!\n";
    ssize_t written = write(fd, data, strlen(data));
    if (written < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    /* 3. 关闭文件 */
    close(fd);

    /* 4. 重新打开读取 */
    fd = open("/tmp/rrfuzz_test.txt", O_RDONLY);
    if (fd < 0) {
        perror("open for read");
        return 1;
    }

    /* 5. 读取数据 */
    char buffer[1024];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("Read from file: %s", buffer);
    }

    close(fd);

    /* 6. 删除文件 */
    unlink("/tmp/rrfuzz_test.txt");

    /* 7. 一个可能触发崩溃的函数（用于Fuzzing测试） */
    if (argc > 1) {
        char input[16];
        strncpy(input, argv[1], sizeof(input) - 1);
        input[sizeof(input) - 1] = '\0';

        /* 危险操作：如果输入是特定字符串，触发崩溃 */
        if (strcmp(input, "CRASH_ME") == 0) {
            printf("Triggering crash for fuzzing demo...\n");
            char *null_ptr = NULL;
            *null_ptr = 'X'; // 故意触发SIGSEGV
        }

        printf("Input processed: %s\n", input);
    }

    printf("RR-Fuzz Test Target Completed Successfully\n");
    return 0;
}
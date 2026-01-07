#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

void process_data() {
    char header[4];
    unsigned char size;
    char buffer[16];

    if (read(STDIN_FILENO, header, 4) != 4) return;
    if (strncmp(header, "BUFF", 4) != 0) return;
    if (read(STDIN_FILENO, &size, 1) != 1) return;
    if (read(STDIN_FILENO, buffer, size) <= 0) return;
    printf("[Target] Data received: %u bytes\n", size);
}

int main(int argc, char *argv[]) {
    // 增加 dummy syscalls 绕过 mutator 的早期保护 (index < 40)
    for (int i = 0; i < 50; i++) {
        getpid();
    }

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    process_data();
    return 0;
}

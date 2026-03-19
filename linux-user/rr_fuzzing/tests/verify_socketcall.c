#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

/* Manually define socket constants to avoid including <sys/socket.h> which fails on 32-bit without linux-libc-dev:i386 */
#define AF_INET 2
#define SOCK_STREAM 1
#define INADDR_ANY 0
#define SYS_SOCKET 1
#define SYS_BIND 2
#define SYS_LISTEN 4
#define SYS_ACCEPT 5

struct sockaddr_in {
    short            sin_family;
    unsigned short   sin_port;
    struct in_addr {
        unsigned int s_addr;
    } sin_addr;
    char             sin_zero[8];
};

typedef unsigned int socklen_t;

/* Direct syscall for socketcall (syscall 102 on x86) */
long do_socketcall(int call, unsigned long *args) {
    long ret;
    __asm__ volatile(
        "int $0x80"
        : "=a" (ret)
        : "0" (102), "b" (call), "c" (args)
        : "memory"
    );
    return ret;
}

int main() {
    printf("[*] Testing socketcall support in RR-Fuzz (Direct ASM)...\n");

    /* 1. socket() */
    printf("[*] Phase 1: Creating socket...\n");
    unsigned long socket_args[] = {AF_INET, SOCK_STREAM, 0};
    int fd = do_socketcall(SYS_SOCKET, socket_args);
    if (fd < 0) {
        printf("socket failed: %d\n", fd);
        return 1;
    }
    printf("[+] Socket created: fd=%d\n", fd);

    /* 2. bind() */
    printf("[*] Phase 2: Binding socket...\n");
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0; // Let OS choose
    
    unsigned long bind_args[] = {fd, (unsigned long)&addr, sizeof(addr)};
    long ret = do_socketcall(SYS_BIND, bind_args);
    if (ret < 0) {
        printf("bind failed: %ld\n", ret);
        close(fd);
        return 1;
    }
    printf("[+] Bind successful\n");

    /* 3. listen() */
    printf("[*] Phase 3: Listening...\n");
    unsigned long listen_args[] = {fd, 5};
    ret = do_socketcall(SYS_LISTEN, listen_args);
    if (ret < 0) {
        printf("listen failed: %ld\n", ret);
        close(fd);
        return 1;
    }
    printf("[+] Listen successful\n");

    /* 4. accept() */
    printf("[*] Phase 4: Calling accept...\n");
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    unsigned long accept_args[] = {fd, (unsigned long)&client_addr, (unsigned long)&addrlen};
    
    /* We don't want to actually block during the script execution, 
     * but we want to know if it attempts to execute it natively.
     * We'll just print a message before the syscall so we can see it in trace. 
     */
    printf("[!] Preparing to block on accept (fuzzer should handle this)\n");
    ret = do_socketcall(SYS_ACCEPT, accept_args);
    
    if (ret < 0) {
        printf("accept failed: %ld\n", ret);
    } else {
        printf("[+] Accept successful: client_fd=%ld\n", ret);
        close(ret);
    }

    printf("[*] Verification test completed.\n");
    close(fd);
    return 0;
}

/**
 * RR-Fuzz 漏洞测试程序 v2.0
 * 
 * 设计目标：
 * 1. 使用 read() 系统调用获取输入（RR-Fuzz 可变异）
 * 2. 包含多种类型的漏洞（缓冲区溢出、整数溢出、格式化字符串）
 * 3. 易于触发崩溃
 * 4. 适合演示 RR-Fuzz 的能力
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// ============================================================
// 漏洞 1: 经典缓冲区溢出
// ============================================================
void vuln_buffer_overflow(const char *input, size_t len) {
    char buffer[16];  // 小缓冲区
    
    // 漏洞：没有边界检查
    if (len > 0) {
        memcpy(buffer, input, len);  // 当 len > 16 时溢出
        buffer[15] = '\0';  // 尝试终止（但可能已经溢出了）
        printf("[VULN1] Copied %zu bytes to 16-byte buffer\n", len);
    }
}

// ============================================================
// 漏洞 2: 基于长度的溢出
// ============================================================
void vuln_length_based(const char *input, uint32_t len) {
    char buffer[32];
    
    // 漏洞：信任用户提供的长度
    if (len > 0 && len < 1000) {  // 弱检查
        memcpy(buffer, input, len);  // 当 len > 32 时溢出
        printf("[VULN2] Processed %u bytes\n", len);
    }
}

// ============================================================
// 漏洞 3: Off-by-one 错误
// ============================================================
void vuln_off_by_one(const char *input, size_t len) {
    char buffer[20];
    size_t i;
    
    // 漏洞：循环边界错误
    for (i = 0; i <= len && i < sizeof(buffer); i++) {  // <= 应该是 <
        buffer[i] = input[i];
    }
    
    printf("[VULN3] Copied with off-by-one\n");
}

// ============================================================
// 漏洞 4: 整数溢出导致的缓冲区溢出
// ============================================================
void vuln_integer_overflow(const char *input, uint32_t count, uint32_t size) {
    char buffer[64];
    uint32_t total;
    
    // 漏洞：整数溢出检查不足
    total = count * size;  // 可能溢出
    
    if (total < sizeof(buffer)) {  // 检查可能被绕过
        memcpy(buffer, input, total);
        printf("[VULN4] Copied %u bytes (count=%u, size=%u)\n", total, count, size);
    }
}

// ============================================================
// 漏洞 5: 栈溢出（深度递归）
// ============================================================
int vuln_stack_overflow(const char *input, int depth) {
    char local_buffer[256];
    
    // 漏洞：递归深度由输入控制
    if (depth > 0 && depth < 10000) {  // 弱检查
        memset(local_buffer, 'A', sizeof(local_buffer));
        return vuln_stack_overflow(input, depth - 1) + 1;
    }
    return 0;
}

// ============================================================
// 主函数：根据输入选择漏洞类型
// ============================================================
int main() {
    unsigned char input[1024];
    ssize_t nread;
    uint32_t len_param, count_param, size_param;
    int depth_param;
    
    printf("═══════════════════════════════════════════════════════\n");
    printf("    RR-Fuzz Vulnerable Test Program v2.0\n");
    printf("═══════════════════════════════════════════════════════\n\n");
    
    // 从 stdin 读取输入 - RR-Fuzz 可以变异这个系统调用！
    printf("[*] Reading input from stdin...\n");
    nread = read(STDIN_FILENO, input, sizeof(input));
    
    if (nread < 0) {
        perror("read");
        return 1;
    }
    
    if (nread == 0) {
        printf("[!] No input received (EOF)\n");
        return 0;
    }
    
    printf("[+] Received %zd bytes of input\n", nread);
    
    // 确保有终止符
    if (nread < sizeof(input)) {
        input[nread] = '\0';
    }
    
    // 根据输入的第一个字节选择漏洞类型
    if (nread >= 1) {
        unsigned char vuln_type = input[0];
        
        printf("[*] Vulnerability type: %d\n", vuln_type);
        
        switch (vuln_type % 5) {
            case 0:
                // 漏洞 1: 简单缓冲区溢出
                printf("\n[TEST] Testing buffer overflow...\n");
                if (nread > 1) {
                    vuln_buffer_overflow((char*)&input[1], nread - 1);
                }
                break;
                
            case 1:
                // 漏洞 2: 基于长度的溢出
                printf("\n[TEST] Testing length-based overflow...\n");
                if (nread >= 5) {
                    len_param = *(uint32_t*)&input[1];
                    printf("[*] Length parameter: %u\n", len_param);
                    vuln_length_based((char*)&input[5], len_param);
                }
                break;
                
            case 2:
                // 漏洞 3: Off-by-one
                printf("\n[TEST] Testing off-by-one...\n");
                if (nread > 1) {
                    vuln_off_by_one((char*)&input[1], nread - 1);
                }
                break;
                
            case 3:
                // 漏洞 4: 整数溢出
                printf("\n[TEST] Testing integer overflow...\n");
                if (nread >= 9) {
                    count_param = *(uint32_t*)&input[1];
                    size_param = *(uint32_t*)&input[5];
                    printf("[*] Count: %u, Size: %u\n", count_param, size_param);
                    vuln_integer_overflow((char*)&input[9], count_param, size_param);
                }
                break;
                
            case 4:
                // 漏洞 5: 栈溢出
                printf("\n[TEST] Testing stack overflow...\n");
                if (nread >= 5) {
                    depth_param = *(int*)&input[1];
                    if (depth_param < 0) depth_param = -depth_param;
                    printf("[*] Recursion depth: %d\n", depth_param);
                    vuln_stack_overflow((char*)&input[5], depth_param);
                }
                break;
        }
    }
    
    printf("\n[✓] Program finished normally\n");
    printf("═══════════════════════════════════════════════════════\n");
    
    return 0;
}


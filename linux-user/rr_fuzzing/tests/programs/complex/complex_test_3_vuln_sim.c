/*
 * 复杂测试程序3：真实漏洞模拟
 * 
 * 测试目标：
 * - 包含多种常见漏洞模式（受控，不会真正崩溃）
 * - 测试fuzzer发现边界条件的能力
 * - 模拟需要特定输入才能触发的漏洞
 * 
 * 注意：这些是模拟漏洞，用于测试，不会真正造成危害
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// 漏洞发现计数
static int vuln_1_triggered = 0;  // 缓冲区边界
static int vuln_2_triggered = 0;  // 整数溢出检测
static int vuln_3_triggered = 0;  // 格式化字符串模拟
static int vuln_4_triggered = 0;  // 逻辑漏洞
static int vuln_5_triggered = 0;  // 条件竞争模拟

// 模拟缓冲区边界问题
void test_buffer_boundary(const char *input) {
    char buffer[32];
    size_t len = strlen(input);
    
    printf("[测试1] 缓冲区边界检查\n");
    printf("  输入长度: %zu\n", len);
    
    if (len < 32) {
        strcpy(buffer, input);
        printf("  ✅ 安全复制\n");
    } else {
        printf("  ⚠️  输入过长，拒绝复制\n");
    }
    
    // 特殊检测：如果长度恰好是31（边界）
    if (len == 31) {
        vuln_1_triggered = 1;
        printf("  🚨 漏洞1触发：边界条件！\n");
    }
    
    // 特殊检测：如果输入包含特殊模式
    if (len >= 10 && memcmp(input, "AAAAAAAAAA", 10) == 0) {
        printf("  🔍 检测到特殊模式\n");
        vuln_1_triggered = 1;
    }
}

// 模拟整数溢出
void test_integer_overflow(int32_t value) {
    printf("[测试2] 整数溢出检测\n");
    printf("  输入值: %d (0x%08x)\n", value, (uint32_t)value);
    
    // 分配前检查
    if (value > 0 && value < 1000000) {
        printf("  ✅ 值在合理范围\n");
        
        // 模拟计算
        int32_t doubled = value * 2;
        if (doubled < value) {
            vuln_2_triggered = 1;
            printf("  🚨 漏洞2触发：整数溢出！\n");
        }
        
    } else if (value < 0) {
        printf("  ⚠️  负数输入\n");
        
        // 特殊：如果是特定负数
        if (value == -2147483648) {  // INT32_MIN
            vuln_2_triggered = 1;
            printf("  🚨 漏洞2触发：INT_MIN边界！\n");
        }
        
    } else {
        printf("  ⚠️  值过大\n");
        
        // 特殊：如果接近INT_MAX
        if (value > 2147483640) {
            vuln_2_triggered = 1;
            printf("  🚨 漏洞2触发：INT_MAX边界！\n");
        }
    }
}

// 模拟格式化字符串
void test_format_string(const char *format, const char *data) {
    printf("[测试3] 格式化字符串处理\n");
    printf("  格式: %s\n", format);
    printf("  数据: %s\n", data);
    
    // 安全处理：检查格式串
    if (strchr(format, '%') == NULL) {
        printf("  ✅ 安全格式串\n");
    } else {
        printf("  ⚠️  格式串包含格式化符号\n");
        
        // 计数格式化符号
        int count = 0;
        for (const char *p = format; *p; p++) {
            if (*p == '%' && *(p+1) != '%') {
                count++;
            }
        }
        
        printf("  格式化符号数量: %d\n", count);
        
        if (count >= 3) {
            vuln_3_triggered = 1;
            printf("  🚨 漏洞3触发：多个格式化符号！\n");
        }
        
        // 特殊检测：%n
        if (strstr(format, "%n")) {
            vuln_3_triggered = 1;
            printf("  🚨 漏洞3触发：危险的%%n符号！\n");
        }
    }
}

// 模拟逻辑漏洞：权限检查
int test_permission_check(const char *username, const char *password, const char *operation) {
    printf("[测试4] 权限逻辑检查\n");
    printf("  用户: %s\n", username);
    printf("  操作: %s\n", operation);
    
    // 正常逻辑：admin用户可以执行所有操作
    if (strcmp(username, "admin") == 0 && strcmp(password, "admin123") == 0) {
        printf("  ✅ 管理员权限，允许操作\n");
        return 1;
    }
    
    // 普通用户只能读取
    if (strcmp(operation, "read") == 0) {
        printf("  ✅ 读取权限，允许操作\n");
        return 1;
    }
    
    // 逻辑漏洞：特殊用户名绕过
    if (strlen(username) == 0) {
        printf("  ⚠️  空用户名\n");
        // 应该拒绝，但如果密码恰好是"bypass"...
        if (strcmp(password, "bypass") == 0) {
            vuln_4_triggered = 1;
            printf("  🚨 漏洞4触发：逻辑绕过！\n");
            return 1;
        }
    }
    
    // 另一个逻辑漏洞：用户名和密码相同的特殊情况
    if (strcmp(username, password) == 0 && strlen(username) > 5) {
        vuln_4_triggered = 1;
        printf("  🚨 漏洞4触发：用户名/密码相同绕过！\n");
        return 1;
    }
    
    printf("  ❌ 权限不足\n");
    return 0;
}

// 模拟条件竞争检测
void test_race_condition(int delay_ms, int operation_count) {
    printf("[测试5] 条件竞争模拟\n");
    printf("  延迟: %d ms\n", delay_ms);
    printf("  操作次数: %d\n", operation_count);
    
    static int shared_counter = 0;
    
    // 模拟多次操作
    for (int i = 0; i < operation_count; i++) {
        // 读取
        int value = shared_counter;
        
        // 模拟处理延迟（特定延迟会触发"竞争"）
        if (delay_ms == 50) {
            printf("  ⚠️  危险的延迟时间\n");
        }
        
        // 写回
        shared_counter = value + 1;
    }
    
    printf("  最终计数: %d\n", shared_counter);
    
    // 检测条件：如果延迟是50且操作次数是10
    if (delay_ms == 50 && operation_count == 10) {
        vuln_5_triggered = 1;
        printf("  🚨 漏洞5触发：条件竞争窗口！\n");
    }
    
    // 重置计数器
    shared_counter = 0;
}

// 组合漏洞：需要多步骤触发
void test_combined_exploit(const char *step1, int step2, const char *step3) {
    printf("[组合测试] 多步骤漏洞利用\n");
    
    static int stage = 0;
    
    // 阶段1：特定字符串
    if (stage == 0 && strcmp(step1, "init") == 0) {
        stage = 1;
        printf("  阶段1完成 ✓\n");
    }
    
    // 阶段2：特定数值
    if (stage == 1 && step2 == 1337) {
        stage = 2;
        printf("  阶段2完成 ✓\n");
    }
    
    // 阶段3：特定字符串
    if (stage == 2 && strcmp(step3, "pwned") == 0) {
        stage = 3;
        printf("  阶段3完成 ✓\n");
        printf("  🔥 组合漏洞完全触发！\n");
        
        // 标记所有漏洞
        vuln_1_triggered = vuln_2_triggered = vuln_3_triggered = 
        vuln_4_triggered = vuln_5_triggered = 1;
    }
    
    printf("  当前阶段: %d/3\n", stage);
}

int main() {
    char input[256];
    int choice;
    
    printf("=====================================\n");
    printf("  漏洞模拟测试系统 v3.0\n");
    printf("  (仅供安全测试使用)\n");
    printf("=====================================\n\n");
    
    while (1) {
        printf("\n选择测试:\n");
        printf("  1. 缓冲区边界测试\n");
        printf("  2. 整数溢出测试\n");
        printf("  3. 格式化字符串测试\n");
        printf("  4. 权限逻辑测试\n");
        printf("  5. 条件竞争测试\n");
        printf("  6. 组合漏洞测试\n");
        printf("  7. 显示统计\n");
        printf("  0. 退出\n");
        printf("\n选择: ");
        
        if (scanf("%d", &choice) != 1) {
            break;
        }
        
        // 清空输入缓冲区
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        
        printf("\n");
        
        switch (choice) {
            case 1: {
                printf("输入测试字符串: ");
                if (fgets(input, sizeof(input), stdin)) {
                    input[strcspn(input, "\n")] = 0;  // 移除换行
                    test_buffer_boundary(input);
                }
                break;
            }
            
            case 2: {
                int value;
                printf("输入整数值: ");
                if (scanf("%d", &value) == 1) {
                    test_integer_overflow(value);
                }
                break;
            }
            
            case 3: {
                char format[128], data[128];
                printf("输入格式串: ");
                scanf("%127s", format);
                printf("输入数据: ");
                scanf("%127s", data);
                test_format_string(format, data);
                break;
            }
            
            case 4: {
                char username[64], password[64], operation[32];
                printf("用户名: ");
                scanf("%63s", username);
                printf("密码: ");
                scanf("%63s", password);
                printf("操作 (read/write/delete): ");
                scanf("%31s", operation);
                test_permission_check(username, password, operation);
                break;
            }
            
            case 5: {
                int delay, count;
                printf("延迟(ms): ");
                scanf("%d", &delay);
                printf("操作次数: ");
                scanf("%d", &count);
                test_race_condition(delay, count);
                break;
            }
            
            case 6: {
                char s1[64], s3[64];
                int n2;
                printf("步骤1字符串: ");
                scanf("%63s", s1);
                printf("步骤2数值: ");
                scanf("%d", &n2);
                printf("步骤3字符串: ");
                scanf("%63s", s3);
                test_combined_exploit(s1, n2, s3);
                break;
            }
            
            case 7: {
                printf("=====================================\n");
                printf("  漏洞触发统计\n");
                printf("=====================================\n");
                printf("漏洞1 (缓冲区边界):   %s\n", vuln_1_triggered ? "🚨 已触发" : "❌ 未触发");
                printf("漏洞2 (整数溢出):     %s\n", vuln_2_triggered ? "🚨 已触发" : "❌ 未触发");
                printf("漏洞3 (格式化字符串): %s\n", vuln_3_triggered ? "🚨 已触发" : "❌ 未触发");
                printf("漏洞4 (逻辑绕过):     %s\n", vuln_4_triggered ? "🚨 已触发" : "❌ 未触发");
                printf("漏洞5 (条件竞争):     %s\n", vuln_5_triggered ? "🚨 已触发" : "❌ 未触发");
                printf("=====================================\n");
                
                int total = vuln_1_triggered + vuln_2_triggered + vuln_3_triggered +
                           vuln_4_triggered + vuln_5_triggered;
                printf("总触发数: %d/5\n", total);
                
                if (total == 5) {
                    printf("\n🏆 完美！你触发了所有漏洞！\n");
                } else if (total >= 3) {
                    printf("\n⭐ 不错！你发现了大部分漏洞。\n");
                }
                
                break;
            }
            
            case 0:
                goto exit_loop;
            
            default:
                printf("❌ 无效选择\n");
                break;
        }
    }
    
exit_loop:
    printf("\n=====================================\n");
    printf("  测试结束\n");
    printf("=====================================\n");
    printf("最终统计:\n");
    printf("  触发的漏洞: %d/5\n", 
           vuln_1_triggered + vuln_2_triggered + vuln_3_triggered +
           vuln_4_triggered + vuln_5_triggered);
    printf("=====================================\n");
    
    return 0;
}


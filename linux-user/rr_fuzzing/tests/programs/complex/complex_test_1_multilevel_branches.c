/*
 * 复杂测试程序1：多层分支逻辑
 * 
 * 测试目标：
 * - 多层嵌套的条件分支
 * - 需要多个正确输入才能到达深层分支
 * - 模拟真实程序的复杂控制流
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 秘密路径标志
static int secret_path_1_reached = 0;
static int secret_path_2_reached = 0;
static int secret_path_3_reached = 0;
static int jackpot_reached = 0;

// 检查用户名
int check_username(const char *username) {
    if (strcmp(username, "admin") == 0) {
        return 2;  // 管理员
    } else if (strcmp(username, "user") == 0) {
        return 1;  // 普通用户
    }
    return 0;  // 无效用户
}

// 检查密码（多层验证）
int check_password(const char *password, int user_level) {
    size_t len = strlen(password);
    
    // 第一层：长度检查
    if (len < 6) {
        printf("密码太短\n");
        return 0;
    }
    
    // 第二层：必须包含数字
    int has_digit = 0;
    for (size_t i = 0; i < len; i++) {
        if (password[i] >= '0' && password[i] <= '9') {
            has_digit = 1;
            break;
        }
    }
    
    if (!has_digit) {
        printf("密码必须包含数字\n");
        return 0;
    }
    
    // 第三层：用户级别特定检查
    if (user_level == 2) {  // 管理员
        // 秘密路径1：管理员密码必须以"pwd"开头
        if (strncmp(password, "pwd", 3) == 0) {
            secret_path_1_reached = 1;
            printf("🔓 秘密路径1已解锁！\n");
            
            // 第四层：密码长度大于10
            if (len > 10) {
                secret_path_2_reached = 1;
                printf("🔓 秘密路径2已解锁！\n");
                
                // 第五层：包含特殊字符'@'
                for (size_t i = 0; i < len; i++) {
                    if (password[i] == '@') {
                        secret_path_3_reached = 1;
                        printf("🔓 秘密路径3已解锁！\n");
                        break;
                    }
                }
            }
        }
        return 1;
    } else if (user_level == 1) {  // 普通用户
        // 普通用户：密码必须以字母开头
        if ((password[0] >= 'a' && password[0] <= 'z') ||
            (password[0] >= 'A' && password[0] <= 'Z')) {
            return 1;
        }
        printf("普通用户密码必须以字母开头\n");
        return 0;
    }
    
    return 0;
}

// 验证邮箱（额外的分支复杂度）
int verify_email(const char *email) {
    // 必须包含'@'
    const char *at_sign = strchr(email, '@');
    if (!at_sign) {
        printf("邮箱格式错误：缺少@符号\n");
        return 0;
    }
    
    // '@'之后必须有'.'
    const char *dot = strchr(at_sign, '.');
    if (!dot || dot == at_sign + 1) {
        printf("邮箱格式错误：域名无效\n");
        return 0;
    }
    
    // 检查特殊域名（彩蛋）
    if (strstr(email, "@secret.com")) {
        jackpot_reached = 1;
        printf("💎 JACKPOT! 你找到了隐藏彩蛋！\n");
    }
    
    return 1;
}

// 主菜单系统（多分支）
void handle_command(int cmd, int user_level) {
    switch (cmd) {
        case 1:
            printf("查看用户信息\n");
            if (user_level == 2) {
                printf("  特权：可查看所有用户\n");
            }
            break;
        
        case 2:
            printf("修改设置\n");
            if (user_level == 2) {
                printf("  特权：可修改系统设置\n");
            } else {
                printf("  权限不足\n");
            }
            break;
        
        case 3:
            printf("导出数据\n");
            if (user_level == 2 && secret_path_1_reached) {
                printf("  🔓 特殊功能：导出敏感数据\n");
            }
            break;
        
        case 4:
            printf("系统诊断\n");
            if (user_level == 2 && secret_path_2_reached) {
                printf("  🔓 特殊功能：深度系统诊断\n");
            }
            break;
        
        case 5:
            printf("高级工具\n");
            if (user_level == 2 && secret_path_3_reached) {
                printf("  🔓 特殊功能：Root Shell访问！\n");
            }
            break;
        
        default:
            printf("无效命令\n");
            break;
    }
}

int main() {
    char username[64];
    char password[128];
    char email[128];
    int command;
    
    printf("====================================\n");
    printf("  多层分支测试系统 v1.0\n");
    printf("====================================\n\n");
    
    // 第一层：用户名验证
    printf("用户名: ");
    if (scanf("%63s", username) != 1) {
        printf("输入错误\n");
        return 1;
    }
    
    int user_level = check_username(username);
    if (user_level == 0) {
        printf("❌ 用户名无效\n");
        return 1;
    }
    
    printf("用户级别: %s\n", user_level == 2 ? "管理员" : "普通用户");
    
    // 第二层：密码验证
    printf("密码: ");
    if (scanf("%127s", password) != 1) {
        printf("输入错误\n");
        return 1;
    }
    
    if (!check_password(password, user_level)) {
        printf("❌ 密码验证失败\n");
        return 1;
    }
    
    printf("✅ 密码正确\n\n");
    
    // 第三层：邮箱验证（可选）
    printf("邮箱 (可选，输入'skip'跳过): ");
    if (scanf("%127s", email) != 1) {
        printf("输入错误\n");
        return 1;
    }
    
    if (strcmp(email, "skip") != 0) {
        verify_email(email);
    }
    
    // 第四层：命令处理
    printf("\n====================================\n");
    printf("登录成功！\n");
    printf("====================================\n\n");
    
    printf("可用命令:\n");
    printf("  1. 查看用户信息\n");
    printf("  2. 修改设置\n");
    printf("  3. 导出数据\n");
    printf("  4. 系统诊断\n");
    printf("  5. 高级工具\n");
    printf("  0. 退出\n\n");
    
    while (1) {
        printf("请选择命令: ");
        if (scanf("%d", &command) != 1) {
            break;
        }
        
        if (command == 0) {
            break;
        }
        
        handle_command(command, user_level);
        printf("\n");
    }
    
    // 总结
    printf("\n====================================\n");
    printf("  会话统计\n");
    printf("====================================\n");
    printf("秘密路径1: %s\n", secret_path_1_reached ? "✅ 已到达" : "❌ 未到达");
    printf("秘密路径2: %s\n", secret_path_2_reached ? "✅ 已到达" : "❌ 未到达");
    printf("秘密路径3: %s\n", secret_path_3_reached ? "✅ 已到达" : "❌ 未到达");
    printf("隐藏彩蛋: %s\n", jackpot_reached ? "💎 已发现" : "❌ 未发现");
    printf("====================================\n");
    
    // 成就解锁条件
    if (secret_path_1_reached && secret_path_2_reached && 
        secret_path_3_reached && jackpot_reached) {
        printf("\n🎉 恭喜！你解锁了所有隐藏路径！\n");
    }
    
    return 0;
}


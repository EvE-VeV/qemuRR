/*
 * 复杂测试程序2：循环和状态机
 * 
 * 测试目标：
 * - 有状态的程序逻辑
 * - 循环中的分支判断
 * - 需要特定顺序的输入序列
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_HISTORY 100

// 状态机定义
typedef enum {
    STATE_IDLE,
    STATE_AUTHENTICATED,
    STATE_MENU,
    STATE_PROCESSING,
    STATE_ADMIN_MODE,
    STATE_SECRET_MODE,
    STATE_ERROR
} SystemState;

// 全局状态
static SystemState current_state = STATE_IDLE;
static int login_attempts = 0;
static int correct_commands = 0;
static char command_history[MAX_HISTORY][32];
static int history_count = 0;

// 秘密序列检测
static const char *secret_sequence[] = {"up", "up", "down", "down", "left", "right"};
static int secret_progress = 0;

// 添加命令到历史
void add_to_history(const char *cmd) {
    if (history_count < MAX_HISTORY) {
        strncpy(command_history[history_count], cmd, 31);
        command_history[history_count][31] = '\0';
        history_count++;
    }
}

// 检查秘密序列
void check_secret_sequence(const char *cmd) {
    if (secret_progress < 6) {
        if (strcmp(cmd, secret_sequence[secret_progress]) == 0) {
            secret_progress++;
            if (secret_progress == 6) {
                printf("\n🎮 Konami Code 输入成功！进入秘密模式！\n\n");
                current_state = STATE_SECRET_MODE;
            }
        } else {
            // 重置进度
            secret_progress = 0;
            // 但检查这个命令是否是序列的第一个
            if (strcmp(cmd, secret_sequence[0]) == 0) {
                secret_progress = 1;
            }
        }
    }
}

// 状态转换
void transition_to(SystemState new_state) {
    printf("[状态变更: ");
    switch (current_state) {
        case STATE_IDLE: printf("IDLE"); break;
        case STATE_AUTHENTICATED: printf("AUTHENTICATED"); break;
        case STATE_MENU: printf("MENU"); break;
        case STATE_PROCESSING: printf("PROCESSING"); break;
        case STATE_ADMIN_MODE: printf("ADMIN_MODE"); break;
        case STATE_SECRET_MODE: printf("SECRET_MODE"); break;
        case STATE_ERROR: printf("ERROR"); break;
    }
    printf(" -> ");
    switch (new_state) {
        case STATE_IDLE: printf("IDLE"); break;
        case STATE_AUTHENTICATED: printf("AUTHENTICATED"); break;
        case STATE_MENU: printf("MENU"); break;
        case STATE_PROCESSING: printf("PROCESSING"); break;
        case STATE_ADMIN_MODE: printf("ADMIN_MODE"); break;
        case STATE_SECRET_MODE: printf("SECRET_MODE"); break;
        case STATE_ERROR: printf("ERROR"); break;
    }
    printf("]\n");
    current_state = new_state;
}

// 处理循环查找
int process_search(const char *pattern) {
    const char *haystack = "The quick brown fox jumps over the lazy dog. "
                          "Secret code: FLAG{state_machine_pwned}. "
                          "Admin password: super_secret_123";
    
    int matches = 0;
    const char *ptr = haystack;
    
    // 简单的子串搜索
    while ((ptr = strstr(ptr, pattern)) != NULL) {
        matches++;
        ptr++;
        
        // 特殊检测：如果搜索"FLAG"，给予奖励
        if (strcmp(pattern, "FLAG") == 0) {
            printf("  🚩 你找到了FLAG！\n");
            correct_commands++;
        }
    }
    
    return matches;
}

// 处理数据转换
void process_transform(const char *data, const char *mode) {
    char buffer[256];
    strncpy(buffer, data, 255);
    buffer[255] = '\0';
    
    printf("  转换模式: %s\n", mode);
    printf("  输入: %s\n", data);
    
    if (strcmp(mode, "upper") == 0) {
        // 转换为大写
        for (int i = 0; buffer[i]; i++) {
            buffer[i] = toupper(buffer[i]);
        }
        printf("  输出: %s\n", buffer);
        
    } else if (strcmp(mode, "lower") == 0) {
        // 转换为小写
        for (int i = 0; buffer[i]; i++) {
            buffer[i] = tolower(buffer[i]);
        }
        printf("  输出: %s\n", buffer);
        
    } else if (strcmp(mode, "reverse") == 0) {
        // 反转字符串
        int len = strlen(buffer);
        for (int i = 0; i < len / 2; i++) {
            char tmp = buffer[i];
            buffer[i] = buffer[len - 1 - i];
            buffer[len - 1 - i] = tmp;
        }
        printf("  输出: %s\n", buffer);
        
        // 特殊：如果反转后包含"secret"，给予奖励
        if (strstr(buffer, "secret")) {
            printf("  🔓 发现隐藏信息！\n");
            correct_commands++;
        }
    } else if (strcmp(mode, "rot13") == 0) {
        // ROT13编码
        for (int i = 0; buffer[i]; i++) {
            if (buffer[i] >= 'a' && buffer[i] <= 'z') {
                buffer[i] = 'a' + ((buffer[i] - 'a' + 13) % 26);
            } else if (buffer[i] >= 'A' && buffer[i] <= 'Z') {
                buffer[i] = 'A' + ((buffer[i] - 'A' + 13) % 26);
            }
        }
        printf("  输出: %s\n", buffer);
        
        // 特殊：如果输入是"admin"，ROT13后是"nqzva"
        if (strcmp(data, "admin") == 0) {
            printf("  🔑 管理员模式密钥已生成！\n");
            transition_to(STATE_ADMIN_MODE);
        }
    } else {
        printf("  ❌ 未知转换模式\n");
    }
}

// 处理计算命令
void process_calculate(int iterations) {
    printf("  执行%d次迭代计算...\n", iterations);
    
    // 特殊迭代次数检测
    if (iterations == 42) {
        printf("  🎯 生命、宇宙以及一切的答案！\n");
        correct_commands++;
    }
    
    int result = 0;
    for (int i = 1; i <= iterations; i++) {
        result += i;
        
        // 每10次打印一次
        if (i % 10 == 0 || i == iterations) {
            printf("  迭代%d: 累计=%d\n", i, result);
        }
        
        // 特殊检测
        if (iterations == 100 && i == 100) {
            printf("  ✅ 完成100次迭代挑战！\n");
            correct_commands++;
        }
    }
    
    printf("  最终结果: %d\n", result);
}

int main() {
    char command[64];
    char arg1[128];
    char arg2[128];
    
    printf("=====================================\n");
    printf("  状态机测试系统 v2.0\n");
    printf("  提示: 尝试输入秘密序列 😉\n");
    printf("=====================================\n\n");
    
    transition_to(STATE_AUTHENTICATED);
    transition_to(STATE_MENU);
    
    printf("\n可用命令:\n");
    printf("  search <pattern>      - 搜索模式\n");
    printf("  transform <data> <mode> - 转换数据 (upper/lower/reverse/rot13)\n");
    printf("  calculate <n>         - 计算前N项和\n");
    printf("  history               - 显示命令历史\n");
    printf("  stats                 - 显示统计信息\n");
    printf("  up/down/left/right    - 方向键\n");
    printf("  quit                  - 退出\n\n");
    
    // 主命令循环
    while (1) {
        // 显示当前状态
        printf("[");
        switch (current_state) {
            case STATE_MENU: printf("MENU"); break;
            case STATE_ADMIN_MODE: printf("ADMIN"); break;
            case STATE_SECRET_MODE: printf("SECRET"); break;
            default: printf("???"); break;
        }
        printf("]> ");
        
        if (scanf("%63s", command) != 1) {
            break;
        }
        
        add_to_history(command);
        
        // 检查退出
        if (strcmp(command, "quit") == 0) {
            break;
        }
        
        // 检查秘密序列
        check_secret_sequence(command);
        
        // 处理命令
        if (strcmp(command, "search") == 0) {
            if (scanf("%127s", arg1) == 1) {
                printf("搜索: %s\n", arg1);
                int count = process_search(arg1);
                printf("  找到%d个匹配项\n", count);
            }
            
        } else if (strcmp(command, "transform") == 0) {
            if (scanf("%127s %127s", arg1, arg2) == 2) {
                process_transform(arg1, arg2);
            }
            
        } else if (strcmp(command, "calculate") == 0) {
            int n;
            if (scanf("%d", &n) == 1) {
                if (n > 0 && n <= 1000) {
                    transition_to(STATE_PROCESSING);
                    process_calculate(n);
                    transition_to(STATE_MENU);
                } else {
                    printf("  ❌ 迭代次数必须在1-1000之间\n");
                }
            }
            
        } else if (strcmp(command, "history") == 0) {
            printf("命令历史 (%d条):\n", history_count);
            for (int i = 0; i < history_count && i < 20; i++) {
                printf("  %d: %s\n", i + 1, command_history[i]);
            }
            if (history_count > 20) {
                printf("  ... 还有%d条\n", history_count - 20);
            }
            
        } else if (strcmp(command, "stats") == 0) {
            printf("统计信息:\n");
            printf("  命令总数: %d\n", history_count);
            printf("  正确操作: %d\n", correct_commands);
            printf("  当前状态: ");
            switch (current_state) {
                case STATE_MENU: printf("MENU\n"); break;
                case STATE_ADMIN_MODE: printf("ADMIN_MODE 🔑\n"); break;
                case STATE_SECRET_MODE: printf("SECRET_MODE 🎮\n"); break;
                default: printf("UNKNOWN\n"); break;
            }
            printf("  秘密序列进度: %d/6\n", secret_progress);
            
        } else if (strcmp(command, "up") == 0 || strcmp(command, "down") == 0 ||
                   strcmp(command, "left") == 0 || strcmp(command, "right") == 0) {
            printf("方向: %s (进度: %d/6)\n", command, secret_progress);
            
        } else {
            printf("❌ 未知命令: %s\n", command);
        }
        
        printf("\n");
    }
    
    // 最终统计
    printf("\n=====================================\n");
    printf("  会话结束\n");
    printf("=====================================\n");
    printf("总命令数: %d\n", history_count);
    printf("正确操作数: %d\n", correct_commands);
    printf("最终状态: ");
    switch (current_state) {
        case STATE_MENU: printf("MENU\n"); break;
        case STATE_ADMIN_MODE: printf("ADMIN_MODE 🔑\n"); break;
        case STATE_SECRET_MODE: printf("SECRET_MODE 🎮\n"); break;
        default: printf("UNKNOWN\n"); break;
    }
    
    // 成就系统
    printf("\n成就:\n");
    if (correct_commands >= 3) {
        printf("  ⭐ 探索者 - 发现3个隐藏功能\n");
    }
    if (current_state == STATE_ADMIN_MODE) {
        printf("  🔑 管理员 - 进入管理员模式\n");
    }
    if (current_state == STATE_SECRET_MODE) {
        printf("  🎮 秘密大师 - 输入Konami Code\n");
    }
    if (history_count >= 20) {
        printf("  💬 话唠 - 执行超过20条命令\n");
    }
    
    printf("=====================================\n");
    
    return 0;
}


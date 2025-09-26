/**
 * RR-Fuzz Fork Server模块
 * 实现高速Fuzzing的Fork Server机制，对应design.md中的Fork Server部分
 */

#include "rr_framework.h"
#include <sys/wait.h>
#include <signal.h>

static uint32_t g_fork_point = 0;
static bool g_at_fork_point = false;

/**
 * 启动Fork Server
 * 实现design.md中的Fork Server启动逻辑
 */
int rr_start_fork_server(uint32_t fork_point)
{
    RR_VERBOSE("Starting Fork Server initialization");

    if (!rr_framework_enabled()) {
        RR_ERROR("Cannot start Fork Server: framework not enabled");
        return -1;
    }

    g_fork_point = fork_point;
    g_rr_framework->fork_server_active = true;

    RR_INFO("Fork Server started at syscall index %u", fork_point);
    RR_VERBOSE("Fork Server state: active=%s, point=%u",
               g_rr_framework->fork_server_active ? "true" : "false", g_fork_point);

    /* 发送Ready状态给Conductor */
    RR_IPC_TRACE("Sending Ready status to Conductor");
    if (rr_ipc_send_status(1) < 0) { // 1 = Ready
        RR_WARN("Failed to send Ready status");
    }

    return 0;
}

/**
 * 停止Fork Server
 */
void rr_stop_fork_server(void)
{
    if (!g_rr_framework) {
        return;
    }

    g_rr_framework->fork_server_active = false;
    g_at_fork_point = false;

    /* 如果有子进程在运行，等待其结束 */
    if (g_rr_framework->child_pid > 0) {
        kill(g_rr_framework->child_pid, SIGTERM);
        waitpid(g_rr_framework->child_pid, NULL, 0);
        g_rr_framework->child_pid = 0;
    }

    RR_LOG("Fork Server stopped");
}

/**
 * 检查是否到达Fork点
 */
bool rr_check_fork_point(void)
{
    if (!g_rr_framework->fork_server_active) {
        return false;
    }

    /* 检查是否到达指定的Fork点 */
    if (g_rr_framework->replay_index == g_fork_point) {
        g_at_fork_point = true;
        RR_INFO("Reached fork point at syscall index %u", g_fork_point);
        RR_VERBOSE("Fork point reached: replay_index=%u, fork_point=%u",
                   g_rr_framework->replay_index, g_fork_point);

        /* 发送到达Fork点的状态 */
        RR_IPC_TRACE("Sending At Fork Point status");
        if (rr_ipc_send_status(2) < 0) { // 2 = At Fork Point
            RR_WARN("Failed to send At Fork Point status");
        }

        return true;
    }

    return false;
}

/**
 * Fork Server主循环
 * 等待Conductor的命令并执行Fork
 */
int rr_fork_server_loop(void)
{
    if (!g_at_fork_point) {
        return 0; // 还未到达Fork点
    }

    while (g_rr_framework->fork_server_active) {
        /* 接收Conductor命令 */
        int cmd = rr_ipc_receive_command();

        switch (cmd) {
            case 'F': // Fork命令
                {
                    pid_t pid = fork();
                    if (pid == 0) {
                        /* 子进程：继续执行Fuzzing */
                        g_rr_framework->child_pid = 0;
                        RR_LOG("Child process started for fuzzing execution");
                        return 1; // 返回1表示子进程应该继续执行
                    } else if (pid > 0) {
                        /* 父进程：等待子进程完成 */
                        g_rr_framework->child_pid = pid;
                        int status;
                        waitpid(pid, &status, 0);

                        /* 发送执行结果给Conductor */
                        if (WIFEXITED(status)) {
                            rr_ipc_send_status(3); // 3 = Normal Exit
                        } else if (WIFSIGNALED(status)) {
                            int sig = WTERMSIG(status);
                            if (sig == SIGSEGV || sig == SIGABRT || sig == SIGBUS) {
                                rr_ipc_send_status(4); // 4 = Crash Found
                                RR_LOG("Child process crashed with signal %d", sig);
                            } else {
                                rr_ipc_send_status(5); // 5 = Other Signal
                            }
                        }

                        g_rr_framework->child_pid = 0;
                        g_rr_framework->total_executions++;
                    } else {
                        /* Fork失败 */
                        RR_LOG("Fork failed");
                        rr_ipc_send_status(-1); // Error
                    }
                }
                break;

            case 'Q': // 退出命令
                RR_LOG("Fork Server received quit command");
                return -1; // 退出程序

            case 'S': // 保存Snapshot命令
                // TODO: 实现Snapshot保存
                rr_ipc_send_status(6); // 6 = Snapshot Saved
                break;

            case 'L': // 加载Snapshot命令
                // TODO: 实现Snapshot加载
                rr_ipc_send_status(7); // 7 = Snapshot Loaded
                break;

            case 0: // 无命令
                usleep(1000); // 短暂等待
                break;

            default:
                RR_LOG("Unknown fork server command: %d", cmd);
                break;
        }
    }

    return 0;
}
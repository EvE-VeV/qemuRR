# RR-Fuzz 网络系统调用处理：技术深度解析

本文档提供了关于 RR-Fuzz 在模糊测试过程中如何处理网络系统调用的详细技术分析，重点解释了数据注入机制以及如何避免宿主机侧的资源冲突。

## 1. 拦截与分发循环
RR-Fuzz 中所有客户机（Guest）系统调用的入口点是经过修改的 QEMU `do_syscall` 函数，位于 `linux-user/syscall.c`。

```c
// linux-user/syscall.c
abi_long do_syscall(...) {
    // ... 录制-重放初始化 ...
    abi_long rr_ret = rr_do_syscall(cpu_env, num, &rr_args[0], ...);
    
    if (rr_ret != -1) {
        // RR 框架处理了该调用（纯重放或模拟）
        ret = rr_ret;
    } else {
        // 混合重放：使用变异后的参数执行真实的宿主机系统调用
        ret = do_syscall1(cpu_env, num, rr_args[0], ...);
        rr_strace_syscall_post_hook_optimized(cpu_env, num, ret, rr_args);
    }
    // ...
}
```

## 2. 解决 "Address already in use"（推进阶段）
重放网络绑定应用程序的主要挑战之一是对宿主机资源（如 TCP 端口）的冲突。RR-Fuzz 通过对设置相关的系统调用使用 **纯确定性重放（Pure Deterministic Replay）** 来解决这一问题。

### 纯重放路径
当父 QEMU 进程处于 `REPLAY_ADVANCE` 模式（正在推进到检查点）时，它会为网络设置调用调用 `rr_replay_syscall_pure`。

*   **文件：** [rr_replay_pure.c](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/replay/rr_replay_pure.c)
*   **机制：** 框架不调用宿主机操作系统，而是直接返回追踪文件（Trace）中记录的值。
*   **涉及的系统调用：** `bind`、`listen`、`setsockopt`、`accept`、`getsockname`、`getpeername`。

```c
// replay/rr_replay_pure.c
case TARGET_NR_bind:
case TARGET_NR_listen:
case TARGET_NR_setsockopt:
    // 模拟成功，不与宿主机内核交互
    return record->retval;

case TARGET_NR_accept:
    // 将录制的 sockaddr 从 AUX 数据恢复到客户机内存中
    rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
    cpu_memory_rw_debug(env, args[1], aux->data, aux->size, 1);
    return record->retval;
```
**结果：** 父进程认为它已成功绑定端口并接受了连接，但宿主机上并未创建真实的 TCP 套接字。这有效防止了端口冲突。

## 3. 无阻塞的数据注入
数据注入（模糊测试）发生在 Fork Server 创建的子进程的 **混合重放（Hybrid Replay）** 路径中。

### 模拟输入机制
当模糊引擎（Fuzz Engine）为 I/O 系统调用（如 `recv` 或 `read`）提供变异指令时，框架会从“真实执行”切换到“模拟数据注入”。

*   **文件：** [rr_replay.c](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/src/engine/rr_replay.c)
*   **逻辑：**
    1.  检查是否存在活跃的返回值重写（`rr_fuzz_has_retval_override`）。
    2.  如果为真，获取重写后的值（变异后的数据大小）。
    3.  检查是否存在缓冲区填充指令（`rr_fuzz_has_buffer_fill`）。
    4.  通过 `cpu_memory_rw_debug` 将变异模式直接写入客户机内存。
    5.  通过跳转到 `replay_success` **绕过宿主机系统调用**。

```c
// src/engine/rr_replay.c
if (g_rr_framework->mode == RR_MODE_FUZZING && rr_fuzz_has_retval_override()) {
    ret = rr_fuzz_get_retval_override(); // 获取变异后的长度

    if (rr_fuzz_has_buffer_fill()) {
        rr_fuzz_get_buffer_fill(&buf_addr, &buf_size, &pattern);
        cpu_memory_rw_debug(env, buf_addr, pattern, fill_size, 1); // 注入变异数据
    }

    goto replay_success; // 绕过宿主机系统调用
}
```

### 变异策略（模糊引擎）
模糊引擎 ([rr_fuzz_engine.c](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/src/engine/rr_fuzz_engine.c)) 管理以下指令：
*   `FUZZ_CMD_MUTATE_ARG`: 可以重写 `arg_index == 0xFF`（返回值），以控制程序感知的输入数据大小。
*   `FUZZ_CMD_REPLACE_BUFFER`: 覆盖整个客户机缓冲区。
*   `FUZZ_CMD_OVERWRITE_AT_OFFSET`: 在指定偏移处进行精确注入。
*   `FUZZ_CMD_FLIP_BITS`: 用于协议特定变异的位翻转。

## 4. 执行流程总结

| 阶段 | 模式 | 网络系统调用流程 | 宿主机/客户机状态 |
| :--- | :--- | :--- | :--- |
| **父进程推进** | `REPLAY_ADVANCE` | `纯重放` (模拟) | **虚拟态**: 不消耗宿主机端口。 |
| **子进程测试** | `FUZZING` | `混合重放` (真实/变异) | **继承态**: 使用通过 fork 继承的宿主机 FD。 |
| **数据注入** | `FUZZING` | `模拟输入` (绕过) | **注入态**: 数据注入客户机；跳过宿主机调用。 |

## 5. 套接字 FD 继承
当 Fork Server 在检查点（例如追踪中的 `accept` 调用后）分支出子进程时，子进程会继承父进程的文件描述符。
*   如果父进程执行了 **真实** 的 `accept`（例如在非推进模式下），子进程拥有一个真实的已连接套接字。
*   如果父进程执行了 **模拟** 的 `accept`，子进程继承的是一个“幻影” FD。子进程中随后对该 FD 调用的 `recv` 会被拦截，并由模糊引擎提供变异数据。

这种双模方法使 RR-Fuzz 能够保持完整的客户机端应用程序状态，同时完全摆脱宿主机网络的限制。

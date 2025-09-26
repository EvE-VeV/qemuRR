# RR-Fuzz 记录-重放流程详细分析

## 概述

RR-Fuzz的核心是基于记录-重放(Record-Replay)技术的模糊测试框架。本文档详细分析RR流程的实现原理、执行过程和技术细节。

## 1. RR流程总体设计

### 1.1 三阶段执行模型

```
Phase 1: Record        Phase 2: Replay         Phase 3: Fuzzing
┌─────────────┐       ┌─────────────┐         ┌─────────────┐
│ Target App  │  →    │ Trace File  │  →      │ Mutated     │
│ Normal Run  │       │ Deterministic│         │ Execution   │
│             │       │ Replay      │         │             │
└─────────────┘       └─────────────┘         └─────────────┘
      ↓                       ↓                       ↓
┌─────────────┐       ┌─────────────┐         ┌─────────────┐
│ System Call │       │ Exact       │         │ Parameter   │
│ Interception│       │ Reproduction│         │ Mutation    │
└─────────────┘       └─────────────┘         └─────────────┘
      ↓                       ↓                       ↓
┌─────────────┐       ┌─────────────┐         ┌─────────────┐
│ Binary Trace│       │ State       │         │ Vulnerability│
│ Generation  │       │ Consistency │         │ Discovery   │
└─────────────┘       └─────────────┘         └─────────────┘
```

### 1.2 模式切换机制

RR-Fuzz通过配置系统支持动态模式切换：

```c
typedef enum {
    RR_MODE_DISABLED = 0,    // 禁用模式
    RR_MODE_RECORD = 1,      // 记录模式
    RR_MODE_REPLAY = 2,      // 重放模式
    RR_MODE_FUZZING = 3      // 模糊测试模式
} rr_mode_t;
```

## 2. Record阶段详细分析

### 2.1 系统调用拦截机制

**拦截点注入**:
```c
// 在QEMU的do_syscall函数中注入
abi_long do_syscall(CPUArchState *env, int num, abi_long arg1, ...) {
    // 1. RR-Fuzz前置检查
    abi_long rr_result = rr_do_syscall(env, num, arg1, ...);
    if (rr_result != -1) {
        return rr_result;  // RR-Fuzz接管处理
    }

    // 2. 执行原始系统调用
    abi_long ret = target_to_host_syscall(num, arg1, ...);

    // 3. RR-Fuzz后置处理（记录模式）
    if (rr_framework_enabled() && g_rr_framework->mode == RR_MODE_RECORD) {
        rr_syscall_post_hook(env, num, ret, arg1, ...);
    }

    return ret;
}
```

### 2.2 智能参数捕获

**参数分析策略**:
```c
static void capture_syscall_args(CPUArchState *env, int syscall_nr,
                                 const abi_long *args, syscall_record_t *record) {
    switch (syscall_nr) {
        case TARGET_NR_open:
        case TARGET_NR_openat:
            // 捕获文件路径字符串
            record->arg_data[syscall_nr == TARGET_NR_openat ? 1 : 0] =
                rr_capture_string(env, args[syscall_nr == TARGET_NR_openat ? 1 : 0],
                                 &record->arg_size[syscall_nr == TARGET_NR_openat ? 1 : 0]);
            break;

        case TARGET_NR_read:
            // 读操作：捕获缓冲区内容（在系统调用返回后）
            if (args[2] > 0 && args[2] <= 64 * 1024) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
            }
            break;

        case TARGET_NR_write:
            // 写操作：捕获输入数据
            if (args[2] > 0 && args[2] <= 64 * 1024) {
                record->arg_data[1] = rr_capture_buffer(env, args[1], args[2]);
                record->arg_size[1] = args[2];
            }
            break;
    }
}
```

**内存数据捕获**:
```c
uint8_t *rr_capture_string(CPUArchState *env, target_ulong addr, size_t *len) {
    if (addr == 0) {
        *len = 0;
        return NULL;
    }

    // 1. 计算字符串长度
    size_t str_len = 0;
    target_ulong current = addr;
    while (str_len < 4096) {  // 最大4KB限制
        uint8_t byte;
        if (cpu_memory_rw_debug(env_cpu(env), current, &byte, 1, 0) != 0) {
            break;  // 内存访问失败
        }
        if (byte == 0) break;  // 字符串结束
        str_len++;
        current++;
    }

    // 2. 分配并拷贝数据
    uint8_t *data = g_malloc(str_len + 1);
    cpu_memory_rw_debug(env_cpu(env), addr, data, str_len + 1, 0);
    *len = str_len + 1;
    return data;
}
```

### 2.3 文件描述符跟踪

**FD创建检测**:
```c
static bool syscall_creates_fd(int syscall_nr, abi_long ret) {
    if (ret < 0) return false;  // 系统调用失败

    switch (syscall_nr) {
        case TARGET_NR_open:
        case TARGET_NR_openat:
        case TARGET_NR_socket:
        case TARGET_NR_pipe:
        case TARGET_NR_pipe2:
        case TARGET_NR_dup:
        case TARGET_NR_dup2:
        case TARGET_NR_dup3:
            return true;
        default:
            return false;
    }
}
```

**FD映射管理**:
```c
// 记录时建立FD映射关系
if (record->creates_fd) {
    int record_fd = (int)record->retval;
    int real_fd = (int)ret;

    // 建立record_fd -> real_fd的映射
    g_hash_table_insert(g_rr_framework->fd_map,
                       GINT_TO_POINTER(record_fd),
                       GINT_TO_POINTER(real_fd));

    RR_FD_TRACE("FD mapping: record_fd=%d -> real_fd=%d", record_fd, real_fd);
}
```

### 2.4 二进制轨迹格式

**轨迹文件结构**:
```
Trace File Layout:
┌────────────────────────────────────────────────────────┐
│                    File Header                         │
│  Magic: "RRTR" (4 bytes)                              │
│  Version: 1 (4 bytes)                                 │
│  Record Count: N (4 bytes)                            │
└────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────┐
│                    Record 1                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Fixed Part: syscall_record_t struct             │  │
│  │ - index, syscall_nr, args[8], retval            │  │
│  │ - creates_fd, uses_fd, created_fd                │  │
│  │ - arg_size[8] (parameter data sizes)             │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Variable Part: Parameter Data                    │  │
│  │ For each i where arg_size[i] > 0:                │  │
│  │   - arg_index (4 bytes)                          │  │
│  │   - data_size (8 bytes)                          │  │
│  │   - data (data_size bytes)                       │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
│                       ...                              │
┌────────────────────────────────────────────────────────┐
│                    Record N                            │
│                   (same format)                        │
└────────────────────────────────────────────────────────┘
```

**写入实现**:
```c
int rr_record_syscall(CPUArchState *env, int num, const abi_long *args, abi_long ret) {
    // 1. 创建记录结构
    syscall_record_t *record = g_malloc0(sizeof(syscall_record_t));
    record->index = g_rr_framework->trace_length++;
    record->syscall_nr = num;
    memcpy(record->args, args, sizeof(abi_long) * 8);
    record->retval = ret;

    // 2. 分析和捕获参数数据
    capture_syscall_args(env, num, args, record);

    // 3. 检测FD创建
    record->creates_fd = syscall_creates_fd(num, ret);
    if (record->creates_fd) {
        record->created_fd = (int32_t)ret;
    }

    // 4. 写入轨迹文件
    fwrite(record, sizeof(syscall_record_t), 1, g_trace_file);

    // 5. 写入参数数据
    for (int i = 0; i < 8; i++) {
        if (record->arg_data[i] && record->arg_size[i] > 0) {
            fwrite(&i, sizeof(int), 1, g_trace_file);
            fwrite(&record->arg_size[i], sizeof(size_t), 1, g_trace_file);
            fwrite(record->arg_data[i], record->arg_size[i], 1, g_trace_file);
        }
    }

    // 6. 添加到内存轨迹链表
    if (g_rr_framework->trace_tail) {
        g_rr_framework->trace_tail->next = record;
    } else {
        g_rr_framework->trace_head = record;
    }
    g_rr_framework->trace_tail = record;

    return 0;
}
```

## 3. Replay阶段详细分析

### 3.1 轨迹加载与验证

**轨迹文件读取**:
```c
int rr_start_replay(const char *trace_file) {
    // 1. 打开轨迹文件
    g_trace_file = fopen(trace_file, "rb");
    if (!g_trace_file) {
        RR_ERROR("Failed to open trace file: %s", trace_file);
        return -1;
    }

    // 2. 验证文件头
    uint32_t magic, version, record_count;
    if (fread(&magic, sizeof(magic), 1, g_trace_file) != 1 ||
        fread(&version, sizeof(version), 1, g_trace_file) != 1 ||
        fread(&record_count, sizeof(record_count), 1, g_trace_file) != 1) {
        RR_ERROR("Failed to read trace header");
        return -1;
    }

    // 3. 验证魔数
    if (magic != 0x52525254) {  // "RRTR"
        RR_ERROR("Invalid trace file magic: 0x%x", magic);
        return -1;
    }

    RR_INFO("Loaded trace: version=%u, records=%u", version, record_count);
    return 0;
}
```

**记录解析**:
```c
static syscall_record_t *read_next_record(void) {
    if (!g_trace_file) return NULL;

    // 1. 读取基本记录
    syscall_record_t *record = g_malloc0(sizeof(syscall_record_t));
    if (fread(record, sizeof(syscall_record_t), 1, g_trace_file) != 1) {
        g_free(record);
        return NULL;  // 到达文件末尾
    }

    // 2. 读取参数数据
    for (int i = 0; i < 8; i++) {
        if (record->arg_size[i] > 0) {
            int arg_index;
            size_t data_size;

            // 读取参数数据头
            if (fread(&arg_index, sizeof(int), 1, g_trace_file) != 1 ||
                fread(&data_size, sizeof(size_t), 1, g_trace_file) != 1) {
                // 读取失败，清理资源
                for (int j = 0; j < i; j++) {
                    g_free(record->arg_data[j]);
                }
                g_free(record);
                return NULL;
            }

            // 分配并读取数据
            record->arg_data[arg_index] = g_malloc(data_size);
            if (fread(record->arg_data[arg_index], data_size, 1, g_trace_file) != 1) {
                // 读取失败，清理资源
                for (int j = 0; j <= i; j++) {
                    g_free(record->arg_data[j]);
                }
                g_free(record);
                return NULL;
            }
        }
    }

    return record;
}
```

### 3.2 确定性重放执行

**系统调用重放**:
```c
abi_long rr_replay_syscall(CPUArchState *env, int num, abi_long *args) {
    // 1. 获取当前要重放的记录
    if (!g_current_record) {
        g_current_record = read_next_record();
        if (!g_current_record) {
            RR_ERROR("No more records to replay");
            return -ENOSYS;  // 轨迹结束
        }
    }

    // 2. 验证系统调用匹配
    if (g_current_record->syscall_nr != num) {
        RR_ERROR("Syscall mismatch: expected %d, got %d at index %u",
                 g_current_record->syscall_nr, num, g_current_record->index);
        return -EINVAL;
    }

    // 3. 恢复参数（对于某些系统调用）
    restore_syscall_parameters(env, g_current_record, args);

    // 4. 返回记录的返回值
    abi_long ret = g_current_record->retval;

    // 5. 更新FD映射
    if (g_current_record->creates_fd && ret >= 0) {
        update_fd_mapping(g_current_record->created_fd, ret);
    }

    // 6. 移动到下一条记录
    cleanup_current_record();
    g_current_record = NULL;
    g_rr_framework->replay_index++;

    RR_SYSCALL_TRACE("Replayed syscall %d, ret=%ld", num, ret);
    return ret;
}
```

**参数恢复策略**:
```c
static void restore_syscall_parameters(CPUArchState *env, syscall_record_t *record, abi_long *args) {
    switch (record->syscall_nr) {
        case TARGET_NR_read:
            // 对于read系统调用，需要将记录的数据写回用户缓冲区
            if (record->arg_data[1] && record->arg_size[1] > 0 && record->retval > 0) {
                // 将记录的数据写入用户提供的缓冲区
                cpu_memory_rw_debug(env_cpu(env), args[1],
                                   record->arg_data[1], record->retval, 1);
                RR_MEM_TRACE("Restored read buffer: %ld bytes at 0x%lx",
                            record->retval, args[1]);
            }
            break;

        case TARGET_NR_pipe:
        case TARGET_NR_pipe2:
            // 对于pipe调用，需要将FD写回数组
            if (record->retval == 0 && record->arg_data[0]) {
                cpu_memory_rw_debug(env_cpu(env), args[0],
                                   record->arg_data[0], record->arg_size[0], 1);
                RR_FD_TRACE("Restored pipe FDs");
            }
            break;

        // 其他系统调用的参数恢复...
    }
}
```

### 3.3 状态一致性保证

**FD映射同步**:
```c
static void update_fd_mapping(int record_fd, int real_fd) {
    // 更新记录FD到实际FD的映射
    g_hash_table_insert(g_rr_framework->fd_map,
                       GINT_TO_POINTER(record_fd),
                       GINT_TO_POINTER(real_fd));

    RR_FD_TRACE("Updated FD mapping: record_fd=%d -> real_fd=%d",
                record_fd, real_fd);
}

// 在使用FD的系统调用中进行映射转换
static int map_record_fd_to_real(int record_fd) {
    gpointer real_fd_ptr = g_hash_table_lookup(g_rr_framework->fd_map,
                                               GINT_TO_POINTER(record_fd));
    if (real_fd_ptr) {
        return GPOINTER_TO_INT(real_fd_ptr);
    }
    return record_fd;  // 没有映射关系时直接使用原FD
}
```

## 4. Fuzzing阶段详细分析

### 4.1 Fork Server机制

**Fork点检测**:
```c
bool rr_check_fork_point(void) {
    if (!g_rr_framework->fork_server_active) {
        return false;
    }

    // 检查是否到达指定的fork点
    if (g_rr_framework->replay_index == g_fork_point) {
        g_at_fork_point = true;
        RR_INFO("Reached fork point at syscall index %u", g_fork_point);

        // 通知外部控制器
        rr_ipc_send_status(2);  // 2 = At Fork Point

        return true;
    }

    return false;
}
```

**Fork Server主循环**:
```c
int rr_fork_server_loop(void) {
    while (true) {
        // 1. 等待命令
        int cmd = rr_ipc_receive_command();

        switch (cmd) {
            case 'F':  // Fork命令
                {
                    pid_t pid = fork();
                    if (pid == 0) {
                        // 子进程：继续执行fuzzing
                        g_rr_framework->child_pid = getpid();
                        return 0;  // 返回让子进程继续执行
                    } else if (pid > 0) {
                        // 父进程：等待子进程结束
                        int status;
                        waitpid(pid, &status, 0);

                        // 报告执行结果
                        if (WIFSIGNALED(status)) {
                            rr_ipc_send_status(-2);  // 崩溃
                        } else {
                            rr_ipc_send_status(3);   // 正常结束
                        }

                        // 继续等待下一个命令
                        break;
                    } else {
                        // Fork失败
                        rr_ipc_send_status(-1);  // 错误
                        break;
                    }
                }
                break;

            case 'Q':  // 退出命令
                return -1;

            case 'S':  // 保存快照
                {
                    uint32_t snapshot_id = rr_snapshot_save(g_rr_framework->replay_index);
                    rr_ipc_send_status(snapshot_id);
                }
                break;

            case 'L':  // 加载快照
                {
                    // 从共享内存读取快照ID
                    uint32_t snapshot_id = *(uint32_t*)g_rr_framework->shared_memory;
                    if (rr_snapshot_restore(snapshot_id) == 0) {
                        rr_ipc_send_status(1);  // 成功
                    } else {
                        rr_ipc_send_status(-1); // 失败
                    }
                }
                break;

            default:
                // 未知命令，继续等待
                break;
        }
    }
}
```

### 4.2 参数变异机制

**变异指令应用**:
```c
void rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index,
                           abi_long *args, int syscall_nr) {
    if (!g_fuzz_instructions) {
        return;  // 没有变异指令
    }

    // 遍历所有变异指令
    uint8_t *ptr = (uint8_t *)g_fuzz_instructions;
    for (size_t i = 0; i < g_instruction_count; i++) {
        FuzzInstruction *instr = (FuzzInstruction *)ptr;

        if (instr->syscall_index == (int)syscall_index) {
            apply_mutation_instruction(env, instr, args, syscall_nr);
        }

        // 移动到下一个指令
        ptr += sizeof(FuzzInstruction) + instr->data_len;
    }
}

static void apply_mutation_instruction(CPUArchState *env, FuzzInstruction *instr,
                                     abi_long *args, int syscall_nr) {
    switch (instr->cmd) {
        case FUZZ_CMD_MUTATE_ARG:
            // 直接替换参数值
            if (instr->arg_index >= 0 && instr->arg_index < 8 &&
                instr->data_len >= sizeof(abi_long)) {
                abi_long new_value = *(abi_long *)instr->data;
                abi_long old_value = args[instr->arg_index];
                args[instr->arg_index] = new_value;

                RR_VERBOSE("Mutated arg[%d]: %ld -> %ld",
                          instr->arg_index, old_value, new_value);
            }
            break;

        case FUZZ_CMD_REPLACE_BUFFER:
            // 替换缓冲区内容
            if (instr->arg_index >= 0 && instr->arg_index < 8 && instr->data_len > 0) {
                target_ulong buffer_addr = args[instr->arg_index];
                if (buffer_addr != 0) {
                    // 将变异数据写入目标缓冲区
                    cpu_memory_rw_debug(env_cpu(env), buffer_addr,
                                       instr->data, instr->data_len, 1);

                    RR_MEM_TRACE("Replaced buffer at 0x%lx with %zu bytes",
                                buffer_addr, instr->data_len);
                }
            }
            break;
    }
}
```

### 4.3 变异策略生成

**智能变异策略**:
```c
FuzzInstruction *rr_fuzz_generate_mutations(uint32_t target_syscall, int target_arg,
                                          const uint8_t *seed_data, size_t seed_len,
                                          size_t *out_count) {
    // 基于系统调用类型选择变异策略
    syscall_record_t *record = find_syscall_record(target_syscall);
    if (!record) return NULL;

    switch (record->syscall_nr) {
        case TARGET_NR_read:
        case TARGET_NR_write:
            return generate_buffer_mutations(record, target_arg, seed_data, seed_len, out_count);

        case TARGET_NR_open:
        case TARGET_NR_openat:
            return generate_path_mutations(record, target_arg, seed_data, seed_len, out_count);

        case TARGET_NR_ioctl:
            return generate_ioctl_mutations(record, target_arg, seed_data, seed_len, out_count);

        default:
            return generate_generic_mutations(record, target_arg, seed_data, seed_len, out_count);
    }
}

// 缓冲区变异策略
static FuzzInstruction *generate_buffer_mutations(syscall_record_t *record, int target_arg,
                                                 const uint8_t *seed_data, size_t seed_len,
                                                 size_t *out_count) {
    *out_count = 5;  // 生成5种变异
    FuzzInstruction *instructions = g_malloc(sizeof(FuzzInstruction) * 5 + seed_len * 5);

    uint8_t *data_ptr = (uint8_t *)(instructions + 5);

    // 1. 边界值：全零
    instructions[0].cmd = FUZZ_CMD_REPLACE_BUFFER;
    instructions[0].syscall_index = record->index;
    instructions[0].arg_index = target_arg;
    instructions[0].data_len = seed_len;
    memset(data_ptr, 0, seed_len);
    memcpy(instructions[0].data, data_ptr, seed_len);
    data_ptr += seed_len;

    // 2. 边界值：全0xFF
    instructions[1].cmd = FUZZ_CMD_REPLACE_BUFFER;
    instructions[1].syscall_index = record->index;
    instructions[1].arg_index = target_arg;
    instructions[1].data_len = seed_len;
    memset(data_ptr, 0xFF, seed_len);
    memcpy(instructions[1].data, data_ptr, seed_len);
    data_ptr += seed_len;

    // 3. 随机变异
    instructions[2].cmd = FUZZ_CMD_REPLACE_BUFFER;
    instructions[2].syscall_index = record->index;
    instructions[2].arg_index = target_arg;
    instructions[2].data_len = seed_len;
    for (size_t i = 0; i < seed_len; i++) {
        data_ptr[i] = seed_data[i] ^ (rand() & 0xFF);
    }
    memcpy(instructions[2].data, data_ptr, seed_len);
    data_ptr += seed_len;

    // 4. 位翻转
    instructions[3].cmd = FUZZ_CMD_REPLACE_BUFFER;
    instructions[3].syscall_index = record->index;
    instructions[3].arg_index = target_arg;
    instructions[3].data_len = seed_len;
    memcpy(data_ptr, seed_data, seed_len);
    if (seed_len > 0) {
        size_t flip_pos = rand() % seed_len;
        data_ptr[flip_pos] ^= (1 << (rand() % 8));
    }
    memcpy(instructions[3].data, data_ptr, seed_len);
    data_ptr += seed_len;

    // 5. 长度扩展
    instructions[4].cmd = FUZZ_CMD_REPLACE_BUFFER;
    instructions[4].syscall_index = record->index;
    instructions[4].arg_index = target_arg;
    instructions[4].data_len = seed_len * 2;
    memcpy(data_ptr, seed_data, seed_len);
    memcpy(data_ptr + seed_len, seed_data, seed_len);  // 重复数据
    memcpy(instructions[4].data, data_ptr, seed_len * 2);

    return instructions;
}
```

## 5. 性能优化策略

### 5.1 内存管理优化

**轨迹数据结构优化**:
- **延迟分配**: 参数数据仅在需要时分配
- **内存池**: 频繁分配的小对象使用内存池
- **引用计数**: 共享数据使用引用计数管理

### 5.2 I/O优化

**轨迹文件优化**:
- **缓冲写入**: 使用缓冲区减少系统调用次数
- **压缩存储**: 可选的轨迹数据压缩
- **索引构建**: 建立快速查找索引

### 5.3 并发优化

**Fork Server优化**:
- **进程池**: 维护进程池减少fork开销
- **共享内存**: 使用共享内存加速数据交换
- **异步I/O**: 异步I/O处理提高并发性能

这个详细的RR流程分析展示了RR-Fuzz如何通过精确的记录-重放机制实现高效的模糊测试，确保了执行的确定性和变异的有效性。
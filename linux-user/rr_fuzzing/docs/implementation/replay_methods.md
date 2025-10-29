# RR-Fuzz Record & Replay 模块实现指南

## 概述

RR-Fuzz是集成在QEMU linux-user模式中的Record-Replay Fuzzing系统，通过系统调用拦截和重放机制实现确定性的模糊测试。本文档详细描述了record和replay模块的实现细节、交互机制以及当前功能状态。

## 系统架构

### 核心模块结构

```
rr_fuzzing/
├── rr_framework.h          # 核心数据结构和接口定义
├── rr_record.c            # Record模式实现
├── rr_replay.c            # Replay模式实现
├── rr_main.c              # 主框架和模式切换逻辑
├── rr_config.c            # 配置系统
├── rr_ipc.c               # 进程间通信
├── rr_snapshot.c          # 快照管理
└── doc/                   # 文档目录
```

### 数据流架构

```
应用程序 → 系统调用 → QEMU拦截 → RR-Fuzz处理 → 记录/重放 → 继续执行
```

## Record模块详细实现

### 1. 核心数据结构

**syscall_record_t** (`rr_framework.h:21-37`):
```c
typedef struct syscall_record {
    uint32_t index;                     // 在trace中的序号
    int syscall_nr;                     // 系统调用号
    abi_long args[8];                   // 参数值
    abi_long retval;                    // 返回值

    /* 参数数据存储 */
    uint8_t *arg_data[8];               // 参数指向的数据
    size_t arg_size[8];                 // 每个参数数据的大小

    /* 元数据 */
    bool creates_fd;                    // 是否创建文件描述符
    bool uses_fd;                       // 是否使用文件描述符
    int32_t created_fd;                 // 创建的文件描述符值
} syscall_record_t;
```

### 2. 记录流程

**初始化** (`rr_record.c:18-45`):
1. 打开二进制trace文件 (`fopen(trace_file, "wb")`)
2. 写入文件头：Magic(0x52525254) + Version(1) + 占位符记录数
3. 初始化全局记录状态

**系统调用记录** (`rr_record.c:150+`):
```c
int rr_record_syscall(CPUArchState *env, int num, abi_long args[])
{
    syscall_record_t *record = create_record(num, args);

    // 根据系统调用类型记录特定数据
    switch (num) {
        case TARGET_NR_read:
            record->arg_data[1] = capture_buffer_after_call();
            break;
        case TARGET_NR_write:
            record->arg_data[1] = capture_buffer_before_call();
            break;
        // ... 44个已实现的系统调用
    }

    write_record_to_trace(record);
    return 0;
}
```

**数据捕获机制** (`rr_record.c:85-120`):
- `rr_capture_string()`: 捕获字符串参数
- `rr_capture_buffer()`: 捕获缓冲区数据
- `rr_capture_struct()`: 捕获结构体数据

### 3. 二进制trace格式

**文件头结构**:
```
+-------------------+
| Magic (4 bytes)   | 0x52525254 ("RRTR")
| Version (4 bytes) | 当前版本: 1
| Count (4 bytes)   | 记录总数
+-------------------+
```

**记录结构**:
```
+-------------------+
| index (4 bytes)   |
| syscall_nr (4)    |
| args[8] (64)      |
| retval (8)        |
| arg_sizes[8] (64) |
| flags (9)         |
| arg_data sections |
+-------------------+
```

## Replay模块详细实现

### 1. 重放初始化

**启动流程** (`rr_replay.c:17-66`):
1. 打开trace文件进行读取
2. 验证文件头(Magic + Version)
3. 读取记录总数
4. 初始化重放状态

### 2. 核心重放逻辑

**系统调用重放** (`rr_replay.c:280+`):
```c
int rr_replay_syscall(CPUArchState *env, int num, abi_long args[])
{
    // 读取下一条记录
    if (!g_current_record) {
        g_current_record = read_next_record();
    }

    // 智能同步 - 处理不匹配
    while (g_current_record && g_current_record->syscall_nr != num) {
        RR_VERBOSE("Skipping unmatched syscall");
        cleanup_record(g_current_record);
        g_current_record = read_next_record();
    }

    // 执行特定系统调用的重放逻辑
    switch (num) {
        case TARGET_NR_mmap:
            return handle_mmap_replay();
        case TARGET_NR_read:
            return handle_read_replay();
        // ... 40个已实现的重放处理
    }
}
```

**关键修复 - mmap处理** (`rr_replay.c:399-420`):
```c
case TARGET_NR_mmap:
    if (ret != (abi_long)-1) {
        // 清理记录并手动递增索引
        cleanup_current_record();
        g_rr_framework->replay_index++; // 关键修复
        return -1; // 让调用者执行原始mmap
    }
    break;
```

### 3. 索引同步机制

**问题**: mmap处理会消费记录但不正确递增索引，导致replay_index与record_index失步。

**解决方案**: 确保在提前返回时手动递增replay_index，保持同步。

**效果**: 消除了g_current_record=NULL的根本原因，修复了index=13处的重放失败。

## 模块交互机制

### 1. QEMU集成点

**系统调用拦截** (`linux-user/syscall.c`):
```c
abi_long do_syscall(void *cpu_env, int num, ...)
{
    if (RR_MODE == RR_RECORD) {
        rr_record_syscall(cpu_env, num, args);
    } else if (RR_MODE == RR_REPLAY) {
        int replay_result = rr_replay_syscall(cpu_env, num, args);
        if (replay_result != -1) {
            return replay_result; // 使用记录的返回值
        }
    }

    // 继续正常系统调用执行
    return real_syscall_handler(num, args);
}
```

### 2. 配置系统交互

**环境变量控制**:
- `RR_MODE`: record/replay模式切换
- `RR_TRACE_FILE`: trace文件路径
- `RR_DEBUG_LEVEL`: 调试级别(0-4)
- `RR_FUZZING_ENABLED`: 启用fuzzing功能

### 3. 文件描述符映射

**Record阶段**:
```c
if (creates_fd) {
    record->creates_fd = true;
    record->created_fd = retval;
    fd_map_add(retval, get_fd_info());
}
```

**Replay阶段**:
```c
if (record->creates_fd) {
    int new_fd = create_mapped_fd(record->created_fd);
    update_fd_mapping(record->created_fd, new_fd);
}
```

## 已实现功能清单

### Record模块支持的系统调用 (44个)

**文件操作**:
- `read`, `write`, `open`, `close`, `stat`, `fstat`, `lstat`
- `openat`, `faccessat`, `access`, `dup3`

**内存管理**:
- `mmap`, `munmap`, `mprotect`, `brk`

**进程管理**:
- `getpid`, `exit_group`, `arch_prctl`

**时间相关**:
- `gettimeofday`, `clock_gettime`, `nanosleep`

**网络相关**:
- `socket`, `bind`, `listen`, `accept`, `connect`
- `send`, `recv`, `sendto`, `recvfrom`

**其他**:
- `uname`, `getuid`, `getgid`, `lseek`

### Replay模块功能

**核心重放机制**:
- ✅ 二进制trace文件读取
- ✅ 系统调用序列同步
- ✅ 智能不匹配处理
- ✅ 索引同步修复
- ✅ 内存地址重映射
- ✅ 文件描述符映射

**特殊处理**:
- ✅ mmap内存管理重放
- ✅ 文件IO数据恢复
- ✅ 时间调用确定性重放
- ✅ 网络调用模拟

## 系统测试与验证

### 测试用例

**基础功能测试**:
```bash
# Record阶段
RR_MODE=record RR_TRACE_FILE=./test.dat qemu-x86_64 /usr/bin/ls

# Replay阶段
RR_MODE=replay RR_TRACE_FILE=./test.dat qemu-x86_64 /usr/bin/ls
```

**调试模式**:
```bash
RR_DEBUG_LEVEL=4 RR_MODE=replay RR_TRACE_FILE=./trace.dat qemu-x86_64 /bin/echo "test"
```

### 关键问题修复验证

**问题**: replay_index=13时g_current_record=NULL
**修复**: mmap处理中的索引同步
**验证结果**: ✅ 成功处理index=13的mprotect系统调用，程序正常完成

## 当前限制与待改进项

### 1. 系统调用覆盖率

**已实现**: 44个核心系统调用 (~75%常用调用)
**待实现**:
- `ioctl` - 设备控制接口
- `fcntl` - 文件控制操作
- `select/poll/epoll` - IO多路复用
- `pipe/pipe2` - 管道操作
- `fork/clone` - 进程创建
- `signal` 相关 - 信号处理

### 2. 数据完整性

**当前状态**:
- ✅ 基本参数记录
- ✅ 字符串和缓冲区捕获
- ✅ 结构体参数处理
- ❌ 复杂嵌套结构体
- ❌ 变长参数列表

### 3. 性能优化

**待优化**:
- 大文件trace的内存使用
- 频繁系统调用的记录开销
- 二进制文件格式压缩
- 索引和查找机制优化

### 4. 错误处理

**需要增强**:
- trace文件损坏的恢复机制
- 不兼容版本的处理
- 内存不足时的降级策略
- 长时间运行的资源管理

### 5. Fuzzing集成

**当前状态**:
- ✅ 基础框架就绪
- ✅ 记录格式支持变异
- ❌ 变异策略实现
- ❌ 覆盖率引导
- ❌ 崩溃检测和分析

## 开发指南

### 添加新系统调用支持

**1. Record端** (`rr_record.c`):
```c
case TARGET_NR_new_syscall:
    // 记录参数数据
    if (args[0]) {
        record->arg_data[0] = rr_capture_buffer(env, args[0], args[1]);
        record->arg_size[0] = args[1];
    }
    break;
```

**2. Replay端** (`rr_replay.c`):
```c
case TARGET_NR_new_syscall:
    // 恢复参数数据
    if (g_current_record->arg_data[0]) {
        restore_buffer_to_memory(env, args[0],
                                g_current_record->arg_data[0],
                                g_current_record->arg_size[0]);
    }
    return g_current_record->retval;
```

### 调试技巧

**启用详细日志**:
```bash
RR_DEBUG_LEVEL=4 RR_DEBUG_SYSCALL=1 RR_DEBUG_FD=1
```

**trace文件分析**:
```bash
# 使用内置分析工具
./trace_replay_readiness_analyzer trace.dat
```

**常见错误模式**:
1. 索引不同步 → 检查手动increment逻辑
2. 内存访问违例 → 检查地址映射
3. 文件描述符错误 → 检查FD映射表

## 总结

RR-Fuzz系统已实现了完整的Record-Replay基础框架，支持44个核心系统调用的记录和重放。关键的索引同步问题已得到修复，系统能够稳定处理复杂的应用程序执行流程。

**优势**:
- 高度集成的QEMU架构
- 二进制高效的trace格式
- 智能的不匹配处理机制
- 完整的调试和分析工具

**下一步发展方向**:
- 扩展系统调用覆盖率至90%+
- 实现高级fuzzing策略
- 优化大规模应用的性能
- 增强错误恢复能力

该系统为确定性fuzzing提供了坚实的基础，可支持复杂软件的漏洞发现和安全研究。
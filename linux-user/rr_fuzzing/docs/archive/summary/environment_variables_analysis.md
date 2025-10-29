# RR-Fuzz 环境变量配置系统分析

**生成时间**: 2025-10-29  
**分析范围**: 环境变量定义、优先级、依赖关系、使用场景

---

## 1. 环境变量完整清单

### 1.1 核心控制变量

| 变量名 | 类型 | 默认值 | 说明 | 优先级 |
|--------|------|--------|------|--------|
| `RR_FUZZING_ENABLED` | bool | false | 是否启用RR-Fuzz框架 | 最高 |
| `RR_MODE` | string | - | 运行模式：record/replay/fuzzing | 高 |
| `RR_TRACE_FILE` | path | /tmp/rr_trace.dat | trace文件路径 | 中 |

### 1.2 IPC通信变量

| 变量名 | 类型 | 默认值 | 说明 | 优先级 |
|--------|------|--------|------|--------|
| `RR_CMD_PIPE` | fd/path | - | 命令管道FD或路径 | 高 |
| `RR_STATUS_PIPE` | fd/path | - | 状态管道FD或路径 | 高 |
| `RR_SHARED_MEMORY` | string | rr_fuzzing_shm | 共享内存名称 | 中 |
| `RR_SHARED_MEMORY_SIZE` | size | 64KB | 共享内存大小 | 低 |
| `RR_IPC_TIMEOUT` | int | 5000 | IPC超时(毫秒) | 低 |

### 1.3 Fork Server配置变量

| 变量名 | 类型 | 默认值 | 说明 | 优先级 |
|--------|------|--------|------|--------|
| `RR_FORK_POINT` | uint32 | 0 | 废弃：Fork点索引 | 已废弃 |
| `RR_FORK_STRATEGY` | int | STRICT(0) | Fork策略：0=STRICT, 1=RELAXED, 2=AGGRESSIVE, 3=FALLBACK | 中 |
| `RR_FORK_THRESHOLD` | int | 20 | Fallback策略阈值 | 低 |

### 1.4 调试与辅助变量

| 变量名 | 类型 | 默认值 | 说明 | 优先级 |
|--------|------|--------|------|--------|
| `RR_DEBUG_LEVEL` | int | 3 | 日志级别：0=OFF, 1=ERROR, 2=WARN, 3=INFO, 4=VERBOSE, 5=TRACE | 中 |
| `RR_DEBUG_FILE` | path | stderr | 日志输出文件 | 低 |
| `RR_TRACE_PIPE` | path | - | 动态跟踪管道路径 | 低 |
| `RR_DYNAMIC_TRACE` | bool | false | 是否启用动态跟踪 | 低 |
| `RR_STRACE_MODE` | string | - | Strace模式：optimized/legacy | 低 |
| `RR_STRACE_LOG_LEVEL` | int | 3 | Strace日志级别 | 低 |

### 1.5 高级配置变量

| 变量名 | 类型 | 默认值 | 说明 | 优先级 |
|--------|------|--------|------|--------|
| `RR_CONFIG_FILE` | path | - | 配置文件路径 | 最高 |
| `RR_USE_LEGACY_CAPTURE` | bool | false | 使用传统捕获方式 | 低 |

---

## 2. 配置优先级体系

```
配置源优先级（从低到高）:
1. 硬编码默认值 (代码中的DEFAULT_CONFIG)
   ↓
2. 配置文件 (RR_CONFIG_FILE指定的文件)
   ↓
3. 环境变量 (可以覆盖配置文件)
   ↓
4. 命令行参数 (未实现，预留)
```

### 2.1 配置加载流程

```c
// rr_config.c: rr_config_init()
int rr_config_init(void) {
    // Step 1: 加载硬编码默认值
    g_rr_config = DEFAULT_CONFIG;
    
    // Step 2: 读取配置文件（如果指定）
    const char *config_file = getenv("RR_CONFIG_FILE");
    if (config_file) {
        load_config_file(config_file);  // 覆盖默认值
    }
    
    // Step 3: 环境变量覆盖
    const char *rr_enabled = getenv("RR_FUZZING_ENABLED");
    if (rr_enabled) {
        g_rr_config.enabled = parse_bool(rr_enabled, g_rr_config.enabled);
    }
    // ... 其他环境变量按顺序覆盖
    
    return 0;
}
```

---

## 3. 环境变量依赖关系图

```
RR_FUZZING_ENABLED = true
    │
    ├─→ RR_MODE (必需)
    │   ├─→ record: 需要 RR_TRACE_FILE
    │   ├─→ replay: 需要 RR_TRACE_FILE
    │   └─→ fuzzing: 需要 RR_TRACE_FILE + IPC变量
    │
    ├─→ fuzzing模式下的依赖链:
    │   │
    │   ├─→ RR_CMD_PIPE (必需，用于接收命令)
    │   ├─→ RR_STATUS_PIPE (必需，用于发送状态)
    │   ├─→ RR_SHARED_MEMORY (可选，默认值存在)
    │   │
    │   └─→ Fork Server自动启用
    │       ├─→ RR_FORK_STRATEGY (可选，默认STRICT)
    │       └─→ RR_FORK_THRESHOLD (可选，默认20)
    │
    └─→ 可选调试功能:
        ├─→ RR_DEBUG_LEVEL (控制日志详细程度)
        ├─→ RR_TRACE_PIPE (启用动态跟踪)
        └─→ RR_STRACE_MODE (Strace兼容模式)
```

---

## 4. 典型使用场景配置

### 4.1 Record模式（录制trace）

```bash
export RR_FUZZING_ENABLED=true
export RR_MODE=record
export RR_TRACE_FILE=/path/to/trace.dat
export RR_DEBUG_LEVEL=3

qemu-x86_64 /path/to/target_program
```

**关键变量**:
- `RR_MODE=record`: 激活记录模式
- `RR_TRACE_FILE`: 指定输出文件
- 其他IPC变量不需要

**预期行为**:
1. 框架初始化，检测到record模式
2. 打开trace文件用于写入
3. 拦截所有系统调用并记录到trace
4. 程序退出时写入record_count到文件头

---

### 4.2 Replay模式（重放验证）

```bash
export RR_FUZZING_ENABLED=true
export RR_MODE=replay
export RR_TRACE_FILE=/path/to/trace.dat
export RR_DEBUG_LEVEL=4

qemu-x86_64 /path/to/target_program
```

**关键变量**:
- `RR_MODE=replay`: 激活重放模式
- `RR_TRACE_FILE`: 指定输入文件
- `RR_DEBUG_LEVEL=4`: 详细日志用于调试

**预期行为**:
1. 框架初始化，检测到replay模式
2. 打开trace文件用于读取
3. 按序重放每个系统调用
4. Pure/Hybrid路径自动选择
5. 验证返回值一致性

---

### 4.3 Fuzzing模式（模糊测试）

```bash
# Python Conductor端设置
export RR_FUZZING_ENABLED=True
export RR_MODE=fuzzing
export RR_TRACE_FILE=/tmp/rr_trace.dat
export RR_CMD_PIPE=3           # FD数字（通过pass_fds传递）
export RR_STATUS_PIPE=4        # FD数字
export RR_SHARED_MEMORY=rr_fuzz_12345
export RR_DEBUG_LEVEL=3
export RR_FORK_STRATEGY=0      # STRICT策略
export RR_TRACE_PIPE=/tmp/rr_trace_pipe_12345  # 可选：动态跟踪

# Conductor启动QEMU
qemu_process = subprocess.Popen(
    [qemu_path, target_binary],
    env=env,
    pass_fds=[cmd_pipe_read, status_pipe_write],
    ...
)
```

**关键变量**:
- `RR_MODE=fuzzing`: 激活Fuzzing模式
- `RR_CMD_PIPE`: Conductor → QEMU命令通道
- `RR_STATUS_PIPE`: QEMU → Conductor状态通道
- `RR_SHARED_MEMORY`: 变异指令共享内存
- `RR_TRACE_PIPE`: 可选，用于树可视化

**预期行为**:
1. 框架初始化，检测到fuzzing模式
2. 自动启用Fork Server
3. 等待Conductor的'F'命令
4. 到达fork点时：
   - 从共享内存加载fuzz指令
   - fork子进程
   - 子进程重放+应用变异
   - 父进程等待并报告状态
5. 循环执行直到收到'Q'命令

---

## 5. 环境变量与代码模块的对应关系

### 5.1 配置读取模块

| 环境变量 | 读取位置 | 使用模块 |
|---------|---------|---------|
| `RR_FUZZING_ENABLED` | rr_config.c:259 | rr_main.c:224 |
| `RR_MODE` | rr_config.c:270 | rr_main.c:243, 288-334 |
| `RR_TRACE_FILE` | rr_config.c:275 | rr_record.c, rr_replay.c |
| `RR_CMD_PIPE` | rr_config.c:287, rr_main.c:125 | rr_ipc.c:27-47 |
| `RR_STATUS_PIPE` | rr_config.c:293, rr_main.c:126 | rr_ipc.c:49-70 |
| `RR_SHARED_MEMORY` | rr_config.c:281 | rr_ipc.c:73-92 |
| `RR_FORK_STRATEGY` | rr_config.c:322 | rr_fork_server.c:483-511 |
| `RR_DEBUG_LEVEL` | rr_debug.c:94 | 所有模块（日志宏） |
| `RR_TRACE_PIPE` | rr_main.c:271 | rr_dynamic_trace.c |

### 5.2 模块依赖链

```
rr_framework_init() (rr_main.c)
    │
    ├─→ rr_config_init() (rr_config.c)
    │   └─→ 读取所有环境变量
    │
    ├─→ rr_debug_init() (rr_debug.c)
    │   └─→ 读取 RR_DEBUG_LEVEL, RR_DEBUG_FILE
    │
    ├─→ rr_ipc_init() (rr_ipc.c)
    │   └─→ 使用 RR_CMD_PIPE, RR_STATUS_PIPE, RR_SHARED_MEMORY
    │
    ├─→ 模式分支:
    │   ├─→ record: rr_start_recording()
    │   │   └─→ 使用 RR_TRACE_FILE
    │   │
    │   ├─→ replay: rr_start_replay()
    │   │   └─→ 使用 RR_TRACE_FILE
    │   │
    │   └─→ fuzzing: rr_start_replay() + rr_start_fork_server()
    │       ├─→ 使用 RR_TRACE_FILE
    │       ├─→ 使用 RR_FORK_STRATEGY, RR_FORK_THRESHOLD
    │       └─→ 依赖IPC系统
    │
    └─→ 可选: rr_dynamic_trace_init()
        └─→ 使用 RR_TRACE_PIPE
```

---

## 6. 特殊处理逻辑

### 6.1 RR_CMD_PIPE 和 RR_STATUS_PIPE 的双重解析

```c
// rr_ipc.c:27-46
if (g_rr_config.cmd_pipe_path) {
    char *endptr;
    long fd = strtol(g_rr_config.cmd_pipe_path, &endptr, 10);
    if (*endptr == '\0' && fd >= 0) {
        // 是FD数字，直接使用
        g_rr_framework->cmd_pipe_fd = (int)fd;
    } else {
        // 是文件路径，打开它
        g_rr_framework->cmd_pipe_fd = open(g_rr_config.cmd_pipe_path, O_RDONLY | O_NONBLOCK);
    }
}
```

**设计意图**:
- Python Conductor传递FD时：`RR_CMD_PIPE=3`
- 手动测试时：`RR_CMD_PIPE=/tmp/cmd_pipe`
- 灵活支持两种场景

### 6.2 Fuzzing模式自动启用Fork Server

```c
// rr_config.c:305-309
if (g_rr_config.mode == RR_MODE_FUZZING) {
    g_rr_config.fork_server_enabled = true;
    RR_INFO("Auto-enabled Fork Server for fuzzing mode");
}
```

**设计意图**:
- Fuzzing模式下，Fork Server是必需的
- 自动启用，无需额外配置
- 简化用户操作

### 6.3 FD环境对齐（防止FD冲突）

```c
// rr_main.c:116-209
static int align_fd_state(void) {
    // 读取IPC FD，避免关闭它们
    const char *cmd_fd_str = getenv("RR_CMD_PIPE");
    const char *status_fd_str = getenv("RR_STATUS_PIPE");
    
    // 关闭可以关闭的FD，为guest程序腾出fd=3,4,5...
    // 但保护IPC FD不被关闭
}
```

**设计意图**:
- Replay时，guest程序期望fd=3是第一个open的FD
- 但QEMU可能占用了fd=3,4...
- 需要关闭这些FD，但不能关闭IPC管道

---

## 7. 常见配置问题与解决方案

### 7.1 问题：Fuzzing模式下QEMU无响应

**症状**:
```
[Conductor] Waiting for QEMU Ready signal...
[Conductor] ⚠️  Timeout waiting for QEMU Ready signal
```

**原因**:
- `RR_STATUS_PIPE` 未正确设置
- 管道FD未通过`pass_fds`传递

**解决**:
```python
# 确保FD正确传递
qemu_process = subprocess.Popen(
    cmd,
    env=env,
    pass_fds=[self.cmd_pipe_read, self.status_pipe_write],  # ✅ 关键
    ...
)
```

### 7.2 问题：Trace文件读取失败

**症状**:
```
RR_ERROR: Failed to open trace file: /tmp/rr_trace.dat
```

**原因**:
- 环境变量未设置，使用了错误的默认路径
- 文件权限问题

**解决**:
```bash
# 明确指定trace文件
export RR_TRACE_FILE=/path/to/correct/trace.dat

# 检查文件存在性
ls -l /path/to/correct/trace.dat
```

### 7.3 问题：Fork Server未触发

**症状**:
- Fuzzing循环启动，但没有fork
- 日志显示 "fork_server_active=false"

**原因**:
- `RR_MODE` 未设置为 `fuzzing`
- Fork策略配置不当

**解决**:
```bash
# 确保模式正确
export RR_MODE=fuzzing

# 如果仍未触发，使用更激进的策略
export RR_FORK_STRATEGY=2  # AGGRESSIVE

# 或启用fallback
export RR_FORK_STRATEGY=3
export RR_FORK_THRESHOLD=5  # 5个syscall后强制fork
```

---

## 8. 环境变量最佳实践

### 8.1 开发调试配置

```bash
#!/bin/bash
# dev_config.sh - 开发环境配置

export RR_FUZZING_ENABLED=true
export RR_MODE=fuzzing
export RR_TRACE_FILE=./test_trace.dat
export RR_DEBUG_LEVEL=5          # TRACE级别，最详细
export RR_DEBUG_FILE=./rr_debug.log
export RR_FORK_STRATEGY=3        # FALLBACK，确保一定会fork
export RR_FORK_THRESHOLD=3       # 3个syscall后就fork
export RR_DYNAMIC_TRACE=1
export RR_TRACE_PIPE=/tmp/rr_trace_$$

echo "Development config loaded"
echo "Trace: $RR_TRACE_FILE"
echo "Debug log: $RR_DEBUG_FILE"
```

### 8.2 生产环境配置

```bash
#!/bin/bash
# prod_config.sh - 生产环境配置

export RR_FUZZING_ENABLED=true
export RR_MODE=fuzzing
export RR_TRACE_FILE=/data/traces/target.dat
export RR_DEBUG_LEVEL=2          # WARN级别，减少日志
export RR_FORK_STRATEGY=0        # STRICT，高质量fork点
export RR_SHARED_MEMORY_SIZE=65536

echo "Production config loaded"
```

### 8.3 配置验证脚本

```python
#!/usr/bin/env python3
# validate_env.py - 验证环境变量配置

import os
import sys

REQUIRED_VARS = {
    'fuzzing': ['RR_FUZZING_ENABLED', 'RR_MODE', 'RR_TRACE_FILE', 
                'RR_CMD_PIPE', 'RR_STATUS_PIPE'],
    'replay': ['RR_FUZZING_ENABLED', 'RR_MODE', 'RR_TRACE_FILE'],
    'record': ['RR_FUZZING_ENABLED', 'RR_MODE', 'RR_TRACE_FILE'],
}

def validate_config(mode):
    required = REQUIRED_VARS.get(mode, [])
    missing = []
    
    for var in required:
        if not os.getenv(var):
            missing.append(var)
    
    if missing:
        print(f"❌ Missing required variables for {mode} mode:")
        for var in missing:
            print(f"   - {var}")
        return False
    
    print(f"✅ All required variables set for {mode} mode")
    return True

if __name__ == '__main__':
    mode = os.getenv('RR_MODE', 'unknown')
    if not validate_config(mode):
        sys.exit(1)
```

---

## 9. 总结

### 9.1 关键发现

1. **配置系统设计良好**: 支持多层级覆盖，灵活性高
2. **Fuzzing模式依赖复杂**: 需要正确设置5+个环境变量
3. **自动化程度高**: Fuzzing模式自动启用Fork Server，减少配置负担
4. **调试友好**: 详细的日志级别控制

### 9.2 改进建议

1. **增加配置验证**: 启动时检查必需变量，给出明确错误提示
2. **环境变量文档化**: 在代码中增加注释说明每个变量的作用
3. **配置模板**: 提供各模式的配置文件模板
4. **配置冲突检测**: 检测互相矛盾的配置组合

### 9.3 环境变量优先级总结

```
最高优先级: RR_CONFIG_FILE (配置文件路径)
高优先级:   RR_FUZZING_ENABLED, RR_MODE (核心控制)
中优先级:   RR_TRACE_FILE, RR_CMD_PIPE, RR_STATUS_PIPE (关键路径)
低优先级:   RR_DEBUG_LEVEL, RR_FORK_STRATEGY (可选优化)
最低优先级: RR_SHARED_MEMORY_SIZE, RR_IPC_TIMEOUT (性能调优)
```

---

**文档版本**: 1.0  
**最后更新**: 2025-10-29  
**维护者**: RR-Fuzz Analysis Team


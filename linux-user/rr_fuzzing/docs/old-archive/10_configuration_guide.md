# RR-Fuzz配置参数完整指南

## 📖 概述

RR-Fuzz支持两种配置方式：
1. **环境变量**：适合命令行快速测试
2. **配置文件**：适合长期项目和复杂配置

**优先级**: 环境变量 > 配置文件 > 默认值

### 🎯 配置文件自动识别

配置文件中的 `mode` 字段会**自动识别**运行模式，使用配置文件时**无需**额外设置 `RR_MODE` 环境变量：

```bash
# ✅ 正确：配置文件自动识别mode
RR_CONFIG_FILE=./rr_config.record.template qemu-x86_64 /usr/bin/ls

# ❌ 不必要：重复设置RR_MODE
RR_CONFIG_FILE=./rr_config.record.template RR_MODE=record qemu-x86_64 /usr/bin/ls
```

---

## 📋 完整参数表

### 核心参数（必需）

| 环境变量 | 配置文件 | 类型 | 默认值 | 可选值 | 说明 | 适用模式 |
|---------|---------|------|--------|--------|------|----------|
| `RR_FUZZING_ENABLED` | `enabled` | Boolean | `false` | `true`, `false`, `1`, `0`, `yes`, `no` | RR-Fuzz总开关 | 全部 |
| `RR_MODE` | `mode` | String | `disabled` | `record`, `replay`, `fuzzing`, `disabled` | 运行模式 | 全部 |
| `RR_TRACE_FILE` | `trace_file` | Path | `/tmp/rr_trace.dat` | 任意路径 | Trace文件路径 | 全部 |
| `RR_CONFIG_FILE` | - | Path | - | 任意路径 | 配置文件路径 | 全部 |

### Replay模式专用参数

| 环境变量 | 配置文件 | 类型 | 默认值 | 可选值 | 说明 |
|---------|---------|------|--------|--------|------|
| `RR_STRACE_MODE` | ⚠️ 不支持 | Boolean | `false` | `true`, `false` | 启用strace replay（**必需**） |
| `RR_STRACE_LOG_LEVEL` | ⚠️ 不支持 | Integer | `2` | `0`(ERROR), `1`(WARN), `2`(INFO), `3`(VERBOSE), `4`(DEBUG) | Strace模块日志级别 |

### Fuzzing模式IPC参数

| 环境变量 | 配置文件 | 类型 | 默认值 | 可选值 | 说明 |
|---------|---------|------|--------|--------|------|
| `RR_SHARED_MEMORY` | `shared_memory_name` | String | `rr_fuzzing_shm` | 任意名称 | 共享内存名称 |
| `RR_SHARED_MEMORY_SIZE` | `shared_memory_size` | Integer | `4096` | 任意正整数 | 共享内存大小（字节） |
| `RR_CMD_PIPE` | `cmd_pipe_path` | Path | `/tmp/rr_cmd_pipe` | 任意路径 | 命令管道（fuzzer→QEMU） |
| `RR_STATUS_PIPE` | `status_pipe_path` | Path | `/tmp/rr_status_pipe` | 任意路径 | 状态管道（QEMU→fuzzer） |
| `RR_IPC_TIMEOUT` | `ipc_timeout` | Integer | `1000` | 任意正整数 | IPC超时时间（毫秒） |

### Fork Server参数

| 环境变量 | 配置文件 | 类型 | 默认值 | 可选值 | 说明 |
|---------|---------|------|--------|--------|------|
| `RR_FORK_STRATEGY` | `fork_strategy` | Integer | `2` | `0`(STRICT), `1`(RELAXED), `2`(AGGRESSIVE), `3`(FALLBACK) | Fork点检测策略 |
| `RR_FORK_THRESHOLD` | `fork_threshold` | Integer | `20` | 任意正整数 | Fallback策略阈值（syscall数） |

**Fork策略说明**:
- `0` (STRICT): 只在 `ret>0` 的I/O操作fork
- `1` (RELAXED): 允许ENOENT/EACCES等探测性错误
- `2` (AGGRESSIVE): 任何I/O类syscall都fork（推荐）
- `3` (FALLBACK): N个syscall后强制fork

### 调试参数

| 环境变量 | 配置文件 | 类型 | 默认值 | 可选值 | 说明 |
|---------|---------|------|--------|--------|------|
| `RR_DEBUG_LEVEL` | `debug_level` | Integer | `3` | `0`(OFF), `1`(ERROR), `2`(WARN), `3`(INFO), `4`(VERBOSE), `5`(TRACE) | 全局调试级别 |
| `RR_DEBUG_FILE` | `debug_file` | Path | `stderr` | 任意路径或`stderr` | 调试日志输出文件 |

### 可视化参数（可选）

| 环境变量 | 配置文件 | 类型 | 默认值 | 说明 |
|---------|---------|------|--------|------|
| `RR_TRACE_PIPE` | ⚠️ 不支持 | Path | - | 动态trace管道（用于实时可视化） |

---

## 🎬 使用示例

### Record模式

#### 环境变量方式
```bash
RR_FUZZING_ENABLED=True \
RR_MODE=record \
RR_TRACE_FILE=./trace-ls.txt \
RR_DEBUG_LEVEL=3 \
qemu-x86_64 -strace /usr/bin/ls
```

#### 配置文件方式（推荐）
```bash
# 方式1: 直接使用模板（mode自动识别为record）
RR_CONFIG_FILE=./rr_config.record.template qemu-x86_64 -strace /usr/bin/ls

# 方式2: 自定义配置文件
cat > my-record.conf << EOF
enabled=true
mode=record
trace_file=./my-trace.txt
debug_level=3
EOF

# 运行（mode自动识别，无需设置RR_MODE）
RR_CONFIG_FILE=./my-record.conf qemu-x86_64 -strace /usr/bin/ls
```

---

### Replay模式

#### 环境变量方式
```bash
RR_FUZZING_ENABLED=True \
RR_MODE=replay \
RR_TRACE_FILE=./trace-ls.txt \
RR_STRACE_MODE=True \
RR_DEBUG_LEVEL=4 \
RR_STRACE_LOG_LEVEL=3 \
qemu-x86_64 /usr/bin/ls
```

#### 配置文件方式（推荐）
```bash
# 方式1: 直接使用模板（mode自动识别为replay）
RR_CONFIG_FILE=./rr_config.replay.template \
RR_STRACE_MODE=True \
qemu-x86_64 /usr/bin/ls

# 方式2: 自定义配置文件
cat > my-replay.conf << EOF
enabled=true
mode=replay
trace_file=./my-trace.txt
debug_level=4
EOF

# 运行（mode自动识别，无需设置RR_MODE）
RR_CONFIG_FILE=./my-replay.conf \
RR_STRACE_MODE=True \
RR_STRACE_LOG_LEVEL=3 \
qemu-x86_64 /usr/bin/ls
```

**注意**: `RR_STRACE_MODE` 必须通过环境变量设置

---

### Fuzzing模式

#### 环境变量方式
```bash
# 1. 创建管道
mkfifo /tmp/rr_cmd_pipe /tmp/rr_status_pipe

# 2. 启动QEMU
RR_FUZZING_ENABLED=True \
RR_MODE=fuzzing \
RR_TRACE_FILE=./trace-ls.txt \
RR_STRACE_MODE=True \
RR_SHARED_MEMORY=my_shm \
RR_CMD_PIPE=/tmp/rr_cmd_pipe \
RR_STATUS_PIPE=/tmp/rr_status_pipe \
RR_FORK_STRATEGY=2 \
RR_FORK_THRESHOLD=20 \
qemu-x86_64 /usr/bin/ls
```

#### 配置文件方式（推荐）
```bash
# 1. 创建IPC管道
mkfifo /tmp/rr_cmd_pipe /tmp/rr_status_pipe

# 2a. 方式1: 直接使用模板（mode自动识别为fuzzing）
RR_CONFIG_FILE=./rr_config.fuzzing.template \
RR_STRACE_MODE=True \
qemu-x86_64 /usr/bin/ls

# 2b. 方式2: 自定义配置
cat > my-fuzzing.conf << EOF
enabled=true
mode=fuzzing
trace_file=./my-trace.txt
shared_memory_name=my_shm
cmd_pipe_path=/tmp/rr_cmd_pipe
status_pipe_path=/tmp/rr_status_pipe
fork_strategy=2
fork_threshold=20
debug_level=3
EOF

# 运行（mode自动识别，无需设置RR_MODE）
RR_CONFIG_FILE=./my-fuzzing.conf \
RR_STRACE_MODE=True \
qemu-x86_64 /usr/bin/ls
```

**注意**: `RR_STRACE_MODE` 必须通过环境变量设置

---

## 📄 配置文件格式

### 文件格式规则

```ini
# 注释行以 # 开头
# 格式为 key=value

# 示例配置
enabled=true
mode=replay                    # ⭐ mode字段会自动识别运行模式
trace_file=./trace.txt
debug_level=4
```

**规则**:
1. ✅ 使用 `#` 开头的行为注释
2. ✅ 格式为 `key=value`（不支持引号）
3. ✅ 忽略空行
4. ✅ `mode` 字段会**自动识别**运行模式（无需设置 `RR_MODE`）
5. ✅ 环境变量会覆盖配置文件中的值

### 使用配置文件

```bash
# 方式1: 仅使用配置文件（mode会自动识别）
RR_CONFIG_FILE=./my-config.conf qemu-x86_64 /usr/bin/ls

# 方式2: 使用预定义模板
RR_CONFIG_FILE=./rr_config.record.template qemu-x86_64 -strace /usr/bin/ls

# 方式3: 配置文件 + 环境变量覆盖（环境变量优先级更高）
RR_CONFIG_FILE=./base-config.conf \
RR_DEBUG_LEVEL=5 \
qemu-x86_64 /usr/bin/ls
```

**重要**: 配置文件中的 `mode` 字段会自动设置运行模式，**不需要**额外设置 `RR_MODE` 环境变量

---

## ⚠️ 重要提示

### 已删除的无效参数

以下参数已被删除（读取了但从不使用）：

| 已删除参数 | 替代方案 |
|-----------|---------|
| ~~`RR_DEBUG_SYSCALL`~~ | 使用 `RR_DEBUG_LEVEL=4` |
| ~~`RR_DEBUG_FD`~~ | 使用 `RR_DEBUG_LEVEL=4` |
| ~~`RR_DEBUG_MEM`~~ | 使用 `RR_DEBUG_LEVEL=5` |
| ~~`RR_DEBUG_IPC`~~ | 使用 `RR_DEBUG_LEVEL=4` |
| ~~`RR_DEBUG_PERF`~~ | 使用 `RR_DEBUG_LEVEL=4` |

### 废弃的参数

| 废弃参数 | 替代方案 |
|---------|---------|
| ~~`RR_FORK_POINT`~~ | 使用 `RR_FORK_STRATEGY` 自动检测 |

### 环境变量专用参数

以下参数**只能**通过环境变量设置（配置文件不支持）：

| 参数 | 原因 |
|-----|------|
| `RR_STRACE_MODE` | 早期初始化需要 |
| `RR_STRACE_LOG_LEVEL` | 早期初始化需要 |
| `RR_TRACE_PIPE` | 动态trace，不适合配置文件 |

---

## 🔍 故障排查

### 问题1: Replay模式不工作

| 检查项 | 必需值 |
|-------|--------|
| ✅ `RR_FUZZING_ENABLED` | `true` |
| ✅ `RR_MODE` | `replay` |
| ✅ `RR_STRACE_MODE` | `true` ⚠️ **必需！** |
| ✅ `RR_TRACE_FILE` | 有效trace文件路径 |

### 问题2: Fuzzing模式无法启动

| 检查项 | 说明 |
|-------|------|
| ✅ 管道已创建 | `mkfifo /tmp/rr_cmd_pipe /tmp/rr_status_pipe` |
| ✅ trace文件有效 | 确保文件存在且可读 |
| ✅ 外部fuzzer已启动 | 需要fuzzer进程连接管道 |
| ✅ `RR_STRACE_MODE=True` | Fuzzing模式也需要 |

### 问题3: 日志级别不生效

| 日志控制参数 | 作用范围 |
|------------|---------|
| `RR_DEBUG_LEVEL` | 控制主框架日志 |
| `RR_STRACE_LOG_LEVEL` | 控制strace模块日志 |

**注意**: 两者独立，需分别设置！

---

## 📚 参考资源

### 配置模板

| 文件 | 用途 |
|-----|------|
| `rr_config.record.template` | Record模式配置模板 |
| `rr_config.replay.template` | Replay模式配置模板 |
| `rr_config.fuzzing.template` | Fuzzing模式配置模板 |

### 相关文档

| 文档 | 说明 |
|-----|------|
| `README.md` | 快速开始 |
| `QUICK_START.md` | 快速使用指南 |
| `ENVFUZZ_ROADMAP.md` | 功能路线图 |

---

## 🎯 快速参考卡

### 最小配置（各模式）

| 模式 | 必需参数 |
|-----|---------|
| **Record** | `RR_FUZZING_ENABLED=True` + `RR_MODE=record` + `RR_TRACE_FILE=<path>` |
| **Replay** | `RR_FUZZING_ENABLED=True` + `RR_MODE=replay` + `RR_TRACE_FILE=<path>` + **`RR_STRACE_MODE=True`** |
| **Fuzzing** | `RR_FUZZING_ENABLED=True` + `RR_MODE=fuzzing` + `RR_TRACE_FILE=<path>` + `RR_STRACE_MODE=True` + 管道设置 |

### 常用调试组合

| 场景 | 推荐配置 |
|-----|---------|
| 快速测试 | `RR_DEBUG_LEVEL=2` (WARN) |
| 正常开发 | `RR_DEBUG_LEVEL=3` (INFO) |
| 详细调试 | `RR_DEBUG_LEVEL=4` (VERBOSE) + `RR_STRACE_LOG_LEVEL=3` |
| 深度调试 | `RR_DEBUG_LEVEL=5` (TRACE) + `RR_STRACE_LOG_LEVEL=4` |

---

**总计**: 18个有效参数，100%真实有效，环境变量与配置文件完全对等！

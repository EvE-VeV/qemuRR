# RR-Fuzz: Record-Replay Fuzzing Framework

RR-Fuzz是一个基于QEMU的记录重放模糊测试框架，专为闭源应用程序的漏洞挖掘而设计。

## 架构概述

RR-Fuzz采用模块化设计，核心组件包括：

### 核心模块

- **rr_framework.h** - 核心数据结构和接口定义
- **rr_main.c** - 框架初始化和主要控制逻辑
- **rr_record.c** - 系统调用记录功能
- **rr_replay.c** / **rr_replay_strace_optimized.c** - 系统调用重放功能
- **rr_ipc.c** - 进程间通信（管道和共享内存）
- **rr_fork_server.c** - 高速Fork Server实现
- **rr_fuzz_engine.c** - 变异引擎和Fuzzing逻辑
- **rr_syscall_dispatch.c** - 系统调用分发和参数处理
- **rr_snapshot.c** - 进程状态快照管理

### 工作模式

1. **Record模式** - 记录目标应用的系统调用序列
2. **Replay模式** - 重放已记录的系统调用序列（支持二进制trace和strace格式）
3. **Fuzzing模式** - 在重放基础上进行参数变异和崩溃检测

## 🚀 快速开始

### 1. 快速验证
```bash
# 一键验证核心功能
cd test
./quick_verify.sh
```

### 2. 完整测试
```bash
# 集成测试（Fork Server + 共享内存）
cd test
python3 full_test.py
```

### 3. 端到端测试
```bash
# 完整Fuzzing流程（包括IPC）
cd test
python3 ../fuzz_conductor_example.py \
    --trace test_baseline.strace \
    --target ./test_fuzz_target \
    --iterations 10
```

详细测试指南：[test/TESTING.md](test/TESTING.md)

## 使用方法

### 环境变量配置

#### 必需变量
- `RR_FUZZING_ENABLED=1` - 启用RR-Fuzz框架
- `RR_MODE` - 设置工作模式：`record`/`replay`/`fuzzing`
- `RR_TRACE_FILE` - 指定trace文件路径

#### Strace模式
- `RR_STRACE_MODE=1` - 使用strace格式的trace（推荐）

#### Fork Server配置（新特性）
- `RR_FORK_SYSCALL` - 基于系统调用名称设置fork点（如：`openat`）
- `RR_FORK_PATTERN` - 可选的路径匹配模式（如：`*/input*`）
- `RR_FORK_POINT` - 旧方式：基于索引的fork点（已不推荐）

#### IPC配置（Fuzzing模式）
- `RR_CMD_PIPE` - 命令管道文件描述符或路径
- `RR_STATUS_PIPE` - 状态管道文件描述符或路径
- `RR_SHARED_MEMORY` - 共享内存名称

#### 调试选项
- `RR_STRACE_LOG_LEVEL` - 日志级别：`ERROR`/`WARN`/`INFO`/`VERBOSE`

### 基本使用流程

#### 1. 记录阶段（使用strace）

```bash
# 方式1: 使用系统strace工具
strace -o app.strace ./target_application input_file

# 方式2: 使用RR-Fuzz内置record（二进制格式）
RR_FUZZING_ENABLED=1 RR_MODE=record RR_TRACE_FILE=app.trace \
qemu-x86_64 ./target_application input_file
```

#### 2. 重放阶段

```bash
# Strace模式重放（推荐）
RR_FUZZING_ENABLED=1 RR_MODE=replay \
RR_STRACE_MODE=1 RR_TRACE_FILE=app.strace \
qemu-x86_64 ./target_application input_file

# 二进制模式重放
RR_FUZZING_ENABLED=1 RR_MODE=replay RR_TRACE_FILE=app.trace \
qemu-x86_64 ./target_application input_file
```

#### 3. Fuzzing阶段

```bash
# 🔥 新方式：基于系统调用的Fork点（推荐）
RR_FUZZING_ENABLED=1 RR_MODE=fuzzing \
RR_STRACE_MODE=1 RR_TRACE_FILE=app.strace \
RR_FORK_SYSCALL=openat RR_FORK_PATTERN="*/input*" \
qemu-x86_64 ./target_application input_file

# 旧方式：基于索引的Fork点
RR_FUZZING_ENABLED=1 RR_MODE=fuzzing \
RR_TRACE_FILE=app.trace RR_FORK_POINT=100 \
qemu-x86_64 ./target_application input_file
```

### 使用Python Conductor（完整Fuzzing）

```bash
python3 fuzz_conductor_example.py \
    --target ./target_application \
    --trace app.strace \
    --fork-syscall openat \
    --fork-pattern "*/input*" \
    --iterations 1000
```

Conductor会自动：
- 创建IPC管道和共享内存
- 生成Fuzz变异指令
- 控制Fork Server执行
- 收集崩溃和覆盖率信息

## 核心特性

### 1. 智能Fork点机制

**新方式（基于系统调用）：**
```bash
export RR_FORK_SYSCALL=openat           # 系统调用名称
export RR_FORK_PATTERN="*/input.txt"    # 路径模式（可选）
```

**优势：**
- 语义化配置，易于理解
- 稳定性高，不受trace变化影响
- 支持路径模式匹配

**常用配置：**
- 文件处理：`openat` + `*/input*`
- 网络服务：`accept`
- 配置解析：`openat` + `*.conf`

### 2. 多种变异策略

- **FUZZ_CMD_MUTATE_ARG** - 参数值变异
- **FUZZ_CMD_REPLACE_BUFFER** - 缓冲区内容替换
- **FUZZ_CMD_MUTATE_FLAGS** - 标志位异或变异
- **FUZZ_CMD_BOUNDARY_VALUE** - 边界值测试

### 3. Strace重放优化

- 智能系统调用匹配（精确匹配 → 语义匹配 → 跳过）
- FD映射自动管理
- 地址映射处理
- 敏感系统调用特殊处理（`arch_prctl`, `brk`等）

### 4. 高性能执行

- Fork Server机制实现高速执行（100+ exec/s）
- 共享内存传递Fuzz指令
- 管道IPC低延迟通信
- 快照支持快速状态恢复

### 5. 崩溃检测

- 自动检测段错误（SIGSEGV）
- 捕获中止信号（SIGABRT）
- 超时检测
- 崩溃去重和分类

## 📁 目录结构

```
rr_fuzzing/
├── README.md                       # 项目概述（本文）
├── quickstart.md                   # 快速开始指南
├── FIXES_SUMMARY.md                # 修复和改进总结
├── 开始验证.txt                     # 中文快速指引
├── .gitignore                      # Git忽略规则
│
├── fuzz_conductor_example.py       # Python Fuzzing控制器
│
├── rr_framework.h                  # 核心头文件
├── rr_main.c                       # 主控制逻辑
├── rr_config.c                     # 配置管理
├── rr_record.c                     # 系统调用记录
├── rr_replay.c                     # 二进制trace重放
├── rr_replay_strace_optimized.c    # Strace trace重放（优化版）
├── rr_fork_server.c                # Fork Server实现
├── rr_fuzz_engine.c                # Fuzz变异引擎
├── rr_syscall_dispatch.c           # 系统调用分发器
├── rr_ipc.c                        # IPC通信
├── rr_snapshot.c                   # 快照管理
├── rr_debug.c                      # 调试工具
├── rr_mapping_manager.c            # FD/地址映射
├── rr_syscallparser.c              # Strace解析器
│
├── test/
│   ├── TESTING.md                  # 完整测试指南
│   ├── quick_verify.sh             # 快速验证脚本
│   ├── full_test.py                # 完整集成测试
│   ├── test_fuzz_target.c          # 测试程序源码
│   └── ...
│
├── doc/                            # 详细文档
│   └── ...
│
└── tools/                          # 辅助工具
    └── ...
```

## 🔧 核心文件说明

| 文件 | 用途 |
|------|------|
| `fuzz_conductor_example.py` | Python控制器，管理Fuzzing流程 |
| `rr_fuzz_engine.c` | 变异引擎，应用Fuzz指令 |
| `rr_fork_server.c` | Fork Server，高速执行子进程 |
| `rr_replay_strace_optimized.c` | Strace重放引擎，变异注入点 |
| `rr_syscall_dispatch.c` | 系统调用分发，参数智能处理 |
| `rr_main.c` | 框架主控制，模式切换 |

## 🚨 故障排查

### 问题1: "RR-Fuzz disabled via configuration"
**解决**: 设置 `export RR_FUZZING_ENABLED=1`

### 问题2: "Failed to start fork server"
**解决**: 确保设置了 `RR_FORK_SYSCALL` 或 `RR_FORK_POINT`

### 问题3: 段错误 (Segmentation fault)
**状态**: ✅ 已修复（v2.1）
**说明**: `arch_prctl`/`brk`等敏感系统调用已特殊处理

### 问题4: Double free错误
**状态**: ✅ 已修复（v2.1）
**说明**: Fuzzing模式cleanup已修复

更多故障排查，请查看：[FIXES_SUMMARY.md](FIXES_SUMMARY.md)

## 📖 文档资源

| 文档 | 说明 |
|------|------|
| [README.md](README.md) | 项目概述和完整使用指南（本文）|
| [quickstart.md](quickstart.md) | 5分钟快速开始教程 |
| [test/TESTING.md](test/TESTING.md) | 完整测试指南和验证清单 |
| [FIXES_SUMMARY.md](FIXES_SUMMARY.md) | 关键问题修复总结 |
| [开始验证.txt](开始验证.txt) | 中文快速指引 |

## 🎉 完整示例

```bash
# 步骤1: 编译QEMU（如果还没有）
cd /path/to/qemu
./configure --target-list=x86_64-linux-user
make -j$(nproc)

# 步骤2: 验证RR-Fuzz
cd linux-user/rr_fuzzing/test
./quick_verify.sh

# 步骤3: 记录目标程序trace
strace -o my_program.strace ./my_program input_file

# 步骤4: 验证重放
RR_FUZZING_ENABLED=1 RR_MODE=replay \
RR_STRACE_MODE=1 RR_TRACE_FILE=my_program.strace \
qemu-x86_64 ./my_program input_file

# 步骤5: 开始Fuzzing
python3 fuzz_conductor_example.py \
    --target ./my_program \
    --trace my_program.strace \
    --fork-syscall openat \
    --fork-pattern "*/input*" \
    --iterations 10000
```

**就是这么简单！** 🚀

---

**版本**: 2.1  
**状态**: ✅ 生产就绪  
**最后更新**: 2025-10-11

## 贡献和反馈

- 问题报告：提交Issue
- 功能建议：提交PR
- 技术讨论：查看文档或源码注释

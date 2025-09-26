# RR-Fuzz: Record-Replay Fuzzing Framework

RR-Fuzz是一个基于QEMU的记录重放模糊测试框架，专为闭源应用程序的漏洞挖掘而设计。

## 架构概述

RR-Fuzz采用简化的模块化设计，核心组件包括：

### 核心模块

- **rr_framework.h** - 核心数据结构和接口定义
- **rr_main.c** - 框架初始化和主要控制逻辑
- **rr_record.c** - 系统调用记录功能
- **rr_replay.c** - 系统调用重放功能
- **rr_ipc.c** - 进程间通信（管道和共享内存）
- **rr_fork_server.c** - 高速Fork Server实现
- **rr_fuzz_engine.c** - 变异引擎和Fuzzing逻辑
- **rr_snapshot.c** - 进程状态快照管理

### 工作模式

1. **Record模式** - 记录目标应用的系统调用序列
2. **Replay模式** - 重放已记录的系统调用序列
3. **Fuzzing模式** - 在重放基础上进行参数变异和崩溃检测

## 构建和安装

### 依赖项

- QEMU源码
- GLib 2.0
- GCC编译器

### 构建步骤

1. 将RR-Fuzz集成到QEMU构建系统：

```bash
# 在QEMU根目录配置
./configure --enable-rr-fuzzing

# 构建QEMU
make
```

2. 或者单独构建RR-Fuzz模块：

```bash
cd linux-user/fuzzing
make check-deps
make all
```

## 使用方法

### 环境变量配置

- `RR_FUZZING_ENABLED=1` - 启用RR-Fuzz框架
- `RR_MODE` - 设置工作模式：record/replay/fuzzing
- `RR_TRACE_FILE` - 指定轨迹文件路径
- `RR_FORK_POINT` - 设置Fork Server的分叉点（系统调用索引）
- `RR_CMD_PIPE` - 命令管道文件描述符
- `RR_STATUS_PIPE` - 状态管道文件描述符
- `RR_SHARED_MEMORY` - 共享内存名称

### 基本使用流程

#### 1. 记录阶段

```bash
RR_FUZZING_ENABLED=1 RR_MODE=record RR_TRACE_FILE=app.trace \
qemu-x86_64 ./target_application input_file
```

#### 2. 重放阶段

```bash
RR_FUZZING_ENABLED=1 RR_MODE=replay RR_TRACE_FILE=app.trace \
qemu-x86_64 ./target_application input_file
```

#### 3. 模糊测试阶段

```bash
RR_FUZZING_ENABLED=1 RR_MODE=fuzzing RR_TRACE_FILE=app.trace RR_FORK_POINT=100 \
qemu-x86_64 ./target_application input_file
```

### Python Conductor集成

RR-Fuzz支持Python Conductor进行高级控制：

```python
# 示例：启动Fuzzing会话
import subprocess
import os

# 设置环境变量
env = os.environ.copy()
env.update({
    'RR_FUZZING_ENABLED': '1',
    'RR_MODE': 'fuzzing',
    'RR_TRACE_FILE': 'target.trace',
    'RR_FORK_POINT': '100',
    'RR_CMD_PIPE': '3',  # 命令管道FD
    'RR_STATUS_PIPE': '4'  # 状态管道FD
})

# 启动目标进程
process = subprocess.Popen(['qemu-x86_64', './target'], env=env)
```

## 核心特性

### 1. 智能系统调用记录

- 自动检测和记录关键系统调用参数
- 智能缓冲区内容捕获
- 文件描述符映射管理
- 压缩轨迹格式

### 2. 确定性重放

- 严格的系统调用序列同步
- 文件描述符映射保持一致性
- 内存状态恢复
- 防止重放"脱轨"

### 3. 高效模糊测试

- Fork Server机制实现高速执行
- 智能快照管理
- 参数变异和缓冲区替换
- 崩溃检测和分类

### 4. 进程间通信

- 基于管道的命令传输
- 共享内存大数据交换
- 状态同步机制
- 错误处理和恢复

## 轨迹文件格式

RR-Fuzz使用二进制轨迹文件格式：

```
文件头:
- Magic: 0x52525254 ("RRTR")
- Version: uint32_t
- Record Count: uint32_t

每条记录:
- syscall_record_t结构
- 参数数据（变长）
- 结束标记: -1
```

## 调试和监控

启用调试日志：

```bash
# 编译时启用调试
make CFLAGS="-DRR_DEBUG=1"

# 运行时查看日志
RR_FUZZING_ENABLED=1 RR_MODE=record ./target 2>&1 | grep "\\[RR\\]"
```

## 扩展和定制

### 添加新的系统调用支持

1. 在`rr_record.c`的`capture_syscall_args()`函数中添加处理逻辑
2. 在`rr_replay.c`的`rr_replay_syscall()`函数中添加重放逻辑
3. 更新FD映射逻辑（如果涉及文件描述符）

### 自定义变异策略

在`rr_fuzz_engine.c`中扩展`rr_fuzz_generate_mutations()`函数：

```c
// 添加新的变异类型
case FUZZ_CMD_CUSTOM_MUTATION:
    // 实现自定义变异逻辑
    break;
```

## 测试和验证

使用提供的测试程序验证框架：

```bash
./build_test.sh
```

## 限制和注意事项

1. **多线程支持** - 当前版本主要支持单线程应用
2. **系统调用覆盖** - 并非所有系统调用都有完整的记录重放支持
3. **性能开销** - 记录模式会带来一定的性能开销
4. **内存快照** - 完整的内存快照功能需要进一步实现

## 故障排除

### 常见问题

1. **重放失败** - 检查轨迹文件完整性和FD映射
2. **Fork Server无响应** - 检查IPC通信设置
3. **崩溃检测失败** - 验证信号处理配置

### 日志分析

```bash
# 查看系统调用序列
grep "\\[RR\\] Recorded syscall" log_file

# 查看FD映射
grep "\\[RR\\] FD mapping" log_file

# 查看Fork Server状态
grep "\\[RR\\] Fork Server" log_file
```

## 贡献和支持

RR-Fuzz是一个实验性框架，欢迎贡献代码和反馈。主要开发方向：

- 完善系统调用支持
- 优化性能和稳定性
- 扩展变异策略
- 改进Python Conductor接口

## 许可证

本项目遵循QEMU的GPL许可证条款。
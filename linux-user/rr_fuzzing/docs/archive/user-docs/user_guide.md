# RR-Fuzz 配置和使用指南

## 概述

本文档详细介绍RR-Fuzz的配置方法、使用流程和最佳实践，帮助用户快速上手并有效使用RR-Fuzz进行模糊测试。

## 1. 环境准备

### 1.1 构建要求

**系统要求**:
- Linux操作系统（推荐Ubuntu 20.04+或CentOS 8+）
- GCC 7.0+ 或 Clang 10.0+
- Meson 0.55+ 和 Ninja
- 至少4GB RAM（推荐8GB+）

**构建QEMU with RR-Fuzz**:
```bash
# 1. 配置构建
cd /path/to/qemu
mkdir build && cd build
meson setup .. --buildtype=debug -Drr_fuzzing=enabled

# 2. 编译
ninja

# 3. 验证RR-Fuzz支持
./qemu-x86_64 --help | grep -i rr
```

### 1.2 环境变量设置

**基础环境变量**:
```bash
# RR-Fuzz核心配置
export RR_FUZZING_ENABLED=1                    # 启用RR-Fuzz
export RR_MODE=record                           # 设置运行模式
export RR_TRACE_FILE=/tmp/target_trace.dat     # 轨迹文件路径

# 调试配置
export RR_DEBUG_LEVEL=info                     # 调试级别
export RR_DEBUG_SYSCALL=true                   # 启用系统调用跟踪
export RR_DEBUG_FILE=/tmp/rr_debug.log         # 调试日志文件

# IPC配置
export RR_SHARED_MEMORY=rr_fuzz_shm            # 共享内存名称
export RR_CMD_PIPE=/tmp/rr_cmd_pipe            # 命令管道
export RR_STATUS_PIPE=/tmp/rr_status_pipe      # 状态管道
```

## 2. 配置管理

### 2.1 配置文件格式

**配置文件示例** (`rr_config.conf`):
```ini
# RR-Fuzz 配置文件
# 注释以 # 开头

# === 核心配置 ===
enabled=true
mode=record
trace_file=/tmp/my_trace.dat

# === IPC配置 ===
shared_memory_name=my_rr_shm
shared_memory_size=8K
cmd_pipe_path=/tmp/my_cmd_pipe
status_pipe_path=/tmp/my_status_pipe
ipc_timeout=5000

# === Fork Server配置 ===
fork_point=100

# === 调试配置 ===
debug_level=verbose
debug_syscall=true
debug_fd=true
debug_ipc=false
debug_mem=false
debug_perf=true
debug_file=/tmp/rr_debug.log
```

**使用配置文件**:
```bash
export RR_CONFIG_FILE=/path/to/rr_config.conf
./qemu-x86_64 /path/to/target_program
```

### 2.2 配置参数详解

#### 2.2.1 核心配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | false | 是否启用RR-Fuzz |
| `mode` | string | record | 运行模式: record/replay/fuzzing |
| `trace_file` | string | /tmp/rr_trace.dat | 轨迹文件路径 |

#### 2.2.2 IPC配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `shared_memory_name` | string | rr_fuzzing_shm | 共享内存名称 |
| `shared_memory_size` | size | 4K | 共享内存大小（支持K/M/G） |
| `cmd_pipe_path` | string | /tmp/rr_cmd_pipe | 命令管道路径或FD |
| `status_pipe_path` | string | /tmp/rr_status_pipe | 状态管道路径或FD |
| `ipc_timeout` | int | 1000 | IPC超时时间（毫秒） |

#### 2.2.3 Fork Server配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `fork_point` | int | 0 | Fork点位置（系统调用索引） |

**自动启用**: 当`fork_point > 0`时，Fork Server自动启用

#### 2.2.4 调试配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `debug_level` | string/int | info | 调试级别: off/error/warn/info/verbose/trace |
| `debug_syscall` | boolean | false | 系统调用跟踪 |
| `debug_fd` | boolean | false | 文件描述符跟踪 |
| `debug_mem` | boolean | false | 内存操作跟踪 |
| `debug_ipc` | boolean | false | IPC通信跟踪 |
| `debug_perf` | boolean | false | 性能统计 |
| `debug_file` | string | stderr | 调试输出文件 |

## 3. 使用流程

### 3.1 记录阶段 (Record Phase)

**步骤1: 配置记录模式**
```bash
export RR_FUZZING_ENABLED=1
export RR_MODE=record
export RR_TRACE_FILE=/tmp/target_trace.dat
export RR_DEBUG_LEVEL=info
```

**步骤2: 执行目标程序**
```bash
# 执行目标程序进行记录
./qemu-x86_64 /path/to/target_program [program_args]

# 示例：记录一个简单程序
./qemu-x86_64 /bin/ls -la /tmp
```

**步骤3: 验证轨迹文件**
```bash
ls -la /tmp/target_trace.dat
file /tmp/target_trace.dat

# 检查轨迹文件内容（前16字节应该是RRTR magic）
hexdump -C /tmp/target_trace.dat | head -1
```

**预期输出**:
```
[RR-INFO] Configuration loaded successfully
[RR-INFO] IPC subsystem initialized
[RR-INFO] Starting recording mode, trace_file=/tmp/target_trace.dat
[RR-INFO] Recording started successfully to: /tmp/target_trace.dat
...
[RR-INFO] Recording stopped, 45 syscalls recorded
```

### 3.2 重放阶段 (Replay Phase)

**步骤1: 配置重放模式**
```bash
export RR_FUZZING_ENABLED=1
export RR_MODE=replay
export RR_TRACE_FILE=/tmp/target_trace.dat
export RR_DEBUG_LEVEL=verbose
```

**步骤2: 执行重放**
```bash
# 重放之前记录的执行
./qemu-x86_64 /path/to/target_program [same_program_args]

# 示例：重放ls命令
./qemu-x86_64 /bin/ls -la /tmp
```

**步骤3: 验证重放一致性**
```bash
# 检查调试日志确认重放正确
grep "Replayed syscall" /tmp/rr_debug.log | wc -l
```

**预期输出**:
```
[RR-INFO] Started replay from: /tmp/target_trace.dat (version 1)
[RR-INFO] Trace contains 45 syscall records
[RR-VERBOSE] Replayed syscall 158, ret=0
[RR-VERBOSE] Replayed syscall 9, ret=3
...
[RR-INFO] Replay stopped
```

### 3.3 模糊测试阶段 (Fuzzing Phase)

#### 3.3.1 基本模糊测试

**步骤1: 配置模糊测试模式**
```bash
export RR_FUZZING_ENABLED=1
export RR_MODE=fuzzing
export RR_TRACE_FILE=/tmp/target_trace.dat
export RR_FORK_POINT=20                        # 在第20个系统调用处fork
export RR_DEBUG_LEVEL=info
```

**步骤2: 准备IPC通道**
```bash
# 创建命名管道
mkfifo /tmp/rr_cmd_pipe /tmp/rr_status_pipe

# 或者使用文件描述符
export RR_CMD_PIPE=3
export RR_STATUS_PIPE=4
```

**步骤3: 启动目标程序（Fork Server模式）**
```bash
# 在一个终端启动目标程序
./qemu-x86_64 /path/to/target_program [program_args] 3</tmp/rr_cmd_pipe 4>/tmp/rr_status_pipe
```

**步骤4: 控制模糊测试**
```bash
# 在另一个终端发送控制命令
echo "F" > /tmp/rr_cmd_pipe    # 发送Fork命令
cat /tmp/rr_status_pipe        # 读取状态反馈

echo "S" > /tmp/rr_cmd_pipe    # 保存快照
echo "Q" > /tmp/rr_cmd_pipe    # 退出
```

#### 3.3.2 高级模糊测试（外部控制器）

**Python控制器示例**:
```python
#!/usr/bin/env python3
import os
import time
import struct
import mmap

class RRFuzzController:
    def __init__(self, cmd_pipe, status_pipe, shm_name):
        self.cmd_pipe = cmd_pipe
        self.status_pipe = status_pipe
        self.shm_name = shm_name
        self.shm_fd = None
        self.shm_map = None

    def connect(self):
        """连接到RR-Fuzz实例"""
        # 打开管道
        self.cmd_fd = os.open(self.cmd_pipe, os.O_WRONLY)
        self.status_fd = os.open(self.status_pipe, os.O_RDONLY)

        # 打开共享内存
        self.shm_fd = os.open(f"/dev/shm/{self.shm_name}", os.O_RDWR)
        self.shm_map = mmap.mmap(self.shm_fd, 4096)

        print("Connected to RR-Fuzz instance")

    def send_command(self, cmd):
        """发送命令"""
        os.write(self.cmd_fd, cmd.encode())

    def read_status(self):
        """读取状态"""
        data = os.read(self.status_fd, 4)
        return struct.unpack('i', data)[0]

    def fork_and_test(self):
        """Fork并执行测试"""
        self.send_command('F')
        status = self.read_status()

        if status == 3:
            print("Test case completed normally")
        elif status == -2:
            print("Test case crashed - potential bug found!")
        else:
            print(f"Unexpected status: {status}")

        return status

    def save_snapshot(self):
        """保存快照"""
        self.send_command('S')
        snapshot_id = self.read_status()
        print(f"Snapshot saved: ID={snapshot_id}")
        return snapshot_id

    def load_snapshot(self, snapshot_id):
        """加载快照"""
        # 将快照ID写入共享内存
        self.shm_map.seek(0)
        self.shm_map.write(struct.pack('I', snapshot_id))

        self.send_command('L')
        status = self.read_status()
        return status == 1

    def run_fuzzing_campaign(self, test_cases):
        """运行模糊测试活动"""
        crashes = []

        for i, test_case in enumerate(test_cases):
            print(f"Running test case {i+1}/{len(test_cases)}")

            # 应用变异（这里需要根据实际需求实现）
            # self.apply_mutations(test_case)

            # 执行测试
            status = self.fork_and_test()

            if status == -2:  # 崩溃
                crashes.append({
                    'case_id': i,
                    'test_case': test_case,
                    'status': status
                })

        return crashes

    def cleanup(self):
        """清理资源"""
        if self.shm_map:
            self.shm_map.close()
        if self.shm_fd:
            os.close(self.shm_fd)
        if hasattr(self, 'cmd_fd'):
            os.close(self.cmd_fd)
        if hasattr(self, 'status_fd'):
            os.close(self.status_fd)

# 使用示例
if __name__ == "__main__":
    controller = RRFuzzController(
        cmd_pipe="/tmp/rr_cmd_pipe",
        status_pipe="/tmp/rr_status_pipe",
        shm_name="rr_fuzzing_shm"
    )

    try:
        controller.connect()

        # 保存初始快照
        snapshot_id = controller.save_snapshot()

        # 生成测试用例（示例）
        test_cases = [
            b"test_case_1",
            b"test_case_2",
            b"boundary_test",
            b"random_data_" + os.urandom(100)
        ]

        # 运行模糊测试
        crashes = controller.run_fuzzing_campaign(test_cases)

        print(f"Fuzzing completed. Found {len(crashes)} crashes.")
        for crash in crashes:
            print(f"Crash in case {crash['case_id']}: {crash['test_case'][:50]}")

    finally:
        controller.send_command('Q')  # 退出
        controller.cleanup()
```

## 4. 最佳实践

### 4.1 性能优化建议

#### 4.1.1 轨迹文件优化
```bash
# 使用RAM disk存储轨迹文件
sudo mount -t tmpfs -o size=2G tmpfs /tmp/rr_traces
export RR_TRACE_FILE=/tmp/rr_traces/target_trace.dat

# 定期清理旧轨迹文件
find /tmp/rr_traces -name "*.dat" -mtime +7 -delete
```

#### 4.1.2 Fork点选择策略
```bash
# 1. 找到合适的fork点（通常是程序初始化完成后）
export RR_DEBUG_SYSCALL=true
export RR_MODE=record
./qemu-x86_64 /path/to/target | grep -n "syscall"

# 2. 选择一个稳定的syscall位置作为fork点
# 建议选择main函数开始执行后的位置
export RR_FORK_POINT=50  # 根据实际情况调整
```

#### 4.1.3 内存使用优化
```bash
# 限制共享内存大小
export RR_SHARED_MEMORY_SIZE=1M

# 启用性能统计监控资源使用
export RR_DEBUG_PERF=true
```

### 4.2 调试技巧

#### 4.2.1 分级调试
```bash
# 开发阶段：使用详细调试
export RR_DEBUG_LEVEL=trace
export RR_DEBUG_SYSCALL=true
export RR_DEBUG_FD=true

# 生产阶段：使用基本调试
export RR_DEBUG_LEVEL=warn
export RR_DEBUG_SYSCALL=false
```

#### 4.2.2 日志分析
```bash
# 分析系统调用模式
grep "Recording syscall" /tmp/rr_debug.log | awk '{print $4}' | sort | uniq -c

# 检查FD使用情况
grep "FD mapping" /tmp/rr_debug.log

# 分析重放一致性
grep "Syscall mismatch" /tmp/rr_debug.log
```

### 4.3 故障排查

#### 4.3.1 常见问题

**问题1**: 轨迹文件为空或损坏
```bash
# 检查权限
ls -la /tmp/target_trace.dat

# 检查磁盘空间
df -h /tmp

# 重新生成轨迹
rm /tmp/target_trace.dat
export RR_DEBUG_LEVEL=verbose
./qemu-x86_64 /path/to/target
```

**问题2**: 重放不一致
```bash
# 检查目标程序是否有非确定性行为
export RR_DEBUG_SYSCALL=true
export RR_MODE=replay
./qemu-x86_64 /path/to/target 2>&1 | grep -i "mismatch"

# 使用相同的程序参数和环境
env -i RR_FUZZING_ENABLED=1 RR_MODE=replay ./qemu-x86_64 /path/to/target
```

**问题3**: Fork Server无响应
```bash
# 检查管道状态
ls -la /tmp/rr_*_pipe

# 检查进程状态
ps aux | grep qemu

# 使用文件描述符替代命名管道
export RR_CMD_PIPE=3
export RR_STATUS_PIPE=4
./qemu-x86_64 /path/to/target 3</dev/stdin 4>/dev/stdout
```

#### 4.3.2 性能诊断
```bash
# 启用性能统计
export RR_DEBUG_PERF=true

# 监控系统资源
top -p $(pgrep qemu)

# 分析轨迹文件大小
ls -lh /tmp/target_trace.dat

# 统计系统调用数量
grep "total_syscalls" /tmp/rr_debug.log
```

## 5. 高级用法

### 5.1 批量测试脚本

**批量模糊测试脚本** (`batch_fuzz.sh`):
```bash
#!/bin/bash

TARGET_PROGRAM="$1"
TRACE_DIR="/tmp/rr_traces"
RESULTS_DIR="/tmp/rr_results"

if [ -z "$TARGET_PROGRAM" ]; then
    echo "Usage: $0 <target_program>"
    exit 1
fi

# 创建目录
mkdir -p "$TRACE_DIR" "$RESULTS_DIR"

# 配置环境
export RR_FUZZING_ENABLED=1
export RR_DEBUG_LEVEL=warn
export RR_DEBUG_FILE="$RESULTS_DIR/debug.log"

# 1. 记录阶段
echo "=== Recording Phase ==="
export RR_MODE=record
export RR_TRACE_FILE="$TRACE_DIR/trace.dat"
timeout 60s ./qemu-x86_64 "$TARGET_PROGRAM" || true

if [ ! -f "$RR_TRACE_FILE" ]; then
    echo "ERROR: Failed to generate trace file"
    exit 1
fi

# 2. 验证重放
echo "=== Replay Verification ==="
export RR_MODE=replay
timeout 60s ./qemu-x86_64 "$TARGET_PROGRAM" || true

# 3. 模糊测试
echo "=== Fuzzing Phase ==="
export RR_MODE=fuzzing
export RR_FORK_POINT=10

# 创建控制管道
mkfifo "$TRACE_DIR/cmd_pipe" "$TRACE_DIR/status_pipe" 2>/dev/null || true
export RR_CMD_PIPE="$TRACE_DIR/cmd_pipe"
export RR_STATUS_PIPE="$TRACE_DIR/status_pipe"

# 启动目标程序（后台）
timeout 300s ./qemu-x86_64 "$TARGET_PROGRAM" &
QEMU_PID=$!

# 等待一会让程序启动
sleep 2

# 发送测试命令
for i in {1..100}; do
    echo "F" > "$RR_CMD_PIPE"

    # 读取结果（超时处理）
    timeout 5s cat "$RR_STATUS_PIPE" || echo "timeout"

    # 检查程序是否还在运行
    if ! kill -0 $QEMU_PID 2>/dev/null; then
        echo "Target program exited"
        break
    fi
done

# 清理
echo "Q" > "$RR_CMD_PIPE" 2>/dev/null || true
wait $QEMU_PID 2>/dev/null || true
rm -f "$TRACE_DIR/cmd_pipe" "$TRACE_DIR/status_pipe"

echo "=== Results ==="
echo "Trace file: $RR_TRACE_FILE ($(wc -c < "$RR_TRACE_FILE") bytes)"
echo "Debug log: $RR_DEBUG_FILE ($(wc -l < "$RR_DEBUG_FILE") lines)"
grep -i "crash\|error" "$RR_DEBUG_FILE" || echo "No crashes detected"
```

### 5.2 与AFL集成

**AFL-RR-Fuzz集成示例**:
```bash
#!/bin/bash
# AFL + RR-Fuzz集成脚本

AFL_DIR="/path/to/afl"
TARGET="$1"
INPUT_DIR="$2"
OUTPUT_DIR="$3"

# 1. 使用RR-Fuzz记录正常执行
export RR_FUZZING_ENABLED=1
export RR_MODE=record
export RR_TRACE_FILE="/tmp/afl_trace.dat"

# 记录种子输入的执行轨迹
for seed_file in "$INPUT_DIR"/*; do
    echo "Recording: $seed_file"
    cat "$seed_file" | ./qemu-x86_64 "$TARGET"
done

# 2. 使用AFL进行变异，RR-Fuzz进行执行
export RR_MODE=fuzzing
export RR_FORK_POINT=50

# 启动AFL-RR-Fuzz混合模式
"$AFL_DIR/afl-fuzz" -i "$INPUT_DIR" -o "$OUTPUT_DIR" \
    -Q -- ./qemu-x86_64 "$TARGET" @@
```

这个用户指南涵盖了RR-Fuzz的所有使用方面，从基本配置到高级集成，为用户提供了完整的实践指导。
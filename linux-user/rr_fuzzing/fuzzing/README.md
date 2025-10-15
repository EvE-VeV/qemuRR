# RR-Fuzz Fuzzing工具集

本目录包含RR-Fuzz框架的Fuzzing相关工具和脚本。

## 📂 文件说明

### 核心Fuzzing工具

| 文件 | 说明 | 用途 |
|------|------|------|
| `fuzz_conductor.py` | Fuzzing指挥器 | 通过IPC与QEMU通信，发送Fuzz指令并接收执行结果 |
| `analyze_fuzzing_trace.sh` | Fuzzing Trace分析器 | 分析Fuzzing过程中系统调用跟踪的完整性和覆盖率 |

### 可视化工具

| 文件 | 说明 | 用途 |
|------|------|------|
| `realtime_tree_visualizer.py` | 实时Fuzzing树可视化器 | 从QEMU接收动态跟踪消息，实时构建并可视化执行树 |
| `start_realtime_viz.sh` | 可视化启动脚本 | 快速启动实时Fuzzing树可视化工具 |

### 测试工具

| 文件 | 说明 | 用途 |
|------|------|------|
| `test_dynamic_trace.sh` | 动态跟踪测试 | 测试动态跟踪功能是否正常工作 |

## 🚀 快速开始

### 1. 启动实时可视化

```bash
# 启动可视化服务器
./start_realtime_viz.sh
```

然后在浏览器中打开 http://localhost:8000 查看实时执行树。

### 2. 运行Fuzzing指挥器

```bash
# 创建IPC管道
mkfifo /tmp/rr_cmd_pipe /tmp/rr_status_pipe

# 在一个终端启动QEMU
cd ..
RR_FUZZING_ENABLED=True \
RR_MODE=fuzzing \
RR_TRACE_FILE=./trace-record.txt \
RR_STRACE_MODE=True \
RR_CONFIG_FILE=./config/template/rr_config.fuzzing.template \
/home/webfuzz/Documents/qemu/build/build-x86-arm-user/bin/qemu-x86_64 /usr/bin/ls

# 在另一个终端运行fuzzing指挥器
./fuzz_conductor.py
```

### 3. 分析Fuzzing结果

```bash
# 分析fuzzing trace
./analyze_fuzzing_trace.sh
```

## 📋 工作流程

```
1. Record模式录制trace
   ↓
2. Fuzzing模式启动
   ↓
3. fuzz_conductor.py 发送变异指令
   ↓
4. realtime_tree_visualizer.py 实时可视化执行树
   ↓
5. analyze_fuzzing_trace.sh 分析覆盖率和效果
```

## 🔗 相关文档

- 配置指南: `../doc/10_configuration_guide.md`
- 快速开始: `../QUICK_START.md`
- 功能路线图: `../ENVFUZZ_ROADMAP.md`

---

**注意**: 这些工具需要配合RR-Fuzz框架使用，确保QEMU已正确编译并配置。

# RR-Fuzz 使用指南

## 概述

RR-Fuzz 是一个基于 QEMU 的 Record-Replay-Fuzzing 框架，支持系统调用级别的模糊测试。

## 核心组件

### 1. `fuzz_conductor.py` - Fuzzing 指挥脚本

负责：
- 解析 trace 文件并识别可变异的系统调用
- 与 QEMU 通过 IPC 通信，发送变异指令
- 自动启动实时树可视化器（如果需要）
- 生成多种格式的输出报告

### 2. `realtime_tree_visualizer.py` - 实时树可视化器

负责：
- 从 QEMU 接收动态跟踪消息
- 构建完整的系统调用执行树（包括 fork 分支）
- 生成交互式 D3.js 树形可视化

### 3. `trace_analyzer.py` - Trace 分析器

负责：
- 解析 binary trace 文件
- 分类系统调用（Pure Replay / Hybrid / Input IO）
- 提取 aux_data 信息

## 快速开始

### 1. 录制 Trace

```bash
# 设置环境变量
export RR_RECORD_ENABLED=1
export RR_TRACE_FILE=./my_program.dat
export RR_MODE=record

# 运行程序进行录制
qemu-x86_64 /path/to/my_program [args]
```

### 2. 运行 Fuzzing

```bash
python3 fuzz_conductor.py \
    --qemu ~/qemu/build/qemu-x86_64 \
    --trace ./my_program.dat \
    --target /path/to/my_program \
    --iterations 100 \
    --output-format all
```

**参数说明：**
- `--qemu`: QEMU 二进制文件路径
- `--trace`: 录制的 trace 文件
- `--target`: 目标程序路径
- `--iterations`: Fuzzing 迭代次数
- `--output-format`: 输出格式
  - `html` - 仅生成树形可视化
  - `txt` - 仅生成文本 trace
  - `json` - 仅生成 JSON 摘要
  - `all` - 生成所有格式（默认）
  - `none` - 不生成任何输出文件（仅运行 fuzzing）

### 3. 输出文件

Fuzzing 完成后会生成以下文件：

#### 📊 **fuzzing_summary_YYYYMMDD_HHMMSS.json**
JSON 格式的统计摘要：
```json
{
  "fuzzing_session": {
    "target": "/usr/bin/ls",
    "iterations": 100,
    "duration": 5.23
  },
  "statistics": {
    "crashes_found": 2,
    "avg_iteration_time": 0.052
  },
  "mutable_syscalls": {
    "total": 5,
    "pure_replay_total": 3,
    "hybrid_replay_total": 2
  }
}
```

#### 🌳 **fuzzing_tree_YYYYMMDD_HHMMSS.html**
交互式系统调用执行树可视化：
- **树结构统计**（顶部）：
  - Nodes: 完整执行树的节点数
  - Forks: Fork 分支点数量
  - Mutations: 树中被标记为 fuzzed 的节点
  
- **Fuzzing Session 统计**（右下角浮窗）：
  - Iterations: 总迭代次数
  - Mutations: 总变异次数
  - Crashes: 发现的崩溃数
  - Duration: 总耗时
  - Mutable Syscalls: 可变异的系统调用数

**特性：**
- 🔍 可缩放、拖动
- 🌿 Fork 分支高亮显示
- 🎯 被 Fuzz 的系统调用用红色标记
- 💡 鼠标悬停显示详细信息

#### 📝 **fuzzing_trace_YYYYMMDD_HHMMSS.txt**
可读的文本格式 trace：
```
================================================================================
RR-Fuzz Syscall Trace
================================================================================
Target:     /usr/bin/ls
Trace File: ./ls_test.dat
Total Iterations: 100
================================================================================

📋 ORIGINAL TRACE SUMMARY
--------------------------------------------------------------------------------
Total syscalls: 17
Pure replay candidates: 5
Hybrid replay candidates: 3
Mutable syscalls: 5

📜 SYSCALL SEQUENCE
--------------------------------------------------------------------------------
Index  Syscall              Category      Aux Data   Mutable
--------------------------------------------------------------------------------
0      read                 pure_replay   32B        ✓
1      write                output_io     —          ✗
...
```

## 高级用法

### 控制输出格式

```bash
# 只生成 HTML 树形可视化
python3 fuzz_conductor.py ... --output-format html

# 只生成 JSON 摘要
python3 fuzz_conductor.py ... --output-format json

# 只生成文本 trace
python3 fuzz_conductor.py ... --output-format txt

# 不生成任何输出文件（仅运行 fuzzing，用于性能测试）
python3 fuzz_conductor.py ... --output-format none
```

**使用场景：**
- `none` - 性能测试、快速验证、大规模迭代时不需要输出
- `json` - CI/CD 集成、自动化分析
- `html` - 调试时查看执行树
- `txt` - 快速查看 syscall 序列

### 调试模式

查看详细的 QEMU 输出：
```bash
# 终端会实时显示 QEMU 的调试日志
python3 fuzz_conductor.py ... 2>&1 | tee fuzzing_debug.log
```

### 分析 QEMU 日志

使用日志分析工具提取统计信息：

```bash
python3 log_analyzer.py qemu_debug.log
```

输出包括：
- Pure/Hybrid Replay 统计
- 偏离检测详情
- FD 映射记录
- 热点系统调用

## 故障排除

### 问题1：没有生成 HTML 树形文件

**原因**：可能是 `--output-format` 没有包含 `html` 或 `all`

**解决**：
```bash
python3 fuzz_conductor.py ... --output-format html
```

### 问题2：IPC 通信错误

**原因**：有残留的 QEMU 进程或共享内存文件

**解决**：
```bash
# 清理残留进程
killall -9 qemu-x86_64

# 清理共享内存
rm -f /dev/shm/rr_fuzz_*

# 清理 trace pipe
rm -f /tmp/rr_dynamic_trace*
```

### 问题3：树可视化器无法连接

**原因**：QEMU 没有启用动态跟踪

**解决**：确保 `fuzz_conductor.py` 正确启用了动态跟踪（自动处理，无需手动设置）

## 架构说明

```
┌─────────────────────────────────────────────────────────────┐
│                     fuzz_conductor.py                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ TraceAnalyzer│  │SmartMutator  │  │ realtime_tree_   │  │
│  │              │  │              │  │   visualizer     │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ IPC (Pipes + SHM)
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                         QEMU                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  rr_main.c   │  │ rr_replay.c  │  │ rr_dynamic_      │  │
│  │              │  │              │  │   trace.c        │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ Named Pipe
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              realtime_tree_visualizer.py                    │
│                   (独立后台进程)                             │
│              接收动态跟踪 → 构建树 → 生成 HTML               │
└─────────────────────────────────────────────────────────────┘
```

## 工具文件说明

### `log_analyzer.py` - 日志分析工具

独立的 QEMU 日志分析工具，用于提取执行统计：

```bash
python3 log_analyzer.py qemu_debug.log
```

**功能**：
- Pure/Hybrid Replay 覆盖率统计
- 偏离检测分析
- FD 映射跟踪
- 系统调用热点识别
- IPC 校验失败检测

### `corpus_manager.py` - Corpus 管理器 (Phase 3)

用于管理有价值的 fuzzing 样本（待集成）：

```bash
# 查看 corpus 统计
python3 corpus_manager.py /path/to/corpus_dir
```

**功能**：
- 基于覆盖率的样本保存
- SHA256 去重
- 覆盖率追踪
- Top-N 样本检索

**状态**: ⏳ 已实现但未集成，等待 Phase 2 覆盖率反馈完成后启用

## 文件结构

```
fuzzing/
├── fuzz_conductor.py          # 主控脚本 (796行)
├── trace_analyzer.py           # Trace 解析器 (被 conductor 调用)
├── realtime_tree_visualizer.py # 树可视化器 (被 conductor 自动启动)
├── corpus_manager.py           # Corpus 管理 (Phase 3，待集成)
├── log_analyzer.py             # 日志分析工具 (独立使用)
└── README.md                   # 本文档
```

## 开发者信息

- **当前版本**: Phase 1.5
  - ✅ Aux Data Mutation Engine
  - ✅ Pure Replay Reapply
  - ✅ 智能初始化阶段过滤
  - ✅ 自动树形可视化
  - ✅ 多格式输出 (HTML/JSON/TXT)
  - ✅ 代码清理与优化

- **状态**: ✅ 核心功能完成，已删除冗余代码

- **文档**: 
  - `PHASE1_FUZZING_SUMMARY.md` - Phase 1 功能总结
  - `FUZZING_ANALYSIS.md` - 架构分析与改进方案
  - `MAGIC_NUMBERS_AUDIT.md` - 魔数审计报告
  - `PHASE1_2_3_IMPLEMENTATION.md` - 实施计划

## 下一步计划

### Phase 2: 覆盖率反馈 (优先级: P1)
- [ ] QEMU TCG 集成（hook `gen_tb_start`/`end`）
- [ ] AFL-style edge coverage 实现
- [ ] Conductor 反馈循环（读取覆盖率 bitmap）
- [ ] 集成 `corpus_manager.py`

### Phase 3: Corpus 优化 (优先级: P2)
- [ ] TLSH 相似度检测
- [ ] 自适应 corpus 最小化
- [ ] 优先级队列（基于覆盖率增益）

### 代码质量优化 (优先级: P3)
- [ ] 自适应初始化阶段检测（替换硬编码阈值）
- [ ] IPC 状态码枚举化
- [ ] 扩展系统调用覆盖（目标：100+ syscalls）
- [ ] Emulation fallback 机制

---

## 更新历史

### 2025-10-28 - Phase 1.5 代码清理
- ✅ **删除冗余代码**：
  - 删除 `_build_tree_structure()` 和旧的 `save_html_trace()` 方法
  - 从 1497 行精简到 796 行
  - 删除过时脚本：`start_realtime_viz.sh`, `test_dynamic_trace.sh`, `analyze_fuzzing_trace.sh`

- ✅ **集成树形可视化**：
  - `fuzz_conductor.py` 现自动启动 `realtime_tree_visualizer.py`
  - 生成完整的系统调用执行树（包含 fork 分支）
  - HTML 输出包含双层统计（树结构 + Fuzzing Session）

- ✅ **修复魔数问题**：
  - 创建 `rr_constants.h` 统一管理常量
  - 替换所有硬编码数值
  - 修复共享内存大小不一致 bug (4KB → 64KB)

- ✅ **改进输出格式**：
  - 支持 `--output-format` 参数 (html/txt/json/all)
  - JSON 摘要包含完整统计信息
  - TXT 格式包含详细的 syscall 序列
  - HTML 树形可视化包含 Fuzzing Session 浮窗

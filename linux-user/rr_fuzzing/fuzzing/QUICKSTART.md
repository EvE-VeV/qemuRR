# RR-Fuzz Quick Start Guide

## 快速开始

### 前提条件

1. 已编译的 QEMU (支持 RR-Fuzz)
2. 一个 trace 文件 (通过 QEMU record 模式录制)
3. 目标程序二进制文件

### 基本使用

#### 单进程模式

```bash
# 1. 进入 fuzzing 目录
cd linux-user/rr_fuzzing/fuzzing

# 2. 运行基础模糊测试 (随机变异)
python3 fuzz_main.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/example.trace.bin \
    --target /path/to/target \
    --iterations 100

# 3. 运行智能模糊测试 (基于trace分析)
python3 fuzz_main.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/example.trace.bin \
    --target /path/to/target \
    --smart \
    --iterations 1000
```

#### 多进程模式 (推荐生产环境)

```bash
# 1. 多进程fuzzing (8个worker)
python3 fuzz_multiprocess.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/example.trace.bin \
    --target /path/to/target \
    -n 8

# 2. 智能变异 + 多进程 (4个worker)
python3 fuzz_multiprocess.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/example.trace.bin \
    --target /path/to/target \
    -n 4 \
    --smart

# 3. 时间限制 (1小时, 16个worker)
python3 fuzz_multiprocess.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/example.trace.bin \
    --target /path/to/target \
    -n 16 \
    --timeout 3600 \
    --smart
```

## 架构特性

### ✅ 已实现的功能

1. **Layer 1: Trace Storage**
   - TraceManager 管理 trace 池
   - AFL风格的能量驱动选择 (80% exploit, 20% explore)
   - 自动维护高能量 trace 子集

2. **Layer 2: Core Fuzzing**
   - FuzzingCore 主循环协调器
   - QEMUExecutor QEMU进程执行引擎
   - BaseMutator 随机变异器
   - SmartMutator 智能变异器 (基于trace分析)
   - CoverageTracker 覆盖率追踪
   - CrashDetector 崩溃检测和去重

3. **Layer 4: Multi-Process** ⭐ 新增
   - FuzzMaster 多进程协调器
   - Worker进程管理 (启动、监控、重启)
   - Sync directory 同步机制
   - Coverage/Corpus/Crash 共享
   - 聚合统计和监控

4. **完整的Fuzzing流程** (按照 DETAILED_ARCHITECTURE.md)
   - Step 1: Trace选择
   - Step 2: 变异生成
   - Step 3: QEMU执行
   - Step 4: 覆盖率分析
   - Step 5: Trace保存
   - Step 6: 崩溃检测
   - Step 7: 统计更新

## 命令行参数

### 单进程模式 (fuzz_main.py)

**必需参数**:
- `--qemu`: QEMU可执行文件路径
- `--trace`: 初始trace文件路径
- `--target`: 目标程序路径

**可选参数**:
- `--output`: 输出目录 (默认: fuzzing_output)
- `--iterations`: 最大迭代次数
- `--timeout`: 最大运行时间(秒)
- `--qemu-timeout`: QEMU执行超时(秒, 默认: 30)
- `--smart`: 使用智能变异模式
- `--random`: 使用随机变异模式 (默认)
- `--recipe`: Recipe文件路径 (需配合 --smart)

### 多进程模式 (fuzz_multiprocess.py)

**必需参数**:
- `--qemu`: QEMU可执行文件路径
- `--trace`: 初始trace文件路径
- `--target`: 目标程序路径

**可选参数**:
- `-n, --workers`: Worker进程数量 (默认: CPU核心数)
- `--sync-dir`: 同步目录 (默认: sync_dir)
- `--timeout`: 最大运行时间(秒)
- `--display-interval`: 显示间隔(秒, 默认: 5)
- `--smart`: 使用智能变异模式
- `--random`: 使用随机变异模式 (默认)
- `--recipe`: Recipe文件路径 (需配合 --smart)

## 输出说明

```
fuzzing_output/
├── corpus/                    # 新覆盖的traces
│   ├── trace_000000.bin      # Trace文件
│   ├── trace_000000.meta     # 元数据(覆盖率、变异信息等)
│   └── ...
├── crashes/                   # 崩溃信息
│   ├── crash_000000_<hash>.bin
│   ├── crash_000000_<hash>.meta
│   └── ...
└── final_stats.json           # 最终统计数据
```

## 实时监控

Fuzzing过程中会每100次迭代输出一次统计:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Iteration: 100
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Exec speed:  15.2 exec/s
Trace pool:  5 traces
Coverage:    1234 edges
Paths found: 3
Crashes:     0 (0 unique)
Last path:   5.3s ago
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 使用示例

### 示例 1: 短时测试

```bash
# 快速测试100次迭代
python3 fuzz_main.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/test.trace.bin \
    --target /bin/cat \
    --iterations 100 \
    --output test_output
```

### 示例 2: 长时间Fuzzing

```bash
# 运行1小时
python3 fuzz_main.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/nginx.trace.bin \
    --target /usr/sbin/nginx \
    --smart \
    --timeout 3600 \
    --output nginx_fuzzing
```

### 示例 3: Recipe驱动

```bash
# 使用PathFinder生成的recipes
python3 fuzz_main.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/complex.trace.bin \
    --target /path/to/complex_app \
    --smart \
    --recipe recipes.json \
    --iterations 5000
```

## 与旧版本对比

### 旧版 (fuzz_conductor.py)
```bash
python3 fuzz_conductor.py \
    --qemu ./qemu \
    --trace trace.bin \
    --target ./program \
    --iterations 100
```

### 新版 (fuzz_main.py) - 等价配置
```bash
python3 fuzz_main.py \
    --qemu ./qemu \
    --trace trace.bin \
    --target ./program \
    --smart \
    --iterations 100
```

**主要改进**:
- ✅ 模块化架构 (5层)
- ✅ AFL风格的trace选择
- ✅ 增强的覆盖率追踪
- ✅ 崩溃去重
- ✅ 更好的统计信息
- ✅ 更清晰的代码结构

## 常见问题

### Q: 如何知道fuzzing是否有效?
A: 观察以下指标:
- Coverage edges 持续增长
- Paths found > 0
- Exec speed 保持稳定

### Q: 什么时候使用 --smart 模式?
A: 
- 有完整trace文件时使用 --smart
- 目标程序复杂时使用 --smart
- 需要更精准的变异时使用 --smart
- 快速原型测试可以使用 --random

### Q: 如何生成recipes?
A: 使用PathFinder工具(Phase 3, Layer 3):
```bash
python3 tools/pathfinder.py \
    --binary ./target \
    --trace trace.bin \
    --output recipes.json
```

### Q: Trace pool不增长怎么办?
A: 可能原因:
1. 初始trace覆盖率已经很高
2. 变异策略需要调整
3. 目标程序的输入空间有限

尝试:
- 使用不同的初始trace
- 启用 --smart 模式
- 增加迭代次数

## 性能优化建议

1. **使用多核**: 使用 multiprocess/fuzz_master.py (未来功能)
2. **调整超时**: `--qemu-timeout` 根据目标程序调整
3. **智能变异**: 使用 `--smart` 模式提高效率
4. **Recipe驱动**: 使用 `--recipe` 进行定向fuzzing

## 调试技巧

### 检查trace文件是否有效
```bash
python3 trace_analyzer.py seeds/test.trace.bin
```

### 查看详细日志
```bash
# 运行时会输出详细的组件日志
python3 fuzz_main.py ... 2>&1 | tee fuzzing.log
```

### 分析崩溃
```bash
# 查看崩溃元数据
cat fuzzing_output/crashes/crash_000000_*.meta

# 重放崩溃trace
../qemu-x86_64 -rr-mode replay \
    -rr-trace-file fuzzing_output/crashes/crash_000000_*.bin \
    /path/to/target
```

## 下一步

1. 阅读 `ARCHITECTURE_README.md` 了解详细架构
2. 查看 `DETAILED_ARCHITECTURE.md` 了解完整设计
3. 探索 `conductor/` 目录下的核心组件实现
4. 尝试扩展 `BaseMutator` 实现自定义变异策略

## 反馈和支持

遇到问题请查看:
- `ARCHITECTURE_README.md`: 架构说明
- `DETAILED_ARCHITECTURE.md`: 详细设计文档
- 代码注释: 每个组件都有详细的文档字符串


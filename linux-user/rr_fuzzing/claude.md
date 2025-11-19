# RR-Fuzz Project Context
# 项目上下文文档 (For AI Assistant)

**Version**: 3.1 (2025-11-17)
**Purpose**: AI助手快速理解RR-Fuzz项目的核心上下文
**Latest Update**: Enabled Aux Data Mutations + Syscall Tree Export

---

## 一、项目定位

**RR-Fuzz** = Record-Replay Fuzzer

- **核心理念**: 确定性重放 + 覆盖率引导 + Syscall变异
- **技术栈**: C (QEMU修改) + Python (Fuzzing引擎)
- **目标**: 通过变异syscall行为而非输入来发现bugs

**关键优势** vs AFL:
- ✅ 完全确定性（无竞态条件）
- ✅ 变异syscall行为（不只是输入）
- ✅ Syscall级别的精确控制
- ❌ 吞吐量较低（6 vs 200+ execs/sec）

**当前性能**:
```
吞吐量: 6 execs/sec (BaseMutator)
覆盖率: 2840 edges (测试程序完整覆盖)
延迟:   167ms/iteration (QEMU启动占72%)
```

---

## 二、5层架构

```
Layer 5: 监控与分析
  └─ SyscallTreeVisualizer, CrashAnalyzer, CorpusManager

Layer 4: 多进程 & 高级策略  ⭐ 部分已启用
  └─ DynamicForkController (✅ DFS), PathFinder (✅ CFG),
     FuzzMaster (⚠️ 需集成), EnergyScheduler (⚠️ 需重构)

Layer 3: QEMU集成
  └─ QEMUExecutor, Coverage (C侧), AuxDataMutations (✅ 已启用 2025-11-17)

Layer 2: Fuzzing引擎
  └─ FuzzingCore, BaseMutator, SmartMutator, AFLEnhancedMutator (✅ 可用 --afl-enhanced)

Layer 1: RR核心 (C)
  └─ rr_main.c, rr_replay.c, rr_record.c, rr_syscall_tree.c (✅ 导出至 /tmp/syscall_tree.json)
```

**关键组件位置**:
- **C侧核心**: `core/rr_main.c` (框架), `replay/rr_replay.c` (重放+变异)
- **Python核心**: `fuzzing/conductor/fuzzing_core.py` (主循环)
- **Mutator**: `fuzzing/conductor/mutator.py` (BaseMutator + SmartMutator)
- **PathFinder**: `fuzzing/multiprocess/path_finder.py` (CFG分析)
- **DFS探索**: `fuzzing/multiprocess/dynamic_fork_controller.py` (深度优先)

---

## 三、核心数据流

### Record → Replay → Fuzzing

```
1. Record:
   用户程序执行 → syscall → rr_record_syscall()
   → 保存: [syscall_nr, args, retval, aux_data]

2. Replay:
   rr_replay_syscall() → 读取trace → 跳过真实syscall
   → 填充recorded数据 → 程序收到recorded结果

3. Fuzzing:
   Python生成mutations → 写入共享内存 (/tmp/fuzz_instructions_<pid>)
   → rr_apply_mutations() → 修改retval/args/aux_data
   → 程序收到变异后的数据 → 探索新路径
```

### IPC机制 (C ↔ Python)

| 通道 | 方向 | 内容 | 文件路径 |
|------|------|------|---------|
| **Mutations** | Python→C | FuzzInstruction数组 | `/tmp/fuzz_instructions_<pid>` |
| **Coverage** | C→Python | 64KB bitmap | `/tmp/coverage_bitmap_<pid>` |
| **Syscall Tree** | C→Python | JSON (未导出) | `<trace>.tree.json` |
| **环境变量** | Python→C | RR_MODE, RR_TRACE_FILE | - |

---

## 四、🔥 9个重大发现 (已实现但未启用)

### 总潜力评估
如果全部启用: **覆盖率+400%**, **吞吐量+500%**, **Bug发现+600%**

### 发现清单

| # | 功能 | 位置 | 代码量 | 状态 | 潜在提升 |
|---|------|------|-------|------|---------|
| 1 | **Aux Data Mutation Engine** | `fuzzing/qemu_integration/rr_fuzz_aux_mutations.c` | 460行C | ✅**已启用** (2025-11-17) | 覆盖+50%, Bug+80% |
| 2 | **Autonomous Nested Fork** | `utils/rr_nested_fork.c` | 159行C | ⚠️不可控 | 并行+100% |
| 3 | **Syscall Tree JSON Export** | `utils/rr_syscall_tree.c` | 500行C | ✅**已启用** (2025-11-17) | PathFinder精度+80% |
| 4 | **AFLEnhancedMutator** | `fuzzing/conductor/afl_enhanced_mutator.py` | 300行Py | ✅**可用** (--afl-enhanced) | 多样性+100% |
| 5 | **DualLevelPathFinder** | `fuzzing/multiprocess/dual_level_path_finder.py` | 400行Py | ⚠️部分启用 | 精度+40% |
| 6 | **深度优先探索(DFS)** | `fuzzing/multiprocess/dynamic_fork_controller.py` | 300行Py | ✅已启用 | 深层bug+100% |
| 7 | **能量调度系统** | `fuzzing/multiprocess/energy_scheduler.py` | 400行Py | ⚠️需重构 | Seed质量+40% |
| 8 | **高级种子队列** | `fuzzing/multiprocess/seed_queue_advanced.py` | 350行Py | ⚠️需重构 | 覆盖+25% |
| 9 | **FuzzMaster多进程** | `fuzzing/multiprocess/fuzz_master.py` | 500行Py | ⚠️需集成 | 吞吐+200% |

**总计**: 3369行已实现但未充分利用的代码

### 关键发现详解

#### #1: Aux Data Mutation Engine ⭐⭐⭐⭐⭐
- **8种漏洞攻击模式**: 格式化字符串、缓冲区溢出、路径遍历、命令注入等
- **状态**: ✅ **已启用** (2025-11-17)
- **修改**: 在`mutator.py`的`mutation_types`列表添加4个命令:
  - `FUZZ_CMD_MUTATE_AUX_BUFFER`: 核心aux data变异
  - `FUZZ_CMD_TRUNCATE`: 截断攻击
  - `FUZZ_CMD_EXTEND`: 缓冲区溢出
  - `FUZZ_CMD_LIGHT_MUTATION`: 轻量位翻转

#### #3: Syscall Tree Export ⭐⭐⭐⭐⭐
- **状态**: ✅ **已启用** (2025-11-17)
- **导出位置**: `/tmp/syscall_tree.json` (程序退出时自动导出)
- **修改**: 在`rr_main.c:rr_framework_cleanup()`已有导出调用
- **下一步**: PathFinder需要加载JSON文件实现精确BB→Syscall映射

#### #6: 深度优先探索 ⭐⭐⭐⭐⭐
- **已启用**: DynamicForkController默认使用DFS
- **工作原理**: 递归探索IO syscalls，depth=3, 每层fork 3个变体
- **探索树**: Level 0(1) → Level 1(3) → Level 2(9) → Level 3(27) = 40 execs/session

#### #7: 能量调度系统 ⭐⭐⭐⭐⭐
- **5因子**: Coverage新鲜度(40%), 路径深度(20%), 执行速度(15%), 输入熵(15%), Crash潜力(10%)
- **探索-利用平衡**: 动态调整策略
- **问题**: `AdvancedSeedQueue`未被`fuzzing_core.py`导入

#### #9: FuzzMaster多进程 ⭐⭐⭐⭐⭐
- **架构**: Master进程协调N个Workers
- **同步**: Coverage bitmap, Corpus, Crashes
- **问题**: `fuzz_main.py`直接用FuzzingCore，未用FuzzMaster

---

## 五、关键文件索引

### 必读核心文件 (Top 10)

1. **`core/rr_main.c`** - C侧框架初始化和syscall hooks
2. **`replay/rr_replay.c`** - Replay逻辑和mutation应用
3. **`fuzzing/conductor/fuzzing_core.py`** - 主fuzzing循环
4. **`fuzzing/conductor/mutator.py`** - BaseMutator + SmartMutator
5. **`fuzzing/multiprocess/dynamic_fork_controller.py`** - DFS探索
6. **`fuzzing/multiprocess/path_finder.py`** - CFG分析
7. **`fuzzing/qemu_integration/rr_fuzz_aux_mutations.c`** - Aux变异引擎 (未启用)
8. **`utils/rr_syscall_tree.c`** - Syscall Tree构建 (未导出)
9. **`fuzzing/multiprocess/energy_scheduler.py`** - 能量调度 (未启用)
10. **`fuzzing/multiprocess/fuzz_master.py`** - 多进程协调 (未启用)

### 完整目录结构

```
qemu/linux-user/rr_fuzzing/
├── core/                    # Layer 1: RR核心 (C)
│   ├── rr_main.c           # ⭐ 主框架
│   ├── rr_framework.h
│   └── rr_constants.h
├── replay/
│   └── rr_replay.c         # ⭐ Replay + Mutation
├── fuzzing/
│   ├── fuzz_main.py        # ⭐⭐⭐ 入口
│   ├── conductor/          # Layer 2: 引擎
│   │   ├── fuzzing_core.py # ⭐⭐⭐ 主循环
│   │   ├── mutator.py      # ⭐⭐ Mutators
│   │   └── qemu_executor.py
│   ├── multiprocess/       # Layer 4: 高级策略
│   │   ├── dynamic_fork_controller.py  # ⭐ DFS
│   │   ├── path_finder.py  # ⭐⭐ CFG
│   │   ├── energy_scheduler.py  # ❌ 未启用
│   │   ├── seed_queue_advanced.py  # ❌ 未启用
│   │   └── fuzz_master.py  # ❌ 未启用
│   └── qemu_integration/   # Layer 3: QEMU
│       └── rr_fuzz_aux_mutations.c  # ❌ 未启用
├── utils/
│   ├── rr_syscall_tree.c   # ⭐⭐ Tree (未导出)
│   └── rr_nested_fork.c    # ⚠️ 不可控
└── analysis_reports/       # 分析文档
    ├── 09_EXPLORATION_STRATEGIES_ANALYSIS.md  # ⭐ 探索策略
    └── ARCHITECTURE_INTEGRATION_GUIDE.md  # ⭐⭐ 集成指南
```

---

## 六、快速启用指南

### 优先级路线图

```
Week 1: 低风险, 高收益
  ├─ AFLEnhancedMutator (1h) → 多样性+100%
  ├─ Syscall Tree Export (2h) → PathFinder精度+80%
  └─ 能量调度系统 (3h) → Seed质量+40%

Week 2-3: 中风险, 极高收益
  ├─ Aux Data Mutations (3h) → Bug发现+80%
  ├─ DualLevelPathFinder (1h) → 精度+40%
  └─ FuzzMaster多进程 (4h) → 吞吐+200%

Week 4: 高风险, 极高收益
  └─ Nested Fork Control (4h) → 并行+100%
```

### 关键修改位置

#### 1. 启用Aux Data Mutations
**文件**: `fuzzing/conductor/mutator.py:92-100`
```python
# 添加到mutation_types列表
FUZZ_CMD_MUTATE_AUX_BUFFER,  # ⭐ 新增
FUZZ_CMD_EXTEND,             # 溢出攻击
FUZZ_CMD_INTERESTING_VALUES  # 8种漏洞模式
```

#### 2. 导出Syscall Tree
**文件**: `core/rr_main.c:890-920` (rr_framework_finalize)
```c
if (rr_tree_get_node_count() > 0) {
    char json_path[512];
    snprintf(json_path, sizeof(json_path), "%s.tree.json", trace_file);
    rr_tree_export_json(json_path);  // ⭐ 添加此行
}
```

#### 3. 启用能量调度
**文件**: `fuzzing/conductor/fuzzing_core.py:240-250`
```python
from multiprocess.seed_queue_advanced import AdvancedSeedQueue

# 替换TraceManager
self.seed_queue = AdvancedSeedQueue(use_advanced_scheduling=True)
```

#### 4. 启用FuzzMaster
**文件**: `fuzzing/fuzz_main.py:255-285`
```python
if args.workers > 1:
    fuzz_master = FuzzMaster(qemu_path, target_binary, num_workers=args.workers)
    fuzz_master.start()
else:
    fuzzing_core = FuzzingCore(...)  # 单进程模式
```

---

## 七、性能瓶颈与优化

### 当前瓶颈

| 组件 | 时间 | 占比 | 优化方案 | 预期提升 |
|------|------|------|---------|---------|
| QEMU启动 | 120ms | 72% | Fork Server | +25% |
| Python开销 | 30ms | 18% | C扩展 | +10% |
| Coverage计算 | 7ms | 4% | NumPy | +5% |
| Mutation生成 | 10ms | 6% | 预计算 | +3% |

### 优化路线图

```
Phase 1 (1-2周): 快速优化
  Fork Server + Trace缓存 + NumPy
  → 6 execs/sec → 11 execs/sec (+83%)

Phase 2 (1-2月): 深度优化
  Persistent Mode + Syscall Tree + CFG缓存
  → 11 execs/sec → 14 execs/sec (+27%)

Phase 3 (3-6月): 架构优化
  C扩展模块 + 自适应Mutation + 全功能启用
  → 14 execs/sec → 36+ execs/sec (+157%)

总提升: 6 → 36 execs/sec (6x)
```

---

## 八、技术债与改进空间

### P0 (立即修复)
- ❌ **Syscall Tree未导出** → PathFinder精度问题根源
- ❌ **Coverage竞态条件** → 多进程同时写bitmap
- ❌ **PathFinder syscall_index估算不准** → `(source_addr >> 4) % 20`完全不准确

### P1 (本周)
- ❌ **Aux Data Mutations未启用** → 损失8种漏洞模式
- ❌ **能量调度未集成** → Seed选择低效
- ⚠️ **Trace文件泄漏** → finalize未必被调用

### P2 (下周)
- ❌ **Fork Server未集成** → 损失25%性能
- ❌ **FuzzMaster未使用** → 损失200%吞吐量
- ⚠️ **Persistent Mode未完成** → 损失15%性能

---

## 九、常用命令速查

### 基础Fuzzing
```bash
# BaseMutator (快速)
python3 fuzzing/fuzz_main.py \
  --qemu ./build/qemu-x86_64 \
  --target ./tests/programs/vuln/buffer_overflow \
  --trace seed.trace \
  --iterations 100

# SmartMutator (CFG引导)
python3 fuzzing/fuzz_main.py --smart \
  --qemu ./build/qemu-x86_64 \
  --target ./buffer_overflow \
  --trace seed.trace \
  --iterations 100

# AFL-Enhanced (未来: 默认推荐)
python3 fuzzing/fuzz_main.py --afl-enhanced \
  --qemu ./build/qemu-x86_64 \
  --target ./buffer_overflow \
  --trace seed.trace
```

### 多进程Fuzzing (未来)
```bash
python3 fuzzing/fuzz_main.py \
  --workers 4 \
  --sync-dir ./sync \
  --qemu ./build/qemu-x86_64 \
  --target ./buffer_overflow \
  --trace seed.trace
```

---

## 十、详细文档索引

完整分析请参考:
- **`analysis_reports/09_EXPLORATION_STRATEGIES_ANALYSIS.md`** - 探索策略系统详解
- **`ARCHITECTURE_INTEGRATION_GUIDE.md`** - 9个功能的集成指南 (含代码示例)
- **`analysis_reports/00_EXECUTIVE_SUMMARY.md`** - 项目总结
- **`analysis_reports/06_PERFORMANCE_ANALYSIS.md`** - 性能分析
- **`analysis_reports/07_CODE_QUALITY_GAPS.md`** - 代码质量分析

---

**文档版本**: 3.0 (精简版)
**最后更新**: 2025-11-16
**总字数**: ~1500 (之前: ~15000)
**目的**: AI助手快速上下文理解，而非详细教程

**使用提示**:
- 本文档是**快速参考**，详细信息请查阅`analysis_reports/`目录
- 代码修改前请先阅读`ARCHITECTURE_INTEGRATION_GUIDE.md`
- 新功能启用优先级: AFLEnhanced → SyscallTree → AuxData → Energy → FuzzMaster

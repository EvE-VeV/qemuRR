# RR-Fuzz 2.0 测试套件

本目录包含RR-Fuzz 2.0的完整测试程序和脚本。

## 📁 目录结构

```
tests/
├── README.md                      # 本文档
├── scripts/                       # 测试脚本
│   ├── integration/               # 集成测试（端到端）
│   │   ├── system_validation.sh   # 系统全面验证
│   │   ├── test_integrated.sh     # PathFinder + Conductor 集成
│   │   └── run_complete_fuzz.sh   # 完整 fuzzing 流程演示
│   ├── functional/                # 功能测试
│   │   ├── test_vuln_v2.sh        # vuln v2.0 测试
│   │   ├── test_multiprocess_mode.sh      # 多进程模式测试
│   │   ├── test_multiprocess_vuln.sh      # 多进程漏洞测试
│   │   ├── test_pathfinder.sh     # PathFinder 独立测试
│   │   └── test_complex_suite.sh  # 复杂程序测试套件
│   └── unit/                      # 单元/模块测试
│       ├── test_bb_analysis.py    # BB Trace 解析器测试
│       ├── test_coverage_full.py  # Coverage 追踪测试
│       └── test_init_phase_detector.py  # Init Phase 检测器测试
├── programs/                      # 测试程序源代码
│   ├── vuln/                      # 漏洞测试程序
│   │   ├── vuln_stdin.c           # vuln v2.0 源代码
│   │   ├── VULN_V2_README.md      # vuln v2.0 详细文档
│   │   └── VULN_QUICK_REF.md      # 快速参考
│   ├── complex/                   # 复杂测试程序
│   │   ├── complex_test_1_multilevel_branches.c  # 多层分支
│   │   ├── complex_test_2_state_machine.c        # 状态机
│   │   └── complex_test_3_vuln_sim.c             # 漏洞模拟
│   └── simple/                    # 简单测试程序
│       ├── fuzz_target_simple.c   # 简单 fuzzing 目标
│       └── test_bb_trace.c        # BB 追踪测试
└── bin/                           # 编译后的二进制（临时，被 git 忽略）
```

## 🧪 测试分类

### 🥇 集成测试（Integration Tests）

**目的**: 验证端到端功能和系统整体协作

| 测试脚本 | 功能描述 | 优先级 |
|---------|---------|--------|
| `scripts/integration/system_validation.sh` | 系统全面验证（重组后） | ⭐⭐⭐ 必跑 |
| `scripts/integration/test_integrated.sh` | PathFinder + Conductor 集成 | ⭐⭐ 重要 |
| `scripts/integration/run_complete_fuzz.sh` | 完整 fuzzing 流程演示 | ⭐⭐ 重要 |

### 🥈 功能测试（Functional Tests）

**目的**: 验证特定功能模块

| 测试脚本 | 功能描述 | 优先级 |
|---------|---------|--------|
| `scripts/functional/test_vuln_v2.sh` | vuln v2.0 漏洞发现测试 | ⭐⭐⭐ 必跑 |
| `scripts/functional/test_multiprocess_mode.sh` | 多进程模式基础测试 | ⭐⭐ 重要 |
| `scripts/functional/test_multiprocess_vuln.sh` | 多进程漏洞测试 | ⭐⭐ 重要 |
| `scripts/functional/test_pathfinder.sh` | PathFinder 静态分析 | ⭐ 常规 |
| `scripts/functional/test_complex_suite.sh` | 复杂程序分析 | ⭐ 常规 |

### 🥉 单元测试（Unit Tests）

**目的**: 验证单个模块/组件

| 测试脚本 | 功能描述 | 优先级 |
|---------|---------|--------|
| `scripts/unit/test_bb_analysis.py` | BB Trace 解析器验证 | ⭐ 模块修改时 |
| `scripts/unit/test_coverage_full.py` | Coverage 追踪测试 | ⭐ 模块修改时 |
| `scripts/unit/test_init_phase_detector.py` | Init Phase 检测器测试 | ⭐ 模块修改时 |

## 🔧 测试程序

### 漏洞测试程序（Vulnerability Test Programs）

| 程序 | 描述 | 文档 |
|------|------|------|
| `programs/vuln/vuln_stdin.c` | 包含5种漏洞类型的测试程序 | `VULN_V2_README.md` |

**特点**:
- 使用 `read()` 系统调用（RR-Fuzz 可变异）
- 5 种漏洞类型：缓冲区溢出、整数溢出、Off-by-one、栈溢出等
- 详细文档: `programs/vuln/VULN_V2_README.md`

### 复杂测试程序（Complex Test Programs）

| 程序 | 描述 | 测试目标 |
|------|------|---------|
| `programs/complex/complex_test_1_multilevel_branches.c` | 多层嵌套分支 | PathFinder 分支分析能力 |
| `programs/complex/complex_test_2_state_machine.c` | 状态机逻辑 | 有状态程序 fuzzing |
| `programs/complex/complex_test_3_vuln_sim.c` | 漏洞模拟 | 边界条件检测 |

### 简单测试程序（Simple Test Programs）

| 程序 | 描述 | 用途 |
|------|------|------|
| `programs/simple/fuzz_target_simple.c` | 简单 fuzzing 目标 | 端到端流程验证 |
| `programs/simple/test_bb_trace.c` | BB 追踪测试 | 基本块追踪功能验证 |

## 🚀 快速开始

### 1. 完整Fuzzing演示（推荐首次运行）

```bash
cd /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests
./scripts/integration/run_complete_fuzz.sh
```

**测试流程**：
1. 编译`fuzz_target_simple.c`
2. 录制初始种子trace
3. PathFinder分析并生成mutation recipes
4. Conductor执行fuzzing（尝试触发"BUG"）
5. 验证结果

**预期结果**：
- ✅ 成功触发`FUZZ_MAGIC_PWN!`字符串
- ✅ 程序返回码42（BUG触发）
- ✅ 日志显示`🐛 BUG TRIGGERED!`

### 2. 集成测试（PathFinder + Conductor）

```bash
./scripts/integration/test_integrated.sh
```

测试完整的Record → Analyze → PathFinder → Recipe → Fuzz流程。

### 3. vuln v2.0 测试（推荐）

```bash
./scripts/functional/test_vuln_v2.sh
```

测试 RR-Fuzz 的漏洞发现能力（5 种漏洞类型）。

### 4. 复杂程序测试

```bash
./scripts/functional/test_complex_suite.sh
```

测试PathFinder在复杂程序上的表现：
- 多层嵌套分支
- 状态机逻辑
- 漏洞模拟
- PIE二进制支持

## 📊 测试结果位置

所有测试结果默认保存在：
- `/tmp/fuzz_demo/` - 完整fuzzing演示
- `/tmp/integrated_test/` - 集成测试
- `/tmp/complex_test_suite/` - 复杂程序测试

## 🔍 各测试脚本详细说明

### `run_complete_fuzz.sh` - 完整Fuzzing演示

**最重要的测试脚本**，展示RR-Fuzz 2.0的核心能力。

**测试阶段**：
1. **编译目标** - 构建`fuzz_target_simple.c`（非PIE）
2. **录制种子** - 录制3个初始trace（不同输入长度）
3. **PathFinder分析** - 分析CFG，识别未覆盖分支，生成recipes
4. **Fuzzing执行** - Conductor使用recipes驱动fuzzing
5. **结果验证** - 检查是否触发目标分支

**关键验证点**：
- Mutation正确应用到syscall buffer
- Pure Replay模式下mutation生效
- 目标程序能读取到变异后的数据
- BUG触发并返回正确退出码

### `test_integrated.sh` - 集成测试

完整的端到端流程测试，包括所有模块的协作。

**测试覆盖**：
- ✅ Record模式trace录制
- ✅ TraceAnalyzer BB解析
- ✅ PathFinder静态分析
- ✅ Recipe生成（含fallback）
- ✅ Conductor fuzzing循环
- ✅ Coverage反馈统计

### `test_complex_suite.sh` - 复杂程序测试

在真实复杂程序上验证PathFinder和Fuzzer的能力。

**测试程序**：
1. **多层分支** - 用户名/密码验证，多级秘密路径
2. **状态机** - 命令循环，Konami Code序列检测
3. **漏洞模拟** - 缓冲区边界、整数溢出、格式化字符串
4. **PIE二进制** - 验证PIE支持和地址映射

### `test_bb_analysis.py` - BB Trace功能测试

验证基本块追踪的正确性。

**测试内容**：
- BB Trace解析器基本功能
- BB到Syscall的关联正确性
- PC地址合理性验证
- 文件格式一致性检查

### `test_coverage_full.py` - Coverage完整测试

验证AFL风格边覆盖追踪。

**测试内容**：
- Coverage文件生成
- Coverage数据读取
- Python API集成
- Coverage与BB Trace的协同

### `test_pathfinder.sh` - PathFinder测试

独立测试PathFinder的静态分析能力。

**测试内容**：
- CFG构建
- Trace到CFG映射
- 分支点识别
- Recipe生成

## 🎯 测试验证要点

### 当前已验证功能 ✅

1. **Record & Replay**
   - ✅ Syscall trace录制
   - ✅ BB trace录制（`.bbl`文件）
   - ✅ Pure Replay模式
   - ✅ Hybrid Replay模式

2. **PathFinder**
   - ✅ CFG分析（ET_EXEC二进制）
   - ✅ BB地址过滤（主程序 vs 库代码）
   - ✅ 未覆盖分支识别
   - ✅ Recipe生成（基础）

3. **Fuzzing Engine**
   - ✅ IPC通信（Named Pipe）
   - ✅ Mutation指令解析
   - ✅ `FUZZ_CMD_OVERWRITE_AT_OFFSET`
   - ✅ Guest内存写入
   - ✅ Pure Replay mutation时序（已修复）

4. **Conductor**
   - ✅ Recipe加载和解析
   - ✅ ASCII字符串模板
   - ✅ Fork Point处理
   - ✅ Status轮询循环

### 待验证/改进功能 ⚠️

1. **PIE支持**
   - ⚠️ PIE地址映射（基础逻辑已实现，但匹配率0%）
   - ⚠️ 运行时地址重映射
   - ⚠️ `VirtAddr`与`mapped_base`对齐

2. **符号执行**
   - ⚠️ Angr符号执行（`SimFileStream.seek`错误）
   - ⚠️ 约束求解
   - ⚠️ 高置信度recipe生成

3. **Coverage反馈**
   - ⚠️ 新覆盖检测
   - ⚠️ Seed管理和选择

## 🐛 已知问题

1. **PIE二进制匹配率0%**
   - **问题**：PathFinder对PIE程序的BB匹配率为0%
   - **状态**：基础PIE检测和`base_delta`计算正确，但需要进一步调试地址映射逻辑
   - **相关**：`path_finder.py` L200-250

2. **Angr符号执行错误**
   - **问题**：`'SimFileStream' object has no attribute 'seek'`
   - **状态**：已添加fallback逻辑，生成低置信度recipes
   - **影响**：无法生成高质量的约束驱动mutation

## 📝 测试日志分析

### 成功的Fuzzing运行应包含：

```
[Conductor] 🎯 使用recipe[0]: target=0x4012eb
[APPLY] Syscall 16 matched, applying 1 mutations
[OVERWRITE] ✅ Successfully wrote 16 bytes
[Conductor] ✅ Execution completed: Execution Complete
🐛 BUG TRIGGERED!
```

### 失败的迹象：

- `syscall_idx=0 vs target=16` - syscall索引不匹配
- `ERROR: Invalid arg_index` - 参数索引错误
- `Pure replay not supported` - Pure Replay失败
- `Timeout waiting for status` - IPC超时

## 🔧 调试技巧

### 启用详细日志

```bash
# QEMU端日志（修改rr_replay.c，重新编译）
RR_DEBUG_ENABLE=1

# Conductor端日志
# 查看fuzz_conductor.py中的print语句

# PathFinder详细输出
config = PathFinderConfig(verbose=True)
```

### 检查关键文件

```bash
# 检查trace文件
ls -lh /tmp/fuzz_demo/seeds/*.dat*

# 检查recipes
cat /tmp/fuzz_demo/recipes/generated.json | jq '.recipes[] | {syscall_index, offset, size, data_template}'

# 检查QEMU日志
grep -E "(FUZZING|APPLY|OVERWRITE)" /tmp/fuzz_demo/results/*.log
```

## 📚 相关文档

- **主文档**: `/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/README.md`
- **改进总结**: `/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/IMPROVEMENTS_SUMMARY.md`
- **调试报告**: `/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/FUZZING_DEBUG_REPORT.md`
- **最终状态**: `/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/FINAL_FUZZING_STATUS.md`

## 🎓 开发建议

### 添加新测试

1. 在`tests/`目录创建C程序或Shell脚本
2. 确保使用`-no-pie`编译（PIE支持仍在完善）
3. 包含清晰的验证点（如特定输出或返回码）
4. 更新本README

### 修改现有测试

- 保持向后兼容
- 更新预期结果
- 添加适当的错误处理
- 记录变更原因

---

## 🗑️ 最近更新 (2025-10-31)

### 测试文件清理

**已删除过时测试（9个）**:
- `test_improvements_simple.sh` - Phase 2.1 临时测试
- `test_phase2_improvements.sh` - Phase 2 改进测试
- `test_init_detection.sh` - 初始化检测测试
- `test_coverage_feedback.sh` - Coverage 反馈测试
- `test_simple_vuln.sh` - 旧的 argv 输入测试
- `test_vuln_stdin.sh` - 临时测试脚本
- `fix_and_test_pie_fuzzing.sh` - PIE 修复测试
- `test_pie_improved.sh` - PIE 改进测试
- `test_pie_e2e_fuzzing.sh` - PIE 端到端测试

**新增核心测试**:
- ✅ `test_vuln_v2.sh` - 漏洞程序 v2.0 测试（使用 read() 输入）
- ✅ `test_multiprocess_mode.sh` - 多进程模式基础测试
- ✅ `test_multiprocess_vuln.sh` - 多进程漏洞测试

### vuln v2.0 测试结果

**最新测试 (2025-10-31)**:
- 配置: 5 种漏洞类型 × 100 次迭代
- 结果: 发现 2 个崩溃（整数溢出、栈溢出）
- 崩溃发现率: 40% (2/5)
- 状态: ✅ 验证了 read() 输入的有效性

**已知问题**:
- 简单缓冲区溢出未触发（需要增加迭代或改进变异策略）
- 建议参考: `当前问题整理.md`

---

**最后更新**: 2025-10-31  
**RR-Fuzz版本**: 2.0  
**状态**: 核心功能已验证，测试文件已清理，持续优化中


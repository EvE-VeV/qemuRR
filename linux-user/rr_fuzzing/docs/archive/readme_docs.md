# RR-Fuzz 文档导航与目录结构

**最后更新**: 2025-10-29  
**文档总数**: 30+份  
**分类**: 用户文档、分析文档、实现文档、归档文档

---

## 📚 文档分类概览

```
docs/
├── 📖 用户文档 (Getting Started)
├── 🔬 系统分析文档 (Analysis Reports)
├── 🛠️ 实现细节文档 (Implementation Guides)
└── 📦 归档文档 (Old Archive)
```

---

## 📖 用户文档 (Quick Start)

### 必读文档 ⭐⭐⭐

| 文档 | 描述 | 适合人群 |
|------|------|---------|
| **README.md** | 项目总览和快速开始 | 所有用户 |
| **user_guide.md** | 完整使用指南 | 新手 |
| **REPLAY_MODES_COMPARISON.md** | Binary vs Strace模式对比 | 新手/进阶 |
| **api_reference.md** | API参考文档 | 开发者 |

### 配置与环境

| 文档 | 内容 |
|------|------|
| `environment_variables_analysis.md` | 15个环境变量完整说明 |
| `implementation/configuration.md` | 配置管理详解 |

### 格式规范

| 文档 | 内容 |
|------|------|
| `format_spec.md` | Trace文件格式规范 (150字节固定字段) |

---

## 🔬 系统分析文档 (Analysis Reports)

### 综合总结 ⭐⭐⭐

| 文档 | 内容 | 页数 |
|------|------|------|
| **FINAL_ANALYSIS_SUMMARY.md** | 最终分析总结报告 (Phase 1-10) | 526行 |
| **EXECUTIVE_SUMMARY.md** | 执行摘要 (Phase 1-2完成) | 462行 |
| **COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md** | 46个问题详细清单 | 785行 |
| **control_flow_and_module_interactions.md** | 控制流与模块交互分析 | 新增 |

### 分阶段深度分析

| Phase | 文档 | 内容 | 行数 |
|-------|------|------|------|
| 1 | `phase1_architecture_analysis.md` | QEMU集成点分析 | - |
| 2 | `phase2_dataflow_analysis.md` | 数据流与trace格式 | - |
| 3 | `phase3_record_module_analysis.md` | Record模块深度分析 | - |
| 4 | `phase4_replay_module_analysis.md` | Replay模块深度分析 | 921行 |
| 5 | `phase5_fuzzing_module_analysis.md` | Fuzzing模块深度分析 | - |
| 6 | `phase6_coverage_feedback_analysis.md` | Coverage与反馈循环 | - |
| 7-10 | `phase7_10_comprehensive_analysis.md` | 辅助系统与完整性 | 1105行 |

**分析覆盖范围**:
- ✅ 架构设计
- ✅ 数据流
- ✅ Record模块
- ✅ Replay模块 (Binary + Strace)
- ✅ Fuzzing模块
- ✅ Coverage系统
- ✅ 辅助系统

---

## 🛠️ 实现细节文档

### 核心实现

| 文档 | 内容 |
|------|------|
| `implementation/replay_methods.md` | Replay方法详解 |
| `REPLAY_MODES_COMPARISON.md` | **Binary vs Strace深度对比** ⭐ |

### 架构设计

| 文档 | 内容 |
|------|------|
| `architecture.md` | 系统架构设计 |

---

## 📦 归档文档 (old-archive/)

**目录**: `docs/old-archive/`  
**说明**: 旧版本文档，保留用于参考

### 归档文档清单

| 文档 | 描述 | 状态 |
|------|------|------|
| `00_comprehensive_analysis.md` | 旧版综合分析 | 已替代 |
| `01_features.md` | 功能特性 | 已替代 |
| `02_architecture.md` | 旧版架构 | 已替代 |
| `03_rr_workflow.md` | RR工作流 (691行) | 部分参考 |
| `04_user_guide.md` | 旧版用户指南 | 已替代 |
| `05_api_reference.md` | 旧版API参考 | 已替代 |
| `07_rr_implementation_guide.md` | 实现指南 | 参考 |
| `08_replay_methods_comparison.md` | 旧版Replay对比 | 已替代 |
| `09_strace_replay_implementation.md` | **Strace实现详解** ⭐ | 重要参考 |
| `10_configuration_guide.md` | 配置指南 | 已替代 |
| `12_config_to_function_flow.md` | 配置到函数流程 | 参考 |
| `function_level_analysis_part1.md` | 函数级分析 | 参考 |
| `function_level_complete_index.md` | 函数索引 | 参考 |
| `README.md` | 归档说明 | - |

---

## 🎯 按任务查找文档

### 我要快速开始

1. **README.md** - 了解项目
2. **user_guide.md** - 学习使用
3. **REPLAY_MODES_COMPARISON.md** - 选择模式

### 我要进行Fuzzing

1. **user_guide.md** § Fuzzing阶段
2. **phase5_fuzzing_module_analysis.md** - 理解变异策略
3. **phase4_replay_module_analysis.md** - 理解Pure Replay
4. **COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md** § P0问题 - 了解已知问题

### 我要调试/分析

1. **REPLAY_MODES_COMPARISON.md** - 选择Strace模式
2. **old-archive/09_strace_replay_implementation.md** - Strace详细实现
3. **environment_variables_analysis.md** - 配置调试级别
4. **control_flow_and_module_interactions.md** - 理解控制流

### 我要开发/扩展

1. **api_reference.md** - API参考
2. **architecture.md** - 系统架构
3. **format_spec.md** - Trace格式规范
4. **phase1_architecture_analysis.md** - QEMU集成点
5. **COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md** - 待实现功能

### 我要理解内部机制

**完整阅读顺序**:
1. `phase1_architecture_analysis.md` - QEMU集成
2. `phase2_dataflow_analysis.md` - 数据流
3. `phase3_record_module_analysis.md` - Record
4. `phase4_replay_module_analysis.md` - Replay
5. `phase5_fuzzing_module_analysis.md` - Fuzzing
6. `phase6_coverage_feedback_analysis.md` - Coverage
7. `phase7_10_comprehensive_analysis.md` - 辅助系统
8. `control_flow_and_module_interactions.md` - 控制流
9. `FINAL_ANALYSIS_SUMMARY.md` - 总结

### 我要修复问题

1. **COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md** - 46个问题详细清单
2. **FINAL_ANALYSIS_SUMMARY.md** § 问题清单
3. 对应Phase文档的问题章节

---

## 📊 文档统计

### 按类型统计

| 类型 | 数量 | 说明 |
|------|------|------|
| 用户文档 | 5份 | Getting Started |
| 分析报告 | 12份 | Phase 1-10 + 总结 |
| 实现指南 | 4份 | 详细实现 |
| 归档文档 | 13份 | 旧版本参考 |
| **总计** | **34份** | - |

### 按模块统计

| 模块 | 文档数 | 主要文档 |
|------|--------|---------|
| Record | 3份 | phase3_record_module_analysis.md |
| Replay | 5份 | phase4, REPLAY_MODES_COMPARISON, old-archive/09 |
| Fuzzing | 3份 | phase5_fuzzing_module_analysis.md |
| Coverage | 2份 | phase6_coverage_feedback_analysis.md |
| 配置 | 3份 | environment_variables, configuration |
| 通用 | 18份 | 总结、架构、API等 |

### 文档质量

| 级别 | 文档数 | 说明 |
|------|--------|------|
| ⭐⭐⭐ 必读 | 8份 | 核心文档 |
| ⭐⭐ 推荐 | 10份 | 重要参考 |
| ⭐ 参考 | 16份 | 选读 |

---

## 🗂️ 推荐阅读路径

### 路径 1: 新手快速上手 (30分钟)

```
README.md (5分钟)
  ↓
user_guide.md § Quick Start (10分钟)
  ↓
REPLAY_MODES_COMPARISON.md § 模式选择 (10分钟)
  ↓
环境变量配置 (5分钟)
```

### 路径 2: 系统理解 (2小时)

```
EXECUTIVE_SUMMARY.md (15分钟)
  ↓
phase1: QEMU集成 (20分钟)
  ↓
phase2: 数据流 (20分钟)
  ↓
phase4: Replay模块 (30分钟)
  ↓
FINAL_ANALYSIS_SUMMARY.md (35分钟)
```

### 路径 3: 深度研究 (1天)

```
所有Phase文档 (Phase 1-10) (4小时)
  ↓
control_flow_and_module_interactions.md (1小时)
  ↓
COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md (2小时)
  ↓
代码阅读 + 交叉验证 (1小时)
```

### 路径 4: 问题修复 (根据优先级)

```
COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md
  ↓
确定要修复的问题 (P0/P1/P2)
  ↓
查阅相关Phase文档
  ↓
参考old-archive中的实现细节
  ↓
开始修复
```

---

## 🔍 快速查找表

### Binary Replay相关

| 需求 | 文档 |
|------|------|
| 整体设计 | phase4_replay_module_analysis.md |
| Pure路径 | phase4 § Pure Replay |
| Hybrid路径 | phase4 § Hybrid Replay |
| FD映射 | phase4 § FD映射机制 |
| mmap处理 | phase4 § mmap地址映射 |
| 已知问题 | COMPREHENSIVE § P1-1到P1-6 |

### Strace Replay相关

| 需求 | 文档 |
|------|------|
| 整体设计 | REPLAY_MODES_COMPARISON.md § Strace详解 |
| 详细实现 | old-archive/09_strace_replay_implementation.md |
| 对比分析 | REPLAY_MODES_COMPARISON.md § 对比分析 |
| POST-HOOK | old-archive/09 § POST-HOOK实现 |
| 使用建议 | REPLAY_MODES_COMPARISON.md § 使用建议 |

### Fuzzing相关

| 需求 | 文档 |
|------|------|
| 变异策略 | phase5_fuzzing_module_analysis.md § 变异策略 |
| Fork Server | phase5 § Fork Server机制 |
| IPC通信 | phase5 § IPC通信 |
| Conductor | phase5 § Conductor变异生成 |
| 问题修复 | COMPREHENSIVE § P0-2, P0-3 |

### Coverage相关

| 需求 | 文档 |
|------|------|
| Coverage设计 | phase6_coverage_feedback_analysis.md |
| TCG集成 | phase6 § TCG集成设计 |
| 反馈循环 | phase6 § 反馈循环设计 |
| 最严重问题 | COMPREHENSIVE § P0-1 (Coverage TCG未集成) |

---

## ⚠️ 重要提示

### 文档版本管理

- **最新版本**: `FINAL_ANALYSIS_SUMMARY.md`, `COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md`
- **主要参考**: Phase系列文档 (phase1-10)
- **历史参考**: old-archive目录

### 已知废弃文档

以下文档已被新版本替代，**仅作历史参考**:
- `old-archive/00_comprehensive_analysis.md` → FINAL_ANALYSIS_SUMMARY.md
- `old-archive/01_features.md` → user_guide.md
- `old-archive/08_replay_methods_comparison.md` → REPLAY_MODES_COMPARISON.md

### 正在维护的文档

以下文档持续更新，请以最新版本为准:
- ✅ user_guide.md
- ✅ api_reference.md
- ✅ COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md
- ✅ REPLAY_MODES_COMPARISON.md (新)

---

## 📝 文档贡献指南

### 新增文档规范

1. **命名规范**:
   - 用户文档: 小写+下划线 (user_guide.md)
   - 分析文档: phase*_*.md
   - 总结文档: 大写 (FINAL_ANALYSIS_SUMMARY.md)

2. **目录归属**:
   - 最新文档 → `docs/`
   - 实现细节 → `docs/implementation/`
   - 旧版本 → `docs/old-archive/`

3. **文档头部**:
   ```markdown
   # 文档标题
   
   **生成时间**: YYYY-MM-DD
   **文档类型**: 类型
   **分析范围**: 范围
   ```

### 更新本文档

本文档 (`README_DOCS.md`) 应在以下情况更新:
- 新增文档
- 文档重命名或移动
- 重要文档更新
- 归档旧文档

---

## 📞 获取帮助

### 按问题类型

| 问题类型 | 查阅文档 | 搜索关键词 |
|---------|---------|-----------|
| 如何使用 | user_guide.md | "Quick Start" |
| 如何配置 | environment_variables_analysis.md | "RR_MODE" |
| 理解原理 | Phase系列文档 | "架构", "设计" |
| 修复Bug | COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md | "P0", "P1" |
| 扩展功能 | api_reference.md, architecture.md | "API", "hook" |

### 文档搜索技巧

```bash
# 在所有文档中搜索关键词
grep -r "Pure Replay" docs/

# 查找特定模块的分析
ls docs/phase*

# 查找问题相关文档
grep -r "P0" docs/*.md
```

---

**文档维护者**: RR-Fuzz Analysis Team  
**最后更新**: 2025-10-29  
**版本**: 1.0


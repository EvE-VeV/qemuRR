# RR-Fuzz 系统

QEMU-based Record-Replay-Fuzzing 框架

---

## 📂 目录结构

项目采用模块化组织，按功能分类：

```
rr_fuzzing/
├── core/          # 核心框架（初始化、配置、常量）
├── record/        # 录制模块（syscall捕获、aux_data）
├── replay/        # 重放模块（pure/hybrid/strace）
├── fuzzing/       # Fuzzing引擎（变异、覆盖率、Python工具）
├── utils/         # 工具模块（映射、IPC、跟踪、快照）
├── config/        # 配置模板
├── docs/          # 文档
├── analysis/      # 分析报告和实施计划
└── paper/         # 论文相关
```

**核心模块说明**：
- **core/** (5文件) - 框架初始化、配置管理、常量定义
- **record/** (3文件) - 系统调用录制、aux_data捕获
- **replay/** (6文件) - 4个重放引擎（binary/pure/reapply/strace）
- **fuzzing/** (4个C文件 + 5个Python工具) - 变异引擎、覆盖率追踪、conductor
- **utils/** (13文件) - 映射管理、IPC、动态跟踪、快照等

**重组信息**：
- 重组日期：2025-10-28
- 重组前：扁平化结构（40+个文件混杂）
- 重组后：模块化结构（5个功能目录）
- 代码质量：魔数完成度 78% → 87%

---

## 📊 当前状态

| 组件 | 状态 |
|------|------|
| Pure Replay Fuzzing | ✅ 完成 + 性能优化 |
| Hybrid Replay | ⚠️ 部分完成 |
| Fork Server | ✅ 完成 |
| Python Conductor | ✅ 基础完成 |
| Trace 分析器 | ✅ 完成 |

---

## 🚨 已发现的关键问题

详见 `COMPLETE_ISSUES_LIST.md`

### 问题总览

| # | 问题 | 状态 | 优先级 |
|---|------|------|--------|
| 1 | Pure Replay 重复写入 | ✅ **已修复** | - |
| 2 | Hybrid Fuzzing 覆盖率 30% | ⚠️ 设计完成 | P0 |
| 3 | Fork 后系统调用追踪缺失 | ⚠️ 待修复 | P0 |
| 4 | 25-35% 系统调用未记录 | ⚠️ 待修复 | **P0** |

**修复顺序**: 问题 4 → 问题 3 → 问题 2

---

## 📁 核心文档

- `COMPLETE_ISSUES_LIST.md` - **完整问题清单和修复方案**
- `plan/design.md` - 系统设计文档
- `fuzzing/trace_analyzer.py` - Trace 分析工具

---

## 🔧 快速开始

### 一键测试（推荐）
```bash
cd linux-user/rr_fuzzing
./quick_test.sh
```

这将自动运行：
- ✅ Record/Replay 基础测试（4个目标）
- ✅ Fuzzing 模式测试（5次+3次迭代）
- ✅ IPC 通信验证
- ✅ 共享内存安全检查

### 编译
```bash
cd /home/webfuzz/Documents/qemu/build
ninja
sudo ninja install
```

### 测试
```bash
cd linux-user/rr_fuzzing/test
./verify_fix1.sh  # 验证问题1修复
```

---

## 🎯 下一步计划

1. **立即**: 修复问题 4 (全量记录) - 1 天
2. **然后**: 修复问题 3 (Fork 追踪) - 1-2 天
3. **最后**: 完成问题 2 (Hybrid Fuzzing) - 3-4 天

---

**最后更新**: 2025-10-26

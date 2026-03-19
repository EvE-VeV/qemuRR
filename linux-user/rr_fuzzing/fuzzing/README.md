# RR-Fuzz (Record-Replay Fuzzer)

**Version**: 7.0 (Production Ready)  
**Date**: 2026-01-08

RR-Fuzz 是一个基于 QEMU 用户态模拟的高性能、确定性 Fuzzing 框架。它通过 Record-Replay 技术实现 100% 可重现的执行流，并通过系统调用级变异（Syscall Mutation）探索深层程序状态。

---

## 🚀 核心特性 (v7.0)

### 1. 极致性能与扩展性
- **高性能**: 单核 50+ execs/s，多核线性扩展 (4核 > 200 execs/s)。
- **IPC Caching**: 智能缓存机制将 Worker 启动延迟从 5s 降低至 <10ms。
- **多进程架构**: 基于 `FuzzMaster` 的 1+N 架构，高效同步 Coverage 和 Corpus。

### 2. 深度状态探索
- **Exploration Mode**: `PathFinder` 在图饱和时自动切换模式，针对已覆盖路径进行深度变异，打破局部最优。
- **IO 确定性**: 完整 Hook `pread64`, `recvfrom`, `getrandom` 等系统调用，确保 IO 操作的确定性重放。

### 3. 先进的验证成果
- **LAVA-M 验证**: 在真实数据集上取得重大突破 (e.g., `who` coverage 提升 42倍)。
- **全集兼容性**: 成功支持 15+ 种目标程序，包括 Coreutils 标准工具 (`ls`, `cat`, `grep`) 和自定义漏洞程序。

---

## 📂 目录结构

```
linux-user/rr_fuzzing/
├── src/                     # C 语言核心实现 (core/engine/runtime/syscall/common)
├── include/                 # C 头文件
├── fuzzing/                 # Python Fuzzing 引擎
│   ├── conductor/          # 核心逻辑 (FuzzingCore, Mutator, Coverage, Executor)
│   ├── multiprocess/       # 多进程管理 (FuzzMaster, DynamicForkController)
│   ├── config/             # target profiles / 字典 / schema
│   └── utils/              # 辅助工具
├── tests/                   # 测试用例与脚本
└── docs/                    # 架构与分析文档
```

## 🚦 快速开始

### 1. 运行测试
我们提供了开箱即用的测试脚本：

```bash
# 单进程快速验证 (/bin/ls)
./run_ls_fuzz_test.sh

# 多进程压力测试 (推荐)
./run_ls_fuzz_multiprocess.sh
```

### 2. 查看报告
详细的测试结果汇总于项目根目录：
👉 **[FINAL_SUMMARY_REPORT.md](../FINAL_SUMMARY_REPORT.md)**

---

## 🔧 架构设计

RR-Fuzz 采用分层架构设计：

1.  **Layer 1 (Trace Storage)**: 高效的 Trace 存储与索引。
2.  **Layer 2 (Core Fuzzing)**: 主 Fuzzing 循环与变异引擎。
3.  **Layer 3 (QEMU Integration)**: 确定性执行与覆盖率反馈。
4.  **Layer 4 (Multi-Process)**: 分布式协调与资源同步 (v7.0 重点)。
5.  **Layer 5 (Analysis)**: 结果分析与可视化。

详细架构请参考: [DETAILED_ARCHITECTURE.md](../DETAILED_ARCHITECTURE.md)

---

## 🛠️ 故障排除

- **Worker 启动失败**: 检查 `/dev/shm/` 是否有残留文件 (`rm /dev/shm/rr_fuzz_*`)。
- **覆盖率不增长**: 检查 Trace 文件是否为 `record` 模式生成，或尝试使用 `--smart` 启用 PathFinder。
- **"Fork Fail"**: 确保目标程序不包含未 Hook 的 IO 系统调用 (当前已支持绝大多数 Coreutils)。

---
**维护者**: WebFuzz Team
**版权**: Google DeepMind

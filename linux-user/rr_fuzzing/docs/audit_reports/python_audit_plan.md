# Python 端审计计划

## 📊 代码规模

**总计**: ~14,000 行 Python 代码

### Conductor 模块（单进程核心）
| 文件 | 行数 | 优先级 | 功能 |
|------|------|--------|------|
| `fuzzing_core.py` | 1,496 | P0 | 核心 Fuzzing 循环 |
| `mutator.py` | 1,314 | P0 | 变异策略生成器 |
| `qemu_executor.py` | 919 | P0 | QEMU 执行器（IPC桥梁）|
| `afl_enhanced_mutator.py` | 579 | P1 | AFL 风格变异器 |
| `mutation_dependency_graph.py` | 518 | P1 | 变异依赖分析 |
| `trace_manager.py` | 420 | P1 | Trace 管理器 |
| `coverage.py` | 405 | P1 | Coverage 追踪 |
| `io_mutator.py` | 343 | P2 | I/O 专用变异器 |
| `seed_manager_adapter.py` | 318 | P2 | Seed 管理适配器 |
| 其他 | ~500 | P3 | 辅助模块 |

### Multiprocess 模块（多进程调度）
| 文件 | 行数 | 优先级 | 功能 |
|------|------|--------|------|
| `path_finder.py` | 1,408 | P0 | Path Finder 算法 |
| `dynamic_fork_controller.py` | 914 | P0 | 动态 Fork 控制器 |
| `fuzz_master.py` | 576 | P0 | 多进程主控 |
| `crash_analyzer.py` | 510 | P1 | Crash 分析器 |
| `energy_scheduler.py` | 498 | P1 | Energy 调度算法 |
| `dual_level_path_finder.py` | 485 | P1 | 双层 PathFinder |
| `shared_resources.py` | 478 | P1 | 共享资源管理 |
| `corpus_manager.py` | 423 | P2 | Corpus 管理 |
| 其他 | ~700 | P2-P3 | 辅助模块 |

## 🎯 审计目标

### 1. 验证关键假设
- [ ] Coverage 是否真的在BB级别追踪？
- [ ] PathFinder 算法是否合理？
- [ ] 与C端的IPC是否正确实现？

### 2. 检查策略有效性
- [ ] 变异策略是否科学？
- [ ] Fork 决策是否合理？
- [ ] Corpus 管理是否高效？

### 3. 发现潜在问题
- [ ] 性能瓶颈
- [ ] 内存泄漏
- [ ] 死锁风险

## 📝 审计顺序

### Phase 1: 核心执行流 (P0)
1. `fuzz_main.py` - 入口点
2. `fuzzing_core.py` - 主循环
3. `qemu_executor.py` - C端交互
4. `mutator.py` - 变异生成

### Phase 2: 策略算法 (P0-P1)
5. `path_finder.py` - PathFinder 核心
6. `dynamic_fork_controller.py` - Fork 控制
7. `coverage.py` - Coverage 追踪
8. `afl_enhanced_mutator.py` - AFL 变异

### Phase 3: 多进程与调度 (P1)
9. `fuzz_master.py` - 多进程协调
10. `energy_scheduler.py` - 调度算法
11. `crash_analyzer.py` - Crash 处理

### Phase 4: 辅助模块 (P2-P3)
12. Trace/Corpus/Seed 管理
13. 其他工具类

## ⏱️ 预计工作量

- Phase 1: ~40 工具调用
- Phase 2: ~50 工具调用
- Phase 3: ~30 工具调用
- Phase 4: ~30 工具调用

**总计**: ~150 工具调用

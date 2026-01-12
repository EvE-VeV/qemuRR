# RR-Fuzz Project Context
# 项目上下文文档 (For AI Assistant)

**Version**: 7.0 (2026-01-08)
**Purpose**: AI助手快速理解RR-Fuzz项目的核心上下文
**Latest Update**: Multi-Process Scaling & Performance Optimization

---

## 一、项目定位

**RR-Fuzz** = Record-Replay Fuzzer

- **核心理念**: 确定性重放 + 覆盖率引导 + Syscall变异
- **技术栈**: C (QEMU修改) + Python (Fuzzing引擎)
- **目标**: 通过变异syscall行为而非输入来发现bugs (State-Space Exploration)

**关键优势** vs AFL:
- ✅ **完全确定性**: 相同的Seed + Mutation = 100% 相同的轨迹
- ✅ **状态空间变异**: 直接变异 syscall 返回值 (e.g. `read` return 0, `getrandom` return fixed)
- ✅ **Syscall级精确控制**: 精确注入 fault (e.g. buffer overflow in `read`)
- ✅ **LAVA验证**: 在真实 LAVA-M 数据集上验证了有效性

**当前性能**:
```
吞吐量: 50+ execs/sec (Single) / 200+ (Multi-Process 4-core)
延迟:   <20ms/iteration (Trace Caching + IPC优化)
```

---

## 二、5层架构 (已验证)

```
Layer 5: 监控与分析
  └─ SyscallTreeVisualizer, CrashAnalyzer, CorpusManager (✅ 验证通过)

Layer 4: 多进程 & 高级策略
  └─ FuzzMaster (✅ 生产就绪), DynamicForkController (✅ DFS/Explore),
     PathFinder (✅ Exploration Mode)

Layer 3: QEMU集成
  └─ QEMUExecutor (✅ IPC Caching), Coverage (✅ BB-Level), 
     Syscall Hooks (✅ IO/File Support)

Layer 2: Fuzzing引擎
  └─ FuzzingCore, BaseMutator, SmartMutator (✅ Recipe-Driven)

Layer 1: RR核心 (C)
  └─ rr_main.c, rr_replay.c, rr_record.c, rr_syscall_tree.c
```

**关键组件验证状态**:
- ✅ **FuzzMaster**: 实现了 1 Master + N Workers 的高效同步，线性扩展。
- ✅ **IPC Caching**: 解决了 Trace 解析延迟，Worker 启动速度提升 50x。
- ✅ **Exploration Mode**: 解决了 PathFinder 在饱和图上的停滞问题。

---

## 三、核心数据流

### Record → Replay → Fuzzing

```
1. Record (Offset 0):
   用户程序执行 → syscall → rr_record_syscall()
   → 保存: [syscall_nr, args, retval, aux_data]

2. Replay (Offset > 0):
   rr_replay_syscall() → 读取trace → 跳过真实syscall
   → 填充recorded数据 → 程序收到recorded结果

3. Fuzzing (Active):
   Python生成mutations → 写入共享内存 (/tmp/fuzz_instructions_<pid>)
   → rr_apply_mutations() → 修改retval/args/aux_data
   → QEMU执行 → 收集Coverage → 返回Python
```

---

## 四、关键文件索引

### 必读核心文件 (Top 5)

1. **`core/rr_main.c`** - C侧框架初始化, Syscall Hooks, Tree Export
2. **`replay/rr_replay.c`** - Replay逻辑, Mutation 注入核心
3. **`fuzzing/conductor/fuzzing_core.py`** - 主循环, Exploration Mode 逻辑
4. **`fuzzing/multiprocess/fuzz_master.py`** - 多进程协调, 资源同步
5. **`fuzzing/multiprocess/dynamic_fork_controller.py`** - 动态 Fork 点选择, IO 识别

---

## 五、常用命令速查

### 单目标快速测试
```bash
./linux-user/rr_fuzzing/run_ls_fuzz_test.sh
```

### 多进程压力测试
```bash
./linux-user/rr_fuzzing/run_ls_fuzz_multiprocess.sh
```

### 批量运行所有目标
```bash
./linux-user/rr_fuzzing/run_multiple_targets.sh
```

**文档版本**: 7.1 (2026-01-08)
**状态**: 生产就绪 (Production Ready)

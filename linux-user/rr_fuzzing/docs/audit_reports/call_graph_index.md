# RR-Fuzz 完整函数调用图 - 总览

从 `do_syscall` 开始的完整调用流程，包含所有条件分支、功能说明和文件标注。

## 📚 调用图目录

本文档组织为 3 个独立的详细图表，每个图表聚焦于不同的功能模块：

### 1. [Main Entry Flow](./call_graph_main.md) 🟦
**范围**: QEMU 集成点 → 核心调度器 → 模式选择

**关键内容**:
- `do_syscall` (QEMU 入口)
- `rr_do_syscall` (RR-Fuzz 入口)
- 模式路由逻辑 (RECORD/REPLAY/FUZZING)
- Post-hook 调用链

**关键决策点**:
- RR-Fuzz 是否启用？
- 当前运行模式？

---

### 2. [Record & Replay Flow](./call_graph_record_replay.md) 🟩🟨
**范围**: Record 模式 + Pure/Hybrid Replay 模式

**关键内容**:
- **Record Path**: 
  - `rr_record_syscall` - 记录到 trace 文件
  - `capture_syscall_args_aux` - 捕获辅助数据
  - Aux Data 创建和管理
- **Replay Path**:
  - `rr_replay_syscall` - Replay 调度器
  - `rr_replay_syscall_pure` - Pure Replay (无需真实 syscall)
  - Hybrid Replay (需要真实 syscall)
- **Mapping Manager**:
  - FD 映射 (解决 `open` 返回值差异)
  - 地址映射 (解决 ASLR)

**关键决策点**:
- 是否应该捕获 aux data？
- Pure Replay 是否支持该 syscall？
- 如何翻译 FD/地址？

**已知问题**:
- ⚠️ Double Capture Bug (use_legacy_capture)

---

### 3. [Fuzzing & Fork Server Flow](./call_graph_fuzzing.md) 🟥🔶
**范围**: Fuzzing 模式 + Fork Server + 高级特性

**关键内容**:
- **Fuzzing Engine**:
  - 从共享内存加载变异指令
  - 应用 7 种变异策略 (MUTATE_ARG, FLIP_BITS, RETVAL_OVERRIDE, etc.)
  - Aux Data 变异 (漏洞 Payload 注入)
- **Fork Server**:
  - Standard Fork ('F') - 持久化模式
  - Batch Fork ('B') - 批量并行
  - Checkpoint Fork ('C') - 中点 Fork
- **Coverage Tracking**:
  - AFL 风格边覆盖 `(prev >> 1) ^ cur`
  - 共享内存 bitmap
- **Dynamic Trace**:
  - 实时事件流向 Python Visualizer
- **Autonomous Nested Fork**:
  - 子进程自主决策再次 Fork

**关键决策点**:
- Fork Server 收到什么命令？
- 应用哪种变异策略？
- 是否触发嵌套 Fork？

**高级特性**:
- 漏洞 Payload 库（格式化字符串、命令注入等）
- Mid-Point Fork 优化
- 递归 Fuzzing

---

## 🗺️ 架构分层视图

```
┌─────────────────────────────────────────────────────┐
│ Layer 0: QEMU (linux-user/syscall.c)               │
│  └─ do_syscall                                      │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ Layer 1: RR-Fuzz Core (core/rr_main.c)            │
│  ├─ rr_do_syscall         [Pre-hook]               │
│  └─ rr_syscall_post_hook  [Post-hook]              │
└─────────────────────────────────────────────────────┘
                        ↓
        ┌───────────────┼───────────────┐
        ↓               ↓               ↓
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ RECORD MODE │ │ REPLAY MODE │ │ FUZZING MODE│
│ record/     │ │ replay/     │ │ fuzzing/    │
│  rr_record.c│ │  rr_replay.c│ │  rr_fuzz_   │
│             │ │  rr_replay_ │ │  engine.c   │
│             │ │  pure.c     │ │             │
└─────────────┘ └─────────────┘ └─────────────┘
        │               │               │
        └───────────────┼───────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ Layer 3: Utilities (utils/)                        │
│  ├─ rr_mapping_manager.c   [FD/Addr Translation]   │
│  ├─ rr_aux_data.c          [Aux Data Management]   │
│  ├─ rr_syscall_dispatch.c  [Optimized Dispatch]    │
│  ├─ rr_fork_server.c       [Fork Server]           │
│  ├─ rr_ipc.c               [Python Bridge]         │
│  └─ rr_nested_fork.c       [Autonomous Recursion]  │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ Layer 4: Advanced Features                         │
│  ├─ rr_coverage.c          [AFL Coverage]          │
│  ├─ rr_fuzz_aux_mutations.c [Payload Injection]    │
│  ├─ rr_dynamic_trace.c     [Event Streaming]       │
│  ├─ rr_bb_trace.c          [BB Recording]          │
│  └─ rr_syscall_tree.c      [Execution Tree]        │
└─────────────────────────────────────────────────────┘
```

## 📂 关键文件快速索引

| 文件 | 行数 | 主要功能 | 关键函数 |
|------|------|----------|----------|
| **core/rr_main.c** | ~300 | 核心入口 | `rr_do_syscall`, `rr_syscall_post_hook` |
| **record/rr_record.c** | ~400 | Record 模式 | `rr_record_syscall`, `capture_syscall_args_aux` |
| **replay/rr_replay.c** | ~350 | Replay 调度 | `rr_replay_syscall`, `read_next_record` |
| **replay/rr_replay_pure.c** | ~225 | Pure Replay | `rr_replay_syscall_pure` |
| **record/rr_aux_data.c** | ~400 | Aux Data 管理 | `rr_aux_create`, `rr_aux_find` |
| **utils/rr_mapping_manager.c** | ~465 | 映射管理 | `rr_fd_mapping_add/get`, `rr_addr_mapping_add/get` |
| **utils/rr_syscall_dispatch.c** | ~475 | 优化调度 | `apply_file_io_args`, `apply_memory_args` |
| **utils/rr_fork_server.c** | ~750 | Fork Server | `rr_fork_server_loop`, `fork_and_replay` |
| **fuzzing/.../rr_fuzz_engine.c** | ~756 | Fuzzing 引擎 | `rr_fuzz_mutate_syscall`, `apply_mutations_for_syscall` |
| **fuzzing/.../rr_fuzz_aux_mutations.c** | ~460 | Aux 变异 | `inject_interesting_values`, `mutate_aux_buffer` |
| **fuzzing/.../rr_coverage.c** | ~270 | 覆盖率跟踪 | `rr_coverage_trace_edge` |
| **utils/rr_ipc.c** | ~279 | IPC 通信 | `rr_ipc_receive_command`, `rr_ipc_send_status` |
| **utils/rr_dynamic_trace.c** | ~366 | 动态跟踪 | `rr_dynamic_trace_fork`, `rr_dynamic_trace_syscall_enter` |
| **utils/rr_nested_fork.c** | ~164 | 嵌套 Fork | `rr_should_nested_fork`, `rr_autonomous_nested_fork` |

## 🔍 关键决策点汇总

### 1. 模式判断 (rr_main.c)
```c
if (!g_rr_framework || !g_rr_framework->enabled) return;
switch (g_rr_framework->mode) {
    case RR_MODE_RECORD:   // → Graph 2: Record Path
    case RR_MODE_REPLAY:   // → Graph 2: Replay Path  
    case RR_MODE_FUZZING:  // → Graph 3: Fuzzing Path
}
```

### 2. Pure vs Hybrid Replay (rr_replay.c)
```c
if (record->aux_data && rr_replay_syscall_pure(...) == 0) {
    // Pure: 跳过真实 syscall
} else {
    // Hybrid: 执行真实 syscall + 映射翻译
}
```

### 3. Fork Server 命令处理 (rr_fork_server.c)
```c
cmd = rr_ipc_receive_command();
'F' → Standard Fork    // 持久化模式
'B' → Batch Fork       // 批量并行
'C' → Checkpoint Fork  // 中点恢复
'Q' → Quit
```

### 4. 变异策略选择 (rr_fuzz_engine.c)
```c
switch (instr->cmd) {
    FUZZ_CMD_MUTATE_ARG        // 整数变异
    FUZZ_CMD_REPLACE_BUFFER    // 缓冲区替换
    FUZZ_CMD_FLIP_BITS         // AFL 位翻转
    FUZZ_CMD_RETVAL_OVERRIDE   // 返回值覆盖
    FUZZ_CMD_OVERWRITE_AT_OFFSET // PathFinder 定向变异
}
```

## 🐛 已知问题

1. **Double Capture Bug** (record/rr_record.c)
   - **问题**: `use_legacy_capture=true` 时会重复捕获数据
   - **影响**: 浪费内存和磁盘空间
   - **修复**: 设置 `use_legacy_capture=false` (新配置默认值)

2. **Post-Hook 冗余** (rr_main.c vs rr_syscall_dispatch.c)
   - **问题**: `rr_syscall_post_hook` 与 `rr_strace_syscall_post_hook_optimized` 功能重叠
   - **建议**: 优先使用 `rr_syscall_dispatch.c` 中的优化版本

3. **Nested Fork 触发硬编码** (rr_nested_fork.c)
   - **问题**: 当前固定在第 5 个 syscall 触发
   - **状态**: 用于演示/测试，生产环境需改进启发式

## 📊 性能优化点

1. **Zero-Copy Mutations**: 共享内存避免 IPC 拷贝开销
2. **Persistent Fork Server**: 避免 QEMU 重复启动
3. **Pure Replay**: 跳过不必要的真实 syscall 执行
4. **Buffered I/O**: BB Trace 使用缓冲减少磁盘 I/O
5. **Hash Table Mapping**: FD/地址映射 O(1) 查找
6. **Optimized Dispatch**: Handler 表避免 switch 开销

## 🎯 使用建议

### 查看完整调用链
1. 从 [Main Entry Flow](./call_graph_main.md) 开始理解整体架构
2. 根据目标模式跳转到对应详细图
   - Record/Replay → [Graph 2](./call_graph_record_replay.md)
   - Fuzzing → [Graph 3](./call_graph_fuzzing.md)
3. 使用文件快速索引定位具体实现

### 排查问题
- **Trace 文件损坏**: 查看 Record Path (Graph 2)
- **Replay 失败**: 检查 Mapping Manager 和 Pure Replay 逻辑 (Graph 2)
- **Coverage 不准确**: 检查 Coverage Tracking (Graph 3)
- **Fork Server 无响应**: 检查 IPC 和 Fork Server Loop (Graph 3)

### 添加新功能
- **新变异策略**: 修改 `apply_mutations_for_syscall` (Graph 3)
- **新 Replay 策略**: 扩展 `rr_replay_syscall_pure` (Graph 2)
- **新 Fork 模式**: 在 Fork Server Loop 添加新命令 (Graph 3)

---

**创建时间**: 2025-12-18  
**基于版本**: RR-Fuzz Complete C-side Audit  
**维护状态**: ✅ 当前完整且准确

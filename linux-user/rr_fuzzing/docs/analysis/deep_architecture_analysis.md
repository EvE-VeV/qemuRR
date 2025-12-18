# RRFuzz 深度架构分析

**版本**: 9.0 (Deep Dive)  
**日期**: 2025-12-09

---

## 1. 完整执行路径追踪

### 1.1 Python → C 完整调用链

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PYTHON SIDE                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  fuzz_main.py::main()                                                       │
│      │                                                                       │
│      └─▶ FuzzingCore.__init__()     [fuzzing_core.py L221-438]              │
│          │                                                                   │
│          ├─ TraceManager(initial_trace)                                      │
│          ├─ SmartMutator(trace_file)                                        │
│          ├─ CoverageTracker(shared_coverage)                                │
│          ├─ QEMUExecutor(qemu_path, target)                                 │
│          └─ DynamicForkController(...)                                       │
│                                                                              │
│      └─▶ FuzzingCore.run()                                                  │
│          │                                                                   │
│          └─ while True:                                                      │
│              └─▶ run_single_iteration()   [L549-924]                        │
│                  │                                                           │
│                  ├── 1. TraceManager.select_trace()    [L568]               │
│                  │   └── 60%利用/40%探索选择策略                              │
│                  │                                                           │
│                  ├── 2. SmartMutator.mutate(trace)     [L604]               │
│                  │   ├── 70% recipe驱动                                      │
│                  │   └── 30% 随机变异                                        │
│                  │                                                           │
│                  ├── 3. QEMUExecutor.execute(...)      [L638]               │
│                  │   │                                                       │
│                  │   │ ⭐ 关键路径 - 见下方详解                               │
│                  │                                                           │
│                  └── 4. CoverageTracker.has_new_coverage()  [L662]          │
│                      └── 更新global_bitmap                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 QEMUExecutor.execute() 详解

```python
# qemu_executor.py L650-760

def execute(self, trace_file, mutations, iteration_id):
    #                                        ┌─────────────────────────┐
    # Step 0: ⚠️ COVERAGE BUG HERE!         │ L659                    │
    QEMUExecutor.reset_shared_coverage()  # │ 清空64KB共享bitmap      │
    #                                        └─────────────────────────┘
    
    # Step 1: 首次执行 - 启动QEMU Fork Server
    if not self._qemu_ready:
        self._setup_ipc()                    # L669 创建pipes + shm
        self.shm.write_fork_request(...)     # L672 写入空mutations
        self._fork_qemu(trace_file)          # L675 fork+exec QEMU
        status = self._wait_for_status(5.0)  # L679 等待READY
        os.write(cmd_pipe, b'F')             # L692 发送首个Fork命令
        self._qemu_ready = True              # L701
    
    # Step 2: 后续执行 - 使用已有Fork Server
    self.shm.write_fork_request(             # L708 写入mutations
        fork_point=0,
        mutation_variants=[mutations],
        iteration_id=iteration_id
    )
    
    os.write(cmd_pipe, b'F')                 # L711 发送Fork命令
    status = self._wait_for_status(timeout)  # L714 等待结果
    coverage_bitmap = self._read_coverage()  # L729 读取coverage
    
    return ExecutionResult(status, coverage_bitmap, ...)
```

### 1.3 C-side Fork Server Loop 详解

```c
// rr_fork_server.c L270-610

int rr_fork_server_loop(void) {
    while (g_rr_framework->fork_server_active) {
        
        int cmd = rr_ipc_receive_command();   // 阻塞等待Python命令
        
        switch (cmd) {
            case 'F':  // 单次Fork ─────────────────────────────────
                {
                    // 1. 从共享内存读取iteration_id
                    FuzzSharedMemory *shm = g_rr_framework->shared_memory;
                    g_rr_framework->current_iteration_id = shm->iteration_id;
                    
                    // 2. 加载Fuzz指令到全局数组
                    rr_fuzz_load_from_shared_memory(shm);
                    
                    // 3. Fork!
                    pid_t pid = fork();
                    
                    if (pid == 0) {
                        // ═══ 子进程 ═══
                        
                        // 关闭继承的IPC FD
                        close(g_rr_framework->cmd_pipe_fd);
                        close(g_rr_framework->status_pipe_fd);
                        
                        // ⭐ 关键：重置trace位置到开头
                        rr_reset_trace_position();
                        g_rr_framework->replay_index = 0;
                        
                        // ⭐ 重新加载Fuzz指令（fork后COW可能需要）
                        rr_fuzz_load_from_shared_memory(shm);
                        
                        // 返回1，让控制流回到rr_do_syscall
                        // 子进程将从头执行所有syscalls
                        return 1;
                        
                    } else if (pid > 0) {
                        // ═══ 父进程 ═══
                        
                        g_rr_framework->child_pid = pid;
                        
                        // 等待子进程完成（带超时）
                        int status;
                        waitpid(pid, &status, ...);
                        
                        // 发送状态给Python
                        if (WIFSIGNALED(status) && is_crash_signal(...)) {
                            rr_ipc_send_status(STATUS_CRASH);  // 4
                        } else {
                            rr_ipc_send_status(STATUS_AT_FORK_POINT);  // 2
                        }
                    }
                }
                break;
                
            case 'B':  // 批量Fork (多variant) ─────────────────────
                // 类似'F'，但循环fork多个variant
                break;
                
            case 'C':  // Checkpoint Fork (中间点) ─────────────────
                // 支持从trace中间点fork
                break;
                
            case 'E':  // Baseline执行 ────────────────────────────
                // 完整执行trace用于baseline分析
                break;
                
            case 'Q':  // 退出 ────────────────────────────────────
                return -1;
        }
    }
}
```

---

## 2. 覆盖率数据流详解

### 2.1 Coverage Bitmap 生命周期

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          COVERAGE DATA FLOW                                  │
└─────────────────────────────────────────────────────────────────────────────┘

时间轴 ─────────────────────────────────────────────────────────────────────▶

Step 1: Python初始化                   
┌──────────────────────────────────────┐
│ QEMUExecutor._init_shared_coverage() │ L161-201
│                                      │
│ 创建: /dev/shm/rr_coverage_global    │
│ 大小: 64KB                           │
│ 内容: [0,0,0,0,0,...,0]              │
└──────────────────────────────────────┘
              │
              ▼
Step 2: QEMU C-side初始化
┌──────────────────────────────────────┐
│ rr_coverage_init()                   │ rr_coverage.c L141
│                                      │
│ 打开相同共享内存                       │
│ g_coverage->coverage_map指向它        │
│ g_coverage->prev_pc = 0              │
└──────────────────────────────────────┘
              │
              ▼
Step 3: 每次Fuzzing Iteration
              │
    ┌─────────┴─────────┐
    │                   │
    ▼                   │
┌───────────────────┐   │
│ reset_coverage()  │ L659  ⚠️ BUG!
│ memset(64KB, 0)   │   │
│ [0,0,0,...] ←────────│─── 每次清空!
└───────────────────┘   │
    │                   │
    ▼                   │
┌───────────────────────────────────────────────────────┐
│ QEMU Child执行                                        │
│                                                        │
│ 每个TB执行时 (cpu-exec.c:912):                        │
│   rr_coverage_trace_edge(pc);                         │
│                                                        │
│   hash = (prev_pc >> 1) ^ cur_pc                      │
│   idx = hash % 65536                                  │
│   coverage_map[idx]++  ← 写入shared memory            │
│                                                        │
│ 结果: ~3800个非0 slots                                 │
└───────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────┐
│ Python读取                                            │
│                                                        │
│ current_map = executor._read_coverage()  L729         │
│                                                        │
│ 结果: [1,0,3,0,1,0,2,...] (来自shared memory)        │
└───────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────┐
│ CoverageTracker.has_new_coverage(current_map)         │
│                                                        │
│ for i in range(65536):                                │
│   if current_map[i] > 0 and global_bitmap[i] == 0:   │
│     new_edges += 1                                    │
│     global_bitmap[i] = current_map[i]                │
│                                                        │
│ ⚠️ BUG效果:                                          │
│ - 因为C-side每次从0开始 (Step 3 reset)                │
│ - 很多"老"edge又被写入                                │
│ - Python认为是"新"的 → 错误累加                       │
│                                                        │
│ 正常: ~5 new edges/execution                          │
│ BUG:  ~2000 new edges/execution                       │
└───────────────────────────────────────────────────────┘
```

### 2.2 BUG根因可视化

```
                    Execution #1          Execution #2          Execution #3
                    ───────────           ───────────           ───────────

C-side bitmap       [0,0,0,0,...]  ──────▶ [0,0,0,0,...]  ──────▶ [0,0,0,0,...]
(after reset)              ↓                      ↓                      ↓
                     child执行               child执行               child执行
                           ↓                      ↓                      ↓
C-side bitmap       [1,0,3,0,1,...]       [1,0,3,0,1,...]       [1,0,3,0,1,...]
(after execution)          ↓                      ↓                      ↓
                     Python读取               Python读取               Python读取
                           ↓                      ↓                      ↓
Python global       [0,0,0,0,...] →       [1,0,3,0,1,...] →     [1,0,3,0,1,...]
                    发现3800新           发现2000新            发现1500新
                           ↓                      ↓                      ↓
total_edges:              3800                 5800                   7300
                           
                    ⚠️ 持续累加! 应该稳定在~5000左右
```

---

## 3. 组件责任矩阵

| 组件 | 文件 | 行数 | 核心责任 | 关键方法 |
|------|------|------|----------|----------|
| **FuzzingCore** | fuzzing_core.py | 1492 | 主循环协调 | `run_single_iteration()` L549 |
| **QEMUExecutor** | qemu_executor.py | 914 | QEMU进程管理 | `execute()` L640, `reset_shared_coverage()` L204 |
| **CoverageTracker** | coverage.py | 389 | 覆盖率分析 | `has_new_coverage()` L108 |
| **SmartMutator** | mutator.py | 1314 | 智能变异 | `mutate()` L60 |
| **TraceManager** | trace_manager.py | 421 | 种子选择 | `select_trace()` L157 |
| **DynamicForkController** | dynamic_fork_controller.py | 915 | 深度探索 | `explore_multi_path()` L244 |
| **rr_fork_server** | rr_fork_server.c | 1110 | Fork Server | `rr_fork_server_loop()` L270 |
| **rr_coverage** | rr_coverage.c | 359 | 边覆盖 | `rr_coverage_trace_edge()` L243 |
| **rr_fuzz_engine** | rr_fuzz_engine.c | 759 | 变异应用 | `rr_fuzz_mutate_syscall()` L284 |
| **cpu-exec** | cpu-exec.c | 1115 | TB执行 | `cpu_loop_exec_tb()` L912 调用trace_edge |

---

## 4. IPC协议详解

### 4.1 命令字符

| 命令 | 描述 | 发送方 | 响应 |
|------|------|--------|------|
| `F` | 单次Fork执行 | Python | STATUS_AT_FORK_POINT(2) 或 STATUS_CRASH(4) |
| `B` | 批量Fork (多variant) | Python | 多次STATUS_AT_FORK_POINT |
| `C` | Checkpoint Fork (中间点) | Python | STATUS_AT_FORK_POINT |
| `E` | Baseline执行 | Python | STATUS_AT_FORK_POINT |
| `Q` | 退出Fork Server | Python | 进程exit |

### 4.2 状态码

| 值 | 名称 | 含义 |
|----|------|------|
| 0 | STATUS_NONE | 无状态 |
| 1 | STATUS_READY | Fork Server就绪 |
| 2 | STATUS_AT_FORK_POINT | 执行完成，等待下一轮 |
| 3 | STATUS_NORMAL_EXIT | 正常退出 |
| 4 | STATUS_CRASH | 发现Crash |
| 5 | STATUS_OTHER_SIGNAL | 其他信号 |
| 6 | STATUS_TIMEOUT | 超时 |

### 4.3 共享内存格式

```c
// FuzzSharedMemory (约13KB)
typedef struct {
    uint32_t magic;              // 0x46555A5A ("FUZZ")
    uint32_t sequence;           // 序列号
    uint32_t num_variants;       // variant数量
    uint32_t checksum;           // 校验和
    uint32_t iteration_id;       // 迭代ID
    uint32_t reserved_1;
    
    uint32_t fork_point;         // Fork点位置
    uint32_t current_depth;      // Fork深度
    uint32_t reserved_2;
    
    FuzzInstruction instructions[32];  // 单variant模式
    FuzzVariant variants[10];          // 批量variant模式
} FuzzSharedMemory;
```

---

## 5. Coverage Bug修复方案

### 5.1 方案A: Python侧 - 不重置bitmap

```python
# qemu_executor.py L659
# 注释掉或删除这行:
# QEMUExecutor.reset_shared_coverage()  # ⚠️ 移除
```

**影响**: fork后child会继承parent的bitmap (Copy-on-Write)

### 5.2 方案B: 差分计算

```python
# coverage.py - 新增
def has_new_coverage_diff(self, current_map, previous_map):
    """使用差分而非绝对值比较"""
    for i in range(65536):
        diff = current_map[i] - previous_map[i]
        if diff > 0 and self.global_bitmap[i] == 0:
            self.global_bitmap[i] = diff
            new_edges += 1
```

### 5.3 方案C: C侧区分reset类型

```c
// rr_coverage.c - 新增
void rr_coverage_reset_prev_pc_only(void) {
    g_coverage->prev_pc = 0;  // 只重置edge hash状态
    // 不清空bitmap!
}
```

---

## 6. 验证检查清单

- [ ] 修改代码
- [ ] 重编译QEMU: `cd build && ninja`
- [ ] 运行测试: `python3 fuzz_main.py --timeout 1`
- [ ] 检查: `total_edges < 10000`
- [ ] 检查: 每次`new_edges < 100`

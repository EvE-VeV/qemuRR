# RRFuzz 完整架构分析文档

**版本**: 11.0 (Ultimate Comprehensive)  
**日期**: 2025-12-09  
**作者**: RRFuzz Team

---

## 目录

1. [系统架构总览](#1-系统架构总览)
2. [SmartMutator 详解](#2-smartmutator-详解)
3. [PathFinder CFG分析模块](#3-pathfinder-cfg分析模块)
4. [DynamicForkController Checkpoint机制](#4-dynamicforkcontroller-checkpoint机制)
5. [Coverage完整系统分析](#5-coverage完整系统分析)
6. [C端组件详解](#6-c端组件详解)
7. [Coverage Bug分析与修复](#7-coverage-bug分析与修复)

---

## 1. 系统架构总览

### 1.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               RRFuzz Architecture                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐              │
│  │   fuzz_main.py  │───▶│  FuzzingCore    │───▶│   Iteration     │              │
│  │   (入口点)       │    │  (主协调器)      │    │   Processing    │              │
│  └─────────────────┘    └────────┬────────┘    └─────────────────┘              │
│                                  │                                               │
│         ┌────────────────┬───────┴───────┬────────────────┐                     │
│         ▼                ▼               ▼                ▼                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │TraceManager │  │SmartMutator │  │QEMUExecutor │  │CoverageTrack│            │
│  │ (种子管理)   │  │ (变异策略)   │  │ (执行器)    │  │ (覆盖率)    │            │
│  │ [421行]     │  │ [1314行]    │  │ [914行]     │  │ [389行]     │            │
│  └─────────────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘            │
│                          │                │                 │                   │
│         ┌────────────────┤                │                 │                   │
│         ▼                ▼                ▼                 ▼                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ PathFinder  │  │IOReturnVal  │  │ForkServer   │  │SharedCovr   │            │
│  │ (CFG分析)   │  │Mutator      │  │ (IPC)       │  │ (多进程)    │            │
│  │ [1409行]    │  │             │  │             │  │ [479行]     │            │
│  └─────────────┘  └─────────────┘  └──────┬──────┘  └─────────────┘            │
│                                           │                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                        DynamicForkController [915行]                     │   │
│  │                        (深度优先Checkpoint探索)                           │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                     │
├───────────────────────────────────────────┼─────────────────────────────────────┤
│                                    IPC (Pipes + SHM)                            │
├───────────────────────────────────────────┼─────────────────────────────────────┤
│                                           ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                           C-SIDE (QEMU RR Engine)                        │   │
│  │                                                                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │   │
│  │  │ rr_main.c    │  │rr_fork_svr.c │  │rr_coverage.c │  │rr_fuzz_eng.c │ │   │
│  │  │ [942行]      │  │ [1110行]     │  │ [359行]      │  │ [759行]      │ │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 组件统计

| 组件 | 文件 | 行数 | 核心功能 |
|------|------|------|----------|
| FuzzingCore | fuzzing_core.py | 1492 | 主循环协调 |
| SmartMutator | mutator.py | 1314 | 智能变异 |
| PathFinder | path_finder.py | 1409 | CFG分析 |
| DynamicForkController | dynamic_fork_controller.py | 915 | Checkpoint探索 |
| QEMUExecutor | qemu_executor.py | 914 | QEMU管理 |
| CoverageTracker | coverage.py | 389 | 覆盖率追踪 |
| SharedCoverage | shared_resources.py | 479 | 多进程共享 |
| TraceManager | trace_manager.py | 421 | 种子管理 |
| **Python Total** | - | **7333** | - |
| rr_main | rr_main.c | 942 | 框架入口 |
| rr_fork_server | rr_fork_server.c | 1110 | Fork Server |
| rr_coverage | rr_coverage.c | 359 | 边覆盖 |
| rr_fuzz_engine | rr_fuzz_engine.c | 759 | 变异应用 |
| **C Total** | - | **3170** | - |
| **Grand Total** | - | **10503** | - |

---

## 2. SmartMutator 详解

### 2.1 类层次结构

```
mutator.py [1314行]
│
├── BaseMutator (L35-354)
│   ├── __init__(use_io_mutation=True)
│   ├── mutate(trace, fork_point) → List[FuzzInstruction]
│   ├── _generate_io_mutations(trace, fork_point)
│   └── _generate_random_mutations(trace, fork_point)
│
└── SmartMutator (L357-1314)
    ├── __init__(trace_file, recipe_file, target_binary)
    ├── TraceAnalyzer集成
    ├── PathFinder集成
    ├── Recipe模式
    ├── 11种变异策略
    ├── 停滞检测
    └── mutate(trace, fork_point) → List[FuzzInstruction]
```

### 2.2 初始化流程详解

```python
# L368-465
class SmartMutator:
    def __init__(self, trace_file, recipe_file=None, target_binary=None):
        # 1. TraceAnalyzer解析trace (使用缓存)
        if trace_file in SmartMutator._trace_cache:
            self.analyzer = SmartMutator._trace_cache[trace_file]
        else:
            self.analyzer = TraceAnalyzer(trace_file)
            SmartMutator._trace_cache[trace_file] = self.analyzer
        
        # 2. 提取Pure syscalls (有aux_data)
        pure_syscalls = self.analyzer.get_pure_syscalls()
        self.pure_candidates = [Candidate(sc.index, sc.name, sc.syscall_nr) for sc in pure_syscalls]
        
        # 3. 提取Hybrid syscalls (无aux_data)
        hybrid_syscalls = self.analyzer.get_hybrid_syscalls()
        self.hybrid_candidates = [Candidate(...) for sc in hybrid_syscalls]
        
        # 4. 过滤可变异候选 (扩展策略)
        self.mutable_candidates = self._filter_mutable_candidates()
        # 优先级: Important > Primary IO > Secondary IO > Others
        
        # 5. PathFinder CFG分析 (可选)
        if target_binary:
            self._init_pathfinder(trace_file, target_binary)
        
        # 6. Recipe加载/生成
        if recipe_file:
            self._load_recipes(recipe_file)
        auto_recipes = self._generate_automatic_recipes()
        
        # 7. 停滞检测配置
        self.stagnation_threshold = 1000  # 1000次迭代无新coverage = 停滞
        self.is_stagnant = False
```

### 2.3 11种变异策略完整表

| ID | 命令常量 | 功能描述 | 常规权重 | 停滞权重 | 代码行 |
|----|----------|----------|----------|----------|--------|
| 0 | FUZZ_CMD_FLIP_BITS | 随机翻转1-8位 | 12% | 8% | L884-889 |
| 1 | FUZZ_CMD_INTERESTING_VALUES | 边界值/特殊值注入 | 12% | 15% | L891-913 |
| 2 | FUZZ_CMD_TRUNCATE | 截断数据 | 10% | 12% | L915-920 |
| 3 | FUZZ_CMD_EXTEND | 扩展数据(溢出) | 14% | 20% | L922-933 |
| 4 | FUZZ_CMD_LIGHT_MUTATION | 轻量变异(1-2位) | 8% | 5% | L935-940 |
| 5 | FUZZ_CMD_MUTATE_AUX_BUFFER | 变异辅助缓冲区 | 9% | 10% | L942-948 |
| 6 | FUZZ_CMD_REPLACE_BUFFER | 替换小缓冲区(4-32B) | 9% | 8% | L950-955 |
| 7 | FUZZ_CMD_REPLACE_BUFFER | 替换大缓冲区(64-1024B) | 10% | 12% | L957-971 |
| 8 | FUZZ_CMD_BOUNDARY_VALUE | 边界值测试 | 10% | 12% | L973-979 |
| 9 | 漏洞模式注入 | 格式串/注入/路径遍历 | 9% | 10% | L981-1044 |
| 10 | FUZZ_CMD_MUTATE_FLAGS | 标志位变异 | 7% | 8% | L1046-1056 |

### 2.4 漏洞模式注入详解 (策略9)

```python
# L983-1044
vuln_patterns = {
    'format_string': [
        b'%s%s%s%s%n',           # 格式化字符串攻击
        b'%x%x%x%x%x%x',         # 堆栈泄露
        b'%p%p%p%p',             # 指针泄露
    ],
    'injection': [
        b"'; DROP TABLE users;--",  # SQL注入
        b"$(id)",                   # 命令注入
        b"`whoami`",                # 命令替换
    ],
    'path_traversal': [
        b'/../../../etc/passwd',    # 路径遍历
        b'/proc/self/environ',      # 环境变量读取
    ],
    'overflow_patterns': [
        b'A' * 256,                 # 经典缓冲区溢出
        b'%n' * 100,                # 格式化字符串溢出
    ],
    'special_chars': [
        b'\x00' * 32,               # NULL字节注入
        b'\xFF' * 32,               # 高位字节
    ],
    'unicode_attacks': [
        b'\xC0\xAE\xC0\xAE\x2f',    # UTF-8溢出
    ]
}
```

---

## 3. PathFinder CFG分析模块

### 3.1 架构概览

```
path_finder.py [1409行]
│
├── PathFinderConfig (L30-65)
│   ├── verbose: bool
│   ├── mapping_tolerance: int = 16
│   ├── max_cfg_nodes: int = 10000
│   ├── timeout: int = 60
│   └── graceful_disable: bool = True
│
├── MutationRecipe (L68-107)
│   ├── id, source_branch, target_branch
│   ├── mutation_type, syscall_index
│   └── to_dict()
│
└── PathFinder (L110-1409)
    ├── __init__(binary_path, config)
    ├── build_from_trace(trace_file)       # 动态CFG
    ├── _build_cfg()                       # 静态CFG (angr)
    ├── map_trace_to_cfg(bb_sequence)
    ├── generate_recipes(uncovered_branches)
    └── enhance_from_trace_files()
```

### 3.2 双模式CFG构建

```python
# 模式1: 动态CFG (build_from_trace) L255-353
def build_from_trace(self, trace_file):
    """使用TraceAnalyzer解析trace，无需angr"""
    analyzer = TraceAnalyzer(trace_file)
    
    # 从BB trace构建图
    for entry in analyzer.bb_trace_parser.entries:
        node_id = entry.pc & 0xFFFF  # 与coverage bitmap一致
        nodes[node_id] = entry.pc
        
        if entry.syscall_idx >= 0:
            # 构建BB→Syscall映射
            self.bb_to_syscall_map[entry.pc] = entry.syscall_idx
        
        if prev_node is not None:
            edges[prev_node].add(node_id)
        prev_node = node_id
    
    self.graph_mode = "dynamic"
    return True

# 模式2: 静态CFG (_build_cfg) L411-507
def _build_cfg(self):
    """使用angr构建静态CFG"""
    def run_cfg(fast_mode=False):
        return self.project.analyses.CFGFast(
            normalize=True,
            data_references=not fast_mode
        )
    
    # 带超时保护
    self.cfg = run_with_timeout(lambda: run_cfg())
```

### 3.3 Recipe自动生成

```python
# L606-645 (SmartMutator内调用)
def _generate_automatic_recipes(self):
    if not self.path_finder.is_available():
        return []
    
    # 发现未覆盖分支
    uncovered_branches = self._find_uncovered_branches()
    
    # 生成recipes
    recipes = self.path_finder.generate_recipes(
        uncovered_branches, 
        max_recipes=10
    )
    
    return [r.to_dict() for r in recipes]
```

---

## 4. DynamicForkController Checkpoint机制

### 4.1 FuzzCheckpoint数据结构

```python
# L40-58
@dataclass
class FuzzCheckpoint:
    trace_file: str              # Trace文件路径
    syscall_index: int           # Checkpoint的syscall位置
    depth: int                   # 当前探索深度
    coverage_state: bytes        # 覆盖率快照
    unexplored_mutations: List   # 待探索的mutation变种
    parent_checkpoint_id: str    # 父checkpoint ID
    checkpoint_id: str           # 唯一标识
    discovery_iteration: int     # 发现时的迭代号
    mutation_node_ids: List[str] # 关联的mutation节点ID
```

### 4.2 深度优先探索算法

```
explore_multi_path(trace, iteration_id)
│
├── depth_first_mode检查
│
├── _start_depth_exploration(trace, iteration_id)
│   │
│   ├── 静态分析发现IO syscalls (避免baseline执行)
│   │   └── io_syscalls = _find_io_syscalls(trace)
│   │
│   ├── 缓存结果 (节省120ms baseline执行)
│   │   └── self._io_syscalls_cache[trace.file_path] = io_syscalls
│   │
│   └── _explore_at_checkpoint(first_io, depth=0)
│
└── _explore_at_checkpoint(syscall_index, depth, iteration_id)
    │
    ├── 深度限制检查 (max_depth=2)
    │
    ├── 生成mutations
    │   └── for i in range(max_variants_per_checkpoint):
    │       mutation = self.mutator.mutate(trace, fork_point=syscall_index)
    │
    ├── 保存coverage快照
    │   └── coverage_snapshot = self._save_coverage_state()
    │
    ├── 执行批量fork
    │   └── results = executor.execute_fork(trace_file, fork_point, mutations)
    │
    └── 分析结果并递归
        ├── crash检测 → 返回True
        ├── 新coverage → 保存种子 + 递归更深层
        └── 无新发现 → 返回False
```

### 4.3 自适应触发概率

```python
# L153-193
def _calculate_adaptive_probability(self):
    """根据成功率和停滞状态动态调整触发概率"""
    
    # 1. 基于最近fork成功率调整
    if len(self.recent_forks) >= 10:
        success_rate = sum(1 for s, _ in self.recent_forks if s) / len(self.recent_forks)
        
        if success_rate > 0.3:
            # 成功率高 → 增加触发
            current_prob = min(current_prob * 1.2, 0.4)
        elif success_rate < 0.1:
            # 成功率低 → 降低触发
            current_prob = max(current_prob * 0.8, 0.15)
    
    # 2. 基于停滞时间调整
    if time_since_last_coverage > 300:  # 5分钟
        current_prob = min(current_prob * 1.5, 0.4)
    
    return current_prob
```

---

## 5. Coverage完整系统分析

### 5.1 Python端 CoverageTracker

```python
# coverage.py [389行]

class CoverageTracker:
    """AFL风格覆盖率追踪器"""
    
    # AFL hit count buckets
    HIT_COUNT_BUCKETS = [1, 2, 3, 4, 8, 16, 32, 128]
    
    def __init__(self, pid=None, shared_coverage=None):
        self._lock = threading.Lock()  # 线程安全
        self.shared_coverage = shared_coverage  # 多进程支持
        
        # Coverage bitmaps
        self.global_bitmap = bytearray(65536)
        self.virgin_bits = bytearray([255] * 65536)
        
        # 统计
        self.total_edges_cached = 0
        self.edge_hit_counts = defaultdict(int)
        self.hotspots = set()
        self.rare_edges = set()
    
    def has_new_coverage(self, current_map):
        """核心覆盖率分析 - L108-229"""
        with self._lock:
            # 1. 定期从SharedCoverage同步
            if self.total_executions % 100 == 0:
                self.shared_coverage.sync_coverage()
            
            # 2. 遍历64KB bitmap
            for i in range(65536):
                current_val = current_map[i]
                if current_val > 0:
                    old_val = self.global_bitmap[i]
                    
                    # 新edge发现
                    if old_val == 0:
                        new_edges += 1
                        self.total_edges_cached += 1
                        self.global_bitmap[i] = current_val
                        new_coverage = True
                    
                    # 新hit count bucket
                    elif current_val > old_val:
                        old_bucket = self._classify_hit_count(old_val)
                        new_bucket = self._classify_hit_count(current_val)
                        if new_bucket > old_bucket:
                            new_coverage = True
            
            # 3. 更新SharedCoverage
            if new_coverage:
                self.shared_coverage.update_coverage(bytes(self.global_bitmap))
            
            return new_coverage
    
    def get_stats(self):
        """获取统计 - L337-365"""
        with self._lock:
            # ⚠️ 直接计算而非使用缓存 (修复bug)
            actual_total_edges = sum(1 for b in self.global_bitmap if b > 0)
            return {'total_edges': actual_total_edges, ...}
```

### 5.2 C端 rr_coverage

```c
// rr_coverage.c [359行]

// 核心数据结构
typedef struct {
    uint8_t *coverage_map;      // 64KB bitmap
    uint64_t prev_pc;           // 上一个PC (用于edge hash)
    uint64_t total_edges;       // 总边数
    uint64_t unique_edges;      // 唯一边数
    bool enabled;
    int shm_fd;
} rr_coverage_t;

// 边追踪 - L243-274
void rr_coverage_trace_edge(uint64_t cur_pc) {
    // 1. AFL风格边哈希
    uint64_t edge_hash = (g_coverage->prev_pc >> 1) ^ cur_pc;
    
    // 2. 映射到bitmap索引
    uint32_t idx = edge_hash % 65536;
    
    // 3. 饱和计数 (防止溢出)
    if (g_coverage->coverage_map[idx] < 255) {
        g_coverage->coverage_map[idx]++;
    }
    
    // 4. 统计
    if (old_count == 0) {
        g_coverage->unique_edges++;
    }
    g_coverage->total_edges++;
    g_coverage->prev_pc = cur_pc;
}

// 重置 - L284-298 ⚠️ BUG根因
void rr_coverage_reset(void) {
    memset(g_coverage->coverage_map, 0, 65536);  // 清空entire bitmap!
    g_coverage->prev_pc = 0;
    g_coverage->total_edges = 0;
    g_coverage->unique_edges = 0;
}
```

---

## 6. C端组件详解

### 6.1 rr_fork_server.c Fork Server

```c
// rr_fork_server.c [1110行]

// 主循环 - L270-610
int rr_fork_server_loop(void) {
    while (g_rr_framework->fork_server_active) {
        int cmd = rr_ipc_receive_command();
        
        switch (cmd) {
            case 'F':  // 单次Fork - L412-611
                // 1. 从共享内存读取mutations
                rr_fuzz_load_from_shared_memory(shm);
                
                // 2. Fork
                pid_t pid = fork();
                
                if (pid == 0) {
                    // 子进程: 重置trace位置，重新加载mutations
                    rr_reset_trace_position();
                    g_rr_framework->replay_index = 0;
                    return 1;  // 继续执行
                } else {
                    // 父进程: 等待子进程并发送状态
                    waitpid(pid, &status, ...);
                    rr_ipc_send_status(STATUS_AT_FORK_POINT);
                }
                break;
                
            case 'B':  // 批量Fork - L284-410
                // 循环fork多个variant
                break;
                
            case 'C':  // Checkpoint Fork - L716-900
                // 中间点fork
                break;
                
            case 'Q':  // 退出
                return -1;
        }
    }
}
```

### 6.2 IPC协议

| 命令 | 说明 | 发送方 | 响应 |
|------|------|--------|------|
| `F` | 单次Fork | Python | STATUS_AT_FORK_POINT (2) 或 STATUS_CRASH (4) |
| `B` | 批量Fork | Python | 多次 STATUS_AT_FORK_POINT |
| `C` | Checkpoint Fork | Python | STATUS_AT_FORK_POINT |
| `E` | Baseline执行 | Python | STATUS_AT_FORK_POINT |
| `Q` | 退出 | Python | 进程exit |

| 状态码 | 值 | 含义 |
|--------|---|------|
| STATUS_READY | 1 | Fork Server就绪 |
| STATUS_AT_FORK_POINT | 2 | 执行完成，等待下一轮 |
| STATUS_NORMAL_EXIT | 3 | 正常退出 |
| STATUS_CRASH | 4 | 发现Crash |
| STATUS_OTHER_SIGNAL | 5 | 其他信号 |
| STATUS_TIMEOUT | 6 | 超时 |

---

## 7. Coverage Bug分析与修复

### 7.1 问题现象

- **预期**: `total_edges` ≈ 5,000
- **实际**: `total_edges` ≈ 40,000+
- **每次执行报告**: 2,000+ "新" edges (应该 < 100)

### 7.2 根因追踪

```
Python execute() [qemu_executor.py L659]
    │
    ├── reset_shared_coverage()  ⚠️ 清空64KB共享内存
    │
    ├── os.write(cmd_pipe, b'F')
    │
    │   ┌─────────────────────────────────────────────┐
    │   │ C-side Fork Server                           │
    │   │                                              │
    │   │ fork() → 子进程                              │
    │   │   │                                          │
    │   │   ├── 从空bitmap开始执行                     │
    │   │   │                                          │
    │   │   ├── 每个TB执行:                            │
    │   │   │   rr_coverage_trace_edge(pc)            │
    │   │   │   → bitmap[idx]++                        │
    │   │   │                                          │
    │   │   └── 结果: ~3800个slots被写入              │
    │   │                                              │
    │   └── 父进程: waitpid() + send_status()         │
    │                                                  │
    └─────────────────────────────────────────────────┘
    │
    ├── _read_coverage()  → 读取那~3800个slots
    │
    └── has_new_coverage(current_map)
        │
        └── 对比global_bitmap
            → 很多"老"edges被误认为"新"
            → total_edges持续累加
```

### 7.3 修复方案

#### 方案A: Python侧 (最简单, 5分钟)

```python
# qemu_executor.py L659
def execute(self, ...):
    # 注释掉这行:
    # QEMUExecutor.reset_shared_coverage()
    ...
```

#### 方案B: C侧区分Reset类型 (需recompile)

```c
// rr_coverage.c - 新增
void rr_coverage_reset_prev_pc_only(void) {
    // 只重置edge hash状态，保留bitmap
    if (g_coverage) {
        g_coverage->prev_pc = 0;
    }
}
```

#### 方案C: 差分计算 (Python侧)

```python
# coverage.py
class CoverageTracker:
    def __init__(self):
        self.previous_map = bytearray(65536)  # 新增
    
    def has_new_coverage(self, current_map):
        for i in range(65536):
            # 差分计算
            diff = current_map[i] - self.previous_map[i]
            if diff > 0 and self.global_bitmap[i] == 0:
                # 真正的新edge
                ...
        self.previous_map[:] = current_map
```

### 7.4 验证步骤

```bash
# 1. 应用修复
vim linux-user/rr_fuzzing/fuzzing/conductor/qemu_executor.py
# 注释掉 L659

# 2. 如果是方案B，重编译QEMU
cd build && ninja

# 3. 运行测试
cd linux-user/rr_fuzzing/fuzzing
python3 fuzz_main.py --timeout 60 --output /tmp/test_fix

# 4. 验证
grep total_edges /tmp/test_fix/final_stats.json
# 预期: 5000 < total_edges < 10000
```

---

## 附录: 文件索引

| 文件 | 路径 | 行数 |
|------|------|------|
| mutator.py | fuzzing/conductor/mutator.py | 1314 |
| path_finder.py | fuzzing/multiprocess/path_finder.py | 1409 |
| dynamic_fork_controller.py | fuzzing/multiprocess/dynamic_fork_controller.py | 915 |
| coverage.py | fuzzing/conductor/coverage.py | 389 |
| qemu_executor.py | fuzzing/conductor/qemu_executor.py | 914 |
| shared_resources.py | fuzzing/conductor/shared_resources.py | 479 |
| trace_manager.py | fuzzing/conductor/trace_manager.py | 421 |
| fuzzing_core.py | fuzzing/conductor/fuzzing_core.py | 1492 |
| rr_main.c | core/rr_main.c | 942 |
| rr_fork_server.c | utils/rr_fork_server.c | 1110 |
| rr_coverage.c | fuzzing/qemu_integration/rr_coverage.c | 359 |
| rr_fuzz_engine.c | fuzzing/qemu_integration/rr_fuzz_engine.c | 759 |

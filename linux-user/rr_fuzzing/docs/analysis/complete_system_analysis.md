# RRFuzz 完整系统分析

**版本**: 10.0 (Ultimate)  
**日期**: 2025-12-09

---

## 目录

1. [SmartMutator 策略详解](#1-smartmutator-策略详解)
2. [PathFinder CFG分析](#2-pathfinder-cfg分析)
3. [DynamicForkController Checkpoint机制](#3-dynamicforkcontroller-checkpoint机制)
4. [Coverage完整系统分析](#4-coverage完整系统分析)
5. [Coverage Bug修复方案](#5-coverage-bug修复方案)

---

## 1. SmartMutator 策略详解

### 1.1 架构概览

```
mutator.py (1314行)
├── BaseMutator (L35-354)      # 基础随机变异
└── SmartMutator (L357-1314)   # 智能变异引擎
    ├── TraceAnalyzer集成      # 分析trace获取候选
    ├── PathFinder集成         # CFG引导变异
    ├── Recipe模式             # 精确变异配方
    ├── 11种变异策略           # 完整变异能力
    └── 停滞检测               # 自适应调整
```

### 1.2 初始化流程

```python
# L368-465
def __init__(self, trace_file, recipe_file=None, target_binary=None):
    # 1. 使用TraceAnalyzer解析trace
    self.analyzer = TraceAnalyzer(trace_file)
    
    # 2. 提取Pure syscalls (有aux_data的syscall)
    self.pure_candidates = self.analyzer.get_pure_syscalls()
    
    # 3. 提取Hybrid syscalls (无aux_data的syscall)
    self.hybrid_candidates = self.analyzer.get_hybrid_syscalls()
    
    # 4. 过滤可变异候选
    self.mutable_candidates = self._filter_mutable_candidates()
    
    # 5. PathFinder CFG分析 (可选)
    if target_binary:
        self._init_pathfinder(trace_file, target_binary)
    
    # 6. 加载/生成Recipes
    if recipe_file:
        self._load_recipes(recipe_file)
    auto_recipes = self._generate_automatic_recipes()
```

### 1.3 11种变异策略详解

| 策略ID | 命令 | 功能 | 权重(常规) | 权重(停滞) |
|--------|------|------|-----------|-----------|
| 0 | FLIP_BITS | 随机翻转1-8位 | 12% | 8% |
| 1 | INTERESTING_VALUES | 边界值/特殊值注入 | 12% | 15% |
| 2 | TRUNCATE | 截断数据 | 10% | 12% |
| 3 | EXTEND | 扩展数据(溢出) | 14% | 20% |
| 4 | LIGHT_MUTATION | 轻量变异(1-2位) | 8% | 5% |
| 5 | MUTATE_AUX_BUFFER | 变异辅助缓冲区 | 9% | 10% |
| 6 | REPLACE_BUFFER (小) | 替换小缓冲区 | 9% | 8% |
| 7 | REPLACE_BUFFER (大) | 替换大缓冲区 | 10% | 12% |
| 8 | BOUNDARY_VALUE | 边界值测试 | 10% | 12% |
| 9 | MUTATE_FLAGS | 标志位变异 | 9% | 10% |
| 10 | OVERWRITE_AT_OFFSET | 偏移精确覆写 | 7% | 8% |

### 1.4 漏洞模式注入 (策略9)

```python
# L983-1044 - 多样化漏洞模式
vuln_patterns = {
    'format_string': [b'%s%s%s%s%n', b'%x%x%x%x%x%x'],
    'injection': [b"'; DROP TABLE users;--", b"$(id)"],
    'path_traversal': [b'/../../../etc/passwd'],
    'overflow_patterns': [b'A' * 256],
    'special_chars': [b'\x00' * 32, b'\xFF' * 32],
    'unicode_attacks': [b'\xC0\xAE\xC0\xAE\x2f']
}
```

### 1.5 停滞检测与自适应

```python
# L794-822
def update_stagnation_status(self, iteration, has_new_coverage):
    if has_new_coverage:
        self.last_new_coverage_iter = iteration
        self.is_stagnant = False
    else:
        stagnation_duration = iteration - self.last_new_coverage_iter
        if stagnation_duration >= 1000:  # 阈值
            self.is_stagnant = True
            # 切换到激进变异策略权重
```

---

## 2. PathFinder CFG分析

### 2.1 架构概览

```
path_finder.py (1409行)
├── PathFinderConfig    # 配置类
├── MutationRecipe      # 变异配方类
└── PathFinder          # 主类
    ├── angr CFG构建    # 静态分析
    ├── BB Trace映射    # 动态覆盖率
    ├── 未覆盖分支识别  # 目标发现
    └── Recipe自动生成  # 变异引导
```

### 2.2 CFG构建

```python
# L411-507
def _build_cfg(self):
    def run_cfg(fast_mode=False):
        if fast_mode:
            # 快速模式: CFGFast (秒级)
            return self.project.analyses.CFGFast(
                resolve_indirect_jumps=True,
                normalize=True
            )
        else:
            # 精确模式: CFGEmulated (分钟级)
            return self.project.analyses.CFGEmulated(
                keep_state=True,
                normalize=True
            )
    
    # 超时保护: 60秒
    cfg = run_with_timeout(lambda: run_cfg(fast_mode=True))
```

### 2.3 BB Trace映射

```python
# L509-586
def map_trace_to_cfg(self, bb_sequence, syscall_info=None):
    covered_nodes = set()
    uncovered_nodes = set()
    
    for bb_addr in bb_sequence:
        # 容差映射 (PIE程序)
        for tolerance in range(self.config.mapping_tolerance):
            if (bb_addr + tolerance) in self.cfg_nodes:
                covered_nodes.add(bb_addr + tolerance)
                break
    
    # 找到所有未覆盖节点
    for node in self.cfg.nodes():
        if node.addr not in covered_nodes:
            uncovered_nodes.add(node.addr)
    
    return covered_nodes, uncovered_nodes
```

### 2.4 Recipe自动生成

```python
# L606-645 (SmartMutator内)
def _generate_automatic_recipes(self):
    if not self.path_finder or not self.path_finder.is_available():
        return []
    
    # 获取未覆盖分支
    uncovered_branches = self._find_uncovered_branches()
    
    recipes = []
    for branch in uncovered_branches[:20]:  # 最多20个
        # 每个未覆盖分支生成一个recipe
        recipe = {
            'source_branch': branch['addr'],
            'target_branch': branch['target'],
            'syscall_index': estimate_syscall_index(branch),
            'mutation_type': 'buffer_overwrite',
            'priority': branch.get('priority', 5)
        }
        recipes.append(recipe)
    
    return recipes
```

---

## 3. DynamicForkController Checkpoint机制

### 3.1 架构概览

```
dynamic_fork_controller.py (915行)
├── FuzzCheckpoint       # Checkpoint数据结构
└── DynamicForkController
    ├── 深度优先探索     # 主策略
    ├── Checkpoint管理   # 状态保存/恢复
    ├── 自适应触发      # 动态概率调整
    └── 批量Fork执行    # 并行变异
```

### 3.2 Checkpoint数据结构

```python
# L40-58
@dataclass
class FuzzCheckpoint:
    trace_file: str              # Trace文件路径
    syscall_index: int           # Fork点位置
    depth: int                   # 探索深度
    coverage_state: bytes        # 覆盖率快照
    unexplored_mutations: List   # 待探索变异
    parent_checkpoint_id: str    # 父checkpoint
    checkpoint_id: str           # 唯一ID
    discovery_iteration: int     # 发现时的迭代号
    mutation_node_ids: List[str] # 关联的mutation节点
```

### 3.3 深度优先探索流程

```
explore_multi_path(trace)
│
├── _start_depth_exploration()
│   ├── 静态分析发现IO syscalls (避免baseline执行)
│   ├── 缓存IO syscalls位置
│   └── 调用_explore_at_checkpoint(first_io)
│
└── _explore_at_checkpoint(syscall_index, depth)
    ├── 创建checkpoint对象
    ├── 生成max_variants_per_checkpoint个mutations
    ├── executor.execute_fork(batch)  # 批量fork执行
    ├── 分析coverage结果
    └── 如有新coverage → 递归探索下一IO syscall
```

### 3.4 自适应触发概率

```python
# L153-193
def _calculate_adaptive_probability(self):
    success_rate = self._recent_success_rate()
    stagnant_time = time.time() - self._last_coverage_time
    
    if success_rate > 0.3:
        # 成功率高 → 增加触发概率
        return min(self.trigger_probability * 1.2, 0.8)
    elif success_rate < 0.1:
        # 成功率低 → 降低触发概率
        return max(self.trigger_probability * 0.8, 0.1)
    elif stagnant_time > 300:  # 5分钟无新coverage
        # 停滞 → 增加探索
        return min(self.trigger_probability * 1.5, 0.8)
```

---

## 4. Coverage完整系统分析

### 4.1 Coverage精度验证 (最新审计)

根据代码审计验证 (原 `coverage_verification.md`):
- **调用位置**: `/home/webfuzz/Documents/qemu/accel/tcg/cpu-exec.c`
- **粒度确认**: `rr_coverage_trace_edge` 在 QEMU TCG 主循环中被调用，**确认为 Basic Block (TB) 级别**。
- **结论**: 覆盖率粒度极佳 (5/5)，能够精确反馈每个翻译块的执行情况。

### 4.2 双层架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        PYTHON SIDE                               │
├─────────────────────────────────────────────────────────────────┤
│  CoverageTracker (coverage.py)                                  │
│    ├── global_bitmap[65536]    # 全局累积                       │
│    ├── virgin_bits[65536]      # 未触及标记                      │
│    ├── total_edges_cached      # 缓存计数                        │
│    └── has_new_coverage()      # 核心分析函数                    │
│                                                                  │
│  SharedCoverage (shared_resources.py)                           │
│    ├── _global_bitmap          # 进程间共享                      │
│    ├── sync_coverage()         # 同步                           │
│    └── update_coverage()       # 更新                           │
├─────────────────────────────────────────────────────────────────┤
│                   SHARED MEMORY                                  │
│  /dev/shm/rr_coverage_global (64KB)                             │
├─────────────────────────────────────────────────────────────────┤
│                        C SIDE                                    │
├─────────────────────────────────────────────────────────────────┤
│  rr_coverage.c                                                   │
│    ├── g_coverage->coverage_map[65536]  # 共享bitmap            │
│    ├── rr_coverage_trace_edge(pc)       # 边追踪                 │
│    └── rr_coverage_reset()              # 重置 ⚠️ BUG           │
│                                                                  │
│  cpu-exec.c:912                                                  │
│    └── rr_coverage_trace_edge(pc)       # 调用点                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Python CoverageTracker详解

```python
# coverage.py L108-229
def has_new_coverage(self, current_map):
    with self._lock:  # 线程安全
        # 1. 定期从SharedCoverage同步 (每100次)
        if self.shared_coverage and self.total_executions % 100 == 0:
            synced_edges = self.shared_coverage.sync_coverage()
            # 更新bitmap但不增加计数
        
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
                    old_bucket = classify(old_val)
                    new_bucket = classify(current_val)
                    if new_bucket > old_bucket:
                        new_coverage = True
        
        # 3. 更新SharedCoverage
        if new_coverage and self.shared_coverage:
            self.shared_coverage.update_coverage(bytes(self.global_bitmap))
        
        return new_coverage
```

### 4.3 C-side rr_coverage详解

```c
// rr_coverage.c L243-274
void rr_coverage_trace_edge(uint64_t cur_pc) {
    if (!rr_coverage_is_enabled()) return;
    
    // 1. AFL风格边哈希
    uint64_t edge_hash = (g_coverage->prev_pc >> 1) ^ cur_pc;
    
    // 2. 映射到bitmap索引
    uint32_t idx = edge_hash % 65536;
    
    // 3. 饱和计数 (防止溢出)
    uint8_t old_count = g_coverage->coverage_map[idx];
    if (old_count < 255) {
        g_coverage->coverage_map[idx]++;
    }
    
    // 4. 统计unique edges
    if (old_count == 0) {
        g_coverage->unique_edges++;
    }
    
    // 5. 更新总边数和prev_pc
    g_coverage->total_edges++;
    g_coverage->prev_pc = cur_pc;
}

// L284-298
void rr_coverage_reset(void) {
    memset(g_coverage->coverage_map, 0, 65536);  // ⚠️ 清空bitmap
    g_coverage->prev_pc = 0;
    g_coverage->total_edges = 0;
    g_coverage->unique_edges = 0;
}
```

### 4.4 数据流可视化

```
Python execute() ──────────────────────────────────────────────────┐
  │                                                                 │
  │ reset_shared_coverage()                                        │
  │ memset(64KB, 0)  ⚠️                                            │
  ▼                                                                 │
┌─────────────────┐                                                │
│  C-side bitmap  │ ─── fork() ──▶ Child Process                   │
│  [0,0,0,0,...]  │                    │                           │
└─────────────────┘                    │                           │
                                       ▼                           │
                              ┌─────────────────┐                  │
                              │ 执行target程序  │                   │
                              │ trace_edge(pc)  │                   │
                              │ bitmap[idx]++   │                   │
                              └────────┬────────┘                  │
                                       │                           │
                                       ▼                           │
                              ┌─────────────────┐                  │
                              │  C-side bitmap  │                  │
                              │ [1,0,3,0,1,...] │ ~3800非0         │
                              └────────┬────────┘                  │
                                       │                           │
                                       │ child exit                │
                                       ▼                           │
                              ┌─────────────────┐                  │
                              │ Python读取      │ ◀────────────────┘
                              │ _read_coverage()│
                              └────────┬────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │ has_new_coverage│
                              │                  │
                              │ 对比global_bitmap│
                              │ 发现"新"edges   │ ⚠️ BUG: 2000+
                              └─────────────────┘
```

---

## 5. Coverage Bug修复方案

### 5.1 根因确认

```
问题: 每次execution报告2000+个"新"edges (应该<100)

根因:
1. QEMUExecutor.reset_shared_coverage() [L659]
   → 每次execution前清空C-side 64KB bitmap
   
2. C-side rr_coverage_reset() [L284]
   → memset(bitmap, 0, 65536)
   
3. Fork后child从空bitmap开始
   → 写入所有~3800个执行的edges
   
4. Python对比global_bitmap
   → 很多"老"edges被误认为"新"
```

### 5.2 修复方案A: Python侧 (最简单)

```python
# qemu_executor.py L659
def execute(self, ...):
    # ⚠️ 注释掉或删除这行
    # QEMUExecutor.reset_shared_coverage()
    
    # 或者: 只在第一次执行时reset
    if self.total_executions == 1:
        QEMUExecutor.reset_shared_coverage()
```

### 5.3 修复方案B: C侧区分Reset类型

```c
// rr_coverage.c - 新增
void rr_coverage_reset_prev_pc_only(void) {
    // 只重置edge hash状态，保留bitmap
    if (g_coverage) {
        g_coverage->prev_pc = 0;
    }
}

// 修改Python调用
// 从: rr_coverage_reset()
// 到: rr_coverage_reset_prev_pc_only()
```

### 5.4 修复方案C: 差分计算

```python
# coverage.py
class CoverageTracker:
    def __init__(self):
        self.previous_map = bytearray(65536)  # 新增
    
    def has_new_coverage(self, current_map):
        # 使用差分而非绝对值
        for i in range(65536):
            diff = current_map[i] - self.previous_map[i]
            if diff > 0 and self.global_bitmap[i] == 0:
                # 真正的新edge
                ...
        
        # 保存当前map作为下次比较基准
        self.previous_map[:] = current_map
```

### 5.5 推荐修复流程

1. **方案A** (5分钟): 修改qemu_executor.py
2. **测试**: `python3 fuzz_main.py --timeout 1`
3. **验证**: `total_edges < 10000`
4. **如不工作**: 实施方案B (需recompile QEMU)

### 5.6 验证检查清单

- [ ] 修改代码 (方案A或B)
- [ ] 如方案B: `cd build && ninja`
- [ ] 运行测试: `python3 fuzz_main.py --timeout 1`
- [ ] 检查输出: `grep total_edges final_stats.json`
- [ ] 预期: `5000 < total_edges < 10000`

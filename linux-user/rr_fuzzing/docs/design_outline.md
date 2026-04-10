# RRFuzz Design Section Outline

> 论文 §3 Design 章节的结构与内容提纲。
> 基于实际代码实现梳理（2026-04-09）。

---

## 章节结构

```
§3 Design
  3.1 Overview & Threat Model
  3.2 Record Phase — Deterministic Trace Capture
  3.3 Replay Phase — Syscall Interception & Buffer Restoration
  3.4 Syscall Mutation Model（11 cmd types + aux pipeline）
  3.5 Authentication Bypass via Seed Trace（auth_boundary）
  3.6 DFS Exploration with Checkpoints（DFC）
  3.7 CFG-Guided Mutation Targeting（PathFinder + Syscall Tree）
  3.8 Network FD Isolation（semantic correctness）
  3.9 C↔Python IPC Architecture
```

---

## 3.1 Overview & Threat Model

**核心思路**：不变异程序输入，而是变异 syscall 行为（返回值、参数、buffer内容），
在确定性重放中探索新执行路径。

**Threat Model**：
- 目标：嵌入式 HTTP 服务（ARM/MIPS，uclibc/glibc）
- 运行环境：QEMU user-mode（无需全系统仿真）
- 假设：攻击者可发送网络请求，目标无 ASLR（嵌入式固件通常固定地址）
- 目标漏洞类型：堆溢出、栈溢出、格式字符串、路径穿越、命令注入

**架构分层**（5层）：
```
Layer 5: Monitoring & Analytics
  └─ SyscallTreeVisualizer, CrashAnalyzer, CorpusManager

Layer 4: Exploration Strategy
  └─ DynamicForkController (DFS), DualLevelPathFinder (CFG),
     CheckpointManager (persistence)

Layer 3: QEMU Integration
  └─ QEMUExecutor, Coverage bitmap (C-side), IPC channels

Layer 2: Mutation Engine (Python)
  └─ BaseMutator (9 cmds), SmartMutator (11 strategies),
     perform_fd_tracking()

Layer 1: RR Core (C)
  └─ rr_main.c, rr_replay.c, rr_record.c,
     rr_syscall_tree.c, rr_fuzz_aux_mutations.c
```

---

## 3.2 Record Phase — Deterministic Trace Capture

**实现**：`src/engine/rr_record.c`，由 `src/core/rr_main.c` 中的 syscall pre/post hook 驱动。

**每条 trace entry 捕获**：
```c
struct TraceEntry {
    uint32_t  syscall_nr;      // syscall 编号
    abi_long  args[6];         // 入参
    abi_long  retval;          // 返回值
    uint8_t  *aux_data;        // buffer 内容（read/recv 的实际数据）
    uint32_t  aux_size;
};
```

**关键设计**：
- aux_data 捕获：对 `read()`, `recv()`, `recvfrom()`, `recvmsg()` 等 IO syscall，
  在 post-hook 中将实际写入用户 buffer 的内容复制到 trace
- 状态机：`idle → recording → replaying → fuzzing`（由 `RR_MODE` 环境变量控制）

**Syscall Tree 构建**（`rr_syscall_tree.c`）：
- recording 阶段同步构建调用树（syscall 时序 + 父子关系）
- framework finalize 时导出为 JSON（`<trace>.tree.json`）
- PathFinder 用此 JSON 做精确 BB→syscall_index 映射

---

## 3.3 Replay Phase — Syscall Interception & Buffer Restoration

**实现**：`src/engine/rr_replay.c`

**核心流程**：
```
syscall_pre_hook()
  → rr_replay_syscall()
    → 查找当前 syscall_index 对应的 trace entry
    → 若 cmd 中有 mutation instruction → rr_apply_mutations()
    → 设置 g_retval_override + g_has_retval_override = true
    → 跳过真实 syscall 执行（修改 guest CPU 状态）

syscall_post_hook()
  → 若 g_has_retval_override → 将 retval 写入 guest 寄存器
  → 将 aux_data（或变异后数据）写回用户 buffer 地址
```

**确定性保证**：
- 所有 syscall 返回值由 trace 决定，不依赖宿主 OS 状态
- buffer 内容完全由 aux_data 控制
- 时序确定：syscall_index 单调递增，无分支

---

## 3.4 Syscall Mutation Model

### 主 pipeline（C层 `rr_fuzz_engine.c`）

`apply_mutations_for_syscall()` 处理 `FuzzInstruction` 数组：

| cmd | 名称 | 作用 |
|:---:|------|------|
| 1 | MUTATE_ARG | 修改 args[i] 或 retval |
| 2 | REPLACE_BUFFER | 替换整个 aux buffer |
| 3 | MUTATE_FLAGS | XOR flag 掩码到 args[i] |
| 4 | BOUNDARY_VALUE | 设置 args[i] 或 retval 为边界值 |
| 6 | FLIP_BITS | 对 buffer 指定 offset 做 bit mask XOR |
| 11 | OVERWRITE_AT_OFFSET | 在 buffer+offset 处写入任意字节 |

### Aux Data 独立 pipeline（C层 `rr_fuzz_aux_mutations.c`，460行）

`FUZZ_CMD_MUTATE_AUX_BUFFER`（cmd=5）触发 8 种漏洞专向注入：

| pattern_type | 名称 | 注入内容 |
|:---:|------|---------|
| 0 | Format String | `%s%x%n%s%x%n...` |
| 1 | Buffer Overflow | 重复字符（默认 `'A'`）填满 buffer |
| 2 | Null Injection | 插入 `\x00` 字节 |
| 3 | NULL 终止移除 | 删除尾部 `\x00` |
| 4 | （保留） | — |
| 5 | Path Traversal | `/../../../etc/passwd` |
| 6 | Command Injection | `;ls;` / `;id;` |
| 7 | （保留） | — |

### Python层 mutation 生成

**BaseMutator**（`fuzzing/conductor/mutator.py`）：
- 9种 cmd 随机选择
- FD感知：`forbidden_map`（库初始化/early-init FD）+ `network_fd_map`
- `_generate_io_mutations()`：针对 IO syscall 的结构化变异
- `_generate_random_mutations()`：随机 syscall 变异

**SmartMutator**（同文件，530行起）：
- 11种策略权重分布（普通模式 vs 停滞模式不同权重）
- Recipe驱动：PathFinder 自动生成，上限 200 条
- Stagnation 检测：连续 1000 次无新覆盖 → aggressive 模式
  - 停滞时 EXTEND 权重 14→20，INTERESTING_VALUES 12→15
- Shadow Registry：记录 syscall 历史模式，避免重复
- HTTP感知：`_generate_http_request()` 生成语义正确的 HTTP 请求变异
- `_generate_advanced_instruction()`：精细 OVERWRITE_AT_OFFSET + 网络读取场景

---

## 3.5 Authentication Bypass via Seed Trace

**核心洞察**：传统 fuzzer 每次从头执行，必须通过认证才能到达 post-auth 代码。
RRFuzz 将完整认证过的会话录制为 seed trace，replay 时直接从 post-auth 状态展开。

**auth_boundary 自动检测**（`fuzzing_core.py:298-311`）：
```python
# 扫描 trace，找第一个 accept() / socketcall(SYS_ACCEPT)
auth_boundary = trace_analyzer.get_auth_boundary()
```

**效果**：
- TTFA（Time to First post-auth Access）= 0：第一次 replay 即进入 post-auth
- post-auth edge coverage 从 0 变为有意义的正数
- 与认证机制实现细节无关（不需要知道密码/NVRAM/IPC）

**与对比工具的根本差异**：
- Greenhouse+AFL++：每次重走认证流程，认证依赖 NVRAM/IPC 响应不完整时提前返回
- AFLNet：有状态但仍需发送真实认证请求
- RRFuzz：认证过程固化为 trace 常量，bypass 认证壁垒

---

## 3.6 DFS Exploration with Checkpoints（DFC）

**实现**：`fuzzing/multiprocess/dynamic_fork_controller.py`

**核心数据结构**：
```python
@dataclass
class Checkpoint:
    syscall_index: int          # checkpoint 位置（trace 中的 syscall 编号）
    depth: int                  # 当前探索深度
    unexplored_mutations: list  # 该 checkpoint 未探索的变体
    parent_checkpoint_id: str   # 用于回溯
    checkpoint_id: str
    discovery_iteration: int
```

**DFS 探索流程**：
```
1. 从根 trace 选取 IO syscall 作为 fork point，创建 Checkpoint
2. 对 Checkpoint 生成 max_variants_per_checkpoint（默认5）个变体
3. 对每个有新覆盖的结果，在更深处创建新 Checkpoint（depth+1）
4. 达到 max_depth（默认2）或无新覆盖时回溯
5. 继续 Checkpoint queue 中的下一个未探索 Checkpoint
```

**配置参数**（环境变量可覆盖）：
- `RR_MAX_DEPTH`（默认2）：最大 DFS 深度
- `RR_MAX_VARIANTS`（默认5）：每个 checkpoint 的变体数

**与 auth_boundary 协作**：fork point 选择范围限定在 `auth_boundary` 之后的 syscall，
确保所有 DFS 探索均在 post-auth 状态空间内。

**Checkpoint 持久化**（`conductor/checkpoint.py`）：
- `CheckpointManager`：每5分钟保存探索状态到 `output_dir`
- 重启时自动恢复（`auto-resume`），长时间 campaign 不丢失进度

---

## 3.7 CFG-Guided Mutation Targeting（PathFinder + Syscall Tree）

**实现**：`fuzzing/multiprocess/dual_level_path_finder.py`（angr）

**两级分析**：

*Level 1 — 粗粒度 CFG（syscall 可达性过滤）*：
- 构建目标二进制的 CFG（上限 5000 节点）
- 判断每个 syscall 是否从目标代码段可达
- 过滤不可达 syscall，避免在初始化路径上浪费变异

*Level 2 — 精确 BB→syscall_index 映射*：
- 加载 C 层导出的 `syscall_tree.json`
- 将 CFG 基本块地址精确映射到 trace 中的 syscall_index
- 替代之前 `(addr >> 4) % 20` 的粗估计（<10% 命中率 → 精确映射）

**Recipe 自动生成**（`_generate_automatic_recipes()`）：
- PathFinder 分析未覆盖分支（`_find_uncovered_branches()`）
- 为每个未覆盖分支生成针对性 mutation 序列（recipe）
- recipe 上限 200 条（防止内存增长）
- SmartMutator 优先消费 recipe，无 recipe 时退回随机模式

---

## 3.8 Network FD Isolation

**实现**：`fuzzing/conductor/mutator.py`，`perform_fd_tracking()`

**问题**：若对 file-fd syscall（如 `open()`/`fstat()`/`read(fd=3)`）注入网络变异，
会触发 ELF loader 路径崩溃（FILE-FD 假阳性），掩盖真实网络漏洞。

**`perform_fd_tracking(syscalls)` 逻辑**：
```python
# 扫描 trace，追踪每个 fd 的来源：
# - socket()/accept() → network_fd_map[index] = True
# - open()/creat() → forbidden_map[index] = True（库初始化 FD）
# - 继承关系：write/read 用同一 fd → 继承分类
```

**输出两张 map**：
- `forbidden_map[syscall_index]`：True = 库/早期初始化 FD，跳过所有变异
- `network_fd_map[syscall_index]`：True = socket FD，允许高强度变异

**效果**：
- 消除 FILE-FD 假阳性（NB-DL842-01、NB-AX88U-01 被正确排除）
- 集中变异资源在 post-auth socket 路径，提升有效 crash 比例

---

## 3.9 C↔Python IPC Architecture

**4 通道设计**：

| 通道 | 方向 | 格式 | 路径 |
|------|------|------|------|
| Mutations | Python→C | `FuzzInstruction[]`（二进制） | `/tmp/fuzz_instructions_<pid>` |
| Coverage | C→Python | 64KB bitmap | `/tmp/coverage_bitmap_<pid>` |
| Syscall Tree | C→Python | JSON | `<trace>.tree.json` |
| 控制参数 | Python→C | 环境变量 | `RR_MODE`, `RR_TRACE_FILE`, `RR_FUZZ_*` |

**`FuzzInstruction` 结构**（C/Python 共享定义）：
```c
struct FuzzInstruction {
    uint32_t cmd;           // mutation 类型（1-11）
    uint32_t syscall_index; // 目标 syscall 位置
    uint8_t  arg_index;     // 目标参数下标（0xFF = retval）
    uint64_t offset;        // buffer 内偏移
    uint32_t size;          // 写入大小
    uint8_t  data[MAX_DATA];// mutation payload
    uint32_t data_len;
};
```

**Coverage 驱动的 fork point 选择**（`_select_coverage_driven_fork_points()`）：
- 读取 64KB bitmap，找 coverage 边界处的 syscall
- 优先选择刚触达新边的 syscall 作为 fork point

---

## 实现规模参考

| 组件 | 文件 | 代码行数 |
|------|------|:--------:|
| RR Core (C) | `src/core/` + `src/engine/` + `src/syscall/` | ~3,200 |
| Aux Mutation (C) | `rr_fuzz_aux_mutations.c` | 460 |
| BaseMutator (Python) | `mutator.py`（前530行） | 530 |
| SmartMutator (Python) | `mutator.py`（530行起） | 1,384 |
| DFC (Python) | `dynamic_fork_controller.py` | ~600 |
| PathFinder (Python) | `dual_level_path_finder.py` | ~800 |
| FuzzingCore (Python) | `fuzzing_core.py` | ~900 |

**总计**：~7,800 行核心实现代码

---

*文档版本：1.0*
*生成时间：2026-04-09*

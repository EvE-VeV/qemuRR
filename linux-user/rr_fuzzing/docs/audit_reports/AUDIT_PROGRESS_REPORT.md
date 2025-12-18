# 函数审计进展报告 (最终版)

**审计策略**: 基于调用关系的优先级审计  
**当前时间**: 2025-12-18 10:45  
**已审计函数**: 23个 (覆盖 P0, P1, P2, P3 关键路径)

---

## 1. P0 - 核心路径函数 (13个 - 100% 完成)

### rr_main.c (9个)
| 函数名 | 状态 | 关键发现 |
|--------|------|----------|
| `get_syscall_name` | ✅ | 线程不安全（静态缓冲区） |
| `is_expected_deviation` | ✅ | 覆盖范围可扩展 |
| `align_fd_state` | ✅ | 复杂的保守 FD 对齐策略 |
| `rr_framework_init` | ✅ | 框架入口初始化 |
| `rr_framework_cleanup` | ✅ | 资源释放顺序重要 |
| `rr_do_syscall` | ✅ | **Early fork** 机制确保 main() 重放 |
| `rr_handle_mmap_post` | ✅ | mmap 后处理逻辑 |
| `rr_syscall_post_hook` | ✅ | **⚠️ 与 rr_syscall_dispatch.c 冗余** |
| `rr_map_fd_...` 系列 | ✅ | 映射辅助逻辑 |

### record/rr_record.c (2个)
| 函数名 | 状态 | 关键发现 |
|--------|------|----------|
| `rr_start_recording` | ✅ | 文件头格式验证 (0x52525254) |
| `rr_record_syscall` | ✅ | 🔥 **双重捕获问题** (Legacy + Aux) |

### replay/rr_replay.c (2个)
| 函数名 | 状态 | 关键发现 |
|--------|------|----------|
| `rr_start_replay` | ✅ | 包含 rewind 机制支持 fork-server |
| `rr_replay_syscall` | ✅ | Hybrid/Pure 自动分发器，状态管理复杂 |

---

## 4. Layer 3 - 具体业务逻辑 (utils/rr_syscall_dispatch.c)

| 函数类别 | 状态 | 关键发现 |
|----------|------|----------|
| **File I/O** | ✅ | 包含 `open/dup` 的 FD 映射建立，`close` 的映射移除 |
| **Memory** | ✅ | `mmap` 的地址映射是核心；`mprotect/munmap` 也必须应用映射 |
| **Network** | ✅ | `socket/accept` 负责建立 Socket FD 映射 |
| **Dispatch** | ✅ | 使用 `O(1)` 查找表替代了 `rr_main.c` 中的 switch-case |

## 5. Fuzzing 核心组件 (Performance Critical)

### Fork Server (utils/rr_fork_server.c)
| 函数名 | 状态 | 核心机制 |
|--------|------|----------|
| `rr_fork_server_loop` | ✅ | **性能引擎**。支持 4 种命令模式：<br>1. **F (Fork)**: 标准持久化模式<br>2. **B (Batch)**: 并发 Fork 多个变异体<br>3. **C (Checkpoint)**: **Mid-Point Fork** (支持从 Trace 中间 Fork)<br>4. **E (Baseline)**: 基线执行 |
| `rr_check_fork_point` | ✅ | 支持 **自动探测** (首个阻塞 IO) 和 **路径匹配** |

### Coverage (rr_coverage.c)
| 函数名 | 状态 | 核心机制 |
|--------|------|----------|
| `rr_coverage_init` | ✅ | 支持 Global SHM (AFL++) 和 Per-Process SHM |
| `rr_coverage_trace_edge`| ✅ | 经典的 AFL 算法 `(prev >> 1) ^ cur` |

### Fuzzing Engine (rr_fuzz_engine.c & rr_fuzz_aux_mutations.c)
| 函数名 | 状态 | 核心机制 |
|--------|------|----------|
| `apply_mutations_for_syscall` | ✅ | **C端变异执行器**。支持 BitFlip, Dictionary, BufferOver, Retval Override。使用了共享内存指令集。 |
| `inject_interesting_values` | ✅ | **漏洞Payload库**。硬编码了针对 read/getrandom 的格式化字符串、溢出、命令注入 payload (L249)。 |

---

## 6. Utils & Infrastructure (Extended)

### Syscall Parser (rr_syscallparser.c & rr_syscall_info.c)
| 函数名 | 状态 | 核心机制 |
|--------|------|----------|
| `rr_strace_parse_line` | ✅ | 实现了完整的 Strace 文本解析，支持导入外部 log。 |
| `rr_should_auto_fork` | ✅ | **Fork 策略大脑**。支持 Strict/Relaxed/Aggressive 三种启发式策略，决定何时 Fork。 |

### Trace System (rr_bb_trace.c & rr_dynamic_trace.c)
| 函数名 | 状态 | 核心机制 |
|--------|------|----------|
| `rr_bb_trace_log` | ✅ | 基本块追踪，带缓冲 I/O。支持仅记录主程序段 (Filter)。 |
| `rr_dynamic_trace_fork` | ✅ | 实时向 Python 可视化端发送进程树 Fork 事件。 |

### Advanced Utilities (rr_ipc.c, rr_nested_fork.c, rr_syscall_tree.c)
| 函数名 | 状态 | 核心机制 |
|--------|------|----------|
| `rr_ipc_receive_command` | ✅ | **IPC Bridge**。处理与 Python Conductor 的指令交互 ('F', 'C', 'B')。 |
| `rr_autonomous_nested_fork`| ✅ | **Recursive Fuzzing**。允许 Child 进程自主决定进一步 Fork (Grandchildren)，实现深层路径探索。 |
| `rr_tree_add_syscall_node` | ✅ | **Execution Tree**。高性能(Zero-Alloc)的内存执行树构建，用于导出 JSON 分析。 |

---

## 关键技术发现与建议总结

| 函数名 | 所在文件 | 状态 | 功能/发现 |
|--------|----------|------|-----------|
| `capture_syscall_args_aux` | rr_record.c | ✅ | EnvFuzz 风格智能捕获，策略灵活 |
| `rr_replay_syscall_pure` | rr_replay_pure.c | ✅ | **核心创新**: 纯用户态重放，性能极高 |

---

## 3. P2 & P3 - 高频与辅助函数 (8个 - 100% 完成)

### P2 - 映射与解析工具 (utils/rr_mapping_manager.c, replay/rr_replay.c)
| 函数名 | 状态 | 功能与发现 |
|--------|------|------------|
| `rr_fd_mapping_add` | ✅ | 高频调用，哈希表 O(1) 存储 |
| `rr_fd_mapping_get` | ✅ | LRU 访问更新，支持统计 |
| `rr_addr_mapping_add` | ✅ | 处理 ASLR 偏差 |
| `rr_addr_mapping_get` | ✅ | 支持**范围查询** (Range Query) 处理指针偏移 |
| `read_next_record` | ✅ | **手动反序列化**二进制 Trace，处理大端/小端 |

### P3 - Aux 数据管理 (record/rr_aux_data.c)
| 函数名 | 状态 | 功能与发现 |
|--------|------|------------|
| `rr_aux_create` | ✅ | 深拷贝数据，内存管理关键 |
| `rr_aux_append` | ✅ | 链表操作 |
| `rr_aux_find` | ✅ | 按参数掩码查找 |
| `rr_aux_should_record` | ✅ | **智能阈值策略**: <=4KB 记录，>64KB 跳过 |

---

## 关键技术发现与建议总结

### 1. 严重 Bug: 双重捕获 (Double Capture)
- **描述**: 在 `rr_record_syscall` 中，如果启用 `use_legacy_capture`，会同时执行 `capture_syscall_args` (旧) 和 `capture_syscall_args_aux` (新)。
- **后果**: 内存占用翻倍，Trace 文件体积膨胀，严重的性能浪费。
- **修复方案**: 强制互斥，推荐默认禁用 Legacy 捕获。

### 2. 架构冗余: Post Hook 分裂
- **描述**: `core/rr_main.c:rr_syscall_post_hook` 包含巨大的 switch-case，而 `utils/rr_syscall_dispatch.c` 实现了另一套模块化的分发逻辑。
- **后果**: 维护困难，逻辑不一致风险。
- **建议**: 废弃 `rr_main.c` 中的硬编码 switch，统一使用 dispatch 表。

### 3. Pure Replay 的设计权衡
- **描述**: `rr_replay_syscall_pure` 明确不支持输出 (write/send) 和内存管理 (mmap/brk)。
- **评价**: 这是正确的设计。输出操作必须真实执行以维持外部状态；内存操作必须真实执行以维持 QEMU 内存映射。

### 4. 智能记录策略
- **描述**: `rr_aux_should_record` 使用大小阈值 (4KB/16KB/64KB) 动态决定是否记录。
- **评价**: 非常实用的策略，平衡了 Trace 大小和重放确定性。但跳过大数据 (>64KB) 会导致重放必须回退到 Hybrid 模式，可能引入不确定性。

---

## 下一步计划
- [ ] 修复双重捕获 Bug
- [ ] 重构 Post Hook 消除冗余
- [ ] 开始 Python Fuzzing 模块审计 (qemu_executor.py, mutator.py)

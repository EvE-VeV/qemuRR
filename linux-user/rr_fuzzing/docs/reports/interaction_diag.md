# RR-Fuzz 交互流程图

**版本**: RR-Fuzz 2.1  
**日期**: 2025-10-31

---

## 目录

1. [整体架构图](#整体架构图)
2. [Record模式流程](#record模式流程)
3. [Fuzzing模式详细流程](#fuzzing模式详细流程)
4. [IPC通信序列图](#ipc通信序列图)
5. [Mutation应用流程](#mutation应用流程)
6. [Coverage反馈循环](#coverage反馈循环)

---

## 1. 整体架构图

```mermaid
graph TB
    subgraph "User Space - Python侧"
        A[PathFinder<br/>静态分析] --> B[TraceAnalyzer<br/>Trace解析]
        B --> C[SmartMutator<br/>变异引擎]
        C --> D[FuzzConductor<br/>主控制器]
        E[CoverageGuidedFuzzer<br/>反馈引擎] --> D
    end
    
    subgraph "IPC Layer"
        F[Shared Memory<br/>64KB Fuzzing Instructions]
        G[Pipes<br/>cmd_pipe + status_pipe]
        H[Coverage Map<br/>64KB Edge Bitmap]
    end
    
    subgraph "User Space - QEMU侧"
        I[RR Framework Core<br/>rr_main.c]
        J[Record Module<br/>rr_record.c]
        K[Replay Module<br/>rr_replay.c]
        L[Fuzzing Engine<br/>rr_fuzz_engine.c]
        M[Coverage Tracker<br/>rr_coverage.c]
        N[BB Trace<br/>rr_bb_trace.c]
    end
    
    subgraph "Target Program"
        O[User Application<br/>被测程序]
    end
    
    D -->|写入Mutation指令| F
    D -->|发送命令 'F'| G
    G -->|返回Status| D
    D -->|读取Coverage| H
    
    F --> L
    G --> I
    M --> H
    
    I --> J
    I --> K
    I --> L
    L --> K
    K --> N
    L --> M
    
    K -->|Syscall拦截| O
    J -->|Syscall录制| O
    
    style D fill:#e1f5ff
    style L fill:#ffe1e1
    style F fill:#fff4e1
    style G fill:#fff4e1
    style H fill:#e1ffe1
```

---

## 2. Record模式流程

```mermaid
sequenceDiagram
    participant User as 用户
    participant Env as 环境变量
    participant QEMU as QEMU Process
    participant Target as Target Program
    participant Trace as Trace Files
    
    User->>Env: 设置 RR_MODE=record
    User->>Env: 设置 RR_TRACE_FILE=trace.dat
    User->>QEMU: 启动 qemu-x86_64 ./target
    
    QEMU->>QEMU: rr_framework_init()
    QEMU->>QEMU: rr_record_init()
    QEMU->>QEMU: rr_bb_trace_init()
    
    QEMU->>Target: fork() + execve()
    
    loop 程序执行
        Target->>QEMU: syscall(read, fd, buf, len)
        QEMU->>QEMU: do_syscall() 拦截
        QEMU->>QEMU: rr_record_syscall_entry()<br/>记录: nr, args
        QEMU->>QEMU: 执行真实syscall
        QEMU->>QEMU: rr_record_syscall_exit()<br/>记录: retval, aux_data
        QEMU->>Trace: 写入 syscall record
        
        Note over QEMU,Target: 每个BB执行时
        Target->>QEMU: TB执行 (TCG)
        QEMU->>QEMU: rr_bb_trace_log(pc)
        QEMU->>Trace: 写入 BB entry
    end
    
    Target->>QEMU: exit(0)
    QEMU->>Trace: 写入 trace.dat (完整)
    QEMU->>Trace: 写入 trace.dat.bbl (完整)
    QEMU->>User: 程序退出
    
    Note over Trace: trace.dat: Syscall trace<br/>trace.dat.bbl: BB trace
```

---

## 3. Fuzzing模式详细流程

```mermaid
sequenceDiagram
    participant Python as FuzzConductor<br/>(Python)
    participant SHM as Shared Memory<br/>(64KB)
    participant Pipe as Pipes<br/>(cmd+status)
    participant QEMU as QEMU Process
    participant Engine as Fuzz Engine
    participant Replay as Replay Module
    participant Target as Target Program
    participant Cov as Coverage Map
    
    Note over Python,QEMU: === 初始化阶段 ===
    Python->>Python: 创建 pipes
    Python->>SHM: 创建共享内存
    Python->>QEMU: fork() + exec qemu
    QEMU->>QEMU: rr_framework_init()<br/>mode=FUZZING
    QEMU->>QEMU: rr_replay_init()
    QEMU->>QEMU: rr_fuzz_engine_init()
    QEMU->>Cov: rr_coverage_init()
    QEMU->>Pipe: 发送 READY (status=1)
    Python->>Pipe: 接收 READY
    
    Note over Python,QEMU: === 主Fuzzing循环 ===
    loop 每轮迭代
        Python->>Python: SmartMutator.build_instructions(i)
        Python->>SHM: 写入 FuzzSharedMemory<br/>magic=0x46555A5A<br/>sequence=N<br/>instructions[3]
        Python->>Pipe: 发送 'F' 命令
        
        QEMU->>Pipe: 读取 'F'
        QEMU->>Engine: rr_fuzz_engine_check_command()
        Engine->>SHM: 读取并验证指令
        Engine->>Engine: 复制到本地缓冲区
        
        Note over QEMU,Target: === Replay + Mutation ===
        QEMU->>Target: 开始执行程序
        
        loop 每个Syscall
            Target->>Replay: syscall(nr, args...)
            Replay->>Replay: rr_replay_syscall()<br/>从trace读取record
            Replay->>Replay: 恢复 retval, aux_data
            
            alt 需要应用Mutation
                Engine->>Engine: rr_apply_mutations(record)
                Engine->>Engine: 检查 syscall_index 匹配
                Engine->>Engine: 根据cmd类型变异数据<br/>FLIP_BITS / REPLACE_BUFFER / ...
                Engine->>Replay: 返回变异后的数据
            end
            
            Replay->>Target: 返回 syscall 结果
            
            Note over Target,Cov: BB执行时更新Coverage
            Target->>Cov: 每个BB触发<br/>rr_coverage_update(from, to)
        end
        
        alt 程序正常退出
            Target->>QEMU: exit(0)
            QEMU->>Pipe: 发送 status=3 (Normal Exit)
        else 程序Crash
            Target->>QEMU: SIGSEGV / SIGABRT
            QEMU->>Pipe: 发送 status=4 (Crash Found)
        end
        
        Python->>Pipe: 接收 status
        Python->>Cov: 读取 coverage map
        Python->>Python: 检查新 coverage
        
        alt 发现新Coverage
            Python->>Python: SeedQueue.add(new_seed)
            Python->>Python: 调整 energy
        end
        
        alt 发现Crash
            Python->>Python: 保存 crash input
            Python->>Python: Break loop
        end
    end
    
    Note over Python,QEMU: === 清理阶段 ===
    Python->>QEMU: 发送 'S' (Stop)
    QEMU->>QEMU: rr_framework_cleanup()
    Python->>Python: 打印统计信息
```

---

## 4. IPC通信序列图

```mermaid
sequenceDiagram
    participant P as Python<br/>FuzzConductor
    participant CM as cmd_pipe<br/>(P→Q)
    participant SM as status_pipe<br/>(Q→P)
    participant SH as Shared Memory<br/>(/dev/shm)
    participant Q as QEMU<br/>Fuzz Engine
    
    Note over P,Q: 初始化
    P->>SH: shm_open("rr_fuzz_PID")
    P->>SH: ftruncate(64KB)
    P->>SH: mmap()
    P->>CM: pipe()
    P->>SM: pipe()
    P->>Q: fork() + exec
    Q->>SH: shm_open("rr_fuzz_PID")
    Q->>SH: mmap()
    Q->>CM: 打开 read end
    Q->>SM: 打开 write end
    Q->>SM: write(READY)
    SM->>P: read() = READY
    
    Note over P,Q: Fuzzing迭代
    P->>P: 生成 instructions[3]
    P->>SH: mem[0:32] = Header<br/>(magic, seq, count, checksum)
    P->>SH: mem[32:312] = instructions[0]
    P->>SH: mem[312:592] = instructions[1]
    P->>SH: mem[592:872] = instructions[2]
    P->>SH: msync() / flush()
    
    P->>CM: write('F')
    CM->>Q: read() = 'F'
    Q->>SH: 读取 magic, 验证
    Q->>SH: 读取 sequence, 验证
    Q->>SH: 读取 checksum, 验证
    Q->>SH: 复制 instructions 到本地
    Q->>Q: 开始 replay + fuzzing
    Q->>Q: ... 执行程序 ...
    Q->>Q: 检测到 exit(0)
    Q->>SM: write(status=3)
    SM->>P: read() = 3
    
    P->>P: 解析 status
    P->>P: 进入下一轮
```

---

## 5. Mutation应用流程

```mermaid
flowchart TD
    A[Target程序执行] --> B{遇到Syscall?}
    B -->|是| C[do_syscall 拦截]
    B -->|否| A
    
    C --> D[rr_replay_syscall]
    D --> E[从trace读取record]
    E --> F[获取: syscall_nr, args, retval, aux_data]
    
    F --> G{Fuzzing模式?}
    G -->|否| M[直接返回record数据]
    G -->|是| H[rr_apply_mutations]
    
    H --> I{有匹配的instruction?}
    I -->|否| M
    I -->|是| J[遍历所有instructions]
    
    J --> K{syscall_index匹配?}
    K -->|否| J
    K -->|是| L{检查cmd类型}
    
    L -->|REPLACE_BUFFER| N[替换aux_data缓冲区]
    L -->|FLIP_BITS| O[翻转指定bit]
    L -->|OVERWRITE_AT_OFFSET| P[在offset处写入data]
    L -->|TRUNCATE| Q[截断数据]
    L -->|EXTEND| R[扩展数据]
    L -->|INTERESTING_VALUES| S[注入特殊值]
    L -->|其他8种| T[对应的mutation操作]
    
    N --> U[更新record的aux_data]
    O --> U
    P --> U
    Q --> U
    R --> U
    S --> U
    T --> U
    
    U --> V[继续检查下一个instruction]
    V --> K
    
    M --> W[将数据复制到Target内存]
    W --> X[Target继续执行<br/>使用变异后的数据]
    X --> Y{程序行为}
    
    Y -->|正常| Z[继续执行]
    Y -->|Crash| AA[捕获SIGSEGV]
    Y -->|新路径| AB[触发新BB]
    
    Z --> A
    AA --> AC[报告Crash]
    AB --> AD[更新Coverage]
    AD --> A
    
    style H fill:#ffe1e1
    style L fill:#fff4e1
    style U fill:#e1ffe1
    style AA fill:#ff9999
    style AB fill:#99ff99
```

---

## 6. Coverage反馈循环

```mermaid
flowchart TB
    subgraph "初始化"
        A[加载初始trace] --> B[解析BB序列]
        B --> C[创建初始Seed]
        C --> D[添加到SeedQueue]
        D --> E[初始化CoverageTracker]
    end
    
    subgraph "主循环"
        F[从SeedQueue选择Seed] --> G{按优先级}
        G -->|HIGH| H1[高优先级Seed<br/>energy=2.0]
        G -->|NORMAL| H2[普通Seed<br/>energy=1.0]
        G -->|LOW| H3[低优先级Seed<br/>energy=0.5]
        
        H1 --> I[生成Mutation]
        H2 --> I
        H3 --> I
        
        I --> J[执行Fuzzing]
        J --> K[收集Coverage]
        
        K --> L{检查新Coverage}
        L -->|有新edge| M[计算新edge数量]
        L -->|无新| N[能量-=0.1]
        
        M --> O[创建新Seed]
        O --> P{评估重要性}
        
        P -->|新edge > 10| Q[优先级=HIGH<br/>energy=2.0]
        P -->|新edge > 3| R[优先级=NORMAL<br/>energy=1.5]
        P -->|新edge > 0| S[优先级=LOW<br/>energy=1.0]
        
        Q --> T[添加到队列]
        R --> T
        S --> T
        
        N --> U{energy > 0.1?}
        U -->|是| V[重新加入队列<br/>降低优先级]
        U -->|否| W[从队列移除]
        
        T --> X{队列大小}
        V --> X
        W --> X
        
        X -->|< max_size| Y[保留所有]
        X -->|≥ max_size| Z[修剪低能量Seed]
        
        Y --> F
        Z --> F
    end
    
    subgraph "统计"
        AA[Total Iterations]
        AB[New Coverage Seeds]
        AC[Crashes Found]
        AD[Queue Size]
        AE[Coverage Growth Rate]
    end
    
    J --> AA
    T --> AB
    J --> AC
    X --> AD
    K --> AE
    
    style M fill:#e1ffe1
    style Q fill:#ffe1e1
    style AC fill:#ff9999
    style T fill:#e1f5ff
```

---

## 7. PathFinder PIE地址映射流程

```mermaid
flowchart TD
    A[开始: PathFinder.map_trace_to_cfg] --> B[加载Binary]
    B --> C{检查ELF类型}
    C -->|ET_EXEC| D[non-PIE程序]
    C -->|ET_DYN| E[PIE程序]
    
    D --> F[直接映射<br/>CFG地址 = Trace地址]
    
    E --> G[启动PIE地址搜索]
    
    G --> H[采样Trace地址]
    H --> I[采样: 前100个BB]
    
    G --> J[采样CFG节点]
    J --> K[采样: 10个分位点]
    
    I --> L[生成候选Delta]
    K --> L
    
    L --> M[策略1: Trace×CFG配对<br/>30个trace × 10个cfg]
    M --> N[策略2: 常见PIE基址<br/>8个预定义基址]
    N --> O[策略3: 地址分布启发式<br/>min对齐, max对齐]
    
    O --> P[得到候选deltas集合<br/>约300个候选]
    
    P --> Q[测试每个delta]
    Q --> R{遍历所有delta}
    
    R --> S[normalized = trace - delta]
    S --> T[指标1: 基础匹配率<br/>匹配的BB数 / 总BB数]
    T --> U[指标2: 精确匹配率<br/>exact匹配数 / 总BB数]
    U --> V[指标3: 连续匹配奖励<br/>最长连续匹配 / 总BB数]
    V --> W[指标4: 地址范围相似度<br/>在CFG范围内的BB / 总BB数]
    
    W --> X[综合评分<br/>= 0.5×指标1 + 0.2×指标2<br/>+ 0.2×指标3 + 0.1×指标4]
    
    X --> Y{score > best_score?}
    Y -->|是| Z[更新 best_delta, best_score]
    Y -->|否| R
    
    Z --> R
    R -->|所有delta测试完| AA{best_score ≥ 30%?}
    
    AA -->|是| AB[✅ 找到良好映射<br/>使用 best_delta]
    AA -->|否| AC[⚠️ 低匹配率<br/>仍使用 best_delta]
    
    F --> AD[开始映射每个BB]
    AB --> AD
    AC --> AD
    
    AD --> AE{遍历trace BBs}
    AE --> AF[normalized_pc = pc - delta]
    AF --> AG{查找CFG节点}
    
    AG -->|精确匹配| AH[covered_blocks.add]
    AG -->|容差匹配| AI[在±tolerance范围内搜索]
    AI -->|找到| AH
    AI -->|未找到| AJ[unmatched++]
    
    AH --> AE
    AJ --> AE
    AE -->|所有BB处理完| AK[计算未覆盖分支]
    
    AK --> AL[uncovered = all_nodes - covered]
    AL --> AM[返回 covered, uncovered]
    
    style E fill:#ffe1e1
    style P fill:#fff4e1
    style X fill:#e1ffe1
    style AB fill:#99ff99
    style AC fill:#ffaa99
```

---

## 8. 数据结构关系图

```mermaid
classDiagram
    class FuzzSharedMemory {
        +uint32_t magic
        +uint32_t sequence
        +uint32_t instruction_count
        +uint32_t checksum
        +uint32_t flags
        +FuzzInstruction instructions[32]
    }
    
    class FuzzInstruction {
        +fuzz_cmd_type_t cmd
        +uint32_t syscall_index
        +uint32_t arg_index
        +uint32_t offset
        +uint32_t size
        +uint32_t data_len
        +uint8_t data[256]
    }
    
    class syscall_record {
        +uint32_t index
        +int syscall_nr
        +abi_long args[8]
        +abi_long retval
        +uint8_t* arg_data[8]
        +size_t arg_size[8]
        +rr_aux_data* aux_data
        +bool has_aux_data
        +syscall_record* next
    }
    
    class rr_aux_data {
        +uint8_t kind
        +uint8_t arg_mask
        +uint32_t size
        +void* data
        +rr_aux_data* next
    }
    
    class rr_bb_entry {
        +uint64_t pc
        +uint32_t syscall_idx
        +uint32_t flags
    }
    
    class Seed {
        +str seed_id
        +str trace_file
        +Set~int~ coverage
        +float energy
        +SeedPriority priority
        +str parent_id
        +int generation
        +bool crash
    }
    
    class SeedQueue {
        +List~Seed~ seeds
        +Dict seed_map
        +Set coverage_hashes
        +add()
        +pop()
        +update_energy()
    }
    
    class CoverageTracker {
        +Set~int~ global_coverage
        +Dict edge_coverage
        +update()
        +get_coverage_rate()
    }
    
    FuzzSharedMemory "1" --> "0..32" FuzzInstruction : contains
    syscall_record "1" --> "0..*" rr_aux_data : has
    SeedQueue "1" --> "*" Seed : manages
    Seed "1" --> "1" CoverageTracker : tracks
    
    note for FuzzSharedMemory "Python写入\nQEMU读取"
    note for syscall_record "QEMU内部\nTrace格式"
    note for Seed "Python侧\nCoverage反馈"
```

---

## 9. 时序对比：Record vs Replay vs Fuzzing

```mermaid
gantt
    title Syscall执行时序对比
    dateFormat X
    axisFormat %L ms
    
    section Record模式
    syscall entry hook    :0, 1
    真实syscall执行       :1, 15
    读取返回数据          :15, 17
    记录到trace           :17, 20
    syscall exit hook     :20, 21
    
    section Replay模式
    syscall entry hook    :0, 1
    从trace读取record     :1, 3
    恢复retval+aux_data   :3, 5
    跳过真实执行          :5, 5
    syscall exit hook     :5, 6
    
    section Fuzzing模式
    syscall entry hook    :0, 1
    从trace读取record     :1, 3
    检查mutation指令      :3, 5
    应用mutation          :5, 8
    恢复+变异的数据       :8, 10
    跳过真实执行          :10, 10
    更新coverage          :10, 12
    syscall exit hook     :12, 13
```

**对比分析**:
- Record: ~21ms（真实执行开销大）
- Replay: ~6ms（跳过真实执行，提速3.5x）
- Fuzzing: ~13ms（额外mutation开销，仍比Record快1.6x）

---

## 10. 错误处理流程

```mermaid
flowchart TD
    A[开始Fuzzing] --> B{共享内存验证}
    B -->|Magic错误| C[错误: Invalid Magic]
    B -->|Checksum错误| D[错误: Checksum Mismatch]
    B -->|✅ 验证通过| E[读取Instructions]
    
    C --> Z[返回错误]
    D --> Z
    
    E --> F{Syscall执行}
    F --> G{Trace匹配}
    G -->|索引越界| H[错误: Index Out of Range]
    G -->|Syscall不匹配| I[警告: Syscall Mismatch<br/>尝试继续]
    G -->|✅ 匹配| J[应用Mutation]
    
    H --> Z
    I --> J
    
    J --> K{Mutation操作}
    K -->|数据大小错误| L[警告: Size Mismatch<br/>截断或填充]
    K -->|Offset越界| M[警告: Offset OOB<br/>调整到边界]
    K -->|✅ 正常| N[执行Mutation]
    
    L --> N
    M --> N
    
    N --> O{程序执行}
    O -->|SIGSEGV| P[捕获: Segmentation Fault]
    O -->|SIGABRT| Q[捕获: Abort]
    O -->|Timeout| R[捕获: Execution Timeout]
    O -->|✅ 正常退出| S[收集Coverage]
    
    P --> T[保存Crash Info]
    Q --> T
    R --> T
    
    T --> U[报告Crash<br/>status=4]
    S --> V[报告Normal<br/>status=3]
    
    U --> W[Python处理]
    V --> W
    Z --> W
    
    W --> X[记录日志]
    X --> Y[继续下一轮或退出]
    
    style C fill:#ff9999
    style D fill:#ff9999
    style H fill:#ff9999
    style P fill:#ff6666
    style Q fill:#ff6666
    style R fill:#ffaa66
    style S fill:#99ff99
```

---

## 总结

这些交互图展示了RR-Fuzz的核心工作流程：

1. **架构清晰**: Python分析 + QEMU执行，职责分明
2. **IPC高效**: 共享内存传递数据 + Pipe传递控制信号
3. **Mutation精准**: 在syscall重放时刻应用变异
4. **Coverage驱动**: 实时反馈指导seed选择
5. **错误健壮**: 多层验证和错误处理

**性能特点**:
- Record: 慢（真实执行）
- Replay: 快（3.5x）
- Fuzzing: 中等（1.6x，包含mutation开销）

**可靠性**:
- 多重校验（Magic + Checksum）
- 优雅降级（部分失败仍可继续）
- 详细日志（便于调试）

---

**文档生成**: 2025-10-31  
**工具**: Mermaid + ASCII Art  
**用途**: 技术分析、团队培训、系统理解


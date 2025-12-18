# RR-Fuzz 完整系统调用图

从 `do_syscall` 开始的完整调用关系全景图。

```mermaid
flowchart TB
    %% ========== QEMU 入口层 ==========
    START([Guest 程序执行 Syscall])
    START --> QEMU_ENTRY["do_syscall<br/>📁 linux-user/syscall.c<br/>🔵 QEMU 主调度器"]
    
    %% ========== RR-Fuzz 核心层 ==========
    QEMU_ENTRY -->|Pre Hook| RR_ENTRY["rr_do_syscall<br/>📁 core/rr_main.c<br/>🟢 RR-Fuzz 入口点"]
    
    RR_ENTRY --> CHECK_ENABLED{RR-Fuzz<br/>已启用?}
    CHECK_ENABLED -->|否| SKIP_TO_REAL
    CHECK_ENABLED -->|是| MODE_SELECT{运行模式?}
    
    %% ========== 三大模式分支 ==========
    MODE_SELECT -->|RECORD| RECORD_FLOW
    MODE_SELECT -->|REPLAY| REPLAY_FLOW
    MODE_SELECT -->|FUZZING| FUZZING_FLOW
    
    %% ========== RECORD 模式子图 ==========
    subgraph RECORD_FLOW ["🟩 RECORD 模式"]
        REC_START["rr_record_syscall<br/>📁 record/rr_record.c"]
        REC_START --> REC_EXEC["执行真实 Syscall"]
        REC_EXEC --> REC_AUX_CHK{需要捕获<br/>aux_data?}
        REC_AUX_CHK -->|是| REC_AUX["capture_syscall_args_aux<br/>📝 捕获缓冲区/随机数"]
        REC_AUX_CHK -->|否| REC_WRITE
        REC_AUX --> REC_CREATE_AUX["rr_aux_create<br/>📁 record/rr_aux_data.c<br/>📝 创建 aux 节点"]
        REC_CREATE_AUX --> REC_WRITE["写入 Trace 文件<br/>📝 二进制格式"]
        REC_WRITE --> REC_MAP["更新 FD/地址映射<br/>📁 utils/rr_mapping_manager.c"]
    end
    
    %% ========== REPLAY 模式子图 ==========
    subgraph REPLAY_FLOW ["🟨 REPLAY 模式"]
        REP_START["read_next_record<br/>📁 replay/rr_replay.c<br/>📝 读取 trace 记录"]
        REP_START --> REP_DISPATCH["rr_replay_syscall<br/>📝 Replay 调度器"]
        REP_DISPATCH --> REP_HAS_AUX{有 aux_data?}
        
        %% Pure Replay 分支
        REP_HAS_AUX -->|是| REP_PURE["rr_replay_syscall_pure<br/>📁 replay/rr_replay_pure.c<br/>📝 尝试 Pure Replay"]
        REP_PURE --> REP_PURE_OK{Pure 成功?}
        REP_PURE_OK -->|是| REP_RESTORE["从 aux_data 恢复状态<br/>📝 跳过真实 syscall!"]
        REP_PURE_OK -->|否| REP_HYBRID
        
        %% Hybrid Replay 分支
        REP_HAS_AUX -->|否| REP_HYBRID
        REP_HYBRID["执行真实 Syscall<br/>📝 Hybrid 模式"]
        REP_HYBRID --> REP_MAP["应用 FD/地址映射<br/>📁 utils/rr_mapping_manager.c<br/>📝 翻译 ASLR 差异"]
        REP_MAP --> REP_VERIFY["验证返回值"]
    end
    
    %% ========== FUZZING 模式子图 ==========
    subgraph FUZZING_FLOW ["🟥 FUZZING 模式"]
        %% Fork Server 入口
        FUZZ_FORK_SERVER["Fork Server 主循环<br/>📁 utils/rr_fork_server.c"]
        FUZZ_FORK_SERVER --> FUZZ_CMD["接收命令<br/>📁 utils/rr_ipc.c"]
        FUZZ_CMD --> FUZZ_CMD_TYPE{命令类型?}
        
        FUZZ_CMD_TYPE -->|F: Fork| FUZZ_FORK_STD["fork() 标准模式"]
        FUZZ_CMD_TYPE -->|B: Batch| FUZZ_FORK_BATCH["fork() N 个子进程"]
        FUZZ_CMD_TYPE -->|C: Checkpoint| FUZZ_FORK_CKPT["fork() 中点恢复"]
        
        FUZZ_FORK_STD --> FUZZ_CHILD
        FUZZ_FORK_BATCH --> FUZZ_CHILD
        FUZZ_FORK_CKPT --> FUZZ_CHILD
        
        %% 子进程执行流
        FUZZ_CHILD["子进程: 重放 + 变异"]
        FUZZ_CHILD --> FUZZ_LOAD["加载变异指令<br/>📁 fuzzing/.../rr_fuzz_engine.c<br/>📝 从共享内存读取"]
        
        FUZZ_LOAD --> FUZZ_MUTATE["应用变异<br/>📝 rr_fuzz_mutate_syscall"]
        FUZZ_MUTATE --> FUZZ_MUT_TYPE{变异类型?}
        
        FUZZ_MUT_TYPE -->|参数变异| FUZZ_MUT_ARG["MUTATE_ARG<br/>📝 修改整数参数"]
        FUZZ_MUT_TYPE -->|缓冲区替换| FUZZ_MUT_BUF["REPLACE_BUFFER<br/>📝 覆写缓冲区"]
        FUZZ_MUT_TYPE -->|位翻转| FUZZ_MUT_FLIP["FLIP_BITS<br/>📝 AFL 位翻转"]
        FUZZ_MUT_TYPE -->|返回值覆盖| FUZZ_MUT_RET["RETVAL_OVERRIDE<br/>📝 覆盖返回值"]
        FUZZ_MUT_TYPE -->|定向变异| FUZZ_MUT_OFF["OVERWRITE_AT_OFFSET<br/>📝 PathFinder 引导"]
        
        FUZZ_MUT_ARG --> FUZZ_EXEC
        FUZZ_MUT_BUF --> FUZZ_EXEC
        FUZZ_MUT_FLIP --> FUZZ_EXEC
        FUZZ_MUT_RET --> FUZZ_EXEC
        FUZZ_MUT_OFF --> FUZZ_EXEC
        
        FUZZ_EXEC["执行变异后的 Syscall"]
        
        %% Aux Data 变异（高级）
        FUZZ_MUTATE -.->|可选| FUZZ_AUX_MUT["Aux Data 变异<br/>📁 fuzzing/.../rr_fuzz_aux_mutations.c<br/>📝 注入漏洞 Payload"]
        
        %% 覆盖率跟踪
        FUZZ_EXEC --> FUZZ_COV["覆盖率追踪<br/>📁 fuzzing/.../rr_coverage.c<br/>📝 AFL 边覆盖 (prev>>1)^cur"]
        FUZZ_COV --> FUZZ_BITMAP["写入 Coverage Bitmap<br/>📝 共享内存"]
        
        %% 嵌套 Fork（自主）
        FUZZ_CHILD -.->|可能触发| FUZZ_NESTED["自主嵌套 Fork<br/>📁 utils/rr_nested_fork.c<br/>📝 子进程自主 fork 孙进程"]
    end
    
    %% ========== 真实 Syscall 执行 ==========
    SKIP_TO_REAL["执行真实 Syscall"]
    REC_EXEC --> SKIP_TO_REAL
    REP_HYBRID --> SKIP_TO_REAL
    FUZZ_EXEC --> SKIP_TO_REAL
    
    SKIP_TO_REAL --> REAL_SYSCALL["QEMU Syscall 处理器<br/>📁 linux-user/syscall.c"]
    
    %% ========== Post Hooks ==========
    REAL_SYSCALL --> POST_HOOK1["rr_strace_syscall_post_hook_optimized<br/>📁 utils/rr_syscall_dispatch.c<br/>⚡ 优化的 Post Hook"]
    
    POST_HOOK1 --> POST_HOOK2["rr_syscall_post_hook<br/>📁 core/rr_main.c<br/>⚠️ 遗留 Post Hook"]
    
    POST_HOOK2 --> RETURN([返回 Guest 程序])
    
    %% ========== 辅助模块（侧边连接）==========
    subgraph UTILS ["🔷 辅助模块"]
        MAP_MGR["Mapping 管理器<br/>📁 utils/rr_mapping_manager.c<br/>📝 FD/地址映射<br/>rr_fd_mapping_add/get<br/>rr_addr_mapping_add/get"]
        
        AUX_DATA["Aux Data 管理<br/>📁 record/rr_aux_data.c<br/>📝 辅助数据链表<br/>rr_aux_create<br/>rr_aux_find<br/>rr_aux_should_record"]
        
        IPC_MGR["IPC 管理<br/>📁 utils/rr_ipc.c<br/>📝 Python 通信<br/>rr_ipc_receive_command<br/>rr_ipc_send_status"]
        
        DYN_TRACE["动态跟踪<br/>📁 utils/rr_dynamic_trace.c<br/>📝 实时事件流<br/>rr_dynamic_trace_fork<br/>rr_dynamic_trace_syscall_enter/exit"]
        
        TREE_BUILD["执行树构建<br/>📁 utils/rr_syscall_tree.c<br/>📝 内存执行树<br/>rr_tree_add_syscall_node<br/>rr_tree_export_json"]
    end
    
    %% 辅助模块的连接关系
    REC_MAP -.->|使用| MAP_MGR
    REP_MAP -.->|使用| MAP_MGR
    REC_CREATE_AUX -.->|使用| AUX_DATA
    REP_PURE -.->|使用| AUX_DATA
    FUZZ_CMD -.->|使用| IPC_MGR
    FUZZ_FORK_STD -.->|通知| DYN_TRACE
    FUZZ_CHILD -.->|记录| TREE_BUILD
    
    %% ========== 样式定义 ==========
    classDef qemu fill:#e3f2fd,stroke:#1976d2,stroke-width:3px,color:#000
    classDef core fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px,color:#000
    classDef record fill:#c8e6c9,stroke:#388e3c,stroke-width:2px,color:#000
    classDef replay fill:#ffe0b2,stroke:#e65100,stroke-width:2px,color:#000
    classDef fuzzing fill:#ffcdd2,stroke:#c62828,stroke-width:2px,color:#000
    classDef decision fill:#fff9c4,stroke:#f57c00,stroke-width:2px,color:#000
    classDef utility fill:#e0e0e0,stroke:#616161,stroke-width:2px,color:#000
    classDef aux fill:#b2ebf2,stroke:#00838f,stroke-width:2px,color:#000
    
    class QEMU_ENTRY,REAL_SYSCALL qemu
    class RR_ENTRY,POST_HOOK2 core
    class REC_START,REC_AUX,REC_CREATE_AUX,REC_WRITE,REC_MAP record
    class REP_START,REP_DISPATCH,REP_PURE,REP_HYBRID,REP_MAP,REP_VERIFY replay
    class FUZZ_FORK_SERVER,FUZZ_LOAD,FUZZ_MUTATE,FUZZ_EXEC,FUZZ_COV,FUZZ_BITMAP fuzzing
    class CHECK_ENABLED,MODE_SELECT,REC_AUX_CHK,REP_HAS_AUX,REP_PURE_OK,FUZZ_CMD_TYPE,FUZZ_MUT_TYPE decision
    class MAP_MGR,IPC_MGR,DYN_TRACE,TREE_BUILD utility
    class AUX_DATA aux
```

## 📊 调用图说明

### 🔵 蓝色：QEMU 集成层
- **do_syscall**: QEMU 的系统调用入口
- **真实 Syscall 处理器**: 执行实际的系统调用

### 🟢 绿色：RR-Fuzz 核心 + Record 模式
- **rr_do_syscall**: RR-Fuzz 的统一入口点
- **Record 路径**: 记录 syscall 到 trace 文件

### 🟨 黄色：Replay 模式
- **Pure Replay**: 从 aux_data 恢复，无需真实 syscall
- **Hybrid Replay**: 执行真实 syscall，使用映射翻译

### 🟥 红色：Fuzzing 模式
- **Fork Server**: 持久化 fuzzing 框架
- **Mutation Engine**: 7 种变异策略
- **Coverage Tracking**: AFL 风格边覆盖

### 🔷 灰色：辅助模块
- **Mapping Manager**: 解决 ASLR 问题
- **Aux Data**: Pure Replay 核心数据
- **IPC**: Python ↔ C 通信桥梁

### ⚠️ 黄色菱形：关键决策点
- 是否启用 RR-Fuzz？
- 当前运行模式？
- 是否有 aux_data？
- Pure Replay 是否成功？

## 🎯 三大执行路径

### 路径 1: Record (绿色)
```
do_syscall → rr_do_syscall → rr_record_syscall 
→ 执行真实 syscall → 捕获 aux_data → 写入 trace → 更新映射
```

### 路径 2: Replay (黄色)
```
do_syscall → rr_do_syscall → read_next_record → rr_replay_syscall
├─ Pure: 从 aux_data 恢复 → 跳过真实 syscall
└─ Hybrid: 执行真实 syscall → 应用映射翻译
```

### 路径 3: Fuzzing (红色)
```
Fork Server 循环 → 接收命令 → fork() 
→ 子进程: 加载变异 → 应用变异 → 执行 syscall → 记录覆盖率
```

## 🔗 关键模块依赖

```
Record ──使用──> Mapping Manager
             └──> Aux Data Manager

Replay ──使用──> Mapping Manager  
             └──> Aux Data Manager

Fuzzing ──使用──> IPC Manager
              ├──> Coverage Tracker
              ├──> Dynamic Trace
              └──> Fork Server
```

---

**说明**: 
- 实线箭头 (→) 表示直接函数调用
- 虚线箭头 (-.→) 表示模块依赖或可选调用
- 子图表示功能模块的边界

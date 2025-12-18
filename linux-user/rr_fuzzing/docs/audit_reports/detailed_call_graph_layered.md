# RR-Fuzz 详细调用图（优化版）

优化的完整调用关系图，解决了Mermaid解析问题。

由于完整的超详细图表过于复杂，我创建了**分层视图**：

## 📊 第1层：核心入口与模式选择

```mermaid
flowchart TB
    START([Guest Syscall])
    START --> QEMU["do_syscall<br/>syscall.c"]
    
    QEMU -->|Pre-Hook| RR_ENTRY["rr_do_syscall<br/>core/rr_main.c"]
    
    RR_ENTRY --> CHK{框架已初始化?}
    CHK -->|No| REAL
    CHK -->|Yes| MODE{当前模式?}
    
    MODE -->|RECORD| REC_FLOW[" 🟩 RECORD 流程"]
    MODE -->|REPLAY| REP_FLOW["🟨 REPLAY 流程"]
    MODE -->|FUZZING| FUZZ_FLOW["🟥 FUZZING 流程"]
    
    REC_FLOW --> REAL["执行真实 Syscall<br/>syscall.c"]
    REP_FLOW --> REAL
    FUZZ_FLOW --> REAL
    
    REAL --> POST["Post Hooks"]
    POST --> RETURN([返回])
    
    class QEMU,REAL qemu
    class RR_ENTRY core
    class REC_FLOW record
    class REP_FLOW replay
    class FUZZ_FLOW fuzzing
    
    classDef qemu fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef core fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    classDef record fill:#a5d6a7,stroke:#388e3c,stroke-width:2px
    classDef replay fill:#ffcc80,stroke:#e65100,stroke-width:2px
    classDef fuzzing fill:#ef9a9a,stroke:#c62828,stroke-width:2px
```

## 📊 第2层：RECORD 模式详细流程

```mermaid
flowchart TB
    REC_START["rr_record_syscall<br/>record/rr_record.c"]
    
    REC_START --> REC_ALLOC["分配 syscall_record_t"]
    REC_ALLOC --> REC_FILL["填充基本信息"]
    REC_FILL --> REC_EXEC["执行真实 Syscall"]
    
    REC_EXEC --> REC_AUX_CHK{需要捕获<br/>aux_data?}
    REC_AUX_CHK -->|Yes| REC_CAP_AUX["capture_syscall_args_aux<br/>record/rr_record.c"]
    REC_AUX_CHK -->|No| REC_UPDATE_MAP
    
    REC_CAP_AUX --> REC_AUX_CREATE["rr_aux_create<br/>record/rr_aux_data.c"]
    REC_AUX_CREATE --> REC_AUX_APPEND["rr_aux_append"]
    
    REC_AUX_APPEND --> REC_UPDATE_MAP["更新映射表"]
    
    REC_UPDATE_MAP --> REC_FD_CHK{返回 FD?}
    REC_FD_CHK -->|Yes| REC_FD_MAP["rr_fd_mapping_add<br/>mapping_manager.c"]
    REC_FD_CHK -->|No| REC_ADDR_CHK
    
    REC_FD_MAP --> REC_ADDR_CHK{返回地址?}
    REC_ADDR_CHK -->|Yes| REC_ADDR_MAP["rr_addr_mapping_add"]
    REC_ADDR_CHK -->|No| REC_WRITE
    
    REC_ADDR_MAP --> REC_WRITE["fwrite(record, trace_file)"]
    REC_WRITE --> REC_DONE([完成])
    
    class REC_START,REC_CAP_AUX,REC_AUX_CREATE record
    classDef record fill:#a5d6a7,stroke:#388e3c,stroke-width:2px
```

## 📊 第3层：REPLAY 模式详细流程

```mermaid
flowchart TB
    REP_START["rr_replay_syscall<br/>replay/rr_replay.c"]
    
    REP_START --> REP_READ["read_next_record<br/>从 trace 读取"]
    REP_READ --> REP_PARSE["解析记录:<br/>magic, syscall_nr, args, aux"]
    
    REP_PARSE --> REP_HAS_AUX{有 aux_data?}
    
    REP_HAS_AUX -->|Yes| REP_TRY_PURE["rr_replay_syscall_pure<br/>replay/rr_replay_pure.c"]
    
    REP_TRY_PURE --> REP_PURE_TYPE{syscall 类型?}
    REP_PURE_TYPE -->|read| REP_PURE_READ["从 aux 恢复 buffer"]
    REP_PURE_TYPE -->|getrandom| REP_PURE_RAND["从 aux 恢复随机数"]
    REP_PURE_TYPE -->|recv| REP_PURE_RECV["从 aux 恢复网络数据"]
    REP_PURE_TYPE -->|其他| REP_HYBRID
    
    REP_PURE_READ --> REP_SKIP["跳过真实 syscall"]
    REP_PURE_RAND --> REP_SKIP
    REP_PURE_RECV --> REP_SKIP
    
    REP_HAS_AUX -->|No| REP_HYBRID
    REP_HYBRID["Hybrid Replay"]
    
    REP_HYBRID --> REP_MAP_FD["rr_fd_mapping_get<br/>翻译 FD"]
    REP_MAP_FD --> REP_MAP_ADDR["rr_addr_mapping_get<br/>翻译地址"]
    
    REP_MAP_ADDR --> REP_APPLY["apply_syscall_args<br/>syscall_dispatch.c"]
    REP_APPLY --> REP_EXEC["执行真实 Syscall"]
    
    REP_EXEC --> REP_VERIFY["验证返回值"]
    REP_SKIP --> REP_DONE([完成])
    REP_VERIFY --> REP_DONE
    
    class REP_START,REP_TRY_PURE,REP_PURE_READ replay
    classDef replay fill:#ffcc80,stroke:#e65100,stroke-width:2px
```

## 📊 第4层：FUZZING 模式 - Fork Server

```mermaid
flowchart TB
    FS_INIT["rr_fork_server_init<br/>utils/rr_fork_server.c"]
    
    FS_INIT --> IPC_INIT["rr_ipc_init<br/>utils/rr_ipc.c"]
    IPC_INIT --> IPC_OPEN["打开管道:<br/>cmd_pipe, status_pipe"]
    IPC_OPEN --> IPC_SHM["rr_map_shared_memory"]
    
    IPC_SHM --> COV_INIT["rr_coverage_init<br/>fuzzing/rr_coverage.c"]
    COV_INIT --> FS_LOOP["Fork Server 主循环"]
    
    FS_LOOP --> FS_RECV["rr_ipc_receive_command"]
    FS_RECV --> FS_CMD{命令类型?}
    
    FS_CMD -->|F: Standard| FS_FORK_STD["fork() 标准模式"]
    FS_CMD -->|B: Batch| FS_FORK_BATCH["fork() N 次"]
    FS_CMD -->|C: Checkpoint| FS_FORK_CKPT["fork() 中点恢复"]
    FS_CMD -->|Q: Quit| FS_EXIT["退出"]
    
    FS_FORK_STD --> FS_CHILD{进程?}
    FS_CHILD -->|Parent| FS_WAIT["wait 子进程"]
    FS_CHILD -->|Child| CHILD_FLOW["子进程执行流"]
    
    FS_WAIT --> FS_STATUS["rr_ipc_send_status"]
    FS_STATUS --> FS_LOOP
    
    class FS_INIT,FS_LOOP,FS_FORK_STD fuzzing
    classDef fuzzing fill:#ef9a9a,stroke:#c62828,stroke-width:2px
```

## 📊 第5层：FUZZING 模式 - 子进程变异

```mermaid
flowchart TB
    CHILD_START["Child 进程开始"]
    
    CHILD_START --> CHILD_REOPEN["重新打开 trace 文件"]
    CHILD_REOPEN --> CHILD_LOAD["rr_fuzz_load_from_shared_memory<br/>fuzzing/rr_fuzz_engine.c"]
    
    CHILD_LOAD --> CHILD_VERIFY["验证 magic 和 checksum"]
    CHILD_VERIFY --> CHILD_COPY["复制变异指令到本地"]
    
    CHILD_COPY --> CHILD_REPLAY_LOOP["Replay 循环开始"]
    
    CHILD_REPLAY_LOOP --> CHILD_READ["read_next_record"]
    CHILD_READ --> CHILD_MUTATE["rr_fuzz_mutate_syscall"]
    
    CHILD_MUTATE --> CHILD_APPLY["apply_mutations_for_syscall"]
    
    CHILD_APPLY --> CHILD_MUT_TYPE{变异类型?}
    CHILD_MUT_TYPE -->|MUTATE_ARG| CHILD_MUT_ARG["修改参数值"]
    CHILD_MUT_TYPE -->|REPLACE_BUFFER| CHILD_MUT_BUF["替换缓冲区"]
    CHILD_MUT_TYPE -->|FLIP_BITS| CHILD_MUT_FLIP["翻转位"]
    CHILD_MUT_TYPE -->|RETVAL_OVERRIDE| CHILD_MUT_RET["覆盖返回值"]
    CHILD_MUT_TYPE -->|OVERWRITE_AT_OFFSET| CHILD_MUT_OFF["偏移覆写"]
    
    CHILD_MUT_ARG --> CHILD_EXEC
    CHILD_MUT_BUF --> CHILD_EXEC
    CHILD_MUT_FLIP --> CHILD_EXEC
    CHILD_MUT_RET --> CHILD_EXEC
    CHILD_MUT_OFF --> CHILD_EXEC
    
    CHILD_EXEC["执行变异后的 Syscall"]
    
    CHILD_EXEC --> CHILD_COV["rr_coverage_trace_edge"]
    CHILD_COV --> CHILD_COV_CALC["edge = (prev_pc >> 1) XOR cur_pc"]
    CHILD_COV_CALC --> CHILD_COV_UPDATE["coverage_bitmap 更新"]
    
    CHILD_COV_UPDATE --> CHILD_NEXT{更多记录?}
    CHILD_NEXT -->|Yes| CHILD_REPLAY_LOOP
    CHILD_NEXT -->|No| CHILD_EXIT["_exit(0)"]
    
    class CHILD_LOAD,CHILD_MUTATE,CHILD_COV fuzzing
    classDef fuzzing fill:#ef9a9a,stroke:#c62828,stroke-width:2px
```

## 📊 第6层：辅助模块接口

```mermaid
flowchart LR
    subgraph MAP["Mapping Manager<br/>utils/rr_mapping_manager.c"]
        M1["rr_mapping_manager_init"]
        M2["rr_fd_mapping_add"]
        M3["rr_fd_mapping_get"]
        M4["rr_addr_mapping_add"]
        M5["rr_addr_mapping_get"]
    end
    
    subgraph AUX["Aux Data Manager<br/>record/rr_aux_data.c"]
        A1["rr_aux_create"]
        A2["rr_aux_append"]
        A3["rr_aux_find"]
        A4["rr_aux_should_record"]
    end
    
    subgraph IPC["IPC Manager<br/>utils/rr_ipc.c"]
        I1["rr_ipc_init"]
        I2["rr_ipc_receive_command"]
        I3["rr_ipc_send_status"]
        I4["rr_map_shared_memory"]
    end
    
    subgraph DISP["Syscall Dispatch<br/>utils/rr_syscall_dispatch.c"]
        D1["rr_syscall_dispatch_init"]
        D2["apply_file_io_args"]
        D3["apply_memory_args"]
        D4["post_file_io_hook"]
    end
```

## 🔗 模块依赖关系

```mermaid
flowchart TB
    RECORD["Record 模式"] --> MAP_MGR["Mapping Manager"]
    RECORD --> AUX_MGR["Aux Data Manager"]
    
    REPLAY["Replay 模式"] --> MAP_MGR
    REPLAY --> AUX_MGR
    REPLAY --> DISPATCH["Syscall Dispatch"]
    
    FUZZING["Fuzzing 模式"] --> IPC_MGR["IPC Manager"]
    FUZZING --> COV["Coverage Tracker"]
    FUZZING --> FUZZ_ENG["Fuzz Engine"]
    
    class RECORD record
    class REPLAY replay
    class FUZZING fuzzing
    
    classDef record fill:#a5d6a7,stroke:#388e3c,stroke-width:2px
    classDef replay fill:#ffcc80,stroke:#e65100,stroke-width:2px
    classDef fuzzing fill:#ef9a9a,stroke:#c62828,stroke-width:2px
```

## 📈 函数调用统计

### Record 模式主要函数
1. `rr_record_syscall` - 主入口
2. `capture_syscall_args_aux` - 捕获辅助数据
3. `rr_aux_create` - 创建 aux 节点
4. `rr_fd_mapping_add` - FD 映射
5. `rr_addr_mapping_add` - 地址映射
6. `fwrite` - 写入 trace

### Replay 模式主要函数
1. `rr_replay_syscall` - 主入口
2. `read_next_record` - 读取记录
3. `rr_replay_syscall_pure` - Pure Replay 尝试
4. `rr_aux_find` - 查找 aux 数据
5. `rr_fd_mapping_get` - FD 翻译
6. `rr_addr_mapping_get` - 地址翻译
7. `apply_syscall_args` - 参数应用

### Fuzzing 模式主要函数
1. `rr_fork_server_loop` - 主循环
2. `rr_ipc_receive_command` - 接收命令
3. `fork` - 创建子进程
4. `rr_fuzz_load_from_shared_memory` - 加载指令
5. `apply_mutations_for_syscall` - 应用变异
6. `rr_coverage_trace_edge` - 覆盖率追踪
7. `rr_ipc_send_status` - 状态报告

## 🎯 关键决策点总结

| 决策点 | 位置 | 判断条件 |
|--------|------|----------|
| **RR-Fuzz 启用** | rr_do_syscall | g_rr_framework != NULL && enabled |
| **模式选择** | rr_do_syscall | mode (RECORD/REPLAY/FUZZING) |
| **Aux Data 捕获** | rr_record_syscall | rr_aux_should_record() |
| **Pure Replay** | rr_replay_syscall | aux_data != NULL && syscall 支持 |
| **Fork Server 命令** | Fork Server Loop | 'F'/'B'/'C'/'Q' |
| **变异类型** | apply_mutations | instr->cmd |

---

这个分层视图更易于理解，同时避免了 Mermaid 的解析问题。每一层都聚焦于特定的功能模块，可以独立查看。

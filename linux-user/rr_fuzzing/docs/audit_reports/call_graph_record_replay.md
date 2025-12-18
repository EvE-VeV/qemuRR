# RR-Fuzz Call Graph - Part 2: Record & Replay Flow

Record 和 Replay 模式的完整调用流程，包括 Pure Replay 和 Hybrid Replay 分支。

```mermaid
flowchart TD
    %% ===== RECORD MODE =====
    subgraph RECORD ["🟩 RECORD MODE"]
        REC_START["rr_do_syscall<br/>(mode=RECORD)"]
        
        REC_START --> REC_SYSCALL["rr_record_syscall<br/>📁 record/rr_record.c<br/>📝 Record syscall to trace"]
        
        %% Syscall execution happens here (in main flow)
        REC_SYSCALL --> EXEC_REAL["[Execute Real Syscall]"]
        
        EXEC_REAL --> REC_AUX_CHK{Should capture<br/>aux data?}
        
        REC_AUX_CHK -->|"Yes (IO syscalls)"| CAP_AUX["capture_syscall_args_aux<br/>📁 record/rr_record.c<br/>📝 Capture buffers/data"]
        REC_AUX_CHK -->|"No"| REC_WRITE
        
        CAP_AUX --> REC_WRITE["write to trace file<br/>📝 Binary format"]
        
        REC_WRITE --> UPDATE_MAP["Update FD/Addr mappings<br/>📁 utils/rr_mapping_manager.c"]
    end
    
    %% ===== REPLAY MODE =====
    subgraph REPLAY ["🟨 REPLAY MODE"]
        REP_START["rr_do_syscall<br/>(mode=REPLAY)"]
        
        REP_START --> READ_REC["read_next_record<br/>📁 replay/rr_replay.c<br/>📝 Read from trace"]
        
        READ_REC --> REP_DISPATCH["rr_replay_syscall<br/>📁 replay/rr_replay.c<br/>📝 Replay dispatcher"]
        
        REP_DISPATCH --> CHK_AUX{Has<br/>aux_data?}
        
        %% Pure Replay path
        CHK_AUX -->|"Yes"| TRY_PURE["rr_replay_syscall_pure<br/>📁 replay/rr_replay_pure.c<br/>📝 Attempt pure replay"]
        
        TRY_PURE --> PURE_CHK{Pure replay<br/>successful?}
        
        PURE_CHK -->|"Yes"| RESTORE_STATE["Restore state from aux_data<br/>📝 No real syscall needed!"]
        PURE_CHK -->|"No (unsupported)"| HYBRID
        
        %% Hybrid Replay path
        CHK_AUX -->|"No"| HYBRID
        
        HYBRID["[Execute Real Syscall]<br/>📝 Hybrid mode"]
        
        HYBRID --> APPLY_MAP["Apply FD/Addr mappings<br/>📁 utils/rr_mapping_manager.c<br/>📝 Resolve ASLR differences"]
        
        APPLY_MAP --> VERIFY["Verify return value<br/>📝 Compare with recorded"]
        
        RESTORE_STATE --> SKIP_EXEC["Skip real execution"]
        VERIFY --> UPDATE_REP_MAP["Update replay mappings"]
    end
    
    %% ===== Aux Data Management =====
    subgraph AUX_DATA ["🔷 Aux Data Management"]
        AUX_CREATE["rr_aux_create<br/>📁 record/rr_aux_data.c<br/>📝 Allocate aux node"]
        
        AUX_APPEND["rr_aux_append<br/>📝 Add to linked list"]
        
        AUX_FIND["rr_aux_find<br/>📝 Query by arg_mask"]
        
        AUX_SHOULD["rr_aux_should_record<br/>📝 Heuristic: size threshold"]
        
        AUX_CREATE --> AUX_APPEND
        AUX_APPEND --> AUX_FIND
    end
    
    CAP_AUX -.->|"Uses"| AUX_CREATE
    TRY_PURE -.->|"Uses"| AUX_FIND
    
    %% ===== Mapping Manager =====
    subgraph MAPPING ["🔷 Mapping Manager"]
        MAP_FD_ADD["rr_fd_mapping_add<br/>📁 utils/rr_mapping_manager.c<br/>📝 Record: actual_fd"]
        
        MAP_FD_GET["rr_fd_mapping_get<br/>📝 Replay: translate fd"]
        
        MAP_ADDR_ADD["rr_addr_mapping_add<br/>📝 Record: mmap addr"]
        
        MAP_ADDR_GET["rr_addr_mapping_get<br/>📝 Replay: translate addr"]
    end
    
    UPDATE_MAP -.->|"Calls"| MAP_FD_ADD
    UPDATE_MAP -.->|"Calls"| MAP_ADDR_ADD
    APPLY_MAP -.->|"Calls"| MAP_FD_GET
    APPLY_MAP -.->|"Calls"| MAP_ADDR_GET
    
    %% Styling
    classDef record fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
    classDef replay fill:#ffe0b2,stroke:#f57c00,stroke-width:2px
    classDef decision fill:#fff9c4,stroke:#f57c00,stroke-width:2px
    classDef utility fill:#e0e0e0,stroke:#616161,stroke-width:2px
    
    class REC_START,REC_SYSCALL,CAP_AUX,REC_WRITE record
    class REP_START,READ_REC,REP_DISPATCH,TRY_PURE,HYBRID replay
    class REC_AUX_CHK,CHK_AUX,PURE_CHK decision
    class AUX_CREATE,AUX_APPEND,AUX_FIND,AUX_SHOULD utility
    class MAP_FD_ADD,MAP_FD_GET,MAP_ADDR_ADD,MAP_ADDR_GET utility
```

## 关键决策点

### 1. Aux Data Capture Decision (record/rr_record.c:L245)
```c
bool should_capture_aux = rr_aux_should_record(syscall_nr, args, ret);
// Heuristic: IO syscalls + success + size > threshold
if (should_capture_aux) {
    capture_syscall_args_aux(env, num, args, ret, record);
}
```

### 2. Pure vs Hybrid Replay (replay/rr_replay.c:L85)
```c
if (record->aux_data) {
    // Try Pure Replay first
    int pure_result = rr_replay_syscall_pure(env, record, args);
    if (pure_result == 0) {
        return; // Success, skip real syscall
    }
    // Fall through to Hybrid
}
// Hybrid: execute real syscall with mapping translation
```

### 3. Pure Replay Supported Syscalls (replay/rr_replay_pure.c:L50-120)
✅ **Supported**:
- `read`, `pread64` - restore buffer content
- `getrandom` - restore random bytes
- `recv`, `recvfrom` - restore network data
- `ioctl` - restore output buffers

❌ **Not Supported** (fallback to Hybrid):
- `brk`, `mmap` - need real execution for address allocation
- `write`, `send` - output syscalls
- Most others

### 4. Mapping Manager Strategy
**Problem**: ASLR causes different memory addresses between Record & Replay.

**Solution**:
1. **Record**: Store `(recorded_fd, actual_fd)` and `(recorded_addr, actual_addr)` pairs
2. **Replay**: Translate all FD/addresses using hash table lookup (O(1))

## Known Issues

⚠️ **Double Capture Bug** (record/rr_record.c):
- If `use_legacy_capture=true`, both `capture_syscall_args()` and `capture_syscall_args_aux()` may capture the same data
- **Fix**: Set `use_legacy_capture=false` (default in new config)

## Next Steps
- [Graph 3: Fuzzing & Fork Server Flow](./call_graph_fuzzing.md)

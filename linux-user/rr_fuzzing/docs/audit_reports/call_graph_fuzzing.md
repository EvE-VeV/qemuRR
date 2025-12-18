# RR-Fuzz Call Graph - Part 3: Fuzzing & Advanced Features

Fuzzing 模式的完整调用流程，包括 Fork Server、Mutation Engine、Coverage Tracking 和 Dynamic Tracing。

```mermaid
flowchart TD
    %% ===== FUZZING MODE Entry =====
    subgraph FUZZ_ENTRY ["🟥 FUZZING MODE Entry"]
        FUZZ_START["rr_do_syscall<br/>(mode=FUZZING)"]
        
        FUZZ_START --> LOAD_INSTR["rr_fuzz_load_from_shared_memory<br/>📁 fuzzing/qemu_integration/rr_fuzz_engine.c<br/>📝 Load mutations from Python"]
        
        LOAD_INSTR --> MUTATE["rr_fuzz_mutate_syscall<br/>📝 Apply mutations"]
        
        MUTATE --> APP_MUT["apply_mutations_for_syscall<br/>📝 Mutation executor"]
        
        APP_MUT --> MUT_TYPE{Mutation<br/>Type?}
        
        MUT_TYPE -->|"MUTATE_ARG"| MUT_ARG["Modify integer args"]
        MUT_TYPE -->|"REPLACE_BUFFER"| MUT_BUF["Overwrite buffer content"]
        MUT_TYPE -->|"FLIP_BITS"| MUT_FLIP["AFL-style bit flips"]
        MUT_TYPE -->|"RETVAL_OVERRIDE"| MUT_RET["Override return value"]
        MUT_TYPE -->|"OVERWRITE_AT_OFFSET"| MUT_OFF["PathFinder-guided mutation"]
        
        MUT_ARG --> EXEC_MUTATED
        MUT_BUF --> EXEC_MUTATED
        MUT_FLIP --> EXEC_MUTATED
        MUT_RET --> EXEC_MUTATED
        MUT_OFF --> EXEC_MUTATED
        
        EXEC_MUTATED["[Execute Mutated Syscall]"]
        
        EXEC_MUTATED --> TRACK_COV["rr_coverage_trace_edge<br/>📁 fuzzing/qemu_integration/rr_coverage.c<br/>📝 AFL-style edge coverage"]
    end
    
    %% ===== Fork Server =====
    subgraph FORK_SERVER ["🔶 Fork Server Lifecycle"]
        FS_INIT["rr_fork_server_init<br/>📁 utils/rr_fork_server.c<br/>📝 Setup IPC pipes"]
        
        FS_INIT --> FS_LOOP["Fork Server Main Loop"]
        
        FS_LOOP --> RECV_CMD["rr_ipc_receive_command<br/>📁 utils/rr_ipc.c<br/>📝 Read command from Conductor"]
        
        RECV_CMD --> CMD_TYPE{Command<br/>Type?}
        
        %% Standard Fork
        CMD_TYPE -->|"'F' Fork"| FORK_STD["fork()<br/>📝 Standard persistent mode"]
        
        FORK_STD --> CHILD_STD{Process?}
        CHILD_STD -->|"Parent"| WAIT_STD["wait() for child"]
        CHILD_STD -->|"Child"| RELOAD_TRACE["Reopen trace file"]
        
        RELOAD_TRACE --> START_REPLAY["Start replay from begin"]
        
        %% Batch Fork
        CMD_TYPE -->|"'B' Batch"| FORK_BATCH["fork() N times<br/>📝 Parallel exploration"]
        
        FORK_BATCH --> CHILDREN_BATCH["N children execute"]
        
        %% Checkpoint Fork
        CMD_TYPE -->|"'C' Checkpoint"| FORK_CKPT["fork() at mid-point<br/>📁 utils/rr_checkpoint.c<br/>📝 Save checkpoint target"]
        
        FORK_CKPT --> CHILD_CKPT{Process?}
        CHILD_CKPT -->|"Parent"| WAIT_CKPT["wait()"]
        CHILD_CKPT -->|"Child"| SEEK_CKPT["Seek to checkpoint index"]
        
        SEEK_CKPT --> START_MID["Start replay from checkpoint"]
        
        %% Exit
        CMD_TYPE -->|"'Q' Quit"| FS_EXIT["Exit fork server"]
        
        WAIT_STD --> SEND_STATUS
        WAIT_CKPT --> SEND_STATUS
        
        SEND_STATUS["rr_ipc_send_status<br/>📝 Report to Conductor"]
        
        SEND_STATUS --> FS_LOOP
    end
    
    %% ===== Aux Data Mutation (Advanced) =====
    subgraph AUX_MUT ["🔷 Aux Data Mutation"]
        direction LR
        AUX_MUT_ENTRY["rr_fuzz_mutate_aux_data<br/>📁 fuzzing/qemu_integration/rr_fuzz_aux_mutations.c"]
        
        AUX_MUT_ENTRY --> AUX_STRAT{Strategy?}
        
        AUX_STRAT -->|"FLIP_BITS"| AUX_FLIP["flip_bits<br/>📝 Random bit mutations"]
        AUX_STRAT -->|"TRUNCATE"| AUX_TRUNC["truncate_data<br/>📝 Shrink buffer"]
        AUX_STRAT -->|"EXTEND"| AUX_EXT["extend_data<br/>📝 Grow buffer"]
        AUX_STRAT -->|"INJECT_VALUES"| AUX_INJ["inject_interesting_values<br/>📝 Vulnerability payloads"]
        
        AUX_INJ --> PAYLOAD{Syscall<br/>Type?}
        PAYLOAD -->|"read/recv"| PAY_IO["Format strings<br/>Buffer overflows<br/>Command injection"]
        PAYLOAD -->|"getrandom"| PAY_RAND["Weak randomness patterns"]
    end
    
    %% ===== Coverage Tracking =====
    subgraph COVERAGE ["🔷 Coverage Tracking"]
        COV_INIT["rr_coverage_init<br/>📁 fuzzing/qemu_integration/rr_coverage.c<br/>📝 Setup shared memory"]
        
        COV_TRACE["rr_coverage_trace_edge<br/>📝 (prev_pc >> 1) ^ cur_pc"]
        
        COV_BITMAP["Write to AFL bitmap<br/>📝 Global or per-process SHM"]
    end
    
    TRACK_COV -.->|"Calls"| COV_TRACE
    COV_TRACE -.->|"Updates"| COV_BITMAP
    
    %% ===== Dynamic Trace =====
    subgraph DYN_TRACE ["🔷 Dynamic Trace (Optional)"]
        DT_INIT["rr_dynamic_trace_init<br/>📁 utils/rr_dynamic_trace.c<br/>📝 Setup pipe to Visualizer"]
        
        DT_SYSCALL_ENTER["rr_dynamic_trace_syscall_enter<br/>📝 Send enter event"]
        
        DT_SYSCALL_EXIT["rr_dynamic_trace_syscall_exit<br/>📝 Send exit event"]
        
        DT_FORK["rr_dynamic_trace_fork<br/>📝 Send fork event"]
        
        DT_PIPE["Write to pipe<br/>📝 Binary struct to Python"]
    end
    
    FORK_STD -.->|"Notifies"| DT_FORK
    EXEC_MUTATED -.->|"Notifies"| DT_SYSCALL_ENTER
    TRACK_COV -.->|"Notifies"| DT_SYSCALL_EXIT
    
    DT_SYSCALL_ENTER --> DT_PIPE
    DT_SYSCALL_EXIT --> DT_PIPE
    DT_FORK --> DT_PIPE
    
    %% ===== Nested Fork (Advanced) =====
    subgraph NESTED ["🔶 Autonomous Nested Fork"]
        NESTED_CHK["rr_should_nested_fork<br/>📁 utils/rr_nested_fork.c<br/>📝 Heuristic: depth < 2"]
        
        NESTED_CHK -->|"Yes"| NESTED_FORK["rr_autonomous_nested_fork<br/>📝 Child forks grandchildren"]
        
        NESTED_FORK --> GRAND["fork() N grandchildren<br/>📝 Deep path exploration"]
    end
    
    START_REPLAY -.->|"May trigger"| NESTED_CHK
    
    %% Styling
    classDef fuzzing fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    classDef forkserver fill:#ffe0b2,stroke:#e65100,stroke-width:2px
    classDef utility fill:#e0e0e0,stroke:#616161,stroke-width:2px
    classDef decision fill:#fff9c4,stroke:#f57c00,stroke-width:2px
    
    class FUZZ_START,LOAD_INSTR,MUTATE,APP_MUT fuzzing
    class FS_INIT,FS_LOOP,FORK_STD,FORK_BATCH,FORK_CKPT forkserver
    class MUT_TYPE,CMD_TYPE,CHILD_STD,CHILD_CKPT decision
    class COV_INIT,COV_TRACE,DT_INIT utility
```

## 关键决策点

### 1. Fork Server Command Processing (utils/rr_fork_server.c:L200-350)
```c
char cmd = rr_ipc_receive_command();
switch (cmd) {
    case 'F': // Standard Fork - persistent mode
        fork_and_replay();
        break;
    case 'B': // Batch Fork - N parallel children
        batch_fork_and_replay(N);
        break;
    case 'C': // Checkpoint Fork - resume from mid-point
        checkpoint_fork(checkpoint_index);
        break;
    case 'Q': // Quit
        return;
}
```

### 2. Mutation Type Application (fuzzing/qemu_integration/rr_fuzz_engine.c:L228-465)
```c
switch (instr->cmd) {
    case FUZZ_CMD_MUTATE_ARG:         // Integer mutation
    case FUZZ_CMD_REPLACE_BUFFER:     // Buffer content replacement
    case FUZZ_CMD_FLIP_BITS:          // AFL bit flips
    case FUZZ_CMD_INTERESTING_VALUES: // Dictionary injection
    case FUZZ_CMD_OVERWRITE_AT_OFFSET: // PathFinder-guided
    case FUZZ_CMD_MUTATE_RETVAL:      // Return value override
}
```

### 3. Coverage Strategy (fuzzing/qemu_integration/rr_coverage.c:L158-250)
```c
// AFL-style edge coverage
uint32_t edge = (prev_pc >> 1) ^ cur_pc;
coverage_bitmap[edge % BITMAP_SIZE]++;
prev_pc = cur_pc;
```

**Shared Memory Strategies**:
- **Global SHM**: `RR_COVERAGE_SHM` - AFL++ compatible
- **Per-Process SHM**: `RR_COVERAGE_SHM_<PID>`
- **File-backed**: `file:/tmp/coverage.map`

### 4. Autonomous Nested Fork (utils/rr_nested_fork.c:L35-162)
**Trigger Conditions**:
1. `is_autonomous_child == true` (created by Fork Server)
2. `current_depth < 2` (prevent fork bomb)
3. `forks_this_iteration < MAX_FORKS_PER_PROCESS`
4. **Hardcoded**: Currently triggers on 5th syscall (demo/test)

**Mechanism**:
- Child process autonomously decides to fork grandchildren
- Each grandchild gets independent trace file handle
- Parent waits for all grandchildren before continuing

## Advanced Features

### Vulnerability Payload Injection
`inject_interesting_values` (rr_fuzz_aux_mutations.c:L249-372) contains hardcoded payloads:
- **Format String**: `%s%n`, `%p%x`
- **Buffer Overflow**: `'A' * N`
- **Command Injection**: `$(id)`
- **Path Traversal**: `../../etc/passwd`
- **Integer Overflow**: `0x7FFFFFFF`, `0xFFFFFFFF`

### Checkpoint Mid-Point Fork
Allows forking from arbitrary trace positions:
1. Conductor sends `'C'` command with `fork_point=50`
2. Child seeks trace file to position 50
3. Resumes replay from that point
4. **Benefit**: Skip expensive early initialization syscalls

## Integration with Python Conductor

```
Python Conductor
    ↓ (Write to Shared Memory)
[FuzzInstruction array]
    ↓ (Send Fork command via Pipe)
Fork Server (QEMU C-side)
    ↓ (fork())
Child Process
    ↓ (Replay + Mutate)
Coverage Bitmap
    ↑ (Read from Shared Memory)
Python Conductor
```

## Performance Optimizations

1. **Zero-Copy Mutations**: Shared memory avoids IPC overhead
2. **Persistent Fork Server**: Avoid QEMU startup cost
3. **Batch Forking**: Parallel exploration
4. **Pure Replay**: Skip real syscalls when possible
5. **Buffered I/O**: Reduce trace file I/O

## Next Steps
- [Main Index](./call_graph_index.md) - Overview of all graphs

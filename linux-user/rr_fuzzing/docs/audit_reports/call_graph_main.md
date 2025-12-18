# RR-Fuzz Call Graph - Part 1: Main Entry Flow

从 `do_syscall` 到模式选择的完整调用流程。

```mermaid
flowchart TD
    %% ===== QEMU Entry Point =====
    START([QEMU Guest Syscall])
    START --> DO_SYSCALL
    
    DO_SYSCALL["do_syscall<br/>📁 syscall.c<br/>📝 QEMU syscall handler"]
    
    %% Pre-execution hook
    DO_SYSCALL -->|"Pre-Hook"| RR_DO_SYSCALL
    
    RR_DO_SYSCALL["rr_do_syscall<br/>📁 core/rr_main.c<br/>📝 RR-Fuzz entry point"]
    
    %% Check if enabled
    RR_DO_SYSCALL --> CHK_ENABLED{Is RR-Fuzz<br/>enabled?}
    CHK_ENABLED -->|"No"| EXEC_SYSCALL
    CHK_ENABLED -->|"Yes"| CHK_MODE{"Current<br/>Mode?"}
    
    %% Mode branching
    CHK_MODE -->|"RECORD"| RECORD_PATH["Recording Path"]
    CHK_MODE -->|"REPLAY"| REPLAY_PATH["Replay Path"]
    CHK_MODE -->|"FUZZING"| FUZZING_PATH["Fuzzing Path"]
    CHK_MODE -->|"DISABLED"| EXEC_SYSCALL
    
    %% Real syscall execution
    EXEC_SYSCALL["Execute Real Syscall<br/>📁 syscall.c<br/>📝 Original QEMU logic"]
    
    RECORD_PATH --> EXEC_SYSCALL
    REPLAY_PATH -.->|"May skip"| EXEC_SYSCALL
    FUZZING_PATH --> EXEC_SYSCALL
    
    %% Post-execution hooks
    EXEC_SYSCALL -->|"Post-Hook 1"| STRACE_POST["rr_strace_syscall_post_hook_optimized<br/>📁 utils/rr_syscall_dispatch.c<br/>📝 Optimized post-hook"]
    
    STRACE_POST -->|"Post-Hook 2"| RR_POST["rr_syscall_post_hook<br/>📁 core/rr_main.c<br/>📝 Legacy post-hook"]
    
    RR_POST --> RETURN([Return to Guest])
    
    %% Styling
    classDef qemu fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef core fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
    classDef decision fill:#fff9c4,stroke:#f57c00,stroke-width:2px
    classDef record fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
    classDef replay fill:#ffe0b2,stroke:#f57c00,stroke-width:2px
    classDef fuzzing fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    
    class DO_SYSCALL,EXEC_SYSCALL qemu
    class RR_DO_SYSCALL,RR_POST core
    class CHK_ENABLED,CHK_MODE decision
    class RECORD_PATH record
    class REPLAY_PATH replay
    class FUZZING_PATH fuzzing
```

## 关键决策点

### 1. RR-Fuzz Enabled Check (rr_do_syscall:L10-15)
```c
if (!g_rr_framework || !g_rr_framework->enabled) {
    // Skip to real syscall
}
```

### 2. Mode Selection (rr_do_syscall:L20-40)
```c
switch (g_rr_framework->mode) {
    case RR_MODE_RECORD:   // Record path
    case RR_MODE_REPLAY:   // Replay path  
    case RR_MODE_FUZZING:  // Fuzzing path
    case RR_MODE_DISABLED: // Fallthrough
}
```

### 3. Post-Hook Redundancy Issue
⚠️ **Known Issue**: `rr_syscall_post_hook` has overlapping functionality with `rr_strace_syscall_post_hook_optimized`. The optimized version in `rr_syscall_dispatch.c` is preferred.

## Next Steps
- [Graph 2: Record & Replay Detailed Flow](./call_graph_record_replay.md)
- [Graph 3: Fuzzing Detailed Flow](./call_graph_fuzzing.md)

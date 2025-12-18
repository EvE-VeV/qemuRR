
# Code Audit Task List

## Phase 1: C Module Audit (Core & Utils)
- [x] **Core Architecture Audit**
    - [x] `core/rr_main.c` - 逐函数审计 (P0)
    - [x] `utils/rr_syscall_dispatch.c` - 系统调用分发逻辑审计 (Layer 3)
    - [x] `utils/rr_fork_server.c` - Fork Server 核心审计 (Mid-Point Fork)
    - [x] `fuzzing/qemu_integration/rr_coverage.c` - [x] **Auditing Remaining C Modules**
    - [x] Fuzzing Engine (`rr_fuzz_engine.c`, `rr_fuzz_aux_mutations.c`)
    - [x] Syscall Parsing (`utils/rr_syscallparser.c`, `utils/rr_syscall_info.c`)
    - [x] Trace System (`core/rr_bb_trace.c`, `utils/rr_dynamic_trace.c`)
    - [x] Config System (`core/rr_config.c`)
    - [x] Advanced Utils (IPC, Nested Fork, Tree Builder)
    - [x] `record` 和 `replay` 模块深度审计 (P1/P2)
    - [x] `utils` 和 `aux_data` 模块审计 (P3)
- [x] 审计 `fuzzing` (Python) 并评估 C 语言重写可行性 <!-- id: 6 -->
- [ ] 撰写最终审计报告 (Summary of Findings) <!-- id: 7 -->

## Phase 2: Documentation & Fixes
- [ ] Add Doxygen comments to all C files (Completed)
- [ ] Fix "Double Capture" Bug in `rr_record.c`
- [ ] Evaluate "Autonomous Nested Fork" stability

## Phase 3: Python Module Audit
- [ ] `fuzzing/conductor/`
- [ ] `fuzzing/multiprocess/`

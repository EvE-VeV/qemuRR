# Task Checklist

## Phase 1: RAX30 Analysis & Reproduction [DONE]
- [x] Establish RAX30 simulation environment (`setup_rax30.sh`)
- [x] Validate `rex_cgi` execution with Mock Libs
- [x] Reproduce CVE-2023-27357 crash via direct trace recording
- [x] Setup `run_rax30_fuzz.sh` for mass fuzzing

## Phase 2: Horizontal Expansion (DIR-820L) [DONE]
- [x] Identify MIPS target (`jjhttpd` from D-Link DIR-820L)
- [x] Create `setup_dir820l.sh` and Mock Libs (`libapmib_mock.c`)
- [x] Solve "Suspicious arg_size" errors (Standardized Trace Format)
- [x] Solve "EOF" and Sync issues (Strict 0-indexing)

## Phase 3: Vertical Expansion (Cross-Architecture & Protocol) [IN PROGRESS]
- [x] Verify Universal Trace Format on x86_64 (`test_universal`)
- [x] **Verify Full Fuzzing Pipeline on x86_64**
    - [x] Trace Analysis (Python 64-bit parser)
    - [x] CFG Analysis (PathFinder coverage)
    - [x] Mutation & Feedback Loop
- [ ] **Cross-Protocol Targets**
    - [ ] `upnp` (RAX30 ARM) - Coverage collection fixed, need deeper fuzzing
    - [ ] `miniupnpd` (DIR-820L MIPS)

## Phase 4: Fuzzing Intelligence Upgrade [NEW]
- [x] **Implement Dictionary Mutation Support**
    - [x] Add `strings` extraction to `AFLEnhancedMutator`
    - [x] Implement `EXTRAS_AO` mutation stage
    - [x] Verify dictionary extraction on real binaries (Verified on `/bin/ls` (x86), `jjhttpd` (MIPS), and `test_universal`)
    - [x] Verify Coverage Improvement (Crash found on `test_universal`)

## Phase 5: Result Consolidation [IN PROGRESS]
## Phase 5: Result Consolidation [IN PROGRESS]
- [/] Run 24h Fuzzing Campaign on all targets (Launched, currently **PAUSED** by user request)
    - [x] Fix `jjhttpd` Trace Desynchronization (Re-recorded trace)
    - [x] Fix `upnp` Coverage Stagnation (Ported Dictionary to `SmartMutator`)
- [x] Triage unique crashes
- [x] Project Cleanup (Removed legacy scripts and logs)
- [ ] Produce final report

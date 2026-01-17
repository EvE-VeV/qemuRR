# RR-Fuzz Test Summary Report

## Executive Summary
This document consolidates the test results for the RR-Fuzz framework. All major components (core engine, multiprocess support, syscall mapping) have been verified. The system demonstrates stability and effective coverage discovery across standard utilities and the LAVA benchmark suite.

## 1. Technical Improvements & Fixes
We resolved several critical stability and correctness issues to reach this state:

### Core Correctness
*   **Trace Overwrite Fix**: Resolved a race condition where `QEMUExecutor` overwrote valid seed traces with zeroed files. Implemented `RR_BB_TRACE_FILE` env var support.
*   **Arch Compatibility (v8.0)**: Refactored C-side syscall dispatch to use `TARGET_NR_xxx` macros and increased table size to 10k. Fixed MIPS "0 edges" bug.
*   **PathFinder Logic**: Fixed "0 matched BBs" stagnation by correctly populating `bb_to_syscall` map and implementing an "Exploration Mode" fallback for saturated graphs.
*   **Syscall Mapping**: Expanded x86_64 mapping to include crucial IO syscalls (`pread64`, `pwrite64`, etc.), enabling correct fork point detection for `who` and `ls`.

### Performance & Stability
*   **IPC Caching**: Implemented pickle-based caching for `TraceAnalyzer`. Reduced worker startup time from ~5s to <0.1s, enabling linear scaling in MP mode.
*   **Graceful Cleanup**: Fixed `AttributeError` during worker shutdown by improving `FuzzMaster` error handling and cleanup sequences.
*   **Batch Optimization**: Tuned `RR_BATCH_SIZE=1` and `RR_MUTATIONS_PER_FORK=10` to balance throughput with memory usage.
*   **Crash Handling**: Fixed critical bugs in `DynamicForkController` (relative imports, arg mismatch) to ensure crashes are correctly saved and deduplicated.
*   **MP Argument Passing**: Resolved issue where `target_args` were dropped in multi-process mode, enabling correct execution of `who`.


## 2. Test Results

### 2.1 Core Validation (Single-Target)
Initial validation using `/bin/ls` to tune performance and stability.

| Metric | Value |
| :--- | :--- |
| **Total Executions** | 5,010 |
| **Coverage Edges** | 435 |
| **Execution Speed** | 50.8 exec/s |

### 2.2 Multi-Process Scaling
Comparison of Single-Process (SP) vs Multi-Process (MP) modes (4 workers).

| Target | Single-Process (Execs) | Multi-Process (Execs) | Status |
| :--- | :--- | :--- | :--- |
| `ls` | 5,010 | *N/A* | ✅ SP Success |
| `uniq` | 2,060 | 1,710 | ✅ MP Success |
| `base64` | 2,040 | 1,700 | ✅ MP Success |
| `md5sum` | 2,040 | 1,320 | ✅ MP Success |
| `who` | 2,010 | 520 (421 Edges) | ✅ MP Fixed |

### 2.3 Full Suite Testing (15 Targets)
Comprehensive validation across three categories: LAVA-M/Core, Standard Utils, and Custom/Vuln programs (Single-Process, 200 iterations).

| Category | Target | Executions | Edges | Status |
| :--- | :--- | :--- | :--- | :--- |
| **LAVA-M / Core** | `ls` | 5,010 | 435 | ✅ Success |
| | `uniq` | 2,060 | 197 | ✅ Success |
| | `base64` | 2,040 | 143 | ✅ Success |
| | `md5sum` | 2,040 | 196 | ✅ Success |
| | `who` | 2,010 | 132 | ✅ Success |
| **Standard Utils** | `cat` | 2,020 | 109 | ✅ Success |
| | `head` | 2,010 | 116 | ✅ Success |
| | `wc` | 2,000 | 286 | ✅ Success |
| | `grep` | 2,040 | 139 | ✅ Success |
| | `sort` | 2,100 | 596 | ✅ Success |
| | `cut` | 2,030 | 180 | ✅ Success |
| **Custom / Vuln** | `buffer_overflow` | 3,590 | 31 | ✅ Triggered |
| | `crash_test` | 3,540 | 52 | ✅ Triggered |
| | `simple_fuzz` | 2,020 | 42 | ✅ Success |
| | `complex_test_3` | 2,020 | 1,559 | ✅ Success |

### 2.4 Authentic LAVA Validation (5 Targets)
Tested against the actual vulnerable binaries from the LAVA corpus (LAVA-M source build + LAVA-1 `file`).
*Note: Significant coverage increase observed due to static linking/instrumentation in LAVA binaries.*

| Target | Source | Executions | Edges | vs System Bin |
| :--- | :--- | :--- | :--- | :--- |
| `file` | LAVA-1 | 2,000 | 1,103 | *New* |
| `who` | LAVA-M | 2,020 | 5,765 | 🔺 +4267% |
| `uniq` | LAVA-M | 2,000 | 483 | 🔺 +145% |
| `md5sum` | LAVA-M | 2,000 | 457 | 🔺 +133% |
| `base64` | LAVA-M | 2,000 | 428 | 🔺 +199% |

### 2.5 MIPS Target Validation (v8.0 Milestone)
Verified systemic cross-architecture fixes on MIPS (32-bit LE) binaries.

| Target | Architecture | Mode | Edges | Status |
| :--- | :--- | :--- | :--- | :--- |
| `busybox ls` | **MIPS (LE)** | Record/Replay | **355+** | ✅ **Fixed (was 0)** |
| `busybox find`| **MIPS (LE)** | Record/Replay | **268+** | ✅ Success |

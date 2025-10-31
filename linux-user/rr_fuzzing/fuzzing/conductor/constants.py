#!/usr/bin/env python3
"""
RR-Fuzz Constants and Command Definitions

This module contains all constants and command type definitions used across
the RR-Fuzz system. These values must match the C-side definitions in
rr_constants.h and rr_framework.h.
"""

# ===== Fuzz Command Types (must match C-side definitions) =====
FUZZ_CMD_NONE = 0
FUZZ_CMD_MUTATE_ARG = 1
FUZZ_CMD_REPLACE_BUFFER = 2
FUZZ_CMD_MUTATE_FLAGS = 3
FUZZ_CMD_BOUNDARY_VALUE = 4
# Phase 1: New mutation commands for aux_data
FUZZ_CMD_MUTATE_AUX_BUFFER = 5
FUZZ_CMD_FLIP_BITS = 6
FUZZ_CMD_TRUNCATE = 7
FUZZ_CMD_EXTEND = 8
FUZZ_CMD_INTERESTING_VALUES = 9
FUZZ_CMD_LIGHT_MUTATION = 10
# Phase 2: Precise memory overwrite command
FUZZ_CMD_OVERWRITE_AT_OFFSET = 11

# ===== Shared Memory Constants (must match rr_constants.h) =====
FUZZ_MAGIC = 0x46555A5A  # "FUZZ" - shared memory magic number
FUZZ_MAX_INSTRUCTIONS = 32  # Maximum instruction queue length
FUZZ_INSTRUCTION_DATA = 256  # Data payload size per instruction
FUZZ_SHM_SIZE = 64 * 1024  # Shared memory size: 64KB (⚠️ must match rr_constants.h)

# ===== Phase 3: Coverage Constants =====
COVERAGE_MAP_SIZE = 64 * 1024  # Coverage bitmap size: 64KB
FUZZ_FLAG_CAPTURE_SEED = (1 << 0)  # Flag to request seed capture

# ===== Phase 1: Initialization Phase Filtering Configuration =====
# These syscalls should not be mutated during the initialization phase
# to avoid breaking memory layout
INIT_SYSCALLS = {
    'mmap', 'brk', 'set_tid_address', 'set_robust_list', 'arch_prctl',
    'munmap', 'mprotect', 'rt_sigprocmask', 'rt_sigaction'
}

# Initialization phase threshold: skip initialization syscalls in the first N syscalls
# Note: This is a heuristic value, can be automatically detected by InitPhaseDetector
INIT_PHASE_THRESHOLD = 25  # Default value (if auto-detection fails)

# Important I/O syscalls that should never be skipped
IMPORTANT_SYSCALLS = {'send', 'sendto', 'recv', 'recvfrom', 'write', 'read'}


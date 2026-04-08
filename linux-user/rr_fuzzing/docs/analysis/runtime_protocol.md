# RR-Fuzz Runtime Protocol

This document captures the current runtime contract between the Python conductor
and the QEMU `linux-user` RR-Fuzz runtime. It is intentionally descriptive: it
documents the implementation as it exists today and is meant to be kept in sync
with code before larger refactors.

## Commands

The conductor writes one-byte commands to `RR_CMD_PIPE`.

- `F`: Standard fork execution from the beginning of the trace.
- `B`: Batch fork execution for multiple variants.
- `C`: Mid-point fork execution using `fork_point` from shared memory.
- `E`: Baseline execution without mutations.
- `Q`: Quit the fork server loop.

## Status Codes

The runtime writes status values to `RR_STATUS_PIPE`.

- `0`: `STATUS_NONE`
- `1`: `STATUS_READY`
- `2`: `STATUS_AT_FORK_POINT`
- `3`: `STATUS_NORMAL_EXIT`
- `4`: `STATUS_CRASH`
- `5`: `STATUS_OTHER_SIGNAL`
- `6`: `STATUS_TIMEOUT`

Crash reports are encoded as three 32-bit integers:

1. `STATUS_CRASH`
2. `exit_code`
3. `signal_number`

Non-crash reports write only one 32-bit integer.

## Shared Memory Header

The conductor and runtime share the `FuzzSharedMemory` layout.

Header fields:

1. `magic`
2. `sequence`
3. `num_variants`
4. `checksum`
5. `iteration_id`
6. `reserved_1`
7. `fork_point`
8. `current_depth`
9. `reserved_2`

Checksum rule:

`checksum = magic ^ sequence ^ num_variants ^ fork_point ^ current_depth`

The checksum write is the commit step on the Python side.

## Execution Modes

### `F` mode

- Runtime loads variant `0` from shared memory.
- Coverage is reset before forking.
- Child reopens the trace from the beginning and continues execution.
- Parent waits for child completion and usually reports `STATUS_AT_FORK_POINT`
  to signal that the persistent parent is ready for the next iteration.

### `C` mode

- `fork_point` and `current_depth` come from shared memory.
- If `replay_index < fork_point`, the runtime does not fork immediately.
  Instead it sets:
  - `checkpoint_target = fork_point`
  - `silent_replay_mode = true`
  - `resume_from_checkpoint = true`
- The runtime returns control so replay can advance to the target.
- When the loop is re-entered at the target, children are forked and continue
  from the inherited process state.

### `B` mode

- Runtime reads `num_variants` from shared memory.
- Each child reloads its own variant instructions by index.
- Parent waits for all children and reports one status per child.

### `E` mode

- Runtime executes a baseline child without mutation instructions.
- The baseline child switches to replay mode and exits after baseline execution.

## Invariants

- Child processes must close inherited command and status pipe FDs.
- For crash PC reporting, the child must set `g_child_variant_ptr` before
  execution and install fatal signal handlers.
- In mid-point fork children, `replay_index` must be aligned to `fork_point`
  after trace fast-forward.
- Checkpoint children must not re-enter the fork server loop after resuming
  execution.

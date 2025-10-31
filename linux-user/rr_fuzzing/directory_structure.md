# RR-Fuzz Directory Structure

## Overview

This document explains the improved directory structure of RR-Fuzz.

## Directory Organization

```
fuzzing/
├── qemu_integration/       # C code for QEMU integration
│   ├── rr_coverage.c       # Coverage tracking implementation
│   ├── rr_coverage.h       # Coverage tracking header
│   ├── rr_fuzz_aux_mutations.c  # Auxiliary data mutation
│   └── rr_fuzz_engine.c    # Core fuzzing engine
│
├── conductor/              # Single-process conductor core
│   ├── __init__.py         # Package exports
│   ├── constants.py        # All constants and command definitions
│   ├── init_detector.py    # Initialization phase detection
│   ├── instruction.py      # Fuzz instruction representation
│   ├── coverage.py         # Basic coverage tracking
│   ├── shared_memory.py    # Shared memory management
│   └── mutator.py          # Smart mutation engine
│
├── multiprocess/           # Multi-process orchestration
│   ├── __init__.py         # Package exports
│   ├── fuzz_master.py      # Multi-process coordinator (MAIN ENTRY)
│   ├── corpus_manager.py   # Corpus persistence
│   ├── crash_analyzer.py   # Crash triaging
│   ├── coverage_feedback.py # Advanced coverage-guided fuzzing
│   ├── energy_scheduler.py # Energy-based seed scheduling
│   ├── seed_queue_advanced.py # Advanced seed queue
│   ├── shared_resources.py # Multi-process shared resources
│   └── multiprocess_extensions.py # Multi-process extensions
│
├── fuzz_conductor.py       # Legacy single-process entry (for backward compat)
├── trace_analyzer.py       # Trace file analyzer
├── log_analyzer.py         # Log analyzer
├── realtime_tree_visualizer.py # Real-time visualization
├── README.md               # Basic README
└── USAGE_GUIDE.md          # Complete usage guide
```

## Naming Rationale

### qemu_integration/
- **Purpose**: Contains C code that directly interfaces with QEMU
- **Why this name**: Clearly indicates this is the integration layer between the fuzzer and QEMU
- **Previous name**: `c/` (too generic, only indicates language)

### conductor/
- **Purpose**: Core components for single-process fuzzing conductor
- **Why this name**: "Conductor" metaphor - orchestrates the fuzzing process like a conductor leads an orchestra
- **Previous name**: `core/` (kept similar meaning, more specific)

### multiprocess/
- **Purpose**: Components for multi-process parallel fuzzing
- **Why this name**: Clearly indicates this handles multiple processes
- **Previous name**: `python/` (too generic, only indicates language)

## Component Responsibilities

### qemu_integration/ (C-side)
- ✅ Implements coverage tracking hooks in QEMU TCG
- ✅ Handles fuzzing instruction application
- ✅ Manages auxiliary data mutations
- ✅ Communicates with Python via shared memory

### conductor/ (Python single-process)
- ✅ Parses trace files
- ✅ Generates mutation instructions
- ✅ Manages IPC with QEMU
- ✅ Detects initialization phase
- ✅ Basic coverage tracking

### multiprocess/ (Python multi-process)
- ✅ Coordinates multiple fuzzing workers
- ✅ Manages shared coverage bitmap
- ✅ Implements advanced seed scheduling
- ✅ Handles corpus persistence
- ✅ Performs crash analysis and deduplication

## Usage Patterns

### Single-Process Mode (Legacy/Debugging)
```bash
python3 fuzz_conductor.py --qemu ./qemu --trace ./trace.bin --target ./program
```

### Multi-Process Mode (Production)
```bash
python3 multiprocess/fuzz_master.py -n 8 -p ./program -q ./qemu -t ./trace.bin
```

## Import Patterns

### Importing conductor components
```python
from conductor import InitPhaseDetector, SmartMutator, FuzzInstruction
from conductor.constants import FUZZ_CMD_FLIP_BITS
```

### Importing multiprocess components
```python
from multiprocess.fuzz_master import FuzzMaster
from multiprocess.shared_resources import SharedCoverage
```

## Migration Notes

All import paths have been updated to reflect the new structure:
- `from core.X` → `from conductor.X`
- `from python.X` → `from multiprocess.X`
- C files remain unchanged (no imports)


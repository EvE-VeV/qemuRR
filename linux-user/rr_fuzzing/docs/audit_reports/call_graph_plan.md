# RR-Fuzz Complete Call Graph - Implementation Plan

## Objective
Create a comprehensive function call graph starting from `do_syscall` that shows:
- Complete call chain with accurate relationships
- Conditional branches (Record/Replay/Fuzzing modes)
- Function descriptions
- File locations

## Approach

### 1. Visualization Format: Mermaid Flowchart
**Rationale**: 
- Native Markdown support
- Excellent for conditional logic (diamond nodes)
- Supports subgraphs for modular organization
- Can handle complex hierarchies

### 2. Organization Strategy

#### Layered Architecture (Top to Bottom):
```
Layer 0: QEMU Entry Point
  └─ do_syscall (linux-user/syscall.c)

Layer 1: RR-Fuzz Core Dispatcher
  ├─ rr_do_syscall (核心入口)
  └─ rr_syscall_post_hook

Layer 2: Mode Routers
  ├─ Record Path
  ├─ Replay Path (Pure/Hybrid)
  └─ Fuzzing Path

Layer 3: Utilities & Helpers
  ├─ Mapping Manager
  ├─ Aux Data
  ├─ Syscall Dispatch
  └─ IPC

Layer 4: Advanced Features
  ├─ Fork Server
  ├─ Coverage
  ├─ Fuzzing Engine
  └─ Dynamic Trace
```

### 3. Node Conventions

#### Node Types:
- **Rectangle**: Regular function call
- **Diamond**: Conditional branch (if/switch)
- **Parallelogram**: I/O operation (file/pipe)
- **Rounded Box**: Module boundary

#### Color Coding:
- 🟦 Blue: QEMU Integration
- 🟩 Green: Record Mode
- 🟨 Yellow: Replay Mode
- 🟥 Red: Fuzzing Mode
- ⚪ Gray: Shared Utilities

#### Annotations:
```
function_name
📁 file.c
📝 Brief description
```

### 4. Graph Sections

Due to complexity, will create **3 separate graphs**:

#### Graph 1: Main Flow (do_syscall → mode selection)
- Entry point
- Core dispatcher
- Mode routing

#### Graph 2: Record & Replay Paths
- Record syscall flow
- Pure replay flow
- Hybrid replay flow
- Aux data management

#### Graph 3: Fuzzing & Advanced Features
- Fork Server operations
- Mutation application
- Coverage tracking
- Dynamic tracing

## Implementation Steps

1. ✅ Create plan document (this file)
2. 🔄 Generate Graph 1: Main Entry Flow
3. 🔄 Generate Graph 2: Record/Replay Flows
4. 🔄 Generate Graph 3: Fuzzing Flow
5. 📊 Create index document linking all graphs

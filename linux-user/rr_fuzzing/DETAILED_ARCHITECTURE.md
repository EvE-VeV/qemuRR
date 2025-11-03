# RR-Fuzz 详细架构文档

**版本**: 6.0  
**日期**: 2025-11-02  
**特点**: 超详细的框架图和Fuzzing流程

---

## 📐 完整系统架构图（超详细）

### 整体架构（5层架构）

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                RR-Fuzz Complete Architecture                              │
│                                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │  Layer 1: Trace Storage Layer (存储层)                                            │   │
│  ├──────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                    │   │
│  │  ┌─────────────────────────────────────────────────────────────────────────┐     │   │
│  │  │  TraceManager                                                            │     │   │
│  │  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────────────┐      │     │   │
│  │  │  │  trace_pool    │  │ active_traces  │  │  coverage_map        │      │     │   │
│  │  │  │  [trace_001    │  │ [高能量traces] │  │  {trace_id:          │      │     │   │
│  │  │  │   trace_002    │  │                │  │   coverage_info}     │      │     │   │
│  │  │  │   ...]         │  │                │  │                      │      │     │   │
│  │  │  └────────────────┘  └────────────────┘  └──────────────────────┘      │     │   │
│  │  │                                                                          │     │   │
│  │  │  Methods:                                                                │     │   │
│  │  │  • add_trace(trace, coverage) → None                                    │     │   │
│  │  │  • select_trace() → Trace                                               │     │   │
│  │  │  • get_trace_by_id(id) → Trace                                          │     │   │
│  │  │  • remove_trace(id) → None                                              │     │   │
│  │  │  • get_statistics() → dict                                              │     │   │
│  │  └─────────────────────────────────────────────────────────────────────────┘     │   │
│  │                                                                                    │   │
│  │  Trace Format:                                                                     │   │
│  │  ┌───────────────────────────────────────────────────────────────────────┐       │   │
│  │  │  Trace {                                                               │       │   │
│  │  │    id: str                                                             │       │   │
│  │  │    file_path: str                    # trace.bin路径                  │       │   │
│  │  │    syscalls: List[SyscallRecord]     # 系统调用序列                   │       │   │
│  │  │    coverage: CoverageInfo            # 覆盖率信息                     │       │   │
│  │  │    metadata: {                                                         │       │   │
│  │  │      creation_time: timestamp                                          │       │   │
│  │  │      parent_trace_id: str           # 来自哪个trace变异               │       │   │
│  │  │      mutation_applied: List[FuzzInstruction]                           │       │   │
│  │  │    }                                                                    │       │   │
│  │  │  }                                                                      │       │   │
│  │  └───────────────────────────────────────────────────────────────────────┘       │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                               │
│                                           │ Trace Objects                                 │
│                                           ▼                                               │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │  Layer 2: Core Fuzzing Layer (核心Fuzzing层)                                     │   │
│  ├──────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  FuzzingCore (主循环协调器)                                            │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  State:                                                        │     │      │   │
│  │  │  │  • trace_manager: TraceManager                                │     │      │   │
│  │  │  │  • mutator: BaseMutator | SmartMutator                        │     │      │   │
│  │  │  │  • coverage_tracker: CoverageTracker                          │     │      │   │
│  │  │  │  • execution_engine: QEMUExecutor                             │     │      │   │
│  │  │  │  • crash_detector: CrashDetector                              │     │      │   │
│  │  │  │  • stats: FuzzingStatistics                                   │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  Main Loop:                                                    │     │      │   │
│  │  │  │  while True:                                                   │     │      │   │
│  │  │  │    1. trace = trace_manager.select_trace()                    │     │      │   │
│  │  │  │    2. mutations = mutator.mutate(trace)                       │     │      │   │
│  │  │  │    3. result = execution_engine.execute(trace, mutations)     │     │      │   │
│  │  │  │    4. coverage = coverage_tracker.analyze(result)             │     │      │   │
│  │  │  │    5. if coverage.has_new_edges:                              │     │      │   │
│  │  │  │         new_trace = save_trace(result)                        │     │      │   │
│  │  │  │         trace_manager.add_trace(new_trace, coverage)          │     │      │   │
│  │  │  │    6. if result.crashed:                                      │     │      │   │
│  │  │  │         crash_detector.save_crash(result)                     │     │      │   │
│  │  │  │    7. stats.update(result)                                    │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  BaseMutator (基础变异器)                                              │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  mutate(trace) → List[FuzzInstruction]:                      │     │      │   │
│  │  │  │    1. num_mutations = random.randint(1, 3)                   │     │      │   │
│  │  │  │    2. syscall_indices = random_sample(trace.syscalls)        │     │      │   │
│  │  │  │    3. for each index:                                         │     │      │   │
│  │  │  │         mutation_type = random_choice([                       │     │      │   │
│  │  │  │           MUTATE_ARG, REPLACE_BUFFER,                        │     │      │   │
│  │  │  │           MUTATE_FLAGS, BOUNDARY_VALUE, ...                  │     │      │   │
│  │  │  │         ])                                                    │     │      │   │
│  │  │  │         instruction = create_instruction(type, index)        │     │      │   │
│  │  │  │         mutations.append(instruction)                         │     │      │   │
│  │  │  │    4. return mutations                                        │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  Strategies:                                                            │      │   │
│  │  │  • Random: 完全随机变异                                                 │      │   │
│  │  │  • Havoc: 多个连续变异                                                  │      │   │
│  │  │  • Dictionary: 使用字典值                                               │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  QEMUExecutor (QEMU执行引擎)                                           │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  execute(trace, mutations) → ExecutionResult:                │     │      │   │
│  │  │  │    1. Setup IPC:                                              │     │      │   │
│  │  │  │         cmd_pipe = create_pipe()                              │     │      │   │
│  │  │  │         status_pipe = create_pipe()                           │     │      │   │
│  │  │  │         shm = create_shared_memory()                          │     │      │   │
│  │  │  │    2. Write mutations to shm:                                 │     │      │   │
│  │  │  │         shm.write_instructions(mutations)                     │     │      │   │
│  │  │  │    3. Fork QEMU process:                                      │     │      │   │
│  │  │  │         qemu_pid = fork()                                     │     │      │   │
│  │  │  │         if qemu_pid == 0:                                     │     │      │   │
│  │  │  │           exec("qemu-x86_64",                                 │     │      │   │
│  │  │  │                "-rr-mode", "fuzzing",                         │     │      │   │
│  │  │  │                "-rr-trace-file", trace.file_path,             │     │      │   │
│  │  │  │                "-rr-cmd-pipe", cmd_pipe,                      │     │      │   │
│  │  │  │                "-rr-status-pipe", status_pipe,                │     │      │   │
│  │  │  │                "-rr-shm-id", shm.id,                          │     │      │   │
│  │  │  │                target_program)                                │     │      │   │
│  │  │  │    4. Send 'F' command to start:                              │     │      │   │
│  │  │  │         write(cmd_pipe, 'F')                                  │     │      │   │
│  │  │  │    5. Wait for result:                                        │     │      │   │
│  │  │  │         status = read(status_pipe)                            │     │      │   │
│  │  │  │         coverage_bitmap = shm.read_coverage()                 │     │      │   │
│  │  │  │    6. Cleanup and return:                                     │     │      │   │
│  │  │  │         kill(qemu_pid)                                        │     │      │   │
│  │  │  │         return ExecutionResult(status, coverage_bitmap)       │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  CoverageTracker (覆盖率追踪器)                                        │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  State:                                                        │     │      │   │
│  │  │  │  • global_bitmap: bytes[65536]  # 全局覆盖率位图              │     │      │   │
│  │  │  │  • edge_count: dict             # edge → 执行次数             │     │      │   │
│  │  │  │  • unique_edges: set            # 已发现的edge                │     │      │   │
│  │  │  │  • virgin_bits: bytes[65536]    # 未触及的bits               │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  analyze(result) → CoverageInfo:                              │     │      │   │
│  │  │  │    1. new_bitmap = result.coverage_bitmap                     │     │      │   │
│  │  │  │    2. new_edges = []                                          │     │      │   │
│  │  │  │    3. for i in range(len(new_bitmap)):                        │     │      │   │
│  │  │  │         if new_bitmap[i] & virgin_bits[i]:                    │     │      │   │
│  │  │  │           # 发现新的覆盖                                       │     │      │   │
│  │  │  │           new_edges.append(i)                                 │     │      │   │
│  │  │  │           virgin_bits[i] &= ~new_bitmap[i]                    │     │      │   │
│  │  │  │           unique_edges.add(i)                                 │     │      │   │
│  │  │  │    4. global_bitmap |= new_bitmap                             │     │      │   │
│  │  │  │    5. return CoverageInfo(                                    │     │      │   │
│  │  │  │         has_new_edges=len(new_edges) > 0,                     │     │      │   │
│  │  │  │         new_edges=new_edges,                                  │     │      │   │
│  │  │  │         total_unique_edges=len(unique_edges)                  │     │      │   │
│  │  │  │       )                                                        │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                           │                                               │
│                                           │ Optional Enhancement                          │
│                                           ▼                                               │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │  Layer 3: Optimization Layer (优化层 - 可选)                                     │   │
│  ├──────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  PathFinder (静态分析器)                                                │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  State:                                                        │     │      │   │
│  │  │  │  • cfg: ControlFlowGraph                                      │     │      │   │
│  │  │  │  • basic_blocks: dict[addr → BBInfo]                          │     │      │   │
│  │  │  │  • edges: List[(src_addr, dst_addr)]                          │     │      │   │
│  │  │  │  • covered_blocks: set[addr]                                  │     │      │   │
│  │  │  │  • covered_edges: set[(src, dst)]                             │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  build_cfg(binary_path):                                      │     │      │   │
│  │  │  │    1. project = angr.Project(binary_path)                     │     │      │   │
│  │  │  │    2. cfg = project.analyses.CFGFast()                        │     │      │   │
│  │  │  │    3. for node in cfg.graph.nodes():                          │     │      │   │
│  │  │  │         bb_info = {                                            │     │      │   │
│  │  │  │           'addr': node.addr,                                  │     │      │   │
│  │  │  │           'size': node.size,                                  │     │      │   │
│  │  │  │           'instructions': disassemble(node),                  │     │      │   │
│  │  │  │           'successors': [],                                   │     │      │   │
│  │  │  │           'has_syscall': check_syscall(node),                 │     │      │   │
│  │  │  │           'branch_type': analyze_branch(node)                 │     │      │   │
│  │  │  │         }                                                      │     │      │   │
│  │  │  │         basic_blocks[node.addr] = bb_info                     │     │      │   │
│  │  │  │    4. for (src, dst) in cfg.graph.edges():                    │     │      │   │
│  │  │  │         edges.append((src.addr, dst.addr))                    │     │      │   │
│  │  │  │         basic_blocks[src.addr]['successors'].append(dst.addr) │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  analyze_trace(trace):                                        │     │      │   │
│  │  │  │    1. for syscall in trace.syscalls:                          │     │      │   │
│  │  │  │         if syscall.pc:                                        │     │      │   │
│  │  │  │           covered_blocks.add(syscall.pc)                      │     │      │   │
│  │  │  │    2. for i in range(len(trace.syscalls) - 1):                │     │      │   │
│  │  │  │         edge = (trace.syscalls[i].pc,                         │     │      │   │
│  │  │  │                 trace.syscalls[i+1].pc)                       │     │      │   │
│  │  │  │         if edge in edges:                                     │     │      │   │
│  │  │  │           covered_edges.add(edge)                             │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  find_uncovered_branches() → List[Branch]:                    │     │      │   │
│  │  │  │    uncovered = []                                             │     │      │   │
│  │  │  │    for bb_addr in basic_blocks:                               │     │      │   │
│  │  │  │      if bb_addr not in covered_blocks:                        │     │      │   │
│  │  │  │        continue  # 该BB未执行，跳过                           │     │      │   │
│  │  │  │      for succ_addr in basic_blocks[bb_addr]['successors']:    │     │      │   │
│  │  │  │        edge = (bb_addr, succ_addr)                            │     │      │   │
│  │  │  │        if edge not in covered_edges:                          │     │      │   │
│  │  │  │          # 发现未覆盖的分支!                                  │     │      │   │
│  │  │  │          condition = analyze_branch_condition(bb_addr)        │     │      │   │
│  │  │  │          uncovered.append({                                   │     │      │   │
│  │  │  │            'source': bb_addr,                                 │     │      │   │
│  │  │  │            'target': succ_addr,                               │     │      │   │
│  │  │  │            'condition': condition,                            │     │      │   │
│  │  │  │            'difficulty': estimate_difficulty(bb_addr, succ)   │     │      │   │
│  │  │  │          })                                                    │     │      │   │
│  │  │  │    return uncovered                                           │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  generate_recipes(uncovered_branches) → List[Recipe]:         │     │      │   │
│  │  │  │    recipes = []                                               │     │      │   │
│  │  │  │    for branch in uncovered_branches:                          │     │      │   │
│  │  │  │      condition = branch['condition']                          │     │      │   │
│  │  │  │      if not condition:                                        │     │      │   │
│  │  │  │        continue                                               │     │      │   │
│  │  │  │      # 回溯找到影响条件的syscalls                             │     │      │   │
│  │  │  │      influencing_syscalls = backtrack_to_syscall(             │     │      │   │
│  │  │  │        branch['source'], condition                            │     │      │   │
│  │  │  │      )                                                         │     │      │   │
│  │  │  │      for syscall_info in influencing_syscalls:                │     │      │   │
│  │  │  │        recipe = MutationRecipe(                               │     │      │   │
│  │  │  │          type='SINGLE',                                       │     │      │   │
│  │  │  │          source_branch=branch['source'],                      │     │      │   │
│  │  │  │          target_branch=branch['target'],                      │     │      │   │
│  │  │  │          syscall_name=syscall_info['name'],                   │     │      │   │
│  │  │  │          arg_index=condition['arg_index'],                    │     │      │   │
│  │  │  │          suggested_values=generate_values(condition),         │     │      │   │
│  │  │  │          priority=calculate_priority(branch),                 │     │      │   │
│  │  │  │          reason=condition['description']                      │     │      │   │
│  │  │  │        )                                                       │     │      │   │
│  │  │  │        recipes.append(recipe)                                 │     │      │   │
│  │  │  │    return recipes                                             │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  RecipePool (Recipe池管理器)                                           │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  State:                                                        │     │      │   │
│  │  │  │  • active_recipes: List[Recipe]    # 活跃的recipes           │     │      │   │
│  │  │  │  • retired_recipes: List[Recipe]   # 已淘汰的recipes         │     │      │   │
│  │  │  │  • recipe_index: dict[syscall_name → List[Recipe]]            │     │      │   │
│  │  │  │  • stats: dict                                                │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  get_recipe_for_trace(trace) → Recipe|None:                   │     │      │   │
│  │  │  │    1. matching_recipes = []                                   │     │      │   │
│  │  │  │    2. for recipe in active_recipes:                           │     │      │   │
│  │  │  │         if recipe_matches_trace(recipe, trace):               │     │      │   │
│  │  │  │           matching_recipes.append(recipe)                     │     │      │   │
│  │  │  │    3. if not matching_recipes:                                │     │      │   │
│  │  │  │         return None                                           │     │      │   │
│  │  │  │    4. # 按优先级和尝试次数排序                                │     │      │   │
│  │  │  │    sorted_recipes = sorted(matching_recipes,                  │     │      │   │
│  │  │  │       key=lambda r: (r.priority, -r.attempt_count))           │     │      │   │
│  │  │  │    5. return sorted_recipes[0]                                │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  update_recipe_result(recipe, success, new_coverage):         │     │      │   │
│  │  │  │    recipe.attempt_count += 1                                  │     │      │   │
│  │  │  │    if success:                                                │     │      │   │
│  │  │  │      recipe.success_count += 1                                │     │      │   │
│  │  │  │      recipe.new_coverage_count += new_coverage                │     │      │   │
│  │  │  │    recipe.success_rate = (recipe.success_count /              │     │      │   │
│  │  │  │                           recipe.attempt_count)                │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  SmartMutator (智能变异器)                                              │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  State:                                                        │     │      │   │
│  │  │  │  • recipe_pool: RecipePool  # 可选                            │     │      │   │
│  │  │  │  • use_recipe_probability: float = 0.7                        │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  mutate(trace) → List[FuzzInstruction]:                       │     │      │   │
│  │  │  │    mutations = []                                             │     │      │   │
│  │  │  │    # 策略1: 优先尝试使用recipe (70%)                          │     │      │   │
│  │  │  │    if recipe_pool and random() < use_recipe_probability:      │     │      │   │
│  │  │  │      recipe = recipe_pool.get_recipe_for_trace(trace)         │     │      │   │
│  │  │  │      if recipe:                                               │     │      │   │
│  │  │  │        recipe_mutation = apply_recipe(trace, recipe)          │     │      │   │
│  │  │  │        mutations.append(recipe_mutation)                      │     │      │   │
│  │  │  │        trace.used_recipe = recipe  # 标记使用了recipe         │     │      │   │
│  │  │  │    # 策略2: 始终保持随机探索 (30%)                            │     │      │   │
│  │  │  │    if random() < 0.3 or not mutations:                        │     │      │   │
│  │  │  │      random_mutation = _random_mutation(trace)                │     │      │   │
│  │  │  │      mutations.append(random_mutation)                        │     │      │   │
│  │  │  │    return mutations                                           │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │  Layer 4: Multi-Process Layer (多进程层 - 可选)                                  │   │
│  ├──────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  FuzzMaster (主控进程)                                                  │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  State:                                                        │     │      │   │
│  │  │  │  • workers: List[Process]          # Worker进程列表           │     │      │   │
│  │  │  │  • sync_dir: Path                  # 同步目录                 │     │      │   │
│  │  │  │  • shared_trace_pool: SharedMemory # 共享trace池              │     │      │   │
│  │  │  │  • shared_coverage: SharedMemory   # 共享覆盖率               │     │      │   │
│  │  │  │  • worker_stats: List[dict]        # Worker统计               │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  │  ┌──────────────────────────────────────────────────────────────┐     │      │   │
│  │  │  │  Master Loop:                                                  │     │      │   │
│  │  │  │    1. Initialize:                                              │     │      │   │
│  │  │  │         - Create sync_dir                                     │     │      │   │
│  │  │  │         - Setup shared memory                                 │     │      │   │
│  │  │  │         - Distribute initial traces                           │     │      │   │
│  │  │  │    2. Start N workers:                                        │     │      │   │
│  │  │  │         for i in range(n_workers):                            │     │      │   │
│  │  │  │           worker_process = Process(                           │     │      │   │
│  │  │  │             target=worker_main,                               │     │      │   │
│  │  │  │             args=(i, sync_dir, shared_memory)                 │     │      │   │
│  │  │  │           )                                                    │     │      │   │
│  │  │  │           worker_process.start()                              │     │      │   │
│  │  │  │           workers.append(worker_process)                      │     │      │   │
│  │  │  │    3. Monitor loop (每5秒):                                   │     │      │   │
│  │  │  │         while True:                                           │     │      │   │
│  │  │  │           - check_workers_alive()                             │     │      │   │
│  │  │  │           - collect_statistics()                              │     │      │   │
│  │  │  │           - display_progress()                                │     │      │   │
│  │  │  │           - sync_new_traces()                                 │     │      │   │
│  │  │  │           - sync_coverage()                                   │     │      │   │
│  │  │  │           sleep(5)                                            │     │      │   │
│  │  │  │    4. Periodic tasks (每60秒):                                │     │      │   │
│  │  │  │         - reanalyze_coverage()      # PathFinder重新分析      │     │      │   │
│  │  │  │         - update_recipes()                                    │     │      │   │
│  │  │  │         - save_corpus()                                       │     │      │   │
│  │  │  └──────────────────────────────────────────────────────────────┘     │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  │                                                                                    │   │
│  │  Sync Directory Structure:                                                         │   │
│  │  sync_dir/                                                                         │   │
│  │  ├── queue/                      # 所有待测试的traces                            │   │
│  │  │   ├── trace_000.bin                                                            │   │
│  │  │   ├── trace_001.bin                                                            │   │
│  │  │   └── ...                                                                      │   │
│  │  ├── crashes/                    # 发现的crashes                                 │   │
│  │  │   ├── worker0/                                                                 │   │
│  │  │   │   ├── crash_001.bin                                                        │   │
│  │  │   │   └── crash_001.meta                                                       │   │
│  │  │   └── worker1/                                                                 │   │
│  │  ├── coverage/                   # 覆盖率数据                                     │   │
│  │  │   ├── global_bitmap.bin                                                        │   │
│  │  │   └── unique_edges.txt                                                         │   │
│  │  ├── recipes.json                # Recipe池                                       │   │
│  │  ├── corpus/                     # 持久化corpus                                  │   │
│  │  └── stats/                      # 统计数据                                       │   │
│  │      ├── worker0_stats.json                                                       │   │
│  │      └── worker1_stats.json                                                       │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐   │
│  │  Layer 5: Monitoring & Analysis Layer (监控分析层)                                │   │
│  ├──────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  SyscallTree Visualizer                                                 │      │   │
│  │  │  • 监听RR_TRACE_PIPE (named pipe)                                       │      │   │
│  │  │  • 接收QEMU发送的实时syscall事件                                        │      │   │
│  │  │  • 标记被fuzz的syscall                                                  │      │   │
│  │  │  • 构建进程树                                                            │      │   │
│  │  │  • 生成HTML/JSON/TXT可视化                                              │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  CrashAnalyzer                                                          │      │   │
│  │  │  • Crash去重                                                            │      │   │
│  │  │  • Stack trace分析                                                      │      │   │
│  │  │  • 根因分析                                                              │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  │                                                                                    │   │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │   │
│  │  │  CorpusManager                                                          │      │   │
│  │  │  • Trace持久化                                                          │      │   │
│  │  │  • Coverage持久化                                                       │      │   │
│  │  │  • 进度恢复                                                              │      │   │
│  │  └────────────────────────────────────────────────────────────────────────┘      │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 超详细Fuzzing流程

### 主流程：Single Iteration (单次迭代的完整过程)

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Fuzzing Main Loop - Single Iteration                                    │
└──────────────────────────────────────────────────────────────────────────┘

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Step 1: Trace Selection (Trace选择)                                     ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Input:  trace_manager.trace_pool (所有trace)
        trace_manager.active_traces (高能量trace子集)

Process:
  1.1 Decision: 选择策略
      ┌─────────────────────────────────────────────┐
      │ random_value = random.random()              │
      │                                             │
      │ if random_value < 0.8:                      │
      │   # 80%概率：利用策略                       │
      │   source = active_traces                    │
      │ else:                                       │
      │   # 20%概率：探索策略                       │
      │   source = trace_pool                       │
      └─────────────────────────────────────────────┘

  1.2 Selection: 从source中选择
      ┌─────────────────────────────────────────────┐
      │ if len(source) == 0:                        │
      │   # Fallback到全池                          │
      │   source = trace_pool                       │
      │                                             │
      │ selected_trace = random.choice(source)      │
      └─────────────────────────────────────────────┘

  1.3 Load Trace: 加载trace文件
      ┌─────────────────────────────────────────────┐
      │ trace_data = load_trace_file(               │
      │   selected_trace.file_path                  │
      │ )                                           │
      │ # 包含:                                     │
      │ # - syscall序列                             │
      │ # - 参数值                                  │
      │ # - 返回值                                  │
      │ # - aux_data                                │
      └─────────────────────────────────────────────┘

Output: selected_trace (Trace对象)
        trace_data (完整的trace内容)

Metrics:
  • Trace pool size: N个traces
  • Active traces: M个高能量traces
  • Selection time: ~0.001 ms

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Step 2: Mutation Generation (变异生成)                                  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Input:  selected_trace
        mutator (BaseMutator | SmartMutator)
        recipe_pool (如果有PathFinder)

Process:
  2.1 Recipe Check: 检查是否有适用的recipe
      ┌─────────────────────────────────────────────────────────────┐
      │ if isinstance(mutator, SmartMutator):                        │
      │   if random.random() < mutator.use_recipe_probability:       │
      │     # 70%概率尝试使用recipe                                  │
      │     recipe = recipe_pool.get_recipe_for_trace(               │
      │       selected_trace                                         │
      │     )                                                         │
      │     if recipe:                                               │
      │       USE_RECIPE = True                                      │
      │     else:                                                    │
      │       USE_RECIPE = False                                     │
      │   else:                                                      │
      │     USE_RECIPE = False                                       │
      │ else:                                                        │
      │   USE_RECIPE = False  # BaseMutator没有recipe                │
      └─────────────────────────────────────────────────────────────┘

  2.2 Generate Mutations:
      
      2.2.A IF USE_RECIPE == True:
            ┌───────────────────────────────────────────────────────┐
            │ Recipe-Driven Mutation:                               │
            │                                                       │
            │ recipe = selected recipe                              │
            │                                                       │
            │ # 找到对应的syscall                                   │
            │ target_syscall_idx = None                             │
            │ for i, sc in enumerate(selected_trace.syscalls):      │
            │   if sc.name == recipe.syscall_name:                  │
            │     target_syscall_idx = i                            │
            │     break                                             │
            │                                                       │
            │ if target_syscall_idx is None:                        │
            │   # Recipe不适用，fallback到随机                      │
            │   goto RANDOM_MUTATION                                │
            │                                                       │
            │ # 从建议值中选择                                       │
            │ mutation_value = random.choice(                       │
            │   recipe.suggested_values                             │
            │ )                                                     │
            │                                                       │
            │ instruction = FuzzInstruction(                        │
            │   syscall_index=target_syscall_idx,                   │
            │   cmd=recipe.mutation_type,                           │
            │   arg_index=recipe.arg_index,                         │
            │   value=mutation_value                                │
            │ )                                                     │
            │                                                       │
            │ mutations = [instruction]                             │
            │                                                       │
            │ # 标记使用了recipe                                    │
            │ selected_trace.used_recipe = recipe                   │
            └───────────────────────────────────────────────────────┘

      2.2.B IF USE_RECIPE == False OR random.random() < 0.3:
            ┌───────────────────────────────────────────────────────┐
            │ RANDOM_MUTATION:                                      │
            │                                                       │
            │ # 随机选择1-3个syscall进行变异                        │
            │ num_mutations = random.randint(1, 3)                  │
            │                                                       │
            │ syscall_indices = random.sample(                      │
            │   range(len(selected_trace.syscalls)),                │
            │   num_mutations                                       │
            │ )                                                     │
            │                                                       │
            │ mutations = []                                        │
            │ for idx in syscall_indices:                           │
            │   # 随机选择变异类型                                  │
            │   mutation_type = random.choice([                     │
            │     'MUTATE_ARG',        # 修改参数                   │
            │     'REPLACE_BUFFER',    # 替换缓冲区                 │
            │     'MUTATE_FLAGS',      # 修改标志位                 │
            │     'BOUNDARY_VALUE',    # 边界值                     │
            │     'BIT_FLIP',          # 位翻转                     │
            │     'ARITHMETIC',        # 算术运算                   │
            │     'INTERESTING_VALUE'  # 特殊值                     │
            │   ])                                                  │
            │                                                       │
            │   instruction = create_instruction(                   │
            │     type=mutation_type,                               │
            │     syscall_idx=idx,                                  │
            │     arg_idx=random.randint(0, 5),                     │
            │     value=generate_random_value(mutation_type)        │
            │   )                                                   │
            │                                                       │
            │   mutations.append(instruction)                       │
            └───────────────────────────────────────────────────────┘

  2.3 Validate Mutations: 验证生成的变异
      ┌─────────────────────────────────────────────┐
      │ for instruction in mutations:               │
      │   # 检查syscall_index是否有效               │
      │   if instruction.syscall_index >= len(      │
      │        selected_trace.syscalls):            │
      │     mutations.remove(instruction)           │
      │   # 检查arg_index是否有效                   │
      │   if instruction.arg_index > 5:             │
      │     instruction.arg_index = 5               │
      └─────────────────────────────────────────────┘

Output: mutations (List[FuzzInstruction])

Mutation Example:
  [
    FuzzInstruction(
      syscall_index=5,           # 第5个syscall (read)
      cmd=FUZZ_CMD_MUTATE_ARG,   # 变异参数
      arg_index=2,               # 第2个参数 (count)
      value=0xFFFFFFFF           # 新值
    ),
    FuzzInstruction(
      syscall_index=8,           # 第8个syscall (write)
      cmd=FUZZ_CMD_REPLACE_BUFFER,
      buffer=b"AAAAAAA..."       # 新缓冲区
    )
  ]

Metrics:
  • Mutation generation time: ~0.01 ms
  • Number of instructions: 1-3
  • Recipe used: True/False

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Step 3: QEMU Execution (QEMU执行)                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Input:  selected_trace
        mutations (List[FuzzInstruction])

Process:
  3.1 Setup IPC: 创建进程间通信通道
      ┌─────────────────────────────────────────────┐
      │ # 创建管道                                  │
      │ cmd_pipe_read, cmd_pipe_write = os.pipe()   │
      │ status_pipe_read, status_pipe_write =       │
      │   os.pipe()                                 │
      │                                             │
      │ # 创建共享内存                              │
      │ shm_id = create_shared_memory(              │
      │   size=SHM_SIZE  # 默认1MB                 │
      │ )                                           │
      │ shm = attach_shared_memory(shm_id)          │
      └─────────────────────────────────────────────┘

  3.2 Write to Shared Memory: 写入变异指令
      ┌─────────────────────────────────────────────┐
      │ # SHM Layout:                               │
      │ # [0-4]     : magic (0x46555A5A)            │
      │ # [4-8]     : num_instructions              │
      │ # [8-...]   : instructions array            │
      │ # [...]     : coverage bitmap (64KB)        │
      │                                             │
      │ shm_write_u32(shm, 0, FUZZ_MAGIC)           │
      │ shm_write_u32(shm, 4, len(mutations))       │
      │                                             │
      │ offset = 8                                  │
      │ for inst in mutations:                      │
      │   shm_write_instruction(shm, offset, inst)  │
      │   offset += sizeof(FuzzInstruction)         │
      │                                             │
      │ # 清空coverage bitmap                       │
      │ memset(shm + COVERAGE_OFFSET, 0, 65536)     │
      └─────────────────────────────────────────────┘

  3.3 Fork QEMU Process: 启动QEMU进程
      ┌─────────────────────────────────────────────┐
      │ qemu_pid = os.fork()                        │
      │                                             │
      │ if qemu_pid == 0:                           │
      │   # Child process: exec QEMU                │
      │   os.close(cmd_pipe_write)                  │
      │   os.close(status_pipe_read)                │
      │                                             │
      │   # 设置环境变量                            │
      │   os.environ['RR_CMD_PIPE'] =               │
      │     str(cmd_pipe_read)                      │
      │   os.environ['RR_STATUS_PIPE'] =            │
      │     str(status_pipe_write)                  │
      │   os.environ['RR_SHM_ID'] = str(shm_id)     │
      │                                             │
      │   # Exec QEMU                               │
      │   os.execv("qemu-x86_64", [                 │
      │     "qemu-x86_64",                          │
      │     "-rr-mode", "fuzzing",                  │
      │     "-rr-trace-file",                       │
      │       selected_trace.file_path,             │
      │     target_program                          │
      │   ])                                        │
      │                                             │
      │ # Parent process continues                  │
      │ os.close(cmd_pipe_read)                     │
      │ os.close(status_pipe_write)                 │
      └─────────────────────────────────────────────┘

  3.4 Send Start Command: 发送启动命令
      ┌─────────────────────────────────────────────┐
      │ # 等待QEMU准备就绪                          │
      │ status = os.read(status_pipe_read, 4)       │
      │ status_code = struct.unpack('i', status)[0] │
      │                                             │
      │ if status_code == STATUS_READY:             │
      │   # QEMU已准备好，发送'F'命令开始fuzzing   │
      │   os.write(cmd_pipe_write, b'F')            │
      └─────────────────────────────────────────────┘

  3.5 QEMU Replay with Mutation: (QEMU内部)
      ┌─────────────────────────────────────────────────────────┐
      │ // rr_main.c: rr_do_syscall() in RR_MODE_FUZZING        │
      │                                                          │
      │ for (int i = 0; i < trace.num_syscalls; i++) {          │
      │   syscall_record_t *rec = &trace.syscalls[i];           │
      │                                                          │
      │   // 1. 检查是否有对应的FuzzInstruction                 │
      │   fuzz_instruction_t *instr = NULL;                     │
      │   for (int j = 0; j < shm->num_instructions; j++) {     │
      │     if (shm->instructions[j].syscall_index == i) {      │
      │       instr = &shm->instructions[j];                    │
      │       break;                                            │
      │     }                                                   │
      │   }                                                     │
      │                                                          │
      │   // 2. 应用变异 (如果有)                                │
      │   if (instr) {                                          │
      │     switch (instr->cmd) {                               │
      │       case FUZZ_CMD_MUTATE_ARG:                         │
      │         // 修改参数                                     │
      │         args[instr->arg_index] = instr->value;          │
      │         break;                                          │
      │                                                          │
      │       case FUZZ_CMD_REPLACE_BUFFER:                     │
      │         // 替换aux_data (对read/recv等)                 │
      │         memcpy(aux_data, instr->buffer,                 │
      │                instr->buffer_size);                     │
      │         break;                                          │
      │                                                          │
      │       case FUZZ_CMD_MUTATE_FLAGS:                       │
      │         args[instr->arg_index] ^= instr->value;         │
      │         break;                                          │
      │                                                          │
      │       // ... 其他变异类型                               │
      │     }                                                   │
      │                                                          │
      │     // 标记为FUZZED (用于dynamic trace)                 │
      │     rr_dynamic_trace_mark_fuzzed(i);                    │
      │   } else {                                              │
      │     // 使用trace中的原始值                              │
      │     memcpy(args, rec->args, sizeof(args));              │
      │   }                                                     │
      │                                                          │
      │   // 3. 执行系统调用                                     │
      │   ret = do_syscall(env, rec->syscall_nr,                │
      │                    args[0], args[1], args[2],           │
      │                    args[3], args[4], args[5]);          │
      │                                                          │
      │   // 4. 收集覆盖率                                       │
      │   rr_coverage_update(current_bb_addr, shm->coverage);   │
      │                                                          │
      │   // 5. 发送dynamic trace (如果启用)                     │
      │   if (rr_trace_pipe) {                                  │
      │     rr_dynamic_trace_syscall_exit(                      │
      │       rec->syscall_nr, ret, instr != NULL               │
      │     );                                                  │
      │   }                                                     │
      │                                                          │
      │   // 6. 检查crash                                        │
      │   if (target_crashed) {                                 │
      │     write(status_pipe, &STATUS_CRASH, 4);               │
      │     exit(1);                                            │
      │   }                                                     │
      │ }                                                       │
      │                                                          │
      │ // 正常退出                                              │
      │ write(status_pipe, &STATUS_NORMAL_EXIT, 4);             │
      │ exit(0);                                                │
      └─────────────────────────────────────────────────────────┘

  3.6 Wait for Result: 等待执行结果
      ┌─────────────────────────────────────────────┐
      │ # 设置超时 (默认30秒)                       │
      │ timeout = 30.0                              │
      │ start_time = time.time()                    │
      │                                             │
      │ while time.time() - start_time < timeout:   │
      │   ready, _, _ = select.select(              │
      │     [status_pipe_read], [], [], 1.0         │
      │   )                                         │
      │                                             │
      │   if ready:                                 │
      │     status_bytes = os.read(                 │
      │       status_pipe_read, 4                   │
      │     )                                       │
      │     status = struct.unpack('i',             │
      │       status_bytes)[0]                      │
      │     break                                   │
      │                                             │
      │ if not ready:                               │
      │   # 超时，kill QEMU                         │
      │   os.kill(qemu_pid, signal.SIGKILL)         │
      │   status = STATUS_TIMEOUT                   │
      └─────────────────────────────────────────────┘

  3.7 Read Coverage: 读取覆盖率bitmap
      ┌─────────────────────────────────────────────┐
      │ coverage_bitmap = bytearray(65536)          │
      │ shm_read(shm, COVERAGE_OFFSET,              │
      │          coverage_bitmap, 65536)            │
      └─────────────────────────────────────────────┘

  3.8 Cleanup: 清理资源
      ┌─────────────────────────────────────────────┐
      │ os.close(cmd_pipe_write)                    │
      │ os.close(status_pipe_read)                  │
      │ detach_shared_memory(shm)                   │
      │ os.waitpid(qemu_pid, 0)  # 回收子进程       │
      └─────────────────────────────────────────────┘

Output: ExecutionResult {
          status: STATUS_NORMAL_EXIT | STATUS_CRASH | 
                  STATUS_TIMEOUT | STATUS_OTHER_SIGNAL
          coverage_bitmap: bytes[65536]
          execution_time: float
          qemu_exit_code: int
        }

Metrics:
  • Execution time: 1-100 ms (取决于trace大小)
  • Timeout: 30 seconds
  • Coverage bitmap size: 64KB

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Step 4: Coverage Analysis (覆盖率分析)                                  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Input:  result.coverage_bitmap
        coverage_tracker.global_bitmap (全局累积)
        coverage_tracker.virgin_bits (未触及的bits)

Process:
  4.1 Compare Bitmaps: 对比新旧bitmap
      ┌─────────────────────────────────────────────────────────┐
      │ new_bitmap = result.coverage_bitmap                      │
      │ global_bitmap = coverage_tracker.global_bitmap           │
      │ virgin_bits = coverage_tracker.virgin_bits               │
      │                                                          │
      │ new_edges = []                                           │
      │ interesting = False                                      │
      │                                                          │
      │ for i in range(len(new_bitmap)):                         │
      │   # 检查是否有新的覆盖                                   │
      │   if new_bitmap[i] & virgin_bits[i]:                     │
      │     # 发现新bit!                                         │
      │     new_edges.append(i)                                  │
      │     interesting = True                                   │
      │                                                          │
      │     # 更新virgin_bits (标记为已触及)                     │
      │     virgin_bits[i] &= ~new_bitmap[i]                     │
      │                                                          │
      │     # 更新global_bitmap                                  │
      │     global_bitmap[i] |= new_bitmap[i]                    │
      │                                                          │
      │     # 记录到unique_edges                                 │
      │     coverage_tracker.unique_edges.add(i)                 │
      └─────────────────────────────────────────────────────────┘

  4.2 Calculate Coverage Metrics: 计算覆盖率指标
      ┌─────────────────────────────────────────────┐
      │ coverage_info = {                           │
      │   'has_new_edges': interesting,             │
      │   'new_edges': new_edges,                   │
      │   'new_edge_count': len(new_edges),         │
      │   'total_unique_edges':                     │
      │     len(coverage_tracker.unique_edges),     │
      │   'coverage_percentage':                    │
      │     len(coverage_tracker.unique_edges)      │
      │       / 65536 * 100,                        │
      │   'stability': calculate_stability(         │
      │     new_bitmap, global_bitmap               │
      │   )                                         │
      │ }                                           │
      └─────────────────────────────────────────────┘

  4.3 Recipe Verification (如果使用了recipe):
      ┌─────────────────────────────────────────────────────────┐
      │ if hasattr(selected_trace, 'used_recipe'):               │
      │   recipe = selected_trace.used_recipe                    │
      │                                                          │
      │   # 检查是否到达了recipe的目标分支                       │
      │   # 方法1: 检查target_branch对应的coverage bit           │
      │   target_bit = hash(recipe.target_branch) % 65536        │
      │   recipe_success = (new_bitmap[target_bit] != 0)         │
      │                                                          │
      │   # 方法2: 检查是否有新coverage (更宽松的标准)           │
      │   recipe_success = interesting                           │
      │                                                          │
      │   # 更新recipe统计                                       │
      │   recipe_pool.update_recipe_result(                      │
      │     recipe, recipe_success, len(new_edges)               │
      │   )                                                      │
      └─────────────────────────────────────────────────────────┘

Output: coverage_info (dict)

Metrics:
  • New edges found: 0-N
  • Total unique edges: accumulated count
  • Coverage percentage: 0-100%
  • Analysis time: ~0.01 ms

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Step 5: Trace Saving (Trace保存)                                        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Input:  coverage_info
        result
        selected_trace
        mutations

Process:
  5.1 Decision: 是否保存trace
      ┌─────────────────────────────────────────────┐
      │ should_save = False                         │
      │                                             │
      │ # 条件1: 发现新coverage                     │
      │ if coverage_info['has_new_edges']:          │
      │   should_save = True                        │
      │   save_reason = "NEW_COVERAGE"              │
      │                                             │
      │ # 条件2: Crash                              │
      │ if result.status == STATUS_CRASH:           │
      │   should_save = True                        │
      │   save_reason = "CRASH"                     │
      │                                             │
      │ # 条件3: 高稳定性且深路径                   │
      │ if (coverage_info['stability'] > 0.9 and    │
      │     path_depth > threshold):                │
      │   should_save = True                        │
      │   save_reason = "DEEP_PATH"                 │
      └─────────────────────────────────────────────┘

  5.2 IF should_save == True:
      ┌─────────────────────────────────────────────────────────┐
      │ # 生成新trace ID                                         │
      │ new_trace_id = generate_trace_id()                       │
      │                                                          │
      │ # 创建新trace文件                                        │
      │ new_trace_path = f"sync_dir/queue/trace_{               │
      │   new_trace_id}.bin"                                     │
      │                                                          │
      │ # 方法1: 保存修改后的trace (重新录制)                    │
      │ # 启动QEMU在RECORD模式，应用相同mutations                │
      │ # (成本高，但trace完整)                                  │
      │                                                          │
      │ # 方法2: 复制原trace + 保存mutations (推荐)               │
      │ shutil.copy(selected_trace.file_path,                    │
      │             new_trace_path)                              │
      │                                                          │
      │ # 保存metadata                                           │
      │ metadata = {                                             │
      │   'id': new_trace_id,                                    │
      │   'parent_trace_id': selected_trace.id,                  │
      │   'mutations': [inst.to_dict()                           │
      │                 for inst in mutations],                  │
      │   'coverage_info': coverage_info,                        │
      │   'save_reason': save_reason,                            │
      │   'timestamp': time.time(),                              │
      │   'used_recipe': selected_trace.used_recipe.id           │
      │                 if hasattr(selected_trace,               │
      │                           'used_recipe') else None        │
      │ }                                                        │
      │                                                          │
      │ with open(f"{new_trace_path}.meta", 'w') as f:           │
      │   json.dump(metadata, f)                                 │
      │                                                          │
      │ # 添加到trace manager                                    │
      │ new_trace = Trace(                                       │
      │   id=new_trace_id,                                       │
      │   file_path=new_trace_path,                              │
      │   metadata=metadata                                      │
      │ )                                                        │
      │                                                          │
      │ trace_manager.add_trace(new_trace, coverage_info)        │
      └─────────────────────────────────────────────────────────┘

  5.3 IF result.status == STATUS_CRASH:
      ┌─────────────────────────────────────────────────────────┐
      │ # 保存crash                                              │
      │ crash_id = generate_crash_id()                           │
      │ crash_dir = f"sync_dir/crashes/worker{worker_id}"        │
      │ os.makedirs(crash_dir, exist_ok=True)                    │
      │                                                          │
      │ crash_path = f"{crash_dir}/crash_{crash_id}.bin"         │
      │ shutil.copy(selected_trace.file_path, crash_path)        │
      │                                                          │
      │ # 保存crash metadata                                     │
      │ crash_metadata = {                                       │
      │   'id': crash_id,                                        │
      │   'trace_id': selected_trace.id,                         │
      │   'mutations': [inst.to_dict()                           │
      │                 for inst in mutations],                  │
      │   'signal': result.signal,                               │
      │   'exit_code': result.qemu_exit_code,                    │
      │   'timestamp': time.time()                               │
      │ }                                                        │
      │                                                          │
      │ with open(f"{crash_path}.meta", 'w') as f:               │
      │   json.dump(crash_metadata, f)                           │
      │                                                          │
      │ # 通知crash analyzer                                     │
      │ crash_detector.analyze_crash(crash_metadata)             │
      └─────────────────────────────────────────────────────────┘

Output: new_trace (如果保存了)
        crash_record (如果crashed)

Metrics:
  • Traces saved: 0 or 1
  • Crashes detected: 0 or 1
  • Save time: ~1 ms

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Step 6: Statistics Update (统计更新)                                    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Input:  result
        coverage_info
        iteration_time

Process:
  6.1 Update Global Stats:
      ┌─────────────────────────────────────────────┐
      │ stats.total_execs += 1                      │
      │ stats.total_time += iteration_time          │
      │ stats.execs_per_sec = (                     │
      │   stats.total_execs / stats.total_time      │
      │ )                                           │
      │                                             │
      │ if coverage_info['has_new_edges']:          │
      │   stats.paths_found += 1                    │
      │   stats.last_new_path = time.time()         │
      │                                             │
      │ if result.status == STATUS_CRASH:           │
      │   stats.crashes_found += 1                  │
      │   stats.unique_crashes += 1  # 去重后       │
      │                                             │
      │ stats.trace_pool_size =                     │
      │   len(trace_manager.trace_pool)             │
      │                                             │
      │ stats.total_coverage =                      │
      │   coverage_info['total_unique_edges']       │
      └─────────────────────────────────────────────┘

  6.2 Update Worker Stats (if multi-process):
      ┌─────────────────────────────────────────────┐
      │ worker_stats[worker_id] = {                 │
      │   'execs': stats.total_execs,               │
      │   'paths': stats.paths_found,               │
      │   'crashes': stats.crashes_found,           │
      │   'coverage': stats.total_coverage,         │
      │   'exec_speed': stats.execs_per_sec,        │
      │   'last_update': time.time()                │
      │ }                                           │
      └─────────────────────────────────────────────┘

  6.3 Display Progress (每100次迭代):
      ┌─────────────────────────────────────────────────────────┐
      │ if stats.total_execs % 100 == 0:                         │
      │   print(f"""                                             │
      │   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━              │
      │   Iteration: {stats.total_execs}                         │
      │   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━              │
      │   Exec speed:  {stats.execs_per_sec:.1f} exec/s          │
      │   Trace pool:  {stats.trace_pool_size} traces            │
      │   Coverage:    {stats.total_coverage} edges              │
      │   Paths found: {stats.paths_found}                       │
      │   Crashes:     {stats.crashes_found} (                   │
      │                {stats.unique_crashes} unique)            │
      │   Last path:   {time.time() - stats.last_new_path:.1f}s  │
      │                ago                                       │
      │   """)                                                   │
      └─────────────────────────────────────────────────────────┘

Output: Updated statistics

Metrics:
  • Total executions: accumulated count
  • Execution speed: execs/second
  • Trace pool growth: traces/hour
  • Coverage growth: edges/hour

┌──────────────────────────────────────────────────────────────────────────┐
│  End of Single Iteration                                                  │
│  → Return to Step 1 for next iteration                                    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 数据流图

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Complete Data Flow                           │
└─────────────────────────────────────────────────────────────────────┘

User Input         QEMU RECORD                 PathFinder
    │                   │                           │
    ▼                   ▼                           │
┌────────┐        ┌──────────┐                     │
│Program │───────►│ trace.bin│──────────┐          │
│+ Input │        └──────────┘          │          │
└────────┘             │                 │          │
                       │                 ▼          │
                       │            ┌────────────┐  │
                       │            │ CFG Build  │◄─┘
                       │            └─────┬──────┘
                       │                  │
                       │                  ▼
                       │            ┌────────────┐
                       │            │  Analyze   │
                       │            │ Uncovered  │
                       │            │  Branches  │
                       │            └─────┬──────┘
                       │                  │
                       │                  ▼
                       │            ┌────────────┐
                       │            │ Generate   │
                       │            │  Recipes   │
                       │            └─────┬──────┘
                       │                  │
                       │        ┌─────────┴──────────┐
                       │        │                    │
                       ▼        ▼                    │
                  ┌────────────────┐          ┌─────▼──────┐
                  │ TraceManager   │          │RecipePool  │
                  │  .add_trace()  │          │            │
                  └────────┬───────┘          └─────┬──────┘
                           │                        │
                           │  select_trace()        │
                           ├────────────┐           │
                           │            │           │
                           ▼            │           │
                      ┌─────────┐       │           │
                      │  Trace  │       │           │
                      └────┬────┘       │           │
                           │            │           │
                           │            │           │
                   ┌───────▼────────────▼───────────▼──────┐
                   │         Mutator                        │
                   │  (Base or Smart)                       │
                   │  .mutate(trace, recipe_hint)           │
                   └───────┬────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  FuzzInstructions│
                  └────────┬─────────┘
                           │
                           │   write to SHM
                           ▼
                  ┌─────────────────┐
                  │  Shared Memory  │
                  │  + IPC Pipes    │
                  └────────┬─────────┘
                           │
                           │   fork + exec
                           ▼
                  ┌─────────────────┐
                  │  QEMU FUZZING   │
                  │  (replays trace │
                  │   with mutations│
                  └────────┬─────────┘
                           │
                           │   coverage + status
                           ▼
                  ┌─────────────────┐
                  │ ExecutionResult │
                  │  - status       │
                  │  - coverage     │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │CoverageTracker  │
                  │ .analyze()      │
                  └────────┬─────────┘
                           │
            ┌──────────────┴──────────────┐
            │                             │
            ▼                             ▼
    ┌──────────────┐            ┌─────────────────┐
    │ has_new_edges│            │   crashed?      │
    │     ?        │            │                 │
    └──────┬───────┘            └────────┬────────┘
           │ YES                         │ YES
           ▼                             ▼
    ┌──────────────┐            ┌─────────────────┐
    │  Save New    │            │  Save Crash     │
    │  Trace       │            │  + Analyze      │
    └──────┬───────┘            └────────┬────────┘
           │                             │
           └──────────────┬──────────────┘
                          │
                          ▼
                  ┌─────────────────┐
                  │ Update Stats    │
                  └────────┬─────────┘
                           │
                           │
                           └────► Loop back to TraceManager
```

---

**维护者**: RR-Fuzz Team  
**最后更新**: 2025-11-02  
**版本**: 6.0 (超详细版)


╔══════════════════════════════════════════════════════════════════╗
║     RR-Fuzz Strace Replay - 函数级别详细分析 (Part 1/4)         ║
║              rr_replay_strace_optimized.c 模块分析               ║
╚══════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════
【文件概览】
═══════════════════════════════════════════════════════════════════

文件: rr_replay_strace_optimized.c
总行数: 560行
功能: Strace重放引擎的主控制逻辑
依赖:
  - rr_framework.h
  - rr_syscallparser.h
  - rr_syscall_dispatch.h
  - rr_mapping_manager.h

关键数据结构: 4个
关键函数: 20个
全局变量: 5个

═══════════════════════════════════════════════════════════════════
【全局变量分析】
═══════════════════════════════════════════════════════════════════

1. g_strace_parser (static rr_strace_parser_t*)
   ┌────────────────────────────────────────────────────────┐
   │ 作用: Strace解析器实例指针                            │
   │ 初始化: rr_strace_replay_init() 中创建                │
   │ 使用: optimized_find_matching_record() 调用其API      │
   │ 生命周期: init→使用→cleanup                           │
   │ 线程安全: 否 (单线程设计)                             │
   └────────────────────────────────────────────────────────┘

2. g_strace_state (static rr_strace_replay_state_t)
   ┌────────────────────────────────────────────────────────┐
   │ 结构定义:                                              │
   │   typedef struct {                                     │
   │       bool enabled;              // 模块是否启用       │
   │       bool strict_mode;          // 严格模式标志       │
   │       bool skip_unmatched;       // 跳过不匹配         │
   │       int max_lookahead;         // 最大前瞻数         │
   │       uint64_t total_syscalls;   // 总系统调用数       │
   │       uint64_t matched_syscalls; // 匹配成功数         │
   │       uint64_t skipped_syscalls; // 跳过数             │
   │       uint64_t error_syscalls;   // 错误数             │
   │       uint64_t fallback_syscalls;// fallback数         │
   │       char *trace_filename;      // trace文件名        │
   │       size_t current_record_index; // 当前索引         │
   │       bool trace_exhausted;      // trace是否耗尽      │
   │       bool allow_fallback_execution; // 允许fallback   │
   │   } rr_strace_replay_state_t;                          │
   │                                                        │
   │ 作用: 维护整个重放系统的状态                           │
   │ 更新频率: 每个syscall都会更新                         │
   │ 重要字段:                                              │
   │   - trace_exhausted: 一旦为true，所有后续syscall fallback │
   │   - total_syscalls: 用于周期性统计输出                │
   └────────────────────────────────────────────────────────┘

3. g_current_record (static rr_strace_record_t*)
   ┌────────────────────────────────────────────────────────┐
   │ 作用: 保存当前正在处理的record，供POST-HOOK使用       │
   │ 生命周期: 非常短暂                                     │
   │   设置: rr_replay_syscall_strace_optimized() 中       │
   │   使用: rr_strace_syscall_post_hook_optimized() 中    │
   │   清理: POST-HOOK执行后立即置NULL                      │
   │ 关键性: 极其重要! 连接PRE和POST处理的桥梁            │
   └────────────────────────────────────────────────────────┘

4. g_stats_filename (static char[256])
   ┌────────────────────────────────────────────────────────┐
   │ 作用: 统计文件路径                                     │
   │ 格式: /tmp/rr_strace_optimized_stats_PID.txt          │
   │ 用途: 周期性写入统计信息                               │
   └────────────────────────────────────────────────────────┘

5. g_strace_log_level (static strace_log_level_t)
   ┌────────────────────────────────────────────────────────┐
   │ 枚举定义:                                              │
   │   STRACE_LOG_ERROR = 0    // 仅错误                   │
   │   STRACE_LOG_WARN = 1     // 错误+警告                │
   │   STRACE_LOG_INFO = 2     // +基本信息                │
   │   STRACE_LOG_VERBOSE = 3  // +详细信息                │
   │   STRACE_LOG_DEBUG = 4    // +调试信息                │
   │                                                        │
   │ 控制: 环境变量 RR_STRACE_LOG_LEVEL                    │
   │ 默认: STRACE_LOG_INFO (2)                             │
   └────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════
【核心函数详细分析】
═══════════════════════════════════════════════════════════════════

函数 1/20: rr_strace_replay_init
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

函数签名:
  int rr_strace_replay_init(const char *trace_file)

参数:
  trace_file - strace格式的trace文件路径 (例如: ./strace-ls-record.txt)

返回值:
  0  - 成功
  -1 - 失败

调用者:
  rr_framework_init() [rr_main.c]

被调用函数:
  1. init_strace_log_level()              // 初始化日志级别
  2. rr_syscall_dispatch_init()           // 初始化分发器
  3. rr_mapping_manager_init(256, 128)    // 初始化映射管理器
  4. rr_strace_parser_init(trace_file)    // 创建parser
  5. rr_strace_parser_load(parser)        // 加载trace文件
  6. rr_strace_get_stats(parser, ...)     // 获取统计信息
  7. signal(SIGINT, handler)              // 注册信号处理器

执行流程:
  ┌─────────────────────────────────────────────────────────┐
  │ [步骤1] 参数验证                                        │
  │   if (!trace_file) → return -1                          │
  │                                                         │
  │ [步骤2] 初始化日志系统                                  │
  │   init_strace_log_level()                               │
  │   → 读取环境变量 RR_STRACE_LOG_LEVEL                   │
  │   → 设置 g_strace_log_level                            │
  │                                                         │
  │ [步骤3] 初始化全局状态                                  │
  │   memset(&g_strace_state, 0, ...)                       │
  │   g_strace_state.trace_filename = strdup(trace_file)    │
  │   g_strace_state.strict_mode = false                    │
  │   g_strace_state.skip_unmatched = true                  │
  │   g_strace_state.max_lookahead = 5                      │
  │   g_strace_state.trace_exhausted = false                │
  │   g_strace_state.allow_fallback_execution = true        │
  │                                                         │
  │ [步骤4] 初始化系统调用分发器                            │
  │   rr_syscall_dispatch_init()                            │
  │   → 创建syscall_lookup_table[512]                       │
  │   → 填充handler指针                                     │
  │   失败处理: 清理trace_filename，return -1              │
  │                                                         │
  │ [步骤5] 初始化映射管理器                                │
  │   rr_mapping_manager_init(256, 128)                     │
  │   → FD哈希表: 256 buckets                              │
  │   → 地址哈希表: 128 buckets                            │
  │   失败处理: 清理dispatcher和trace_filename，return -1  │
  │                                                         │
  │ [步骤6] 创建并加载strace解析器                          │
  │   g_strace_parser = rr_strace_parser_init(trace_file)   │
  │   → 创建parser结构体                                    │
  │   → 打开trace文件                                       │
  │                                                         │
  │   rr_strace_parser_load(g_strace_parser)                │
  │   → while (fgets(line, ...)) {                          │
  │        parse_strace_line(line)                          │
  │        → 创建rr_strace_record_t                         │
  │        → 解析syscall_name, args[], ret_value           │
  │        → 添加到records数组                              │
  │     }                                                   │
  │   → 例如: 加载100条records                             │
  │                                                         │
  │   失败处理: 清理所有已初始化资源，return -1            │
  │                                                         │
  │ [步骤7] 获取统计信息                                    │
  │   rr_strace_get_stats(parser, &total, &current)         │
  │   → total_records = 100                                 │
  │   → current_index = 0                                   │
  │                                                         │
  │ [步骤8] 标记为启用状态                                  │
  │   g_strace_state.enabled = true                         │
  │                                                         │
  │ [步骤9] 注册信号处理器                                  │
  │   signal(SIGINT, rr_strace_signal_handler)              │
  │   signal(SIGTERM, rr_strace_signal_handler)             │
  │   signal(SIGQUIT, rr_strace_signal_handler)             │
  │   → 确保Ctrl+C时保存统计信息                           │
  │                                                         │
  │ [步骤10] 设置统计文件名并初始保存                       │
  │   snprintf(g_stats_filename, ...,                       │
  │            "/tmp/rr_strace_optimized_stats_%d.txt", pid)│
  │   rr_strace_save_stats_to_file(g_stats_filename)        │
  │                                                         │
  │ [步骤11] 输出初始化成功信息                             │
  │   RR_INFO("Optimized strace replay initialized...")     │
  │   RR_INFO("- Trace file: %s", trace_file)               │
  │   RR_INFO("- Total records: %zu", total_records)        │
  │   RR_INFO("- Stats file: %s", g_stats_filename)         │
  │                                                         │
  │ return 0                                                │
  └─────────────────────────────────────────────────────────┘

内存分配:
  1. g_strace_state.trace_filename - strdup()分配
  2. g_strace_parser结构体 - malloc()
  3. parser->records数组 - malloc()
  4. FD哈希表 - calloc(256 * sizeof(ptr))
  5. 地址哈希表 - calloc(128 * sizeof(ptr))

错误处理路径:
  ┌────────────────────┐
  │ trace_file == NULL │ → return -1
  └────────────────────┘
          │
  ┌────────────────────┐
  │ strdup失败         │ → return -1
  └────────────────────┘
          │
  ┌────────────────────┐
  │ dispatch_init失败  │ → free(trace_filename) → return -1
  └────────────────────┘
          │
  ┌────────────────────┐
  │ mapping_init失败   │ → cleanup(dispatch) + free(trace_filename)
  └────────────────────┘
          │
  ┌────────────────────┐
  │ parser_init失败    │ → cleanup(mapping + dispatch + trace_filename)
  └────────────────────┘
          │
  ┌────────────────────┐
  │ parser_load失败    │ → cleanup(parser + mapping + dispatch + filename)
  └────────────────────┘

性能特征:
  - 时间复杂度: O(N) N=trace文件行数
  - 空间复杂度: O(M) M=records数量
  - 一次性开销: ~0.5ms (100 records)
  - 内存占用: ~50KB (100 records + hash tables)

典型调用示例:
  int ret = rr_strace_replay_init("./strace-ls-record.txt");
  if (ret < 0) {
      fprintf(stderr, "Failed to initialize strace replay\n");
      return -1;
  }


函数 2/20: rr_replay_syscall_strace_optimized
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

函数签名:
  abi_long rr_replay_syscall_strace_optimized(
      CPUArchState *env, 
      int num, 
      abi_long *args
  )

参数:
  env  - QEMU CPU状态 (用于copy_to_user等)
  num  - 系统调用号 (例如: 257=openat, 63=uname)
  args - 系统调用参数数组 [8] (会被修改!)

返回值:
  0或正数 - 系统调用结果 (直接返回给应用，不执行真实syscall)
  -1      - 需要QEMU执行真实syscall (混合执行模式)

调用者:
  rr_replay_syscall_strace() [同文件的包装函数]
  ← rr_do_syscall() [rr_main.c]
  ← do_syscall() [syscall.c]

被调用函数:
  1. rr_strace_check_periodic_stats()       // 周期性统计
  2. optimized_find_matching_record(num, args) // 查找匹配
  3. rr_handle_deterministic_uname(env, args[0]) // uname特殊处理
  4. rr_get_syscall_name_fast(num)          // 获取syscall名称
  5. copy_to_user(args[0], &uts, size)      // 写入uname buffer
  6. rr_apply_syscall_args_optimized(record, args) // 应用参数
  7. rr_apply_fd_mapping_optimized(num, args)      // FD映射

执行流程详解:
  ┌─────────────────────────────────────────────────────────┐
  │ [步骤0] 前置检查                                        │
  │   RR_DEBUG("Processing syscall %d", num)                │
  │   if (!g_strace_state.enabled)                          │
  │      RR_ERROR("Module not initialized")                 │
  │      return -1                                          │
  │                                                         │
  │ [步骤1] 更新总计数                                      │
  │   g_strace_state.total_syscalls++                       │
  │   ⚠️ 重要: 必须在trace_exhausted检查之前              │
  │                                                         │
  │ [步骤2] 检查trace是否已耗尽                             │
  │   if (g_strace_state.trace_exhausted) {                 │
  │      g_strace_state.fallback_syscalls++                 │
  │      RR_VERBOSE("Trace exhausted, fallback for %s...",  │
  │                 syscall_name)                           │
  │      return -1  // 直接fallback，不再尝试匹配          │
  │   }                                                     │
  │   💡 性能优化: 避免耗尽后的无效匹配尝试               │
  │                                                         │
  │ [步骤3] 周期性统计检查                                  │
  │   rr_strace_check_periodic_stats()                      │
  │   → if (total_syscalls % 10 == 0)                       │
  │        rr_strace_save_stats_to_file(...)                │
  │                                                         │
  │ [步骤4] 查找匹配的record                                │
  │   record = optimized_find_matching_record(num, args)    │
  │   → 详见函数3的详细分析                                │
  │   → 可能返回NULL (未找到匹配)                          │
  │                                                         │
  │ [步骤5] 特殊处理: uname syscall                         │
  │   if (!record && num == 63) {                           │
  │      RR_INFO("uname match failed, deterministic...")    │
  │      return rr_handle_deterministic_uname(env, args[0]) │
  │      → matched_syscalls++                               │
  │      → return 0 (成功)                                  │
  │   }                                                     │
  │   💡 为什么特殊处理？                                  │
  │      uname可能不在trace中，或者环境不同导致失败        │
  │      直接返回固定值，避免触发fallback路径              │
  │                                                         │
  │ [步骤6] 处理未匹配情况                                  │
  │   if (!record) {                                        │
  │      g_strace_state.error_syscalls++                    │
  │      RR_WARN("No matching record for %s (%d)",          │
  │              syscall_name, num)                         │
  │      if (g_strace_state.skip_unmatched)                 │
  │         return -1  // fallback执行                      │
  │      else                                               │
  │         errno = ENOSYS                                  │
  │         return -1                                       │
  │   }                                                     │
  │                                                         │
  │ [步骤7] 匹配成功，更新计数                              │
  │   g_strace_state.matched_syscalls++                     │
  │   RR_VERBOSE("Found matching record: %s, ret=%ld",      │
  │              record->syscall_name, record->ret_value)   │
  │                                                         │
  │ [步骤8] 特殊处理: uname需要提前填充buffer              │
  │   if (num == 63) {  // TARGET_NR_uname                  │
  │      RR_INFO("uname: filling buffer BEFORE param mod")  │
  │      struct new_utsname uts;                            │
  │      memset(&uts, 0, sizeof(uts))                       │
  │      strcpy(uts.sysname, "Linux")                       │
  │      strcpy(uts.nodename, "replay-node")                │
  │      strcpy(uts.release, "6.8.0")                       │
  │      strcpy(uts.version, "#1 SMP PREEMPT_DYNAMIC")      │
  │      strcpy(uts.machine, "x86_64")                      │
  │      strcpy(uts.domainname, "(none)")                   │
  │                                                         │
  │      if (args[0]) {                                     │
  │         int result = copy_to_user(args[0], &uts, ...)   │
  │         RR_INFO("uname: copy result=%d, addr=0x%lx",    │
  │                 result, args[0])                        │
  │         if (result == 0) {                              │
  │            RR_INFO("uname: success, returning 0")       │
  │            return 0  // ⚠️ 直接返回，不执行真实syscall  │
  │         }                                               │
  │      }                                                  │
  │   }                                                     │
  │   💡 为什么在修改参数之前？                            │
  │      因为参数修改可能改变args[0]地址                    │
  │      需要使用原始地址写入buffer                         │
  │                                                         │
  │ [步骤9] 保存原始参数用于对比                            │
  │   abi_long orig_args[8]                                 │
  │   for (int i = 0; i < 8; i++)                           │
  │      orig_args[i] = args[i]                             │
  │                                                         │
  │ [步骤10] 应用记录的参数                                 │
  │   rr_apply_syscall_args_optimized(record, args)         │
  │   → 详见函数级分析                                      │
  │   → 根据syscall类型应用不同的参数                       │
  │                                                         │
  │ [步骤11] 应用FD映射                                     │
  │   rr_apply_fd_mapping_optimized(num, args)              │
  │   → 详见函数级分析                                      │
  │   → 将recorded FD转换为actual FD                        │
  │                                                         │
  │ [步骤12] 检测并输出参数修改                             │
  │   bool args_modified = false                            │
  │   for (int i = 0; i < 8; i++) {                         │
  │      if (orig_args[i] != args[i]) {                     │
  │         args_modified = true                            │
  │         RR_DEBUG("PARAM: %s arg[%d] %ld -> %ld",        │
  │                  name, i, orig_args[i], args[i])        │
  │      }                                                  │
  │   }                                                     │
  │   if (args_modified)                                    │
  │      RR_DEBUG("PARAM: %s replacement completed", name)  │
  │                                                         │
  │ [步骤13] 保存当前record供POST-HOOK使用                  │
  │   g_current_record = record                             │
  │   ⚠️ 极其重要! POST-HOOK依赖此变量                     │
  │                                                         │
  │ [步骤14] 返回-1，让QEMU执行真实syscall                  │
  │   RR_VERBOSE("Hybrid mode: letting QEMU execute...")    │
  │   return -1                                             │
  │   💡 混合执行模式的关键:                                │
  │      - 参数来自record (确定性)                          │
  │      - 执行用真实syscall (兼容性)                       │
  └─────────────────────────────────────────────────────────┘

参数修改示例:
  ┌──────────────────────────────────────────────────────┐
  │ syscall: openat(-100, "/etc/ld.so.cache", O_RDONLY) │
  │                                                      │
  │ 步骤10前: args = [-100, 0x7fff..., 0x80000, ...]    │
  │          (应用程序传入的原始参数)                     │
  │                                                      │
  │ 步骤10后: args = [-100, 0x7fff..., 0x80000, 0, ...] │
  │          (args[2]=flags, args[3]=mode从record应用)   │
  │                                                      │
  │ 步骤11后: args = [-100, 0x7fff..., 0x80000, 0, ...] │
  │          (args[0]=-100不需要FD映射)                  │
  └──────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────┐
  │ syscall: mmap(NULL, 84536, PROT_READ, MAP_PRIVATE,  │
  │              5, 0)                                   │
  │                                                      │
  │ 步骤10前: args = [0, 84536, 1, 2, 5, 0]             │
  │                                                      │
  │ 步骤10后: args = [0, 84536, 1, 2, 5, 0]             │
  │          (mmap的apply_args应用了args[4]=5从record)   │
  │                                                      │
  │ 步骤11后: args = [0, 84536, 1, 2, 6, 0]             │
  │          (FD映射: 5 → 6, 因为实际FD是6)             │
  └──────────────────────────────────────────────────────┘

控制流决策:
  1. enabled检查 → 未初始化则返回-1
  2. trace_exhausted → true则直接fallback
  3. record查找结果 → NULL + uname特殊处理
  4. record查找结果 → NULL + 其他syscall → error或fallback
  5. record查找结果 → found → 应用参数+FD映射
  6. uname特殊情况 → 提前填充buffer → return 0

性能分析:
  - 平均执行时间: ~0.1ms
    * 匹配查找: 0.05ms
    * 参数应用: 0.01ms
    * FD映射: 0.001ms
  - 最坏情况: ~1ms (需要跳过多个records)
  - 最优情况: ~0.05ms (直接匹配)

副作用:
  ✓ 修改args数组 (PRE处理)
  ✓ 更新g_strace_state统计计数器
  ✓ 设置g_current_record (POST-HOOK依赖)
  ✓ 可能设置trace_exhausted标志
  ✓ 周期性写入统计文件


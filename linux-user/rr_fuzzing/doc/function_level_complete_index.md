╔══════════════════════════════════════════════════════════════════╗
║     RR-Fuzz Strace Replay - 函数级别完整分析索引                ║
╚══════════════════════════════════════════════════════════════════╝

本文档提供所有关键函数的完整索引和详细分析。

═══════════════════════════════════════════════════════════════════
【文档结构】
═══════════════════════════════════════════════════════════════════

FUNCTION_LEVEL_ANALYSIS_PART1.md  - rr_replay_strace_optimized.c
FUNCTION_LEVEL_ANALYSIS_PART2.md  - rr_syscall_dispatch.c
FUNCTION_LEVEL_ANALYSIS_PART3.md  - rr_mapping_manager.c
FUNCTION_LEVEL_ANALYSIS_PART4.md  - rr_syscallparser.c
FUNCTION_LEVEL_COMPLETE_INDEX.md  - 本文件 (索引和概览)

═══════════════════════════════════════════════════════════════════
【函数总览】
═══════════════════════════════════════════════════════════════════

模块1: rr_replay_strace_optimized.c (重放引擎)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┌──┬──────────────────────────────────────┬─────┬────────────┐
│ID│ 函数名                                │ 行数│ 复杂度     │
├──┼──────────────────────────────────────┼─────┼────────────┤
│1 │rr_strace_replay_init                 │ 80  │ 中等       │
│2 │rr_replay_syscall_strace_optimized    │ 115 │ 高         │
│3 │optimized_find_matching_record        │ 68  │ 高         │
│4 │rr_strace_syscall_post_hook_optimized │ 14  │ 低         │
│5 │rr_handle_deterministic_uname         │ 8   │ 低         │
│6 │rr_strace_check_periodic_stats        │ 10  │ 低         │
│7 │rr_strace_save_stats_to_file          │ 40  │ 低         │
│8 │rr_strace_replay_print_stats          │ 20  │ 低         │
│9 │rr_strace_signal_handler              │ 12  │ 低         │
│10│rr_strace_replay_cleanup              │ 25  │ 低         │
│11│rr_strace_set_mode_optimized          │ 10  │ 低         │
│12│rr_strace_get_replay_stats_optimized  │ 8   │ 低         │
│13│init_strace_log_level                 │ 15  │ 低         │
└──┴──────────────────────────────────────┴─────┴────────────┘

模块2: rr_syscall_dispatch.c (分发器)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┌──┬──────────────────────────────────────┬─────┬────────────┐
│ID│ 函数名                                │ 行数│ 复杂度     │
├──┼──────────────────────────────────────┼─────┼────────────┤
│14│apply_file_io_args                    │ 22  │ 中等       │
│15│apply_file_io_fd_mapping              │ 17  │ 中等       │
│16│file_io_post_hook                     │ 13  │ 低         │
│17│apply_memory_args                     │ 11  │ 低         │
│18│apply_memory_fd_mapping               │ 8   │ 低         │
│19│memory_post_hook                      │ 16  │ 低         │
│20│apply_network_args                    │ 14  │ 低         │
│21│network_post_hook                     │ 8   │ 低         │
│22│apply_generic_args                    │ 9   │ 低         │
│23│generic_post_hook                     │ 6   │ 极低       │
│24│rr_syscall_dispatch_init              │ 18  │ 低         │
│25│rr_get_syscall_handler                │ 9   │ 极低       │
│26│rr_get_syscall_name_fast              │ 4   │ 极低       │
│27│rr_get_syscall_importance             │ 4   │ 极低       │
│28│rr_apply_syscall_args_optimized       │ 11  │ 低         │
│29│rr_apply_fd_mapping_optimized         │ 8   │ 低         │
│30│rr_syscall_post_hook_optimized        │ 8   │ 低         │
└──┴──────────────────────────────────────┴─────┴────────────┘

模块3: rr_mapping_manager.c (映射管理器)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┌──┬──────────────────────────────────────┬─────┬────────────┐
│ID│ 函数名                                │ 行数│ 复杂度     │
├──┼──────────────────────────────────────┼─────┼────────────┤
│31│hash_fd                               │ 3   │ 极低       │
│32│hash_addr                             │ 3   │ 极低       │
│33│create_fd_mapping                     │ 10  │ 低         │
│34│rr_fd_mapping_add                     │ 27  │ 中等       │
│35│rr_fd_mapping_get                     │ 19  │ 低         │
│36│rr_fd_mapping_remove                  │ 18  │ 低         │
│37│rr_fd_mapping_exists                  │ 14  │ 低         │
│38│create_addr_mapping                   │ 11  │ 低         │
│39│rr_addr_mapping_add                   │ 28  │ 中等       │
│40│rr_addr_mapping_get                   │ 19  │ 低         │
│41│rr_addr_mapping_remove                │ 18  │ 低         │
│42│rr_addr_mapping_exists                │ 14  │ 低         │
│43│rr_mapping_manager_init               │ 43  │ 中等       │
│44│rr_mapping_manager_cleanup            │ 35  │ 中等       │
│45│rr_mapping_get_stats                  │ 41  │ 中等       │
│46│rr_mapping_print_stats                │ 23  │ 低         │
└──┴──────────────────────────────────────┴─────┴────────────┘

模块4: rr_syscallparser.c (解析器)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┌──┬──────────────────────────────────────┬─────┬────────────┐
│ID│ 函数名                                │ 行数│ 复杂度     │
├──┼──────────────────────────────────────┼─────┼────────────┤
│47│rr_strace_parser_init                 │ 20  │ 低         │
│48│rr_strace_parser_load                 │ 120 │ 极高       │
│49│rr_strace_parser_get_next             │ 12  │ 低         │
│50│rr_strace_parser_cleanup              │ 30  │ 中等       │
│51│parse_strace_line                     │ 200+│ 极高       │
│52│parse_syscall_args                    │ 80  │ 高         │
│53│parse_return_value                    │ 40  │ 中等       │
└──┴──────────────────────────────────────┴─────┴────────────┘

═══════════════════════════════════════════════════════════════════
【关键函数调用图】
═══════════════════════════════════════════════════════════════════

应用程序 syscall
    │
    ↓
do_syscall [syscall.c]
    │
    ↓
rr_do_syscall [rr_main.c]
    │
    ├→ if (getpid) return 12345
    ├→ if (getuid) return 1000
    │
    └→ rr_replay_syscall_strace
          │
          └→ rr_replay_syscall_strace_optimized  ⭐ 核心函数2
                │
                ├→ rr_strace_check_periodic_stats  [函数6]
                │
                ├→ optimized_find_matching_record  ⭐ 核心函数3
                │     │
                │     ├→ rr_get_syscall_name_fast  [函数26]
                │     ├→ rr_get_syscall_importance [函数27]
                │     └→ rr_strace_parser_get_next [函数49]
                │
                ├→ rr_handle_deterministic_uname   [函数5]
                │
                ├→ rr_apply_syscall_args_optimized ⭐ 核心函数28
                │     │
                │     ├→ rr_get_syscall_handler_by_name
                │     │
                │     ├→ handler->apply_args
                │     │     ├→ apply_file_io_args    [函数14]
                │     │     ├→ apply_memory_args     [函数17]
                │     │     ├→ apply_network_args    [函数20]
                │     │     └→ apply_generic_args    [函数22]
                │     │
                │     └→ (fallback to generic if no handler)
                │
                └→ rr_apply_fd_mapping_optimized   ⭐ 核心函数29
                      │
                      ├→ rr_get_syscall_handler
                      │
                      └→ handler->apply_fd_mapping
                            ├→ apply_file_io_fd_mapping [函数15]
                            ├→ apply_memory_fd_mapping  [函数18]
                            │     │
                            │     └→ rr_fd_mapping_get  ⭐ 核心函数35
                            │           │
                            │           ├→ hash_fd
                            │           └→ 遍历bucket链表
                            │
                            └→ (network使用file_io的)

do_syscall1 [syscall.c]  ← 真实系统调用执行
    │
    ↓
rr_strace_syscall_post_hook_optimized  ⭐ 核心函数4
    │
    └→ rr_syscall_post_hook_optimized  [函数30]
          │
          ├→ rr_get_syscall_handler
          │
          └→ handler->post_hook
                ├→ file_io_post_hook       ⭐ 核心函数16
                │     │
                │     ├→ if (openat)
                │     │     rr_fd_mapping_add  ⭐ 核心函数34
                │     │        │
                │     │        ├→ hash_fd
                │     │        ├→ create_fd_mapping
                │     │        └→ 插入哈希表
                │     │
                │     └→ if (close)
                │           rr_fd_mapping_remove [函数36]
                │
                ├→ memory_post_hook         [函数19]
                │     │
                │     ├→ if (mmap)
                │     │     rr_addr_mapping_add  [函数39]
                │     │
                │     └→ if (munmap)
                │           rr_addr_mapping_remove [函数41]
                │
                └→ network_post_hook        [函数21]
                      └→ if (socket/accept)
                            rr_fd_mapping_add

═══════════════════════════════════════════════════════════════════
【数据流图】
═══════════════════════════════════════════════════════════════════

trace文件 (strace-ls-record.txt)
    │
    ↓
rr_strace_parser_load [函数48]
    ├→ fopen()
    ├→ while (fgets(line))
    │     ├→ parse_strace_line [函数51]
    │     │     ├→ 提取syscall_name
    │     │     ├→ parse_syscall_args [函数52]
    │     │     └→ parse_return_value [函数53]
    │     │
    │     └→ 创建rr_strace_record_t
    │           ├→ syscall_name: "openat"
    │           ├→ arg_count: 4
    │           ├→ args[]: [-100, path_addr, flags, mode]
    │           └→ ret_value: 5
    │
    └→ g_strace_parser->records[] (内存数组)
          [0]: brk(NULL) = 0x55555557a000
          [1]: arch_prctl(...) = -22
          [2]: uname(...) = 0
          ...
          [99]: write(1, ...) = 1234

运行时: 应用调用 openat(...)
    │
    ├→ args[] = [-100, 0x7fff..., 0x80000, 0]
    │
    ↓
optimized_find_matching_record [函数3]
    │
    ├→ 遍历records，查找"openat"
    │
    └→ 返回: record[6] = {
          syscall_name: "openat",
          args[0]: -100,
          args[1]: path_addr,
          args[2]: 0x80000,  ← flags
          args[3]: 0,        ← mode
          ret_value: 5       ← recorded FD
       }

rr_apply_syscall_args_optimized [函数28]
    │
    ├→ handler = syscall_handlers["openat"]
    │
    ├→ apply_file_io_args(record, args) [函数14]
    │     ├→ args[2] = record->args[2].value  (0x80000)
    │     └→ args[3] = record->args[3].value  (0)
    │
    └→ args[] 变为 [-100, 0x7fff..., 0x80000, 0]

rr_apply_fd_mapping_optimized [函数29]
    │
    ├→ handler = syscall_handlers[257]
    │
    ├→ apply_file_io_fd_mapping("openat", args) [函数15]
    │     └→ if (args[0] != -100)
    │           args[0] = rr_fd_mapping_get(args[0])
    │     (本例中args[0]=-100，不需要映射)
    │
    └→ args[] 保持 [-100, 0x7fff..., 0x80000, 0]

do_syscall1 执行真实syscall
    │
    ├→ ret = openat(-100, "/etc/ld.so.cache", 0x80000, 0)
    │
    └→ ret = 6  ⬅ 实际FD (因为FD=5被trace文件占用)

rr_strace_syscall_post_hook_optimized [函数4]
    │
    └→ file_io_post_hook(record, ret=6, args) [函数16]
          │
          ├→ if (strcmp(name, "openat") == 0)
          │
          └→ rr_fd_mapping_add(
                recorded_fd = record->ret_value = 5,
                actual_fd = ret = 6
             )
             │
             ├→ bucket = hash_fd(5) → 123
             ├→ create_fd_mapping(5, 6)
             └→ g_fd_table->buckets[123] → [5→6] ✓

下一个syscall: mmap(..., fd=5, ...)
    │
    ↓
rr_apply_fd_mapping_optimized
    │
    └→ apply_memory_fd_mapping("mmap", args) [函数18]
          │
          └→ args[4] = rr_fd_mapping_get(5)
                │
                ├→ bucket = hash_fd(5) → 123
                ├→ 遍历 buckets[123] 链表
                ├→ 找到 mapping{recorded=5, actual=6}
                └→ 返回 6  ✓
          │
          └→ args[4] 变为 6

do_syscall1 执行
    │
    └→ mmap(..., fd=6, ...) ✓ 成功!

═══════════════════════════════════════════════════════════════════
【性能分析】
═══════════════════════════════════════════════════════════════════

热路径函数 (每个syscall都会调用):
┌─────────────────────────────────────┬─────────┬──────────┐
│ 函数                                │ 调用次数│ 耗时     │
├─────────────────────────────────────┼─────────┼──────────┤
│ rr_replay_syscall_strace_optimized  │ 100     │ ~10ms    │
│ optimized_find_matching_record      │ 100     │ ~5ms     │
│ rr_apply_syscall_args_optimized     │ 95      │ ~1ms     │
│ rr_apply_fd_mapping_optimized       │ 95      │ ~0.1ms   │
│ rr_strace_syscall_post_hook         │ 95      │ ~0.2ms   │
│ rr_fd_mapping_get                   │ ~200    │ ~0.2ms   │
│ rr_fd_mapping_add                   │ ~10     │ ~0.01ms  │
├─────────────────────────────────────┼─────────┼──────────┤
│ 总计                                │ ~695    │ ~16.5ms  │
└─────────────────────────────────────┴─────────┴──────────┘

冷路径函数 (偶尔调用):
┌─────────────────────────────────────┬─────────┬──────────┐
│ 函数                                │ 调用次数│ 耗时     │
├─────────────────────────────────────┼─────────┼──────────┤
│ rr_strace_check_periodic_stats      │ 10      │ ~1ms     │
│ rr_handle_deterministic_uname       │ 1       │ ~0.01ms  │
│ rr_fd_mapping_remove                │ ~10     │ ~0.01ms  │
└─────────────────────────────────────┴─────────┴──────────┘

初始化/清理 (一次性):
┌─────────────────────────────────────┬─────────┬──────────┐
│ 函数                                │ 调用次数│ 耗时     │
├─────────────────────────────────────┼─────────┼──────────┤
│ rr_strace_replay_init               │ 1       │ ~0.5ms   │
│ rr_strace_parser_load               │ 1       │ ~0.3ms   │
│ rr_mapping_manager_init             │ 1       │ ~0.05ms  │
│ rr_syscall_dispatch_init            │ 1       │ ~0.01ms  │
│ rr_strace_replay_cleanup            │ 1       │ ~0.1ms   │
└─────────────────────────────────────┴─────────┴──────────┘

═══════════════════════════════════════════════════════════════════
【内存使用分析】
═══════════════════════════════════════════════════════════════════

静态分配:
┌──────────────────────────────────┬──────────┬─────────┐
│ 数据结构                         │ 大小     │ 数量    │
├──────────────────────────────────┼──────────┼─────────┤
│ syscall_handlers[]               │ ~8KB     │ 1       │
│ syscall_lookup_table[]           │ ~4KB     │ 1       │
│ g_strace_state                   │ ~100B    │ 1       │
│ g_stats_filename                 │ 256B     │ 1       │
├──────────────────────────────────┼──────────┼─────────┤
│ 小计                             │ ~12KB    │         │
└──────────────────────────────────┴──────────┴─────────┘

动态分配 (初始化时):
┌──────────────────────────────────┬──────────┬─────────┐
│ 数据结构                         │ 大小     │ 数量    │
├──────────────────────────────────┼──────────┼─────────┤
│ rr_strace_record_t               │ ~150B    │ 100     │
│ FD哈希表 buckets                 │ 8B*256   │ 1       │
│ 地址哈希表 buckets               │ 8B*128   │ 1       │
│ rr_strace_parser_t               │ ~200B    │ 1       │
├──────────────────────────────────┼──────────┼─────────┤
│ 小计                             │ ~20KB    │         │
└──────────────────────────────────┴──────────┴─────────┘

运行时分配 (根据需要):
┌──────────────────────────────────┬──────────┬─────────┐
│ 数据结构                         │ 大小     │ 数量    │
├──────────────────────────────────┼──────────┼─────────┤
│ rr_fd_mapping_t                  │ ~24B     │ ~10     │
│ rr_addr_mapping_t                │ ~32B     │ ~50     │
├──────────────────────────────────┼──────────┼─────────┤
│ 小计                             │ ~2KB     │         │
└──────────────────────────────────┴──────────┴─────────┘

总内存占用: ~34KB

═══════════════════════════════════════════════════════════════════
【复杂度分析】
═══════════════════════════════════════════════════════════════════

┌──────────────────────────────────┬────────┬────────┬────────┐
│ 函数                             │ 时间   │ 空间   │ 调用   │
├──────────────────────────────────┼────────┼────────┼────────┤
│ optimized_find_matching_record   │ O(M)   │ O(1)   │ Hot    │
│ rr_fd_mapping_get                │ O(1)*  │ O(1)   │ Hot    │
│ rr_fd_mapping_add                │ O(1)*  │ O(1)   │ Warm   │
│ rr_apply_syscall_args_optimized  │ O(1)   │ O(1)   │ Hot    │
│ rr_strace_parser_load            │ O(N)   │ O(N)   │ Cold   │
│ rr_mapping_manager_init          │ O(B)   │ O(B)   │ Cold   │
└──────────────────────────────────┴────────┴────────┴────────┘

M = max_skip 数量 (5-50)
N = trace文件记录数 (100)
B = 哈希表bucket数 (256+128)
* = 平摊时间复杂度，最坏情况O(N)如果所有映射哈希冲突

═══════════════════════════════════════════════════════════════════

详细的函数级分析请参阅:
  - FUNCTION_LEVEL_ANALYSIS_PART1.md (已完成，448行)
  - FUNCTION_LEVEL_ANALYSIS_PART2.md (待创建)
  - FUNCTION_LEVEL_ANALYSIS_PART3.md (待创建)
  - FUNCTION_LEVEL_ANALYSIS_PART4.md (待创建)

═══════════════════════════════════════════════════════════════════

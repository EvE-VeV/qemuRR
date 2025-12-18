# rr_main.c 调用关系分析

## 分析策略
基于 `rr_main.c` 的实际调用关系，识别需要优先审计的函数。

## 第一级调用 (直接被 rr_main.c 调用的函数)

### 初始化相关
- `rr_config_init()` - 配置系统初始化
- `rr_debug_init()` - 调试系统初始化
- `rr_config_print()` - 打印配置
- `rr_mapping_manager_init()` - FD/地址映射管理器初始化
- `rr_ipc_init()` - IPC通信初始化
- `rr_coverage_init()` - 覆盖率追踪初始化
- `rr_tree_init()` - Syscall Tree Builder初始化
- `rr_dynamic_trace_init()` - 动态跟踪初始化

### 清理相关
- `rr_config_cleanup()` - 配置清理
- `rr_debug_cleanup()` - 调试清理
- `rr_mapping_manager_cleanup()` - 映射管理器清理
- `rr_ipc_cleanup()` - IPC清理
- `rr_coverage_cleanup()` - 覆盖率清理
- `rr_tree_cleanup()` - Tree清理
- `rr_tree_export_json()` - 导出Tree为JSON
- `rr_dynamic_trace_cleanup()` - 动态跟踪清理
- `rr_fuzz_cleanup()` - Fuzzing清理
- `rr_snapshot_cleanup()` - Snapshot清理

### Record/Replay核心
- `rr_start_recording()` - **关键** 启动记录
- `rr_stop_recording()` - 停止记录
- `rr_start_replay()` - **关键** 启动重放
- `rr_stop_replay()` - 停止重放
- `rr_strace_replay_init()` - Strace重放初始化
- `rr_strace_replay_cleanup()` - Strace重放清理
- `rr_strace_replay_enabled()` - 检查Strace模式
- `rr_replay_syscall()` - **关键** 重放系统调用
- `rr_replay_syscall_strace()` - **关键** Strace重放系统调用
- `rr_replay_syscall_strace_optimized()` - 优化的Strace重放
- `rr_record_syscall()` - **关键** 记录系统调用

### Fuzzing核心
- `rr_fork_server_loop()` - **关键** Fork server循环
- `rr_stop_fork_server()` - 停止Fork server
- `rr_reset_fork_point()` - 重置Fork point
- `rr_fuzz_mutate_syscall()` - 应用变异
- `rr_fuzz_has_retval_override()` - 检查返回值覆盖
- `rr_fuzz_get_retval_override()` - 获取返回值覆盖
- `rr_fuzz_has_buffer_fill()` - 检查缓冲区填充
- `rr_fuzz_get_buffer_fill()` - 获取缓冲区填充

### 映射管理
- `rr_fd_mapping_add()` - **高频** 添加FD映射
- `rr_fd_mapping_remove()` - 移除FD映射
- `rr_fd_mapping_get()` - **高频** 获取FD映射
- `rr_addr_mapping_add()` - 添加地址映射
- `rr_handle_mmap_post()` - mmap后处理

### Snapshot管理
- `rr_snapshot_auto_manage()` - 自动快照管理

### 工具函数
- `rr_framework_enabled()` - 检查框架是否启用
- `is_io_syscall()` - 判断是否为IO系统调用
- `is_expected_deviation()` - 判断偏离是否预期

## 优先级排序

### P0 - 关键路径 (必须详细审计)
1. `rr_start_recording()` - record路径入口
2. `rr_record_syscall()` - 记录核心逻辑
3. `rr_start_replay()` - replay路径入口
4. `rr_replay_syscall()` - 重放核心逻辑
5. `rr_fork_server_loop()` - fuzzing核心

### P1 - 高频调用 (应详细审计)
6. `rr_fd_mapping_add()` - 每个open/dup都会调用
7. `rr_fd_mapping_get()` - 每个文件操作都会查询
8. `rr_mapping_manager_init()` - 映射系统初始化

### P2 - 重要但非关键路径
9. `rr_config_init()` - 配置系统
10. `rr_coverage_init()` - 覆盖率系统
11. `rr_tree_init()` - Tree系统

## 下一步行动
按上述优先级顺序，逐个审计被调用的函数。

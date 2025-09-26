# RR-Fuzz API 参考文档

## 概述

本文档提供RR-Fuzz框架的完整API参考，包括核心函数、数据结构、配置接口和扩展机制。适用于开发者进行二次开发和框架扩展。

## 1. 核心API

### 1.1 框架生命周期管理

#### `rr_framework_init()`
**原型**:
```c
int rr_framework_init(void);
```

**功能**: 初始化RR-Fuzz框架

**返回值**:
- `0`: 成功
- `-1`: 失败

**调用时机**: QEMU启动时，在系统调用拦截之前

**示例**:
```c
if (rr_framework_init() < 0) {
    error_report("Failed to initialize RR-Fuzz framework");
    exit(1);
}
```

---

#### `rr_framework_cleanup()`
**原型**:
```c
void rr_framework_cleanup(void);
```

**功能**: 清理RR-Fuzz框架资源

**返回值**: 无

**调用时机**: QEMU退出时

**示例**:
```c
// 注册退出处理函数
atexit(rr_framework_cleanup);
```

---

#### `rr_framework_enabled()`
**原型**:
```c
static inline bool rr_framework_enabled(void);
```

**功能**: 检查RR-Fuzz框架是否启用

**返回值**:
- `true`: 已启用
- `false`: 未启用

**示例**:
```c
if (rr_framework_enabled()) {
    // 执行RR-Fuzz相关处理
}
```

### 1.2 系统调用处理

#### `rr_do_syscall()`
**原型**:
```c
abi_long rr_do_syscall(CPUArchState *env, int num,
                       abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                       abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8);
```

**功能**: 系统调用前置处理入口点

**参数**:
- `env`: CPU架构状态
- `num`: 系统调用号
- `arg1-arg8`: 系统调用参数

**返回值**:
- `!= -1`: RR-Fuzz处理了该调用，返回系统调用返回值
- `== -1`: RR-Fuzz未处理，需要执行原始系统调用

**示例**:
```c
abi_long do_syscall(CPUArchState *env, int num, ...) {
    abi_long rr_result = rr_do_syscall(env, num, arg1, arg2, ...);
    if (rr_result != -1) {
        return rr_result;
    }

    // 执行原始系统调用
    return original_syscall_handler(env, num, ...);
}
```

---

#### `rr_syscall_post_hook()`
**原型**:
```c
void rr_syscall_post_hook(CPUArchState *env, int num, abi_long ret,
                          abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7, abi_long arg8);
```

**功能**: 系统调用后置处理（记录模式使用）

**参数**:
- `env`: CPU架构状态
- `num`: 系统调用号
- `ret`: 系统调用返回值
- `arg1-arg8`: 系统调用参数

**返回值**: 无

**示例**:
```c
abi_long ret = original_syscall_handler(env, num, ...);
if (rr_framework_enabled() && g_rr_framework->mode == RR_MODE_RECORD) {
    rr_syscall_post_hook(env, num, ret, arg1, arg2, ...);
}
return ret;
```

## 2. 记录模块API

### 2.1 记录控制

#### `rr_start_recording()`
**原型**:
```c
int rr_start_recording(const char *trace_file);
```

**功能**: 开始记录系统调用轨迹

**参数**:
- `trace_file`: 轨迹文件路径，`NULL`使用默认路径

**返回值**:
- `0`: 成功
- `-1`: 失败

**示例**:
```c
if (rr_start_recording("/tmp/my_trace.dat") < 0) {
    RR_ERROR("Failed to start recording");
}
```

---

#### `rr_stop_recording()`
**原型**:
```c
void rr_stop_recording(void);
```

**功能**: 停止记录并关闭轨迹文件

**返回值**: 无

**示例**:
```c
// 程序退出时停止记录
rr_stop_recording();
```

---

#### `rr_record_syscall()`
**原型**:
```c
int rr_record_syscall(CPUArchState *env, int num, const abi_long *args, abi_long ret);
```

**功能**: 记录单个系统调用

**参数**:
- `env`: CPU架构状态
- `num`: 系统调用号
- `args`: 系统调用参数数组
- `ret`: 系统调用返回值

**返回值**:
- `0`: 成功
- `-1`: 失败

**使用**: 通常由框架内部调用，不建议直接使用

### 2.2 数据捕获

#### `rr_capture_string()`
**原型**:
```c
uint8_t *rr_capture_string(CPUArchState *env, target_ulong addr, size_t *len);
```

**功能**: 从目标程序内存捕获字符串

**参数**:
- `env`: CPU架构状态
- `addr`: 目标地址
- `len`: 输出字符串长度（包含结束符）

**返回值**:
- 非`NULL`: 指向捕获数据的指针（需要`g_free`释放）
- `NULL`: 捕获失败

**示例**:
```c
size_t str_len;
uint8_t *str_data = rr_capture_string(env, filename_addr, &str_len);
if (str_data) {
    printf("Captured filename: %s\n", (char*)str_data);
    g_free(str_data);
}
```

---

#### `rr_capture_buffer()`
**原型**:
```c
uint8_t *rr_capture_buffer(CPUArchState *env, target_ulong addr, size_t size);
```

**功能**: 从目标程序内存捕获指定大小的缓冲区

**参数**:
- `env`: CPU架构状态
- `addr`: 目标地址
- `size`: 缓冲区大小

**返回值**:
- 非`NULL`: 指向捕获数据的指针（需要`g_free`释放）
- `NULL`: 捕获失败

**示例**:
```c
uint8_t *buffer = rr_capture_buffer(env, buffer_addr, buffer_size);
if (buffer) {
    // 处理缓冲区数据
    process_buffer_data(buffer, buffer_size);
    g_free(buffer);
}
```

## 3. 重放模块API

### 3.1 重放控制

#### `rr_start_replay()`
**原型**:
```c
int rr_start_replay(const char *trace_file);
```

**功能**: 开始重放轨迹文件

**参数**:
- `trace_file`: 轨迹文件路径

**返回值**:
- `0`: 成功
- `-1`: 失败

**示例**:
```c
if (rr_start_replay("/tmp/my_trace.dat") < 0) {
    RR_ERROR("Failed to start replay");
    return -1;
}
```

---

#### `rr_stop_replay()`
**原型**:
```c
void rr_stop_replay(void);
```

**功能**: 停止重放

**返回值**: 无

---

#### `rr_replay_syscall()`
**原型**:
```c
abi_long rr_replay_syscall(CPUArchState *env, int num, abi_long *args);
```

**功能**: 重放单个系统调用

**参数**:
- `env`: CPU架构状态
- `num`: 系统调用号
- `args`: 系统调用参数数组（可能被修改）

**返回值**: 记录的系统调用返回值

**使用**: 通常由框架内部调用

## 4. 模糊测试引擎API

### 4.1 变异控制

#### `rr_fuzz_apply_instructions()`
**原型**:
```c
int rr_fuzz_apply_instructions(const FuzzInstruction *instructions, size_t count);
```

**功能**: 应用模糊测试变异指令

**参数**:
- `instructions`: 变异指令数组
- `count`: 指令数量

**返回值**:
- `0`: 成功
- `-1`: 失败

**示例**:
```c
FuzzInstruction instructions[] = {
    {
        .cmd = FUZZ_CMD_MUTATE_ARG,
        .syscall_index = 10,
        .arg_index = 1,
        .data_len = sizeof(abi_long),
        .data = {0xFF, 0xFF, 0xFF, 0xFF}
    }
};

rr_fuzz_apply_instructions(instructions, 1);
```

---

#### `rr_fuzz_mutate_syscall()`
**原型**:
```c
void rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr);
```

**功能**: 对特定系统调用应用变异

**参数**:
- `env`: CPU架构状态
- `syscall_index`: 系统调用在轨迹中的索引
- `args`: 系统调用参数数组（会被修改）
- `syscall_nr`: 系统调用号

**返回值**: 无

**使用**: 通常由框架内部调用

---

#### `rr_fuzz_generate_mutations()`
**原型**:
```c
FuzzInstruction *rr_fuzz_generate_mutations(uint32_t target_syscall, int target_arg,
                                          const uint8_t *seed_data, size_t seed_len,
                                          size_t *out_count);
```

**功能**: 生成变异指令

**参数**:
- `target_syscall`: 目标系统调用索引
- `target_arg`: 目标参数索引
- `seed_data`: 种子数据
- `seed_len`: 种子数据长度
- `out_count`: 输出生成的指令数量

**返回值**: 指向变异指令数组的指针（需要`g_free`释放）

**示例**:
```c
size_t mutation_count;
FuzzInstruction *mutations = rr_fuzz_generate_mutations(
    target_syscall, 1, seed_data, seed_len, &mutation_count);

if (mutations) {
    rr_fuzz_apply_instructions(mutations, mutation_count);
    g_free(mutations);
}
```

---

#### `rr_fuzz_cleanup()`
**原型**:
```c
void rr_fuzz_cleanup(void);
```

**功能**: 清理模糊测试引擎资源

**返回值**: 无

## 5. Fork Server API

### 5.1 Fork Server控制

#### `rr_start_fork_server()`
**原型**:
```c
int rr_start_fork_server(uint32_t fork_point);
```

**功能**: 启动Fork Server

**参数**:
- `fork_point`: Fork点位置（系统调用索引）

**返回值**:
- `0`: 成功
- `-1`: 失败

**示例**:
```c
if (rr_start_fork_server(50) < 0) {
    RR_ERROR("Failed to start fork server");
}
```

---

#### `rr_stop_fork_server()`
**原型**:
```c
void rr_stop_fork_server(void);
```

**功能**: 停止Fork Server

**返回值**: 无

---

#### `rr_check_fork_point()`
**原型**:
```c
bool rr_check_fork_point(void);
```

**功能**: 检查是否到达Fork点

**返回值**:
- `true`: 已到达Fork点
- `false`: 未到达Fork点

**示例**:
```c
if (rr_check_fork_point()) {
    // 进入Fork Server主循环
    rr_fork_server_loop();
}
```

---

#### `rr_fork_server_loop()`
**原型**:
```c
int rr_fork_server_loop(void);
```

**功能**: Fork Server主循环

**返回值**:
- `0`: 子进程继续执行
- `-1`: 收到退出命令
- `> 0`: 其他状态

**使用**: 通常由框架内部调用

## 6. IPC通信API

### 6.1 IPC管理

#### `rr_ipc_init()`
**原型**:
```c
int rr_ipc_init(void);
```

**功能**: 初始化IPC通信系统

**返回值**:
- `0`: 成功
- `-1`: 失败

**使用**: 由框架自动调用

---

#### `rr_ipc_cleanup()`
**原型**:
```c
void rr_ipc_cleanup(void);
```

**功能**: 清理IPC通信系统

**返回值**: 无

**使用**: 由框架自动调用

### 6.2 通信接口

#### `rr_ipc_send_status()`
**原型**:
```c
int rr_ipc_send_status(int status);
```

**功能**: 向外部控制器发送状态

**参数**:
- `status`: 状态码
  - `1`: Ready
  - `2`: At Fork Point
  - `3`: Execution Complete
  - `-1`: Error
  - `-2`: Crash

**返回值**:
- `0`: 成功
- `-1`: 失败

**示例**:
```c
// 报告程序崩溃
rr_ipc_send_status(-2);
```

---

#### `rr_ipc_receive_command()`
**原型**:
```c
int rr_ipc_receive_command(void);
```

**功能**: 从外部控制器接收命令

**返回值**:
- `'F'`: Fork命令
- `'Q'`: 退出命令
- `'S'`: 保存快照命令
- `'L'`: 加载快照命令
- `0`: 无命令或错误

**示例**:
```c
int cmd = rr_ipc_receive_command();
switch (cmd) {
    case 'F':
        handle_fork_command();
        break;
    case 'Q':
        exit(0);
        break;
}
```

## 7. 快照管理API

### 7.1 快照操作

#### `rr_snapshot_save()`
**原型**:
```c
int rr_snapshot_save(uint32_t syscall_index);
```

**功能**: 保存当前进程状态快照

**参数**:
- `syscall_index`: 快照时的系统调用索引

**返回值**:
- `>= 0`: 快照ID
- `-1`: 失败

**示例**:
```c
uint32_t snapshot_id = rr_snapshot_save(current_syscall_index);
if (snapshot_id >= 0) {
    printf("Snapshot saved with ID: %u\n", snapshot_id);
}
```

---

#### `rr_snapshot_restore()`
**原型**:
```c
int rr_snapshot_restore(uint32_t syscall_index);
```

**功能**: 恢复到指定的快照状态

**参数**:
- `syscall_index`: 要恢复的快照的系统调用索引

**返回值**:
- `0`: 成功
- `-1`: 失败

**示例**:
```c
if (rr_snapshot_restore(target_syscall_index) == 0) {
    printf("Snapshot restored successfully\n");
}
```

---

#### `rr_snapshot_get_latest()`
**原型**:
```c
uint32_t rr_snapshot_get_latest(void);
```

**功能**: 获取最新快照的系统调用索引

**返回值**: 最新快照的系统调用索引，`0`表示无快照

---

#### `rr_snapshot_list()`
**原型**:
```c
int rr_snapshot_list(uint32_t *snapshots, size_t max_count);
```

**功能**: 列出所有可用的快照

**参数**:
- `snapshots`: 输出快照索引数组
- `max_count`: 数组最大容量

**返回值**: 实际快照数量

**示例**:
```c
uint32_t snapshots[10];
int count = rr_snapshot_list(snapshots, 10);
for (int i = 0; i < count; i++) {
    printf("Snapshot %d: syscall_index=%u\n", i, snapshots[i]);
}
```

---

#### `rr_snapshot_should_save()`
**原型**:
```c
bool rr_snapshot_should_save(int syscall_nr, uint32_t syscall_index);
```

**功能**: 判断是否应该在当前位置保存快照

**参数**:
- `syscall_nr`: 系统调用号
- `syscall_index`: 系统调用索引

**返回值**:
- `true`: 应该保存快照
- `false`: 不需要保存快照

**使用**: 用于自动快照策略

---

#### `rr_snapshot_auto_manage()`
**原型**:
```c
void rr_snapshot_auto_manage(int syscall_nr, uint32_t syscall_index);
```

**功能**: 自动管理快照（根据策略自动保存和清理）

**参数**:
- `syscall_nr`: 系统调用号
- `syscall_index`: 系统调用索引

**返回值**: 无

**使用**: 在系统调用处理过程中调用

---

#### `rr_snapshot_cleanup()`
**原型**:
```c
void rr_snapshot_cleanup(void);
```

**功能**: 清理所有快照

**返回值**: 无

## 8. 配置管理API

### 8.1 配置初始化

#### `rr_config_init()`
**原型**:
```c
int rr_config_init(void);
```

**功能**: 初始化配置系统

**返回值**:
- `0`: 成功
- `-1`: 失败

**使用**: 由框架自动调用

---

#### `rr_config_cleanup()`
**原型**:
```c
void rr_config_cleanup(void);
```

**功能**: 清理配置系统

**返回值**: 无

**使用**: 由框架自动调用

### 8.2 配置查询

#### `rr_config_get_mode_name()`
**原型**:
```c
const char *rr_config_get_mode_name(rr_mode_t mode);
```

**功能**: 获取模式名称字符串

**参数**:
- `mode`: 运行模式

**返回值**: 模式名称字符串

**示例**:
```c
printf("Current mode: %s\n", rr_config_get_mode_name(g_rr_config.mode));
```

---

#### `rr_config_print()`
**原型**:
```c
void rr_config_print(void);
```

**功能**: 打印当前配置信息

**返回值**: 无

**示例**:
```c
// 在调试时打印配置
rr_config_print();
```

## 9. 调试支持API

### 9.1 调试控制

#### `rr_debug_init()`
**原型**:
```c
void rr_debug_init(void);
```

**功能**: 初始化调试系统

**返回值**: 无

**使用**: 由框架自动调用

---

#### `rr_debug_set_level()`
**原型**:
```c
void rr_debug_set_level(rr_debug_level_t level);
```

**功能**: 设置调试级别

**参数**:
- `level`: 调试级别（0-5）

**返回值**: 无

**示例**:
```c
// 动态调整调试级别
rr_debug_set_level(RR_DEBUG_VERBOSE);
```

---

#### `rr_debug_set_output()`
**原型**:
```c
void rr_debug_set_output(FILE *file);
```

**功能**: 设置调试输出文件

**参数**:
- `file`: 输出文件句柄

**返回值**: 无

**示例**:
```c
FILE *debug_file = fopen("/tmp/debug.log", "a");
rr_debug_set_output(debug_file);
```

---

#### `rr_debug_cleanup()`
**原型**:
```c
void rr_debug_cleanup(void);
```

**功能**: 清理调试系统

**返回值**: 无

**使用**: 由框架自动调用

---

#### `rr_debug_level_name()`
**原型**:
```c
const char *rr_debug_level_name(rr_debug_level_t level);
```

**功能**: 获取调试级别名称

**参数**:
- `level`: 调试级别

**返回值**: 级别名称字符串

**示例**:
```c
printf("Debug level: %s\n", rr_debug_level_name(g_rr_debug.level));
```

## 10. 数据结构定义

### 10.1 核心数据结构

#### `syscall_record_t`
**定义**:
```c
typedef struct syscall_record {
    uint32_t index;                     // 在轨迹中的序号
    int syscall_nr;                     // 系统调用号
    abi_long args[8];                   // 参数值
    abi_long retval;                    // 返回值

    // 参数数据存储
    uint8_t *arg_data[8];               // 参数指向的数据
    size_t arg_size[8];                 // 每个参数数据的大小

    // 元数据
    bool creates_fd;                    // 是否创建文件描述符
    bool uses_fd;                       // 是否使用文件描述符
    int32_t created_fd;                 // 创建的文件描述符值

    struct syscall_record *next;        // 链表连接
} syscall_record_t;
```

**说明**: 系统调用记录的核心数据结构

#### `FuzzInstruction`
**定义**:
```c
typedef struct {
    enum {
        FUZZ_CMD_NONE = 0,
        FUZZ_CMD_MUTATE_ARG,            // 变异参数
        FUZZ_CMD_REPLACE_BUFFER         // 替换缓冲区
    } cmd;

    int syscall_index;                  // 目标系统调用索引
    int arg_index;                      // 目标参数索引
    size_t data_len;                    // 新数据的长度
    uint8_t data[];                     // 柔性数组，存放新数据
} FuzzInstruction;
```

**说明**: 模糊测试变异指令结构

#### `rr_framework_t`
**定义**:
```c
typedef struct {
    rr_mode_t mode;                 // 当前运行模式
    bool enabled;                   // 框架启用状态

    // Record/Replay状态
    syscall_record_t *trace_head;   // 轨迹头
    syscall_record_t *trace_tail;   // 轨迹尾
    uint32_t trace_length;          // 轨迹长度
    uint32_t replay_index;          // 重放索引

    // FD映射表
    GHashTable *fd_map;             // record_fd -> replay_fd映射

    // IPC通信
    int cmd_pipe_fd;                // 命令管道
    int status_pipe_fd;             // 状态管道
    void *shared_memory;            // 共享内存

    // Fork Server
    bool fork_server_active;        // Fork Server是否活跃
    pid_t child_pid;                // 子进程PID

    // 统计信息
    uint64_t total_syscalls;        // 总系统调用数
    uint64_t total_executions;      // 总执行数
} rr_framework_t;
```

**说明**: RR-Fuzz框架全局状态结构

### 10.2 配置结构

#### `rr_config_t`
**定义**:
```c
typedef struct {
    // 核心配置
    bool enabled;                       // 是否启用RR-Fuzz
    rr_mode_t mode;                     // 运行模式

    // 文件路径配置
    char *trace_file;                   // trace文件路径
    char *shared_memory_name;           // 共享内存名称
    char *cmd_pipe_path;                // 命令管道路径
    char *status_pipe_path;             // 状态管道路径
    char *config_file;                  // 配置文件路径

    // Fork Server配置
    bool fork_server_enabled;           // 是否启用Fork Server
    uint32_t fork_point;                // Fork点位置

    // IPC配置
    size_t shared_memory_size;          // 共享内存大小
    int ipc_timeout;                    // IPC超时(毫秒)
} rr_config_t;
```

**说明**: RR-Fuzz配置结构

#### `rr_debug_config_t`
**定义**:
```c
typedef struct {
    rr_debug_level_t level;     // 全局调试级别
    bool syscall_trace;         // 系统调用追踪
    bool fd_tracking;           // 文件描述符追踪
    bool memory_ops;            // 内存操作追踪
    bool ipc_details;           // IPC通信详情
    bool performance_stats;     // 性能统计
    FILE *log_file;             // 日志输出文件
} rr_debug_config_t;
```

**说明**: RR-Fuzz调试配置结构

## 11. 全局变量

### 11.1 框架全局变量

```c
extern rr_framework_t *g_rr_framework;      // 全局框架实例
extern rr_config_t g_rr_config;             // 全局配置实例
extern rr_debug_config_t g_rr_debug;        // 全局调试配置
```

**使用注意**:
- 这些全局变量由框架管理，外部代码应避免直接修改
- 建议通过相应的API函数访问和修改

## 12. 宏定义

### 12.1 调试宏

```c
#define RR_ERROR(fmt, ...)   // 错误信息
#define RR_WARN(fmt, ...)    // 警告信息
#define RR_INFO(fmt, ...)    // 基本信息
#define RR_VERBOSE(fmt, ...) // 详细信息
#define RR_TRACE(fmt, ...)   // 追踪信息

// 条件调试宏
#define RR_SYSCALL_TRACE(fmt, ...)  // 系统调用追踪
#define RR_FD_TRACE(fmt, ...)       // FD追踪
#define RR_MEM_TRACE(fmt, ...)      // 内存操作追踪
#define RR_IPC_TRACE(fmt, ...)      // IPC通信追踪
#define RR_PERF_TRACE(fmt, ...)     // 性能追踪
```

**使用示例**:
```c
RR_INFO("Starting RR-Fuzz in %s mode", rr_config_get_mode_name(g_rr_config.mode));
RR_SYSCALL_TRACE("Recording syscall %d with ret=%ld", num, ret);
```

### 12.2 模式检查宏

```c
#define RR_MODE_IS_RECORD()  (g_rr_framework && g_rr_framework->mode == RR_MODE_RECORD)
#define RR_MODE_IS_REPLAY()  (g_rr_framework && g_rr_framework->mode == RR_MODE_REPLAY)
#define RR_MODE_IS_FUZZING() (g_rr_framework && g_rr_framework->mode == RR_MODE_FUZZING)
```

**使用示例**:
```c
if (RR_MODE_IS_RECORD()) {
    // 记录模式特定处理
}
```

## 13. 错误码

### 13.1 通用错误码

```c
#define RR_SUCCESS          0    // 成功
#define RR_ERROR_GENERIC   -1    // 通用错误
#define RR_ERROR_NOMEM     -2    // 内存不足
#define RR_ERROR_IO        -3    // I/O错误
#define RR_ERROR_CONFIG    -4    // 配置错误
#define RR_ERROR_STATE     -5    // 状态错误
#define RR_ERROR_TRACE     -6    // 轨迹错误
#define RR_ERROR_IPC       -7    // IPC错误
```

## 14. 编译宏

### 14.1 条件编译

```c
#ifdef CONFIG_RR_FUZZING
    // RR-Fuzz功能代码
#endif

#ifdef RR_DEBUG
    // 调试代码
#else
    // 调试代码被编译时移除
#endif
```

这个API参考文档提供了RR-Fuzz框架的完整接口定义，为开发者进行扩展和集成提供了详细的技术参考。
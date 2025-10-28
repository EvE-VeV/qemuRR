# RR-Fuzz 系统架构文档

## 总体架构

RR-Fuzz 采用模块化的分层架构设计，集成到QEMU用户模式模拟器中，通过拦截系统调用来实现记录-重放和模糊测试功能。

```
┌─────────────────────────────────────────────────────────┐
│                    Target Program                        │
└─────────────────────────┬───────────────────────────────┘
                          │ System Calls
┌─────────────────────────▼───────────────────────────────┐
│                   QEMU User Mode                        │
│  ┌───────────────────────────────────────────────────┐  │
│  │                RR-Fuzz Framework                  │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │              Core Module                    │  │  │
│  │  │  ┌─────────┐ ┌─────────┐ ┌─────────────┐    │  │  │
│  │  │  │ Config  │ │  Debug  │ │    Main     │    │  │  │
│  │  │  └─────────┘ └─────────┘ └─────────────┘    │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │            Execution Modules                │  │  │
│  │  │  ┌─────────┐ ┌─────────┐ ┌─────────────┐    │  │  │
│  │  │  │ Record  │ │ Replay  │ │ Fuzz Engine │    │  │  │
│  │  │  └─────────┘ └─────────┘ └─────────────┘    │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │           Support Modules                   │  │  │
│  │  │  ┌─────────┐ ┌─────────┐ ┌─────────────┐    │  │  │
│  │  │  │   IPC   │ │Snapshot │ │Fork Server  │    │  │  │
│  │  │  └─────────┘ └─────────┘ └─────────────┘    │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                External Components                       │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────────┐   │
│  │ Conductor   │ │ Trace Files  │ │  Config Files   │   │
│  │ (Optional)  │ │              │ │                 │   │
│  └─────────────┘ └──────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## 核心模块设计

### 1. 框架主控模块 (rr_main.c)

**职责**:
- 框架生命周期管理
- 模式切换和协调
- 系统调用拦截入口点

**核心结构**:
```c
typedef struct {
    rr_mode_t mode;                 // 当前运行模式
    bool enabled;                   // 框架启用状态

    // 轨迹管理
    syscall_record_t *trace_head;   // 轨迹链表头
    syscall_record_t *trace_tail;   // 轨迹链表尾
    uint32_t trace_length;          // 轨迹长度
    uint32_t replay_index;          // 重放索引

    // 资源管理
    GHashTable *fd_map;             // 文件描述符映射

    // IPC和Fork Server
    int cmd_pipe_fd;                // 命令管道
    int status_pipe_fd;             // 状态管道
    void *shared_memory;            // 共享内存
    bool fork_server_active;        // Fork Server状态
    pid_t child_pid;                // 子进程PID

    // 统计信息
    uint64_t total_syscalls;        // 总系统调用数
    uint64_t total_executions;      // 总执行数
} rr_framework_t;
```

**关键函数**:
- `rr_framework_init()`: 框架初始化
- `rr_framework_cleanup()`: 框架清理
- `rr_do_syscall()`: 系统调用处理入口
- `rr_syscall_post_hook()`: 系统调用后处理

### 2. 配置管理模块 (rr_config.c)

**职责**:
- 统一配置管理
- 配置文件解析
- 环境变量处理

**配置结构**:
```c
typedef struct {
    // 核心配置
    bool enabled;                   // 是否启用
    rr_mode_t mode;                 // 运行模式

    // 文件路径
    char *trace_file;               // 轨迹文件
    char *shared_memory_name;       // 共享内存名
    char *cmd_pipe_path;            // 命令管道路径
    char *status_pipe_path;         // 状态管道路径
    char *config_file;              // 配置文件路径

    // Fork Server配置
    bool fork_server_enabled;       // Fork Server启用
    uint32_t fork_point;            // Fork点位置

    // IPC配置
    size_t shared_memory_size;      // 共享内存大小
    int ipc_timeout;                // IPC超时
} rr_config_t;
```

**配置优先级**: 配置文件 < 环境变量 < 命令行参数

### 3. 调试支持模块 (rr_debug.c)

**职责**:
- 分级调试输出
- 模块化调试控制
- 性能统计收集

**调试级别**:
```c
typedef enum {
    RR_DEBUG_OFF = 0,        // 关闭所有调试
    RR_DEBUG_ERROR = 1,      // 仅错误信息
    RR_DEBUG_WARN = 2,       // 错误和警告
    RR_DEBUG_INFO = 3,       // 基本信息
    RR_DEBUG_VERBOSE = 4,    // 详细信息
    RR_DEBUG_TRACE = 5       // 追踪信息
} rr_debug_level_t;
```

## 执行模块架构

### 1. 记录模块 (rr_record.c)

**数据流**:
```
System Call → Parameter Capture → Trace Generation → Binary Storage
     ↓              ↓                    ↓              ↓
  - 调用信息      - 智能参数解析        - 轨迹记录       - 文件写入
  - 参数值        - 指针数据捕获        - FD映射        - 格式化存储
  - 返回值        - 缓冲区内容          - 元数据        - 索引管理
```

**轨迹记录结构**:
```c
typedef struct syscall_record {
    uint32_t index;                 // 轨迹索引
    int syscall_nr;                 // 系统调用号
    abi_long args[8];               // 参数值
    abi_long retval;                // 返回值

    // 参数数据
    uint8_t *arg_data[8];           // 参数指向的数据
    size_t arg_size[8];             // 数据大小

    // 元数据
    bool creates_fd;                // 是否创建FD
    bool uses_fd;                   // 是否使用FD
    int32_t created_fd;             // 创建的FD值

    struct syscall_record *next;    // 链表连接
} syscall_record_t;
```

### 2. 重放模块 (rr_replay.c)

**执行流程**:
```
Trace Loading → Record Parsing → System Call Replay → Result Validation
     ↓               ↓                 ↓                    ↓
  - 文件读取       - 二进制解析       - 参数恢复           - 返回值检查
  - 头部验证       - 数据重建         - 状态同步           - 一致性验证
  - 索引构建       - FD映射恢复       - 确定性执行         - 错误处理
```

**重放策略**:
- **确定性重放**: 严格按照记录的顺序和参数执行
- **状态同步**: 维护与记录时一致的程序状态
- **错误处理**: 检测和处理重放过程中的不一致

### 3. 模糊测试引擎 (rr_fuzz_engine.c)

**变异架构**:
```
Mutation Instructions → Parameter Analysis → Mutation Application → Execution
         ↓                     ↓                    ↓                ↓
    - 变异指令解析          - 参数类型分析         - 智能变异           - 重放执行
    - 目标识别              - 依赖关系分析         - 约束满足           - 结果收集
    - 策略选择              - 变异范围计算         - 批量应用           - 反馈分析
```

**变异指令类型**:
```c
typedef struct {
    enum {
        FUZZ_CMD_NONE = 0,
        FUZZ_CMD_MUTATE_ARG,        // 变异参数
        FUZZ_CMD_REPLACE_BUFFER     // 替换缓冲区
    } cmd;

    int syscall_index;              // 目标系统调用索引
    int arg_index;                  // 目标参数索引
    size_t data_len;                // 新数据长度
    uint8_t data[];                 // 变异数据
} FuzzInstruction;
```

## 支持模块架构

### 1. IPC通信模块 (rr_ipc.c)

**通信架构**:
```
┌─────────────┐    Commands     ┌─────────────┐    Status      ┌─────────────┐
│ External    │ ─────────────→  │ RR-Fuzz     │ ─────────────→ │ External    │
│ Conductor   │                 │ Framework   │                │ Monitor     │
└─────────────┘                 └─────────────┘                └─────────────┘
       ↑                               ↑                              ↓
       │          Shared Memory        │                              │
       └───────────────────────────────┴──────────────────────────────┘
```

**通信协议**:
- **命令通道**: F(Fork), Q(Quit), S(Save Snapshot), L(Load Snapshot)
- **状态通道**: 1(Ready), 2(At Fork Point), 3(Complete), -1(Error)
- **共享内存**: 大量数据交换通道

### 2. 快照管理模块 (rr_snapshot.c)

**快照结构**:
```c
typedef struct rr_snapshot {
    uint32_t syscall_index;         // 快照时的系统调用索引
    size_t memory_size;             // 内存快照大小
    void *memory_data;              // 内存数据
    GHashTable *fd_map_snapshot;    // FD映射快照
    struct rr_snapshot *next;       // 链表连接
} rr_snapshot_t;
```

**快照策略**:
- **增量快照**: 仅保存变化的状态信息
- **按需创建**: 在关键执行点创建快照
- **自动清理**: 定期清理不需要的快照

### 3. Fork Server模块 (rr_fork_server.c)

**Fork Server架构**:
```
┌─────────────────┐
│   Parent Process │
│   (Fork Server)  │
└─────────┬───────┘
          │ fork()
          ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Child Process  │     │  Child Process  │     │  Child Process  │
│   (Test Case 1) │     │   (Test Case 2) │     │   (Test Case N) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

**执行流程**:
1. **初始化阶段**: 执行到Fork点，创建进程快照
2. **等待命令**: 监听外部控制命令
3. **Fork执行**: 根据命令fork子进程执行测试用例
4. **结果收集**: 收集执行结果并报告状态
5. **循环执行**: 重复Fork和执行过程

## 数据结构设计

### 1. 全局状态管理

**框架上下文**:
```c
extern rr_framework_t *g_rr_framework;  // 全局框架实例
extern rr_config_t g_rr_config;         // 全局配置实例
extern rr_debug_config_t g_rr_debug;    // 全局调试配置
```

### 2. 轨迹数据结构

**二进制轨迹格式**:
```
File Header:
┌──────────────┬──────────────┬──────────────┐
│ Magic(4bytes)│Version(4bytes)│Count(4bytes) │
│   "RRTR"     │      1        │  N records   │
└──────────────┴──────────────┴──────────────┘

Records:
┌─────────────────────────────────────────────┐
│            syscall_record_t                 │
│  ┌─────────────────────────────────────────┐│
│  │ Basic Record Data                       ││
│  │ - index, syscall_nr, args, retval      ││
│  │ - creates_fd, uses_fd, created_fd       ││
│  └─────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────┐│
│  │ Variable Length Parameter Data          ││
│  │ - arg_index(4bytes)                     ││
│  │ - data_size(8bytes)                     ││
│  │ - data(variable length)                 ││
│  └─────────────────────────────────────────┘│
└─────────────────────────────────────────────┘
```

### 3. 内存管理策略

**资源管理原则**:
- **RAII模式**: 资源获取即初始化
- **智能释放**: 自动内存管理和清理
- **内存池**: 高频分配使用内存池
- **引用计数**: 共享资源的引用计数管理

## 集成架构

### 1. QEMU集成点

**系统调用拦截**:
```c
// 在 linux-user/syscall.c 中
abi_long do_syscall(CPUArchState *env, int num, ...) {
    // RR-Fuzz 前置处理
    abi_long rr_result = rr_do_syscall(env, num, ...);
    if (rr_result != -1) {
        return rr_result;  // RR-Fuzz 处理了调用
    }

    // 原始系统调用处理
    abi_long ret = original_syscall_handling(...);

    // RR-Fuzz 后置处理
    rr_syscall_post_hook(env, num, ret, ...);

    return ret;
}
```

### 2. 构建系统集成

**Meson构建配置**:
```meson
# meson_options.txt
option('rr_fuzzing', type: 'feature', value: 'auto',
       description: 'RR-Fuzz record-replay fuzzing framework support')

# linux-user/rr_fuzzing/meson.build
rr_fuzz_sources = files(
  'rr_main.c', 'rr_record.c', 'rr_replay.c',
  'rr_ipc.c', 'rr_fork_server.c', 'rr_fuzz_engine.c',
  'rr_snapshot.c', 'rr_debug.c', 'rr_config.c'
)

if get_option('rr_fuzzing').enabled()
  linux_user_ss.add(rr_fuzz_sources)
endif
```

## 扩展性设计

### 1. 插件接口

**变异插件接口**:
```c
typedef struct {
    const char *name;
    int (*init)(void);
    FuzzInstruction* (*generate_mutations)(syscall_record_t *record, size_t *count);
    void (*cleanup)(void);
} mutation_plugin_t;
```

### 2. 协议扩展

**IPC命令扩展**:
```c
// 新增命令类型
#define RR_CMD_CUSTOM_BASE  0x100
#define RR_CMD_SET_CONFIG   (RR_CMD_CUSTOM_BASE + 1)
#define RR_CMD_GET_STATS    (RR_CMD_CUSTOM_BASE + 2)
```

### 3. 架构适配

**多架构支持**:
- **统一接口**: 通过统一的抽象接口支持多架构
- **架构特定代码**: 架构相关的实现分离
- **条件编译**: 基于目标架构的条件编译

这个架构设计确保了RR-Fuzz的模块化、可扩展性和高性能，同时保持与QEMU的良好集成。
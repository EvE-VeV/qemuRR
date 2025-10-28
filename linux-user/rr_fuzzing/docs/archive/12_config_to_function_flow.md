# 配置如何驱动 RR-Fuzz 功能运行 - 实战流程

## 📋 目录
1. [概览：配置到功能的完整链路](#概览配置到功能的完整链路)
2. [实战案例1：Record模式](#实战案例1record模式)
3. [实战案例2：Replay模式](#实战案例2replay模式)
4. [实战案例3：Fuzzing模式](#实战案例3fuzzing模式)
5. [配置驱动的关键功能点](#配置驱动的关键功能点)
6. [实际代码执行路径](#实际代码执行路径)
7. [配置变化的影响](#配置变化的影响)

---

## 概览：配置到功能的完整链路

### 整体流程图

```
┌────────────────────────────────────────────────────────────────┐
│                   用户配置（配置文件 + 环境变量）                  │
│  - mode=record/replay/fuzzing                                   │
│  - trace_file=./trace.txt                                       │
│  - fork_strategy=2                                              │
│  - shared_memory_name=rr_shm                                    │
└───────────────────────────┬────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────┐
│              rr_config_init() 解析配置                          │
│              存储到 g_rr_config 全局结构体                      │
└───────────────────────────┬────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────┐
│          rr_framework_init() 根据配置初始化各模块               │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  if (g_rr_config.mode == RR_MODE_RECORD)                │  │
│  │    → rr_start_recording(g_rr_config.trace_file)         │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  if (g_rr_config.mode == RR_MODE_REPLAY)                │  │
│  │    → rr_start_replay(g_rr_config.trace_file)            │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  if (g_rr_config.mode == RR_MODE_FUZZING)               │  │
│  │    → rr_start_replay(g_rr_config.trace_file)            │  │
│  │    → rr_ipc_init() 使用 g_rr_config.shared_memory_name  │  │
│  │    → rr_start_fork_server()                             │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────┬────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────┐
│               程序执行期间，各模块读取 g_rr_config                │
│                                                                 │
│  • 系统调用Hook → 根据mode决定record/replay/fuzz                │
│  • Fork Server → 根据fork_strategy决定fork时机                  │
│  • IPC通信 → 使用shared_memory_name和pipe_path                  │
│  • Trace读写 → 使用trace_file路径                               │
└────────────────────────────────────────────────────────────────┘
```

### 核心原理

**配置是系统行为的"开关"和"参数"**：

1. **`mode` 配置决定系统行为模式**
   - `RR_MODE_RECORD`: 拦截系统调用 → 记录到文件
   - `RR_MODE_REPLAY`: 拦截系统调用 → 从文件读取返回值
   - `RR_MODE_FUZZING`: 拦截系统调用 → 应用mutation + fork

2. **路径配置决定数据流向**
   - `trace_file`: 决定trace数据读写位置
   - `cmd_pipe_path`: 决定从哪里接收fuzzer命令
   - `status_pipe_path`: 决定向哪里发送状态

3. **策略配置决定算法行为**
   - `fork_strategy`: 决定什么时候fork
   - `fork_threshold`: 决定fallback阈值
   - `debug_level`: 决定日志输出详细程度

---

## 实战案例1：Record模式

### 配置文件

```ini
# rr_config.record.template
enabled=true
mode=record
trace_file=./trace-ls.txt
debug_level=3
```

### 执行命令

```bash
RR_CONFIG_FILE=./rr_config.record.template qemu-x86_64 -strace /usr/bin/ls
```

### 配置如何驱动功能

#### Step 1: 配置加载

**代码**: `rr_config.c:235-343`

```c
int rr_config_init(void)
{
    // 1. 加载默认配置
    g_rr_config = DEFAULT_CONFIG;
    
    // 2. 读取配置文件
    const char *config_file = getenv("RR_CONFIG_FILE");
    if (config_file) {
        load_config_file(config_file);  // 解析 rr_config.record.template
    }
    
    // 解析后 g_rr_config 的值：
    // g_rr_config.enabled = true
    // g_rr_config.mode = RR_MODE_RECORD
    // g_rr_config.trace_file = "./trace-ls.txt"
    // g_rr_config.debug_level = 3
}
```

#### Step 2: 根据配置初始化Record模块

**代码**: `rr_main.c:148-154`

```c
switch (g_rr_framework->mode) {  // mode来自 g_rr_config.mode
    case RR_MODE_RECORD:
        RR_INFO("Starting recording mode, trace_file=%s", g_rr_config.trace_file);
        
        // 🔥 关键：使用配置中的 trace_file 路径打开文件
        if (rr_start_recording(g_rr_config.trace_file) < 0) {
            RR_ERROR("Failed to start recording");
            goto error;
        }
        
        RR_INFO("Recording started successfully");
        break;
}
```

**代码**: `rr_record.c`（简化示意）

```c
int rr_start_recording(const char *trace_file)  // trace_file = "./trace-ls.txt"
{
    // 打开trace文件准备写入
    FILE *fp = fopen(trace_file, "w");
    if (!fp) {
        RR_ERROR("Failed to open trace file: %s", trace_file);
        return -1;
    }
    
    g_trace_file = fp;  // 全局变量保存文件指针
    RR_INFO("Opened trace file for recording: %s", trace_file);
    return 0;
}
```

#### Step 3: 程序执行时，系统调用被拦截并记录

**代码**: `linux-user/syscall.c` (QEMU系统调用入口)

```c
abi_long do_syscall(CPUArchState *env, int num, ...)
{
    // 前置Hook：检查是否启用RR-Fuzz
    #ifdef CONFIG_RR_FUZZING
    if (rr_framework_enabled()) {
        abi_long rr_ret = rr_do_syscall(env, num, &arg1, ...);
        
        // Record模式：rr_do_syscall 返回 -1，让真实系统调用继续执行
        if (rr_ret != -1) {
            return rr_ret;
        }
    }
    #endif
    
    // 执行真实系统调用
    ret = do_syscall_real(num, arg1, arg2, ...);
    
    // 后置Hook：记录系统调用结果
    #ifdef CONFIG_RR_FUZZING
    if (rr_framework_enabled()) {
        // 🔥 Record模式：在这里记录系统调用
        rr_syscall_post_hook(env, num, ret, arg1, arg2, ...);
    }
    #endif
    
    return ret;
}
```

**代码**: `rr_main.c:468-492` (后置Hook)

```c
void rr_syscall_post_hook(CPUArchState *env, int num, abi_long ret, ...)
{
    if (g_rr_framework->mode == RR_MODE_RECORD) {
        // 🔥 调用记录函数
        abi_long args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
        int record_result = rr_record_syscall(env, num, args, ret);
        
        if (record_result == 0) {
            g_rr_framework->total_syscalls++;
            RR_VERBOSE("Successfully recorded syscall %d (total: %lu)", 
                      num, g_rr_framework->total_syscalls);
        }
    }
}
```

**代码**: `rr_record.c` (简化示意)

```c
int rr_record_syscall(CPUArchState *env, int num, const abi_long *args, abi_long ret)
{
    // 创建记录
    syscall_record_t record;
    record.syscall_nr = num;
    record.retval = ret;
    memcpy(record.args, args, sizeof(record.args));
    
    // 🔥 写入到trace文件（文件路径来自配置）
    fprintf(g_trace_file, "%d(%ld, %ld, %ld, ...) = %ld\n",
            num, args[0], args[1], args[2], ret);
    
    fflush(g_trace_file);  // 确保数据写入磁盘
    
    RR_VERBOSE("Recorded syscall %d with ret=%ld to %s", 
              num, ret, g_rr_config.trace_file);
    
    return 0;
}
```

### 实际执行效果

```bash
# 执行命令
$ RR_CONFIG_FILE=./rr_config.record.template qemu-x86_64 -strace /usr/bin/ls

# 日志输出（因为 debug_level=3）
[RR-INFO] Configuration loaded successfully
[RR-INFO] Starting recording mode, trace_file=./trace-ls.txt
[RR-INFO] Recording started successfully
[RR-VERBOSE] Recorded syscall 257 (openat) with ret=3
[RR-VERBOSE] Recorded syscall 5 (fstat) with ret=0
[RR-VERBOSE] Recorded syscall 217 (getdents64) with ret=336
...

# 生成的trace文件
$ cat ./trace-ls.txt
257(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
5(3, ...) = 0
3(3) = 0
257(AT_FDCWD, "/lib/x86_64-linux-gnu/libselinux.so.1", O_RDONLY|O_CLOEXEC) = 3
...
```

**关键点**: 
- `mode=record` 配置 → 触发 `rr_start_recording()` → 打开 `./trace-ls.txt` 文件
- `trace_file` 配置 → 决定了记录数据写入的位置
- `debug_level=3` 配置 → 输出 INFO 级别日志

---

## 实战案例2：Replay模式

### 配置文件

```ini
# rr_config.replay.template
enabled=true
mode=replay
trace_file=./trace-ls.txt
debug_level=4
```

### 执行命令

```bash
RR_CONFIG_FILE=./rr_config.replay.template \
RR_STRACE_MODE=True \
qemu-x86_64 /usr/bin/ls
```

### 配置如何驱动功能

#### Step 1: 配置加载（同Record模式）

```c
// g_rr_config 的值：
// g_rr_config.enabled = true
// g_rr_config.mode = RR_MODE_REPLAY  ← 关键差异
// g_rr_config.trace_file = "./trace-ls.txt"
// g_rr_config.debug_level = 4
```

#### Step 2: 根据配置初始化Replay模块

**代码**: `rr_main.c:156-178`

```c
switch (g_rr_framework->mode) {  // mode = RR_MODE_REPLAY
    case RR_MODE_REPLAY:
        strace_mode_env = getenv("RR_STRACE_MODE");
        RR_INFO("Starting replay mode, trace_file=%s", g_rr_config.trace_file);
        
        if (strace_mode_env) {
            RR_INFO("Starting strace replay mode");
            
            // 🔥 关键：使用配置中的 trace_file 加载trace
            if (rr_strace_replay_init(g_rr_config.trace_file) < 0) {
                RR_ERROR("Failed to start strace replay");
                goto error;
            }
            
            RR_INFO("Strace replay started successfully");
        } else {
            // Binary replay 模式
            if (rr_start_replay(g_rr_config.trace_file) < 0) {
                RR_ERROR("Failed to start binary replay");
                goto error;
            }
        }
        break;
}
```

**代码**: `rr_replay_strace_optimized.c`（简化示意）

```c
int rr_strace_replay_init(const char *trace_file)  // trace_file = "./trace-ls.txt"
{
    // 打开trace文件读取
    FILE *fp = fopen(trace_file, "r");
    if (!fp) {
        RR_ERROR("Failed to open trace file: %s", trace_file);
        return -1;
    }
    
    // 解析trace文件，构建replay队列
    while (fgets(line, sizeof(line), fp)) {
        // 解析每一行：257(AT_FDCWD, "/etc/ld.so.cache", ...) = 3
        syscall_record_t *record = parse_strace_line(line);
        
        // 添加到replay队列
        add_to_replay_queue(record);
    }
    
    fclose(fp);
    RR_INFO("Loaded %d syscall records from %s", 
           g_replay_queue_length, trace_file);
    
    return 0;
}
```

#### Step 3: 程序执行时，系统调用被重放

**代码**: `linux-user/syscall.c`

```c
abi_long do_syscall(CPUArchState *env, int num, ...)
{
    #ifdef CONFIG_RR_FUZZING
    if (rr_framework_enabled()) {
        abi_long rr_ret = rr_do_syscall(env, num, &arg1, ...);
        
        // 🔥 Replay模式：rr_do_syscall 返回重放的返回值，不执行真实系统调用
        if (rr_ret != -1) {
            return rr_ret;  // 直接返回重放的值
        }
    }
    #endif
    
    // Replay模式下，大部分系统调用不会执行到这里
    ret = do_syscall_real(num, arg1, arg2, ...);
    return ret;
}
```

**代码**: `rr_main.c:315-421` (rr_do_syscall)

```c
abi_long rr_do_syscall(CPUArchState *env, int num, abi_long *arg1, ...)
{
    switch (g_rr_framework->mode) {
        case RR_MODE_REPLAY:
            // 🔥 调用重放函数，从trace中读取返回值
            if (rr_strace_replay_enabled()) {
                ret = rr_replay_syscall_strace(env, num, args);
            } else {
                ret = rr_replay_syscall(env, num, args);
            }
            break;
    }
    
    return ret;  // 返回重放的值
}
```

**代码**: `rr_replay_strace_optimized.c`（简化示意）

```c
abi_long rr_replay_syscall_strace(CPUArchState *env, int num, abi_long *args)
{
    // 从replay队列中获取下一个记录
    syscall_record_t *record = get_next_replay_record();
    
    if (!record) {
        RR_ERROR("No more records in trace file %s", g_rr_config.trace_file);
        return -1;
    }
    
    // 验证系统调用号匹配
    if (record->syscall_nr != num) {
        RR_WARN("Syscall mismatch: expected %d, got %d", record->syscall_nr, num);
    }
    
    // 🔥 返回trace中记录的返回值（不执行真实系统调用）
    RR_VERBOSE("Replaying syscall %d with recorded ret=%ld", num, record->retval);
    return record->retval;
}
```

### 实际执行效果

```bash
# 执行命令
$ RR_CONFIG_FILE=./rr_config.replay.template \
  RR_STRACE_MODE=True \
  qemu-x86_64 /usr/bin/ls

# 日志输出（因为 debug_level=4, VERBOSE级别）
[RR-INFO] Configuration loaded successfully
[RR-INFO] Starting replay mode, trace_file=./trace-ls.txt
[RR-INFO] Loaded 156 syscall records from ./trace-ls.txt
[RR-VERBOSE] Replaying syscall 257 (openat) with recorded ret=3
[RR-VERBOSE] Replaying syscall 5 (fstat) with recorded ret=0
[RR-VERBOSE] Replaying syscall 217 (getdents64) with recorded ret=336
...

# 程序输出（与record时完全一致）
Desktop  Documents  Downloads  Music  Pictures  Videos
```

**关键点**:
- `mode=replay` 配置 → 触发 `rr_strace_replay_init()` → 读取 `./trace-ls.txt` 文件
- `trace_file` 配置 → 决定了从哪里读取replay数据
- `debug_level=4` 配置 → 输出 VERBOSE 级别日志（比Record时更详细）
- **系统调用不真实执行**，返回值来自trace文件

---

## 实战案例3：Fuzzing模式

### 配置文件

```ini
# rr_config.fuzzing.template
enabled=true
mode=fuzzing
trace_file=./trace-ls.txt
shared_memory_name=rr_fuzzing_shm
shared_memory_size=4096
cmd_pipe_path=/tmp/rr_cmd_pipe
status_pipe_path=/tmp/rr_status_pipe
fork_strategy=2
fork_threshold=20
debug_level=3
```

### 执行命令

```bash
# 1. 创建管道
mkfifo /tmp/rr_cmd_pipe /tmp/rr_status_pipe

# 2. 启动QEMU（另一个终端先启动fuzzer）
RR_CONFIG_FILE=./rr_config.fuzzing.template \
RR_STRACE_MODE=True \
qemu-x86_64 /usr/bin/ls
```

### 配置如何驱动功能

#### Step 1: 配置加载

```c
// g_rr_config 的值：
// g_rr_config.enabled = true
// g_rr_config.mode = RR_MODE_FUZZING  ← 关键
// g_rr_config.trace_file = "./trace-ls.txt"
// g_rr_config.shared_memory_name = "rr_fuzzing_shm"
// g_rr_config.shared_memory_size = 4096
// g_rr_config.cmd_pipe_path = "/tmp/rr_cmd_pipe"
// g_rr_config.status_pipe_path = "/tmp/rr_status_pipe"
// g_rr_config.fork_strategy = 2 (AGGRESSIVE)
// g_rr_config.fork_threshold = 20
```

#### Step 2: 初始化多个子系统

**代码**: `rr_main.c:180-210`

```c
case RR_MODE_FUZZING:
    RR_INFO("Starting fuzzing mode, trace_file=%s", g_rr_config.trace_file);
    
    // 2a. 加载trace（与Replay相同）
    strace_mode_env = getenv("RR_STRACE_MODE");
    if (strace_mode_env) {
        if (rr_strace_replay_init(g_rr_config.trace_file) < 0) {
            RR_ERROR("Failed to start strace replay for fuzzing");
            goto error;
        }
    }
    
    // 2b. 启动Fork Server
    if (g_rr_config.fork_server_enabled) {  // Fuzzing模式自动启用
        RR_INFO("Starting fork server in auto-detection mode");
        if (rr_start_fork_server(NULL, NULL) < 0) {
            RR_ERROR("Failed to start fork server");
            goto error;
        }
    }
    
    RR_INFO("Fuzzing mode started successfully");
    break;
```

#### Step 3: IPC系统使用配置

**代码**: `rr_ipc.c:21-96`

```c
int rr_ipc_init(void)
{
    // 🔥 打开命令管道（从配置读取路径）
    if (g_rr_config.cmd_pipe_path) {
        g_rr_framework->cmd_pipe_fd = open(
            g_rr_config.cmd_pipe_path,  // "/tmp/rr_cmd_pipe"
            O_RDONLY | O_NONBLOCK
        );
        
        if (g_rr_framework->cmd_pipe_fd < 0) {
            RR_WARN("Failed to open command pipe: %s", g_rr_config.cmd_pipe_path);
        } else {
            RR_INFO("Opened command pipe: %s -> FD %d", 
                   g_rr_config.cmd_pipe_path, g_rr_framework->cmd_pipe_fd);
        }
    }

    // 🔥 打开状态管道（从配置读取路径）
    if (g_rr_config.status_pipe_path) {
        g_rr_framework->status_pipe_fd = open(
            g_rr_config.status_pipe_path,  // "/tmp/rr_status_pipe"
            O_WRONLY | O_NONBLOCK
        );
        
        RR_INFO("Opened status pipe: %s -> FD %d", 
               g_rr_config.status_pipe_path, g_rr_framework->status_pipe_fd);
    }

    // 🔥 映射共享内存（从配置读取名称和大小）
    if (g_rr_config.shared_memory_name) {
        int shm_fd = shm_open(
            g_rr_config.shared_memory_name,  // "rr_fuzzing_shm"
            O_RDWR, 
            0666
        );
        
        if (shm_fd >= 0) {
            g_rr_framework->shared_memory = mmap(
                NULL, 
                g_rr_config.shared_memory_size,  // 4096
                PROT_READ | PROT_WRITE,
                MAP_SHARED, 
                shm_fd, 
                0
            );
            
            RR_INFO("Mapped shared memory: %s (%zu bytes)",
                   g_rr_config.shared_memory_name, 
                   g_rr_config.shared_memory_size);
            
            close(shm_fd);
        }
    }

    return 0;
}
```

#### Step 4: Fork Server使用fork_strategy配置

**代码**: `rr_fork_server.c`（简化示意）

```c
bool rr_check_auto_fork_point(int syscall_nr, const char *syscall_name, abi_long ret)
{
    // 🔥 读取配置中的fork策略
    rr_fork_strategy_t strategy = g_rr_config.fork_strategy;  // 2 (AGGRESSIVE)
    
    switch (strategy) {
        case RR_FORK_STRATEGY_STRICT:
            // 严格模式：只有 ret > 0 的I/O操作才fork
            return (ret > 0 && is_io_syscall(syscall_nr));
            
        case RR_FORK_STRATEGY_RELAXED:
            // 宽松模式：允许某些错误码
            return is_io_syscall(syscall_nr) && 
                   (ret > 0 || ret == -ENOENT || ret == -EACCES);
            
        case RR_FORK_STRATEGY_AGGRESSIVE:
            // 🔥 激进模式：任何 I/O 系统调用都fork（配置中设置的策略）
            return is_io_syscall(syscall_nr);
            
        case RR_FORK_STRATEGY_FALLBACK:
            // Fallback模式：N个syscall后强制fork
            static int syscall_count = 0;
            syscall_count++;
            
            // 🔥 使用配置中的阈值
            return (syscall_count >= g_rr_config.fork_fallback_threshold);  // 20
    }
    
    return false;
}
```

**代码**: `rr_main.c:380-405` (Fork点检测)

```c
case RR_MODE_FUZZING:
    // 重放系统调用
    if (rr_strace_replay_enabled()) {
        ret = rr_replay_syscall_strace_optimized(env, num, args);
    } else {
        ret = rr_replay_syscall(env, num, args);
    }
    
    // 🔥 自动检测Fork点（使用配置中的策略）
    {
        const char *syscall_name = get_syscall_name(num);
        
        // 检查是否应该fork（根据配置的fork_strategy）
        if (rr_check_auto_fork_point(num, syscall_name, ret)) {
            RR_INFO("🔄 Entering fork server loop after %s", syscall_name);
            
            // 进入Fork Server主循环
            int fork_result = rr_fork_server_loop();
            
            if (fork_result < 0) {
                RR_INFO("🔄 Exiting due to quit command");
                exit(0);
            } else if (fork_result > 0) {
                RR_INFO("🔄 Child process %d continuing fuzzing", getpid());
            }
        }
    }
    break;
```

#### Step 5: Fork Server循环（与fuzzer交互）

**代码**: `rr_fork_server.c`（简化示意）

```c
int rr_fork_server_loop(void)
{
    while (true) {
        // 🔥 从cmd_pipe读取fuzzer命令
        int cmd = rr_ipc_receive_command();  // 使用配置的管道路径
        
        if (cmd == 'F') {  // Fork命令
            RR_INFO("Received Fork command");
            
            pid_t pid = fork();
            
            if (pid == 0) {
                // 子进程：应用mutation后继续执行
                
                // 🔥 从shared_memory读取mutation指令
                FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
                
                if (shm && shm->magic == FUZZ_MAGIC) {
                    // 应用mutation到系统调用参数
                    rr_fuzz_load_from_shared_memory(shm);
                    RR_INFO("Applied %d mutations from shared memory", 
                           shm->instruction_count);
                }
                
                // 继续执行fuzzing
                return 1;  // 子进程标志
                
            } else {
                // 父进程：等待子进程结束
                int status;
                waitpid(pid, &status, 0);
                
                // 🔥 向status_pipe发送状态
                rr_ipc_send_status(WEXITSTATUS(status));  // 使用配置的管道路径
                
                // 继续等待下一个命令
            }
            
        } else if (cmd == 'Q') {  // Quit命令
            RR_INFO("Received Quit command");
            return -1;  // 退出标志
        }
    }
}
```

### 实际执行效果

```bash
# Terminal 1: 启动fuzzer
$ python fuzzing/fuzz_conductor.py --shm rr_fuzzing_shm \
                                    --cmd-pipe /tmp/rr_cmd_pipe \
                                    --status-pipe /tmp/rr_status_pipe

[Fuzzer] Created shared memory: rr_fuzzing_shm
[Fuzzer] Waiting for QEMU to connect...

# Terminal 2: 启动QEMU
$ RR_CONFIG_FILE=./rr_config.fuzzing.template \
  RR_STRACE_MODE=True \
  qemu-x86_64 /usr/bin/ls

[RR-INFO] Configuration loaded successfully
[RR-INFO] Starting fuzzing mode, trace_file=./trace-ls.txt
[RR-INFO] IPC system initialized
[RR-INFO] Opened command pipe: /tmp/rr_cmd_pipe -> FD 3
[RR-INFO] Opened status pipe: /tmp/rr_status_pipe -> FD 4
[RR-INFO] Mapped shared memory: rr_fuzzing_shm (4096 bytes)
[RR-INFO] Fork Server started
[RR-INFO] Replaying syscall 257 (openat)...
[RR-INFO] 🔄 Entering fork server loop after openat (strategy=AGGRESSIVE)
[RR-INFO] Waiting for command from fuzzer...

# Terminal 1: Fuzzer发送命令
[Fuzzer] Sending Fork command
[Fuzzer] Writing mutation to shared memory: mutate arg[1] = "/tmp/fuzz_file.txt"

# Terminal 2: QEMU响应
[RR-INFO] Received Fork command
[RR-INFO] Forked child process: 12345
[RR-INFO] Applied 1 mutations from shared memory
[RR-INFO] Child continuing with mutated args...
[RR-INFO] Child exited with status: 0
[RR-INFO] 📤 Sending status: 0
[RR-INFO] Waiting for next command...
```

**关键点**:
- `mode=fuzzing` 配置 → 同时启用replay和fork server
- `cmd_pipe_path` 配置 → IPC从这个管道读取fuzzer命令
- `status_pipe_path` 配置 → IPC向这个管道写入执行状态
- `shared_memory_name` 配置 → 从这个共享内存读取mutation指令
- `fork_strategy=2` 配置 → 使用AGGRESSIVE策略，任何I/O syscall都fork
- `fork_threshold=20` 配置 → 如果策略为FALLBACK，20个syscall后强制fork

---

## 配置驱动的关键功能点

### 1. 模式切换（mode配置）

| 配置值 | 系统行为 | rr_do_syscall返回值 | 真实syscall执行 |
|--------|---------|-------------------|----------------|
| `mode=record` | 记录系统调用到文件 | -1（让syscall执行） | ✅ 执行 |
| `mode=replay` | 从文件重放系统调用 | 记录的返回值 | ❌ 不执行 |
| `mode=fuzzing` | 重放+应用mutation+fork | 记录的返回值 | ❌ 不执行 |

**代码路径**:
```
g_rr_config.mode 
  → rr_framework_init() 初始化对应模块
  → rr_do_syscall() 根据mode分支到不同处理逻辑
  → rr_syscall_post_hook() 根据mode决定是否记录
```

### 2. 文件路径（trace_file配置）

| 模式 | trace_file的作用 | 文件操作 |
|------|----------------|---------|
| Record | 写入trace数据 | `fopen(trace_file, "w")` |
| Replay | 读取trace数据 | `fopen(trace_file, "r")` |
| Fuzzing | 读取trace数据（同Replay） | `fopen(trace_file, "r")` |

**代码路径**:
```
g_rr_config.trace_file
  → rr_start_recording() 或 rr_start_replay()
  → fopen() 打开文件
  → 后续所有trace读写操作都使用这个文件
```

### 3. IPC通信（pipe和共享内存配置）

| 配置项 | 作用 | 数据流向 |
|--------|------|---------|
| `cmd_pipe_path` | 接收fuzzer命令 | Fuzzer → QEMU |
| `status_pipe_path` | 发送执行状态 | QEMU → Fuzzer |
| `shared_memory_name` | 共享mutation数据 | Fuzzer ⇄ QEMU |
| `shared_memory_size` | 共享内存大小 | 固定4096字节 |

**代码路径**:
```
g_rr_config.cmd_pipe_path
  → rr_ipc_init() 打开管道
  → rr_ipc_receive_command() 从管道读取
  → rr_fork_server_loop() 根据命令执行fork

g_rr_config.status_pipe_path
  → rr_ipc_init() 打开管道
  → rr_ipc_send_status() 向管道写入

g_rr_config.shared_memory_name
  → rr_ipc_init() 映射共享内存
  → rr_fuzz_load_from_shared_memory() 读取mutation
  → 应用到系统调用参数
```

### 4. Fork策略（fork_strategy配置）

| 策略值 | 策略名称 | Fork触发条件 | 适用场景 |
|--------|---------|------------|---------|
| 0 | STRICT | ret > 0 的I/O syscall | 保守fuzzing |
| 1 | RELAXED | ret > 0 或探测性错误 | 一般fuzzing |
| 2 | AGGRESSIVE | 任何I/O syscall | 快速fuzzing（推荐）|
| 3 | FALLBACK | N个syscall后强制fork | 无I/O程序 |

**代码路径**:
```
g_rr_config.fork_strategy
  → rr_check_auto_fork_point() 检查是否fork
  → 根据strategy值选择判断逻辑
  → 返回true时触发 rr_fork_server_loop()
```

### 5. 调试级别（debug_level配置）

| 级别 | 输出内容 | 使用场景 |
|------|---------|---------|
| 0 (OFF) | 无输出 | 生产环境 |
| 1 (ERROR) | 仅错误 | 故障排查 |
| 2 (WARN) | 错误+警告 | 开发测试 |
| 3 (INFO) | 错误+警告+信息 | 日常调试 |
| 4 (VERBOSE) | 详细日志 | 深度调试 |
| 5 (TRACE) | 所有信息 | 问题追踪 |

**代码路径**:
```
g_rr_debug.level (由g_rr_config.debug_level设置)
  → RR_DEBUG_CHECK(level) 宏检查
  → RR_INFO(), RR_VERBOSE() 等宏根据级别输出
```

---

## 实际代码执行路径

### 路径1：配置 → Record功能

```
用户设置: mode=record, trace_file=./trace.txt
                    ↓
    rr_config_init() 解析配置
      g_rr_config.mode = RR_MODE_RECORD
      g_rr_config.trace_file = "./trace.txt"
                    ↓
    rr_framework_init()
      case RR_MODE_RECORD:
        rr_start_recording(g_rr_config.trace_file)
          → fopen("./trace.txt", "w")
          → g_trace_file = fp
                    ↓
    程序执行系统调用 openat(...)
                    ↓
    do_syscall()
      rr_do_syscall()  → 返回-1（让真实syscall执行）
      执行真实 openat() → ret = 3
      rr_syscall_post_hook()
        if (mode == RR_MODE_RECORD)
          rr_record_syscall()
            → fprintf(g_trace_file, "openat(...) = 3")
                    ↓
    trace.txt 文件内容:
      openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 3
```

### 路径2：配置 → Replay功能

```
用户设置: mode=replay, trace_file=./trace.txt
                    ↓
    rr_config_init() 解析配置
      g_rr_config.mode = RR_MODE_REPLAY
      g_rr_config.trace_file = "./trace.txt"
                    ↓
    rr_framework_init()
      case RR_MODE_REPLAY:
        rr_strace_replay_init(g_rr_config.trace_file)
          → fopen("./trace.txt", "r")
          → 解析所有行，构建replay队列
          → g_replay_queue[0] = {syscall=257, ret=3}
                    ↓
    程序执行系统调用 openat(...)
                    ↓
    do_syscall()
      rr_do_syscall()
        if (mode == RR_MODE_REPLAY)
          rr_replay_syscall_strace()
            → record = g_replay_queue[current_index++]
            → return record->retval  (返回3)
      ← 返回3（不执行真实syscall）
                    ↓
    程序继续执行，认为openat返回了3
```

### 路径3：配置 → Fuzzing功能

```
用户设置: mode=fuzzing, trace_file=./trace.txt,
         fork_strategy=2, shared_memory_name=rr_shm
                    ↓
    rr_config_init() 解析配置
      g_rr_config.mode = RR_MODE_FUZZING
      g_rr_config.trace_file = "./trace.txt"
      g_rr_config.fork_strategy = 2 (AGGRESSIVE)
      g_rr_config.shared_memory_name = "rr_shm"
                    ↓
    rr_framework_init()
      case RR_MODE_FUZZING:
        rr_strace_replay_init(g_rr_config.trace_file)
          → 加载trace（同Replay）
        rr_ipc_init()
          → open(g_rr_config.cmd_pipe_path)
          → shm_open(g_rr_config.shared_memory_name)
        rr_start_fork_server()
          → 等待第一个命令
                    ↓
    程序执行系统调用 openat(...)
                    ↓
    do_syscall()
      rr_do_syscall()
        if (mode == RR_MODE_FUZZING)
          ret = rr_replay_syscall_strace()  → 返回3
          
          rr_check_auto_fork_point(openat, 3)
            strategy = g_rr_config.fork_strategy  (2)
            if (strategy == AGGRESSIVE && is_io_syscall(openat))
              return true  ← openat是I/O syscall
              
          if (fork_point)
            rr_fork_server_loop()
              cmd = read(cmd_pipe_fd)  ← 'F' (Fork)
              
              pid = fork()
              if (pid == 0)  // 子进程
                shm = g_rr_framework->shared_memory
                rr_fuzz_load_from_shared_memory(shm)
                  → 修改args[1] = "/tmp/mutated_path"
                return 1  ← 继续执行
              else  // 父进程
                waitpid(pid)
                write(status_pipe_fd, status)
                continue loop  ← 等待下一个命令
```

---

## 配置变化的影响

### 实验1：修改trace_file路径

**原配置**:
```ini
trace_file=./trace.txt
```

**修改后**:
```ini
trace_file=/tmp/my_custom_trace.txt
```

**影响**:
- Record模式：trace数据写入到 `/tmp/my_custom_trace.txt`
- Replay模式：从 `/tmp/my_custom_trace.txt` 读取trace
- 其他功能完全不变

**代码影响点**:
```c
// rr_record.c
FILE *fp = fopen(g_rr_config.trace_file, "w");  // 打开新路径

// rr_replay.c
FILE *fp = fopen(g_rr_config.trace_file, "r");  // 从新路径读取
```

### 实验2：修改fork_strategy

**原配置**:
```ini
fork_strategy=2  # AGGRESSIVE: 任何I/O syscall都fork
```

**修改后**:
```ini
fork_strategy=0  # STRICT: 只有ret>0的I/O syscall才fork
```

**影响**:
- Fork触发条件更严格
- 错误的syscall（如 openat返回-ENOENT）不会触发fork
- Fuzzing效率可能降低，但更稳定

**实际效果对比**:

| Syscall | 返回值 | AGGRESSIVE (2) | STRICT (0) |
|---------|--------|---------------|-----------|
| `openat("/exist.txt")` | 3 (成功) | ✅ Fork | ✅ Fork |
| `openat("/not_exist")` | -ENOENT | ✅ Fork | ❌ 不Fork |
| `read(3, buf, 100)` | 0 (EOF) | ✅ Fork | ❌ 不Fork |
| `read(3, buf, 100)` | 100 (成功) | ✅ Fork | ✅ Fork |

**代码影响点**:
```c
// rr_fork_server.c
bool rr_check_auto_fork_point(...)
{
    strategy = g_rr_config.fork_strategy;
    
    switch (strategy) {
        case RR_FORK_STRATEGY_STRICT:  // 0
            return (ret > 0 && is_io_syscall(syscall_nr));  ← 新逻辑
            
        case RR_FORK_STRATEGY_AGGRESSIVE:  // 2
            return is_io_syscall(syscall_nr);  ← 原逻辑
    }
}
```

### 实验3：修改debug_level

**原配置**:
```ini
debug_level=3  # INFO: 基本信息
```

**修改后**:
```ini
debug_level=5  # TRACE: 所有信息
```

**影响**:
- 输出更详细的调试日志
- 包括内存操作、FD映射等细节
- 性能略有下降（因为日志I/O）

**输出对比**:

**debug_level=3 (INFO)**:
```
[RR-INFO] Starting replay mode
[RR-INFO] Replaying syscall 257 (openat)
[RR-INFO] Replaying syscall 5 (fstat)
```

**debug_level=5 (TRACE)**:
```
[RR-INFO] Starting replay mode
[RR-TRACE] Reading syscall record from index 0
[RR-TRACE] Memory read at 0x7fffffffd000: "/etc/ld.so.cache"
[RR-VERBOSE] Replaying syscall 257 (openat)
[RR-TRACE] FD mapping: recorded=3 → actual=3
[RR-TRACE] Reading syscall record from index 1
[RR-VERBOSE] Replaying syscall 5 (fstat)
```

**代码影响点**:
```c
// rr_framework.h
#define RR_TRACE(fmt, ...) RR_LOG_LEVEL(RR_DEBUG_TRACE, fmt, ##__VA_ARGS__)

// RR_DEBUG_TRACE = 5
// 只有当 g_rr_debug.level >= 5 时才输出
```

### 实验4：修改shared_memory_size

**原配置**:
```ini
shared_memory_size=4096  # 4KB
```

**修改后**:
```ini
shared_memory_size=65536  # 64KB
```

**影响**:
- 可以传输更多的mutation指令
- 原来最多32条指令（每条128字节），现在可以512条
- 内存占用增加

**代码影响点**:
```c
// rr_ipc.c
g_rr_framework->shared_memory = mmap(
    NULL, 
    g_rr_config.shared_memory_size,  // 现在是65536
    PROT_READ | PROT_WRITE,
    MAP_SHARED, 
    shm_fd, 
    0
);

// rr_fuzz_engine.c
FuzzSharedMemory *shm = (FuzzSharedMemory *)g_rr_framework->shared_memory;
// 现在可以读取更多的mutation指令
```

---

## 总结

### 配置到功能的核心链路

```
配置文件/环境变量
        ↓
  rr_config_init() 解析
        ↓
   g_rr_config 全局变量
        ↓
  各模块读取 g_rr_config
        ↓
   执行相应功能
```

### 关键配置的作用

| 配置项 | 控制的功能 | 不设置的后果 |
|--------|-----------|------------|
| `mode` | 整个系统的运行模式 | 默认为disabled，框架不工作 |
| `trace_file` | Trace数据的读写位置 | 使用默认路径 `/tmp/rr_trace.dat` |
| `fork_strategy` | Fork触发条件 | 默认为2 (AGGRESSIVE) |
| `cmd_pipe_path` | Fuzzer命令接收 | 无法接收fuzzer命令，Fuzzing模式失败 |
| `status_pipe_path` | 状态发送给fuzzer | 无法发送状态，fuzzer无法知道执行结果 |
| `shared_memory_name` | Mutation数据共享 | 无法应用mutation，相当于普通replay |
| `debug_level` | 日志输出详细程度 | 默认为3 (INFO) |

### 最佳实践

1. **使用配置文件**: 将稳定的配置写入文件，方便重复使用
2. **环境变量覆盖**: 临时测试时用环境变量覆盖配置文件
3. **分级调试**: 开发时用 `debug_level=4`，生产时用 `debug_level=2`
4. **策略选择**: 快速fuzzing用 `fork_strategy=2`，稳定性测试用 `fork_strategy=0`

---

**文档版本**: 1.0  
**创建日期**: 2024-01-XX


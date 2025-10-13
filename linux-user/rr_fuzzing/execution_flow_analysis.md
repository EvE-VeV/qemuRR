# RR-Fuzz 执行流程逐步详细分析

**目标**: 深入分析每个执行阶段的详细步骤、数据流转、状态变化和模块交互

---

## 📋 目录

1. [阶段0: 系统启动与初始化](#阶段0-系统启动与初始化)
2. [阶段1: Python Conductor准备](#阶段1-python-conductor准备)
3. [阶段2: QEMU进程启动](#阶段2-qemu进程启动)
4. [阶段3: 框架初始化](#阶段3-框架初始化)
5. [阶段4: 到达Fork点](#阶段4-到达fork点)
6. [阶段5: Fork Server循环](#阶段5-fork-server循环)
7. [阶段6: 子进程Replay执行](#阶段6-子进程replay执行)
8. [阶段7: 父进程等待与响应](#阶段7-父进程等待与响应)
9. [阶段8: 清理与退出](#阶段8-清理与退出)
10. [完整时序图](#完整时序图)

---

## 阶段0: 系统启动与初始化

### 步骤0.1: Python脚本启动

**文件**: `fuzz_conductor_example.py:283-328`

#### 代码执行流程:
```python
def main():
    # 0.1.1 解析命令行参数
    parser = argparse.ArgumentParser(description='RR-Fuzz Conductor Example')
    parser.add_argument('--qemu', default='qemu-x86_64')
    parser.add_argument('--target', required=True)
    parser.add_argument('--trace', required=True)
    parser.add_argument('--fork-syscall', default='openat')
    parser.add_argument('--fork-pattern', help='Path pattern')
    parser.add_argument('--iterations', type=int, default=100)
    args = parser.parse_args()
```

**详细分析**:
- **输入验证**: 检查trace文件和target程序是否存在
- **参数解析**: 将命令行参数转换为内部配置
- **默认值设置**: fork-syscall默认为'openat'

**状态变化**:
```
初始状态: 无
执行后状态: 
  - args.qemu = qemu路径
  - args.target = 目标程序路径
  - args.trace = trace文件路径
  - args.fork_syscall = "openat"
  - args.fork_pattern = "*/input*" 或 None
  - args.iterations = 100
```

**潜在问题**:
- ⚠️ 如果trace文件不存在，程序会报错退出
- ⚠️ 如果qemu路径错误，会在后续启动时失败

---

## 阶段1: Python Conductor准备

### 步骤1.1: 创建FuzzConductor对象

**文件**: `fuzz_conductor_example.py:119-136`

```python
class FuzzConductor:
    def __init__(self, qemu_path, target_binary, trace_file, 
                 fork_syscall="openat", fork_pattern=None):
        self.qemu_path = qemu_path
        self.target_binary = target_binary
        self.trace_file = trace_file
        self.fork_syscall = fork_syscall
        self.fork_pattern = fork_pattern
        
        # 1.1.1 创建IPC管道
        self.cmd_pipe_read, self.cmd_pipe_write = os.pipe()
        self.status_pipe_read, self.status_pipe_write = os.pipe()
        
        # 1.1.2 创建共享内存
        self.shm = FuzzSharedMemory(f"rr_fuzz_{os.getpid()}")
        self.shm.create()
        
        self.qemu_process = None
        self.total_executions = 0
        self.crashes = []
```

#### 详细分析步骤1.1.1: 创建IPC管道

**系统调用**: `pipe()`

```python
self.cmd_pipe_read, self.cmd_pipe_write = os.pipe()
# 返回: (读端FD, 写端FD)
# 例如: (5, 6)
```

**内核操作**:
1. 分配一个管道缓冲区 (通常64KB)
2. 创建两个文件描述符
3. 返回FD对

**数据结构变化**:
```
Python进程FD表:
  FD 0: stdin
  FD 1: stdout
  FD 2: stderr
  FD 3: (可能被其他文件占用)
  FD 4: (可能被其他文件占用)
  FD 5: cmd_pipe_read  ← 新增
  FD 6: cmd_pipe_write ← 新增
  FD 7: status_pipe_read  ← 新增
  FD 8: status_pipe_write ← 新增
```

**管道特性**:
- 单向通信
- FIFO (先进先出)
- 缓冲区大小: 64KB (Linux默认)
- 阻塞模式: 默认阻塞

#### 详细分析步骤1.1.2: 创建共享内存

**文件**: `fuzz_conductor_example.py:69-82`

```python
def create(self):
    # 1.1.2.1 创建共享内存文件
    shm_path = f"/dev/shm/{self.shm_name}"
    # 例如: /dev/shm/rr_fuzz_12345
    
    # 1.1.2.2 打开/创建文件
    self.shm_fd = os.open(shm_path, os.O_CREAT | os.O_RDWR, 0o666)
    
    # 1.1.2.3 设置文件大小
    os.ftruncate(self.shm_fd, self.size)  # size = 65536
    
    # 1.1.2.4 映射到内存
    self.mem = mmap.mmap(self.shm_fd, self.size)
```

**系统调用序列**:
```
1. open("/dev/shm/rr_fuzz_12345", O_CREAT|O_RDWR, 0666)
   → 返回 FD 9
   
2. ftruncate(9, 65536)
   → 设置文件大小为64KB
   
3. mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_SHARED, 9, 0)
   → 返回内存地址 0x7f1234567000
```

**内存布局**:
```
虚拟地址空间:
  0x7f1234567000 ┌─────────────────────────┐
                 │ FuzzSharedMemory        │
                 │ ┌─────────────────────┐ │
                 │ │ magic: 0x46555A5A   │ │ +0
                 │ │ count: 0            │ │ +4
                 │ │ flags: 0            │ │ +8
                 │ │ reserved: 0         │ │ +12
                 │ ├─────────────────────┤ │
                 │ │ instructions[0]     │ │ +16
                 │ │   (268 bytes)       │ │
                 │ ├─────────────────────┤ │
                 │ │ instructions[1]     │ │ +284
                 │ │   ...               │ │
                 │ └─────────────────────┘ │
  0x7f1234577000 └─────────────────────────┘
```

**状态变化**:
```
执行前:
  - 无共享内存
  
执行后:
  - shm_fd = 9
  - mem = mmap对象
  - /dev/shm/rr_fuzz_12345 文件存在
  - 文件大小 = 65536字节
  - 内存已映射到进程地址空间
```

---

## 阶段2: QEMU进程启动

### 步骤2.1: 构建启动命令

**文件**: `fuzz_conductor_example.py:138-172`

```python
def start_qemu(self):
    # 2.1.1 构建环境变量
    env = os.environ.copy()
    env.update({
        'RR_DEBUG_LEVEL':'4',
        'RR_FUZZING_ENABLED': 'True',
        'RR_MODE': 'fuzzing',
        'RR_STRACE_MODE': 'True',
        'RR_TRACE_FILE': self.trace_file,
        'RR_FORK_SYSCALL': self.fork_syscall,
        'RR_CMD_PIPE': str(self.cmd_pipe_read),      # "5"
        'RR_STATUS_PIPE': str(self.status_pipe_write), # "8"
        'RR_SHARED_MEMORY': self.shm.shm_name,      # "rr_fuzz_12345"
    })
    
    if self.fork_pattern:
        env['RR_FORK_PATTERN'] = self.fork_pattern
    
    # 2.1.2 构建命令
    cmd = [self.qemu_path, self.target_binary]
    # 例如: ['/path/to/qemu-x86_64', '/usr/bin/ls']
```

**环境变量详解**:

| 变量 | 值示例 | 用途 | 被哪个模块读取 |
|------|--------|------|--------------|
| RR_DEBUG_LEVEL | "4" | 调试级别 | rr_debug.c |
| RR_FUZZING_ENABLED | "True" | 启用标志 | rr_config.c |
| RR_MODE | "fuzzing" | 运行模式 | rr_config.c |
| RR_STRACE_MODE | "True" | Strace模式 | rr_config.c |
| RR_TRACE_FILE | "../strace-ls-record.txt" | Trace文件 | rr_config.c |
| RR_FORK_SYSCALL | "openat" | Fork点系统调用 | rr_config.c |
| RR_CMD_PIPE | "5" | 命令管道FD | rr_ipc.c |
| RR_STATUS_PIPE | "8" | 状态管道FD | rr_ipc.c |
| RR_SHARED_MEMORY | "rr_fuzz_12345" | 共享内存名 | rr_ipc.c |
| RR_FORK_PATTERN | "*/input*" | 路径模式 | rr_config.c |

### 步骤2.2: 启动子进程

```python
# 2.2.1 使用Popen启动
self.qemu_process = subprocess.Popen(
    cmd,
    env=env,
    pass_fds=[self.cmd_pipe_read, self.status_pipe_write],  # 关键!
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
```

**详细分析pass_fds参数**:

这是关键步骤！`pass_fds`确保子进程继承指定的FD。

**fork()过程**:
```
1. Python调用fork()
   → 创建子进程
   → 子进程复制父进程的FD表
   
2. 子进程FD表:
   FD 0: stdin (继承)
   FD 1: pipe (stdout被重定向到pipe)
   FD 2: pipe (stderr被重定向到pipe)
   FD 3: 被关闭 (默认行为)
   FD 4: 被关闭
   FD 5: cmd_pipe_read  ← pass_fds保留
   FD 6: 被关闭 (不在pass_fds中)
   FD 7: 被关闭
   FD 8: status_pipe_write ← pass_fds保留
   FD 9: 被关闭 (shm_fd)
   
3. 子进程执行exec()
   → 加载qemu-x86_64程序
   → FD 5, 8 仍然保留 (因为没有设置FD_CLOEXEC)
```

**进程关系**:
```
Python Conductor (PID=12345)
  │
  ├─ FD 5: cmd_pipe_read
  ├─ FD 6: cmd_pipe_write  ← 用于发送命令
  ├─ FD 7: status_pipe_read ← 用于接收状态
  ├─ FD 8: status_pipe_write
  │
  └─ fork() → QEMU (PID=12346)
       │
       ├─ FD 5: cmd_pipe_read  ← 用于接收命令
       ├─ FD 8: status_pipe_write ← 用于发送状态
       └─ 执行: qemu-x86_64 /usr/bin/ls
```

**状态变化**:
```
执行前:
  - qemu_process = None
  
执行后:
  - qemu_process = Popen对象
  - qemu_process.pid = 12346
  - QEMU进程正在运行
  - QEMU继承了FD 5和8
```

---

## 阶段3: 框架初始化

### 步骤3.1: QEMU main()入口

**文件**: QEMU的`main()`函数 (不在rr_fuzzing中)

```c
int main(int argc, char **argv) {
    // ... QEMU标准初始化
    
    // 3.1.1 在某个时刻，调用linux-user初始化
    // 这会触发我们的框架初始化
}
```

### 步骤3.2: rr_config_init()

**文件**: `rr_config.c:52-334`

```c
int rr_config_init(void) {
    // 3.2.1 读取环境变量
    const char *enabled = getenv("RR_FUZZING_ENABLED");
    if (!enabled || strcmp(enabled, "1") != 0) {
        if (strcmp(enabled, "True") == 0) {
            g_rr_config.enabled = true;  // ← 匹配!
        }
    }
    
    // 3.2.2 解析模式
    const char *mode_str = getenv("RR_MODE");
    if (strcmp(mode_str, "fuzzing") == 0) {
        g_rr_config.mode = RR_MODE_FUZZING;  // ← 设置为3
    }
    
    // 3.2.3 读取trace文件路径
    const char *trace_file = getenv("RR_TRACE_FILE");
    if (trace_file) {
        g_rr_config.trace_file = strdup(trace_file);
        // ← "../strace-ls-record.txt"
    }
    
    // 3.2.4 读取Fork Server配置
    const char *fork_syscall = getenv("RR_FORK_SYSCALL");
    if (fork_syscall) {
        g_rr_config.fork_syscall_name = strdup(fork_syscall);
        // ← "openat"
        g_rr_config.fork_server_enabled = true;
    }
    
    const char *fork_pattern = getenv("RR_FORK_PATTERN");
    if (fork_pattern) {
        g_rr_config.fork_syscall_pattern = strdup(fork_pattern);
        // ← "*/input*"
    }
    
    // 3.2.5 读取IPC配置
    const char *cmd_pipe = getenv("RR_CMD_PIPE");
    if (cmd_pipe) {
        g_rr_config.cmd_pipe_path = strdup(cmd_pipe);
        // ← "5"
    }
    
    const char *status_pipe = getenv("RR_STATUS_PIPE");
    if (status_pipe) {
        g_rr_config.status_pipe_path = strdup(status_pipe);
        // ← "8"
    }
    
    const char *shm_name = getenv("RR_SHARED_MEMORY");
    if (shm_name) {
        g_rr_config.shared_memory_name = strdup(shm_name);
        // ← "rr_fuzz_12345"
    }
    
    // 3.2.6 设置默认值
    if (g_rr_config.shared_memory_size == 0) {
        g_rr_config.shared_memory_size = 4096;
    }
    
    if (g_rr_config.ipc_timeout == 0) {
        g_rr_config.ipc_timeout = 1000;  // 1秒
    }
    
    return 0;
}
```

**状态变化**:
```
执行前:
  g_rr_config = {全部为0/NULL}
  
执行后:
  g_rr_config = {
    .enabled = true,
    .mode = RR_MODE_FUZZING (3),
    .trace_file = "../strace-ls-record.txt",
    .shared_memory_name = "rr_fuzz_12345",
    .cmd_pipe_path = "5",
    .status_pipe_path = "8",
    .fork_server_enabled = true,
    .fork_syscall_name = "openat",
    .fork_syscall_pattern = "*/input*",
    .shared_memory_size = 4096,
    .ipc_timeout = 1000
  }
```

### 步骤3.3: rr_framework_init()

**文件**: `rr_main.c:95-216`

```c
int rr_framework_init(void) {
    // 3.3.1 分配全局框架结构
    g_rr_framework = g_malloc0(sizeof(rr_framework_t));
    
    // 3.3.2 复制配置
    g_rr_framework->mode = g_rr_config.mode;  // RR_MODE_FUZZING
    g_rr_framework->enabled = g_rr_config.enabled;  // true
    
    // 3.3.3 初始化哈希表
    g_rr_framework->fd_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_rr_framework->addr_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    
    // 3.3.4 注册清理函数
    atexit(rr_framework_cleanup);
    
    // 3.3.5 初始化调试系统
    rr_debug_init();
    
    // 3.3.6 初始化IPC
    if (rr_ipc_init() < 0) {
        goto error;
    }
    
    // 3.3.7 根据模式初始化
    switch (g_rr_framework->mode) {
        case RR_MODE_FUZZING:
            // 3.3.7.1 检查是否使用strace模式
            const char *strace_mode = getenv("RR_STRACE_MODE");
            if (strace_mode && strcmp(strace_mode, "1") == 0) {
                // 3.3.7.2 初始化strace replay
                if (rr_strace_replay_init_optimized(
                        g_rr_config.trace_file) < 0) {
                    goto error;
                }
            }
            
            // 3.3.7.3 启动Fork Server
            if (g_rr_config.fork_server_enabled) {
                rr_start_fork_server(
                    g_rr_config.fork_syscall_name,
                    g_rr_config.fork_syscall_pattern);
            }
            break;
    }
    
    g_rr_framework->enabled = true;
    return 0;
    
error:
    rr_framework_cleanup();
    return -1;
}
```

**详细分析步骤3.3.6: rr_ipc_init()**

**文件**: `rr_ipc.c:15-80`

```c
int rr_ipc_init(void) {
    // 3.3.6.1 解析命令管道FD
    if (g_rr_config.cmd_pipe_path) {
        char *endptr;
        long fd = strtol(g_rr_config.cmd_pipe_path, &endptr, 10);
        // "5" → 5
        
        if (*endptr == '\0' && fd >= 0) {
            g_rr_framework->cmd_pipe_fd = (int)fd;  // ← 5
        }
    }
    
    // 3.3.6.2 解析状态管道FD
    if (g_rr_config.status_pipe_path) {
        char *endptr;
        long fd = strtol(g_rr_config.status_pipe_path, &endptr, 10);
        // "8" → 8
        
        if (*endptr == '\0' && fd >= 0) {
            g_rr_framework->status_pipe_fd = (int)fd;  // ← 8
        }
    }
    
    // 3.3.6.3 打开共享内存
    if (g_rr_config.shared_memory_name) {
        int shm_fd = shm_open(g_rr_config.shared_memory_name, 
                              O_RDWR, 0666);
        // 打开 "/dev/shm/rr_fuzz_12345"
        // 返回 FD 9
        
        if (shm_fd >= 0) {
            g_rr_framework->shared_memory = mmap(
                NULL, 
                g_rr_config.shared_memory_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED, 
                shm_fd, 
                0);
            // 映射到地址: 0x7f9876543000
            
            close(shm_fd);  // 关闭FD，但映射保留
        }
    }
    
    return 0;
}
```

**内存映射图**:
```
Python进程                    QEMU进程
  0x7f1234567000               0x7f9876543000
  ┌─────────────┐             ┌─────────────┐
  │ SharedMem   │ ←─────────→ │ SharedMem   │
  │ (Python写)  │   内核共享   │ (QEMU读)    │
  └─────────────┘             └─────────────┘
       ↑                            ↑
       └────────────────────────────┘
          同一块物理内存
```

**状态变化**:
```
执行前:
  g_rr_framework = NULL
  
执行后:
  g_rr_framework = {
    .mode = RR_MODE_FUZZING,
    .enabled = true,
    .cmd_pipe_fd = 5,
    .status_pipe_fd = 8,
    .shared_memory = 0x7f9876543000,
    .fd_map = GHashTable*,
    .addr_map = GHashTable*,
    .fork_server_active = false (尚未激活)
  }
```

### 步骤3.4: rr_strace_replay_init_optimized()

**文件**: `rr_replay_strace_optimized.c:约100行`

```c
int rr_strace_replay_init_optimized(const char *trace_file) {
    // 3.4.1 创建解析器
    g_strace_parser = rr_strace_parser_create();
    
    // 3.4.2 加载trace文件
    if (rr_strace_parser_load(g_strace_parser, trace_file) < 0) {
        return -1;
    }
    // 解析 "../strace-ls-record.txt"
    // 加载100条系统调用记录
    
    // 3.4.3 初始化replay状态
    g_strace_state.enabled = true;
    g_strace_state.strict_mode = false;
    g_strace_state.skip_unmatched = false;
    g_strace_state.max_lookahead = 50;
    g_strace_state.trace_filename = strdup(trace_file);
    g_strace_state.current_record_index = 0;
    g_strace_state.trace_exhausted = false;
    
    return 0;
}
```

**trace文件解析**:
```
输入文件: ../strace-ls-record.txt
内容示例:
  269361 brk(NULL) = 0x000055555557a000
  269361 arch_prctl(12289,...) = -1 errno=22
  269361 uname(0x79eaaab08640) = 0
  ...
  (共100行)

解析后:
  g_strace_parser->records[0] = {
    .pid = 269361,
    .syscall_name = "brk",
    .syscall_nr = 12,
    .args = [0],
    .ret_value = 0x000055555557a000
  }
  g_strace_parser->records[1] = {
    .pid = 269361,
    .syscall_name = "arch_prctl",
    .syscall_nr = 158,
    .args = [12289, ...],
    .ret_value = -1,
    .errno_val = 22
  }
  ...
  g_strace_parser->record_count = 100
```

**状态变化**:
```
执行前:
  g_strace_parser = NULL
  g_strace_state.enabled = false
  
执行后:
  g_strace_parser = {
    .records = [100条记录],
    .record_count = 100,
    .current_index = 0
  }
  g_strace_state = {
    .enabled = true,
    .current_record_index = 0,
    .trace_exhausted = false,
    .total_syscalls = 0,
    .matched_syscalls = 0
  }
```

### 步骤3.5: rr_start_fork_server()

**文件**: `rr_fork_server.c:27-80`

```c
int rr_start_fork_server(const char *syscall_name, const char *pattern) {
    // 3.5.1 保存配置
    if (syscall_name) {
        g_fork_syscall_name = strdup(syscall_name);  // "openat"
    }
    
    if (pattern) {
        g_fork_syscall_pattern = strdup(pattern);  // "*/input*"
    }
    
    // 3.5.2 激活Fork Server
    g_rr_framework->fork_server_active = true;
    
    // 3.5.3 重置fork点标志
    g_at_fork_point = false;
    
    return 0;
}
```

**全局变量状态**:
```
执行前:
  g_fork_syscall_name = NULL
  g_fork_syscall_pattern = NULL
  g_at_fork_point = false
  g_rr_framework->fork_server_active = false
  
执行后:
  g_fork_syscall_name = "openat"
  g_fork_syscall_pattern = "*/input*"
  g_at_fork_point = false
  g_rr_framework->fork_server_active = true
```

### 步骤3.6: 发送Ready状态

**文件**: `rr_main.c:约210行`

```c
// 初始化完成后
g_rr_framework->enabled = true;

// 发送Ready状态给Python
rr_ipc_send_status(1);  // 1 = Ready
```

**rr_ipc_send_status()详解**:

**文件**: `rr_ipc.c:112-125`

```c
int rr_ipc_send_status(int status) {
    if (g_rr_framework->status_pipe_fd < 0) {
        return 0;
    }
    
    // 写入4字节整数
    if (write(g_rr_framework->status_pipe_fd, &status, sizeof(status)) 
        != sizeof(status)) {
        return -1;
    }
    
    return 0;
}
```

**系统调用**:
```
write(8, &status, 4)
  ↓
写入4字节: 0x01 0x00 0x00 0x00
  ↓
数据流向管道缓冲区
  ↓
Python端read(7, buf, 4)接收
```

**数据流**:
```
QEMU进程                      管道缓冲区                  Python进程
  │                              │                          │
  │ write(8, {1}, 4)            │                          │
  ├────────────────────────────→│                          │
  │                              │ [0x01 0x00 0x00 0x00]   │
  │                              │                          │
  │                              │←─────────────────────────┤
  │                              │  read(7, buf, 4)         │
  │                              │                          │
  │                              │                          ├→ status=1
```

**Python端接收**:

**文件**: `fuzz_conductor_example.py:约220行`

```python
# Python在等待第一个状态
status_bytes = os.read(self.status_pipe_read, 4)
# 读取4字节: b'\x01\x00\x00\x00'

status = struct.unpack('i', status_bytes)[0]
# 解包: status = 1

status_name = {1: "Ready", 2: "At Fork Point", ...}[status]
# status_name = "Ready"

print(f"[Conductor] Execution #1: {status_name}")
# 输出: [Conductor] Execution #1: Ready
```

**状态变化**:
```
QEMU端:
  - 初始化完成
  - Fork Server已激活
  - 等待系统调用执行
  
Python端:
  - 收到Ready状态
  - 知道QEMU已准备好
  - 可以开始发送F命令
```

---

## 阶段4: 到达Fork点

### 步骤4.1: 目标程序开始执行

QEMU开始执行目标程序 `/usr/bin/ls`，每个系统调用都会被拦截。

### 步骤4.2: 第一个系统调用 - brk

**QEMU syscall拦截**: `linux-user/syscall.c`

```c
abi_long do_syscall(CPUArchState *env, int num, ...) {
    // QEMU原生的系统调用处理
    
    // 检查是否启用RR框架
    if (rr_framework_enabled()) {
        // 调用我们的框架
        ret = rr_do_syscall(env, num, &arg1, &arg2, ...);
        if (ret != -1) {
            return ret;  // 框架处理了
        }
    }
    
    // 否则执行原生系统调用
    ...
}
```

**我们的rr_do_syscall()**: `rr_main.c:298-412`

```c
abi_long rr_do_syscall(CPUArchState *env, int num, abi_long *args) {
    // 4.2.1 前置检查
    if (!g_rr_framework || !g_rr_framework->enabled) {
        return -1;
    }
    
    g_rr_framework->total_syscalls++;
    
    // 4.2.2 根据模式分发
    switch (g_rr_framework->mode) {
        case RR_MODE_FUZZING:
            // 4.2.3 检查是否到达fork点
            const char *syscall_name = get_syscall_name(num);
            // num=12 → syscall_name="brk"
            
            if (rr_check_fork_point(num, syscall_name, args)) {
                // 如果到达fork点，进入fork server循环
                int fork_result = rr_fork_server_loop();
                ...
            }
            
            // 4.2.4 执行strace replay
            ret = rr_replay_syscall_strace_optimized(env, num, args);
            break;
    }
    
    return ret;
}
```

**步骤4.2.3详解: rr_check_fork_point()**

**文件**: `rr_fork_server.c:146-212`

```c
bool rr_check_fork_point(int syscall_nr, const char *syscall_name, 
                         const abi_long *args) {
    // 4.2.3.1 检查Fork Server是否激活
    if (!g_rr_framework->fork_server_active) {
        return false;
    }
    
    // 4.2.3.2 如果已经到达fork点，直接返回true
    if (g_at_fork_point) {
        return true;
    }
    
    // 4.2.3.3 检查系统调用名称
    if (!syscall_name || strcmp(syscall_name, g_fork_syscall_name) != 0) {
        // "brk" != "openat"
        return false;  // ← 第一个系统调用不匹配
    }
    
    // ... 后续检查
}
```

**第一个系统调用brk的处理**:
```
输入:
  num = 12
  syscall_name = "brk"
  args = [0]
  
检查过程:
  1. fork_server_active? YES
  2. g_at_fork_point? NO
  3. syscall_name == "openat"? NO ("brk" != "openat")
  
返回: false

继续执行:
  → rr_replay_syscall_strace_optimized(env, 12, [0])
```

### 步骤4.3: 执行系统调用序列

QEMU继续执行系统调用，每个都经过相同的检查：

```
系统调用序列:
  1. brk(NULL)              → 不匹配 → replay
  2. arch_prctl(...)        → 不匹配 → replay
  3. uname(...)             → 不匹配 → replay
  4. mmap(...)              → 不匹配 → replay
  5. access(...)            → 不匹配 → replay
  6. openat("/etc/ld.so.cache", ...) → 匹配! ← 这里
```

### 步骤4.4: 第6个系统调用 - openat (匹配!)

```c
// 第6个系统调用
num = 257  // openat
syscall_name = "openat"
args = [-100, 0x7f..., O_RDONLY|O_CLOEXEC]

// 进入rr_check_fork_point()
bool rr_check_fork_point(int syscall_nr, const char *syscall_name, 
                         const abi_long *args) {
    // 4.4.1 基本检查
    if (!g_rr_framework->fork_server_active) {
        return false;
    }
    
    if (g_at_fork_point) {
        return true;
    }
    
    // 4.4.2 检查系统调用名称
    if (!syscall_name || strcmp(syscall_name, g_fork_syscall_name) != 0) {
        return false;
    }
    // "openat" == "openat" ✓
    
    RR_VERBOSE("Found target syscall: %s", syscall_name);
    
    // 4.4.3 检查路径模式 (如果有)
    if (g_fork_syscall_pattern) {
        // g_fork_syscall_pattern = "*/input*"
        
        // 4.4.3.1 提取路径
        char *path = extract_path_from_syscall(syscall_name, args, NULL);
        // 从args[1]提取字符串
        // path = "/etc/ld.so.cache"
        
        // 4.4.3.2 模式匹配
        int match_result = fnmatch(g_fork_syscall_pattern, path, FNM_PATHNAME);
        // fnmatch("*/input*", "/etc/ld.so.cache", FNM_PATHNAME)
        // 返回: FNM_NOMATCH (不匹配)
        
        free(path);
        
        if (match_result == 0) {
            // 匹配成功
            ...
        } else {
            RR_VERBOSE("Path pattern '%s' did not match, continuing...", 
                      g_fork_syscall_pattern);
            return false;  // ← 路径不匹配，继续
        }
    }
    
    // 4.4.4 如果没有路径模式，直接匹配
    if (!g_fork_syscall_pattern) {
        g_at_fork_point = true;
        RR_INFO("🎯 Reached fork point: %s (no path pattern)", syscall_name);
        
        // 4.4.4.1 发送状态
        rr_ipc_send_status(2);  // 2 = At Fork Point
        
        return true;
    }
    
    return false;
}
```

**两种情况分析**:

#### 情况A: 有路径模式 (fork-pattern="*/input*")

```
第6个openat: "/etc/ld.so.cache"
  → fnmatch("*/input*", "/etc/ld.so.cache") = NO_MATCH
  → 返回false
  → 继续执行

第7个openat: "/lib/x86_64-linux-gnu/libselinux.so.1"
  → fnmatch("*/input*", "/lib/...") = NO_MATCH
  → 返回false
  → 继续执行

...

第N个openat: 如果trace中没有匹配"*/input*"的路径
  → 永远不会到达fork点
  → 第2次F命令会卡住 ← 这就是之前的问题!
```

#### 情况B: 无路径模式 (fork-pattern=None)

```
第6个openat: "/etc/ld.so.cache"
  → 系统调用名称匹配 "openat"
  → 无路径模式要求
  → g_at_fork_point = true
  → 发送状态码2
  → 返回true ✓
```

**状态变化 (情况B)**:
```
执行前:
  g_at_fork_point = false
  g_rr_framework->total_syscalls = 5
  
执行后:
  g_at_fork_point = true  ← 关键变化!
  g_rr_framework->total_syscalls = 6
  
IPC:
  → write(8, {2}, 4)  // 发送"At Fork Point"状态
```

**Python端接收**:
```python
# Python发送了第1个'F'命令后，在等待响应
status_bytes = os.read(self.status_pipe_read, 4)
status = struct.unpack('i', status_bytes)[0]
# status = 2

print(f"[Conductor] Execution #1: At Fork Point")
```

---

## 阶段5: Fork Server循环

### 步骤5.1: 进入Fork Server循环

**文件**: `rr_main.c:378-386`

```c
// 在rr_do_syscall()中
if (rr_check_fork_point(num, syscall_name, args)) {
    // 返回true，说明到达fork点
    
    // 5.1.1 进入Fork Server主循环
    int fork_result = rr_fork_server_loop();
    
    if (fork_result < 0) {
        exit(0);  // 收到退出命令
    } else if (fork_result > 0) {
        // 子进程继续执行
    }
    // 父进程会继续循环
}
```

### 步骤5.2: Fork Server主循环

**文件**: `rr_fork_server.c:218-334`

```c
int rr_fork_server_loop(void) {
    // 5.2.1 检查是否到达fork点
    if (!g_at_fork_point) {
        return 0;  // 还未到达Fork点
    }
    
    // 5.2.2 进入循环
    while (g_rr_framework->fork_server_active) {
        // 5.2.3 接收Conductor命令
        int cmd = rr_ipc_receive_command();
        
        switch (cmd) {
            case 'F':  // Fork命令
                // ... 处理fork
                break;
                
            case 'Q':  // 退出命令
                return -1;
                
            default:
                break;
        }
    }
    
    return 0;
}
```

**步骤5.2.3详解: rr_ipc_receive_command()**

**文件**: `rr_ipc.c:131-158`

```c
int rr_ipc_receive_command(void) {
    if (g_rr_framework->cmd_pipe_fd < 0) {
        return 0;
    }
    
    // 5.2.3.1 从管道读取1字节
    char cmd;
    ssize_t n = read(g_rr_framework->cmd_pipe_fd, &cmd, 1);
    // ← 阻塞在这里，等待Python发送命令
    
    if (n != 1) {
        return 0;  // 无数据或错误
    }
    
    RR_LOG("Received command: %c", cmd);
    
    // 5.2.3.2 解析命令
    switch (cmd) {
        case 'F':
            return 'F';
        case 'Q':
            return 'Q';
        case 'S':
            return 'S';
        case 'L':
            return 'L';
        default:
            return 0;
    }
}
```

**阻塞等待**:
```
QEMU进程状态:
  - 主线程阻塞在read(5, &cmd, 1)
  - 等待Python写入命令
  - CPU使用率: 0% (睡眠状态)
  - 状态: S (Sleeping)

Python进程状态:
  - 已收到"At Fork Point"状态
  - 准备发送'F'命令
  - 可能在准备Fuzz指令
```

### 步骤5.3: Python发送第2个'F'命令

**文件**: `fuzz_conductor_example.py:174-191`

```python
def send_fuzz_command(self, instructions):
    # 5.3.1 写入共享内存
    self.shm.write_instructions(instructions)
    
    # 5.3.2 发送'F'命令触发fork
    os.write(self.cmd_pipe_write, b'F')
    print(f"[Conductor] Sent 'F' command to QEMU")
    
    # 5.3.3 等待执行结果
    status_bytes = os.read(self.status_pipe_read, 4)
    # ← 阻塞在这里，等待QEMU响应
    ...
}
```

**步骤5.3.1详解: 写入共享内存**

**文件**: `fuzz_conductor_example.py:84-101`

```python
def write_instructions(self, instructions):
    if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
        raise ValueError(f"Too many instructions")
    
    # 5.3.1.1 写入头部
    header = struct.pack('IIII', 
                        FUZZ_MAGIC,           # 0x46555A5A
                        len(instructions),    # 例如: 2
                        0,                    # flags
                        0)                    # reserved
    self.mem.seek(0)
    self.mem.write(header)
    
    # 5.3.1.2 写入指令数组
    for instr in instructions:
        self.mem.write(instr.pack())
    
    print(f"[Conductor] Wrote {len(instructions)} instructions to shared memory")
}
```

**共享内存内容**:
```
地址偏移    内容                        说明
0x0000      5A 5A 55 46              magic (0x46555A5A)
0x0004      02 00 00 00              count = 2
0x0008      00 00 00 00              flags
0x000C      00 00 00 00              reserved

0x0010      [FuzzInstruction #0]     268字节
            ├─ cmd: 1 (MUTATE_ARG)
            ├─ syscall_index: 15
            ├─ arg_index: 2
            ├─ data_len: 8
            └─ data: [0xFF, 0xFF, ...]

0x011C      [FuzzInstruction #1]     268字节
            ├─ cmd: 3 (MUTATE_FLAGS)
            ├─ syscall_index: 15
            ├─ arg_index: 3
            ├─ data_len: 4
            └─ data: [0xFF, 0xFF, 0x00, 0x00]
```

**步骤5.3.2: 发送命令**

```python
os.write(self.cmd_pipe_write, b'F')
# write(6, "F", 1)
```

**数据流**:
```
Python                    管道缓冲区              QEMU
  │                          │                    │
  │ write(6, "F", 1)         │                    │
  ├─────────────────────────→│                    │
  │                          │ ['F']              │
  │                          │                    │
  │                          │←───────────────────┤
  │                          │  read(5, &cmd, 1)  │
  │                          │                    │
  │                          │                    ├→ cmd='F'
  │                          │                    │  解除阻塞!
```

### 步骤5.4: QEMU接收到'F'命令

```c
// rr_ipc_receive_command() 返回
int cmd = rr_ipc_receive_command();
// cmd = 'F' (70)

// 进入switch
switch (cmd) {
    case 'F':  // ← 进入这里
        // 处理Fork命令
        ...
}
```

---

## 阶段6: 子进程Replay执行

### 步骤6.1: 加载Fuzz指令

**文件**: `rr_fork_server.c:232-247`

```c
case 'F':  // Fork命令
{
    // 6.1.1 从共享内存加载Fuzz指令
    if (g_rr_framework->shared_memory) {
        RR_VERBOSE("Loading fuzz instructions from shared memory before fork");
        
        int load_result = rr_fuzz_load_from_shared_memory(
            g_rr_framework->shared_memory);
        
        if (load_result < 0) {
            RR_ERROR("Failed to load fuzz instructions");
            rr_ipc_send_status(-1);
            break;
        }
        
        RR_VERBOSE("Fuzz instructions loaded successfully");
    }
    
    // 6.1.2 执行fork
    pid_t pid = fork();
    ...
}
```

**步骤6.1.1详解: rr_fuzz_load_from_shared_memory()**

**文件**: `rr_fuzz_engine.c:30-72`

```c
int rr_fuzz_load_from_shared_memory(void *shm_ptr) {
    FuzzSharedMemory *shm = (FuzzSharedMemory *)shm_ptr;
    
    // 6.1.1.1 验证魔数
    if (shm->magic != FUZZ_MAGIC) {
        RR_ERROR("Invalid magic: 0x%x (expected 0x%x)", 
                shm->magic, FUZZ_MAGIC);
        return -1;
    }
    // shm->magic = 0x46555A5A ✓
    
    // 6.1.1.2 验证指令数量
    if (shm->instruction_count > FUZZ_MAX_INSTRUCTIONS) {
        RR_ERROR("Too many instructions: %u (max %u)", 
                shm->instruction_count, FUZZ_MAX_INSTRUCTIONS);
        return -1;
    }
    // shm->instruction_count = 2 ✓
    
    // 6.1.1.3 复制指令到本地
    memcpy(g_fuzz_engine.instructions, 
           shm->instructions,
           shm->instruction_count * sizeof(FuzzInstruction));
    
    g_fuzz_engine.instruction_count = shm->instruction_count;
    
    RR_VERBOSE("Loaded %zu fuzz instructions", 
              g_fuzz_engine.instruction_count);
    
    return 0;
}
```

**状态变化**:
```
执行前:
  g_fuzz_engine = {
    .instruction_count = 0,
    .instructions = [未初始化]
  }
  
执行后:
  g_fuzz_engine = {
    .instruction_count = 2,
    .instructions = [
      {cmd=1, syscall_index=15, arg_index=2, data=[...]},
      {cmd=3, syscall_index=15, arg_index=3, data=[...]}
    ]
  }
```

### 步骤6.2: 执行fork()

```c
// 6.2.1 调用fork系统调用
pid_t pid = fork();
```

**fork()详细过程**:

```
1. 内核创建新进程
   - 复制进程控制块 (PCB)
   - 复制页表 (写时复制 COW)
   - 复制文件描述符表
   - 分配新的PID

2. 父进程 (QEMU主进程)
   PID = 12346
   返回值: pid = 12347 (子进程PID)
   
3. 子进程 (新创建)
   PID = 12347
   返回值: pid = 0
```

**内存布局 (写时复制)**:
```
fork()前:
  父进程 (PID=12346)
  ┌────────────────────┐
  │ 代码段 (只读)      │ ← 物理页A
  ├────────────────────┤
  │ 数据段             │ ← 物理页B
  │ g_rr_framework     │
  │ g_fuzz_engine      │
  ├────────────────────┤
  │ 堆                 │ ← 物理页C
  ├────────────────────┤
  │ 栈                 │ ← 物理页D
  └────────────────────┘

fork()后:
  父进程 (PID=12346)          子进程 (PID=12347)
  ┌────────────────────┐      ┌────────────────────┐
  │ 代码段             │ ←─┬─→│ 代码段             │
  └────────────────────┘   │  └────────────────────┘
         ↓ 共享物理页A     │         ↓ 共享
  ┌────────────────────┐   │  ┌────────────────────┐
  │ 数据段 (COW标记)   │ ←─┼─→│ 数据段 (COW标记)   │
  │ g_rr_framework     │   │  │ g_rr_framework     │
  │ g_fuzz_engine      │   │  │ g_fuzz_engine      │
  └────────────────────┘   │  └────────────────────┘
         ↓ 共享物理页B     │         ↓ 共享
  
  当任一进程写入时，触发COW，复制页面
```

**文件描述符继承**:
```
父进程FD表:                 子进程FD表:
  FD 0: stdin                 FD 0: stdin (继承)
  FD 1: stdout                FD 1: stdout (继承)
  FD 2: stderr                FD 2: stderr (继承)
  FD 5: cmd_pipe_read         FD 5: cmd_pipe_read (继承)
  FD 8: status_pipe_write     FD 8: status_pipe_write (继承)
  FD 9: trace_file            FD 9: trace_file (继承)
  ...                         ...
```

### 步骤6.3: 父子进程分叉

```c
if (pid == 0) {
    /* ===== 子进程代码路径 ===== */
    
    // 6.3.1 设置子进程标识
    g_rr_framework->child_pid = 0;
    
    // 6.3.2 禁用Fork Server (关键修复!)
    g_rr_framework->fork_server_active = false;
    
    RR_INFO("🔄 Child process started for fuzzing execution (PID=%d)", 
            getpid());
    RR_INFO("🔄 Child will continue replay from current point");
    
    // 6.3.3 返回1，表示子进程继续执行
    return 1;
    
} else if (pid > 0) {
    /* ===== 父进程代码路径 ===== */
    
    // 6.3.4 保存子进程PID
    g_rr_framework->child_pid = pid;
    
    RR_VERBOSE("Parent process waiting for child PID=%d", pid);
    
    // 6.3.5 等待子进程结束
    int status;
    waitpid(pid, &status, 0);  // ← 父进程阻塞在这里
    
    // ... 后续处理
}
```

**状态分叉**:
```
fork()前:
  单一进程 (PID=12346)
  g_rr_framework->child_pid = 0
  g_rr_framework->fork_server_active = true
  g_at_fork_point = true

fork()后:
  
  父进程 (PID=12346):
    g_rr_framework->child_pid = 12347
    g_rr_framework->fork_server_active = true
    状态: 阻塞在waitpid()
    
  子进程 (PID=12347):
    g_rr_framework->child_pid = 0
    g_rr_framework->fork_server_active = false ← 关键!
    状态: 继续执行
```

### 步骤6.4: 子进程继续执行

**子进程从rr_fork_server_loop()返回**:

```c
// rr_fork_server.c:263
return 1;  // 子进程返回1
```

**回到rr_do_syscall()**:

```c
// rr_main.c:380-386
int fork_result = rr_fork_server_loop();
// fork_result = 1 (子进程)

if (fork_result < 0) {
    exit(0);
} else if (fork_result > 0) {
    // 子进程继续执行
    // 不做任何特殊处理，继续往下
}

// 6.4.1 继续执行strace replay
ret = rr_replay_syscall_strace_optimized(env, num, args);
// 当前系统调用: openat (第6个)
```

**子进程执行流程**:
```
1. 从第6个系统调用openat继续
2. rr_replay_syscall_strace_optimized()
3. 查找trace记录
4. 应用fuzz变异
5. 执行实际系统调用
6. 继续下一个系统调用
7. ...
8. trace耗尽
9. exit(0) ← 关键修复
```

### 步骤6.5: 子进程Replay第7个系统调用

**文件**: `rr_replay_strace_optimized.c:462-520`

```c
abi_long rr_replay_syscall_strace_optimized(CPUArchState *env, int num, 
                                            abi_long *args) {
    RR_DEBUG("Processing syscall %d", num);
    
    // 6.5.1 检查模块是否初始化
    if (!g_strace_state.enabled) {
        RR_ERROR("Module not initialized");
        return -1;
    }
    
    g_strace_state.total_syscalls++;
    
    // 6.5.2 检查trace是否已耗尽
    if (g_strace_state.trace_exhausted) {
        g_strace_state.fallback_syscalls++;
        
        /* 🔥 关键修复：子进程trace耗尽后退出 */
        if (g_rr_framework && 
            g_rr_framework->mode == RR_MODE_FUZZING && 
            g_rr_framework->child_pid == 0) {
            RR_INFO("🎯 Trace exhausted in child process (PID=%d), exiting normally", 
                    getpid());
            exit(0);  // ← 子进程正常退出
        }
        
        return -1;
    }
    
    // 6.5.3 查找匹配的记录
    rr_strace_record_t *record = optimized_find_matching_record(num, args);
    
    if (!record) {
        g_strace_state.error_syscalls++;
        
        /* 🔥 如果连续多次找不到匹配，也退出 */
        if (g_rr_framework && 
            g_rr_framework->mode == RR_MODE_FUZZING && 
            g_rr_framework->child_pid == 0 && 
            g_strace_state.error_syscalls > 5) {
            RR_WARN("🎯 Too many unmatched syscalls in child process, exiting");
            exit(1);
        }
        
        return -1;
    }
    
    g_strace_state.matched_syscalls++;
    
    // 6.5.4 应用fuzz变异
    rr_fuzz_mutate_syscall(env, g_strace_state.current_record_index, 
                          args, num);
    
    // 6.5.5 恢复参数和返回值
    // ... (详细见后续分析)
    
    return record->ret_value;
}
```

**步骤6.5.4详解: rr_fuzz_mutate_syscall()**

**文件**: `rr_fuzz_engine.c:80-157`

```c
void rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index,
                            abi_long *args, int syscall_nr) {
    // 6.5.4.1 遍历所有fuzz指令
    for (size_t i = 0; i < g_fuzz_engine.instruction_count; i++) {
        FuzzInstruction *instr = &g_fuzz_engine.instructions[i];
        
        // 6.5.4.2 检查是否匹配当前系统调用
        if (instr->syscall_index != syscall_index) {
            continue;  // 不匹配，跳过
        }
        
        // 6.5.4.3 根据命令类型应用变异
        switch (instr->cmd) {
            case FUZZ_CMD_MUTATE_ARG:
                // 直接修改参数值
                {
                    abi_long new_value = *(abi_long*)instr->data;
                    abi_long old_value = args[instr->arg_index];
                    
                    args[instr->arg_index] = new_value;
                    
                    g_fuzz_engine.arg_mutations++;
                    
                    RR_VERBOSE("FUZZ: Mutated arg[%d]: %ld -> %ld",
                              instr->arg_index, old_value, new_value);
                }
                break;
                
            case FUZZ_CMD_REPLACE_BUFFER:
                // 替换缓冲区内容
                {
                    target_ulong addr = args[instr->arg_index];
                    
                    // 写入新数据到guest内存
                    if (copy_to_user(addr, instr->data, instr->data_len) == 0) {
                        g_fuzz_engine.buffer_mutations++;
                        
                        RR_VERBOSE("FUZZ: Replaced buffer at arg[%d], len=%u",
                                  instr->arg_index, instr->data_len);
                    }
                }
                break;
                
            case FUZZ_CMD_MUTATE_FLAGS:
                // 标志位变异 (XOR)
                {
                    uint32_t xor_mask = *(uint32_t*)instr->data;
                    abi_long old_value = args[instr->arg_index];
                    
                    args[instr->arg_index] ^= xor_mask;
                    
                    RR_VERBOSE("FUZZ: XOR flags arg[%d]: 0x%lx ^ 0x%x = 0x%lx",
                              instr->arg_index, old_value, xor_mask, 
                              args[instr->arg_index]);
                }
                break;
                
            case FUZZ_CMD_BOUNDARY_VALUE:
                // 边界值测试
                {
                    int64_t boundary_value = *(int64_t*)instr->data;
                    args[instr->arg_index] = boundary_value;
                    
                    g_fuzz_engine.boundary_tests++;
                    
                    RR_VERBOSE("FUZZ: Boundary test arg[%d] = %ld",
                              instr->arg_index, boundary_value);
                }
                break;
                
            default:
                RR_WARN("Unknown fuzz command: %d", instr->cmd);
                break;
        }
    }
    
    g_fuzz_engine.total_mutations++;
}
```

**变异示例**:

假设第15个系统调用是`read(fd, buf, count)`:
```
原始参数:
  args[0] = 3      // fd
  args[1] = 0x7fff1234  // buf
  args[2] = 1024   // count

Fuzz指令1: {cmd=MUTATE_ARG, syscall_index=15, arg_index=2, data=-1}
  → args[2] = -1  // 测试负数count

Fuzz指令2: {cmd=MUTATE_FLAGS, syscall_index=15, arg_index=0, data=0xFFFF}
  → args[0] ^= 0xFFFF  // 翻转fd的位

变异后参数:
  args[0] = 3 ^ 0xFFFF = 65532  // 无效FD
  args[1] = 0x7fff1234  // 不变
  args[2] = -1  // 负数
```

### 步骤6.6: 子进程继续执行直到trace耗尽

```
子进程系统调用序列:
  第7个: newfstatat(...) → replay + mutate
  第8个: mmap(...) → replay + mutate
  第9个: close(...) → replay + mutate
  ...
  第100个: exit_group(0) → replay
  
  第101个: (尝试执行下一个系统调用)
    → optimized_find_matching_record() 返回NULL
    → g_strace_state.trace_exhausted = true
    → 检测到子进程 + trace耗尽
    → exit(0) ← 关键修复生效!
```

**exit(0)详解**:
```c
exit(0);
  ↓
调用exit_group系统调用
  ↓
内核清理进程资源:
  - 关闭所有FD
  - 释放内存
  - 通知父进程 (发送SIGCHLD)
  - 设置退出状态为0
  ↓
进程变为僵尸状态 (Z)
  ↓
等待父进程waitpid()回收
```

---

## 阶段7: 父进程等待与响应

### 步骤7.1: 父进程waitpid()返回

**文件**: `rr_fork_server.c:269-290`

```c
// 父进程在这里等待
int status;
waitpid(pid, &status, 0);
// ← 子进程exit(0)后，waitpid()返回

RR_VERBOSE("Parent process: child PID=%d finished", pid);

// 7.1.1 分析退出状态
if (WIFEXITED(status)) {
    // 正常退出
    int exit_code = WEXITSTATUS(status);
    // exit_code = 0
    
    RR_VERBOSE("Child exited normally with code %d", exit_code);
    
    // 7.1.2 发送状态给Python
    rr_ipc_send_status(3);  // 3 = Normal Exit
    
} else if (WIFSIGNALED(status)) {
    // 被信号终止
    int sig = WTERMSIG(status);
    
    RR_VERBOSE("Child terminated by signal %d", sig);
    
    if (sig == SIGSEGV || sig == SIGABRT || sig == SIGILL) {
        // 崩溃信号
        RR_INFO("💥 CRASH DETECTED: signal %d", sig);
        rr_ipc_send_status(4);  // 4 = Crash
    } else {
        // 其他信号
        rr_ipc_send_status(5);  // 5 = Signal
    }
}
```

**waitpid()详解**:

**系统调用**: `waitpid(pid, &status, 0)`

```c
参数:
  pid = 12347  // 等待特定子进程
  status = &status  // 存储退出状态
  options = 0  // 阻塞等待

返回值:
  成功: 返回子进程PID (12347)
  失败: 返回-1

status编码 (32位整数):
  位0-6: 退出信号 (如果被信号终止)
  位7: core dump标志
  位8-15: 退出码 (如果正常退出)
  位16-31: 保留

示例:
  正常退出(0): status = 0x00000000
    WIFEXITED(status) = true
    WEXITSTATUS(status) = 0
    
  SIGSEGV崩溃: status = 0x0000000B
    WIFSIGNALED(status) = true
    WTERMSIG(status) = 11 (SIGSEGV)
```

**状态判断宏**:
```c
WIFEXITED(status)    // 是否正常退出
WEXITSTATUS(status)  // 获取退出码 (0-255)
WIFSIGNALED(status)  // 是否被信号终止
WTERMSIG(status)     // 获取终止信号
WIFSTOPPED(status)   // 是否被停止
WSTOPSIG(status)     // 获取停止信号
```

### 步骤7.2: 发送状态给Python

```c
rr_ipc_send_status(3);  // Normal Exit
  ↓
write(8, {3}, 4)
  ↓
数据: 0x03 0x00 0x00 0x00
  ↓
流向status_pipe
```

**数据流**:
```
QEMU父进程                管道缓冲区              Python进程
  │                          │                      │
  │ write(8, {3}, 4)         │                      │
  ├─────────────────────────→│                      │
  │                          │ [0x03 0x00 0x00 0x00]│
  │                          │                      │
  │                          │←─────────────────────┤
  │                          │  read(7, buf, 4)     │
  │                          │                      │
  │                          │                      ├→ status=3
```

### 步骤7.3: Python接收状态

**文件**: `fuzz_conductor_example.py:183-191`

```python
# Python在send_fuzz_command()中等待
status_bytes = os.read(self.status_pipe_read, 4)
# ← 解除阻塞，读取4字节

if not status_bytes:
    return None  // 管道关闭
    
status = struct.unpack('i', status_bytes)[0]
# status = 3

self.total_executions += 1

return self._parse_status(status)
```

**_parse_status()详解**:

```python
def _parse_status(self, status):
    status_map = {
        1: "Ready",
        2: "At Fork Point",
        3: "Normal Exit",    # ← 匹配
        4: "Crash Found",
        5: "Other Signal",
        -1: "Error"
    }
    
    status_name = status_map.get(status, f"Unknown({status})")
    # status_name = "Normal Exit"
    
    print(f"[Conductor] Execution #{self.total_executions}: {status_name}")
    # 输出: [Conductor] Execution #3: Normal Exit
    
    if (status == 4):
        self.crashes.append(self.total_executions)
        print(f"[Conductor] 💥 CRASH DETECTED in execution #{self.total_executions}")
    
    return status
```

### 步骤7.4: 父进程继续循环

```c
// rr_fork_server.c:290后
// 发送完状态后，继续while循环
while (g_rr_framework->fork_server_active) {
    // 再次等待下一个命令
    int cmd = rr_ipc_receive_command();
    // ← 阻塞，等待Python发送下一个'F'或'Q'
    ...
}
```

**状态变化**:
```
父进程:
  - 子进程已回收
  - child_pid 重置
  - 继续在fork server循环
  - 等待下一个命令
  
Python:
  - 收到Normal Exit
  - total_executions++
  - 可以发送下一个'F'命令
  - 或者发送'Q'退出
```

---

## 阶段8: 清理与退出

### 步骤8.1: Python发送'Q'命令

**文件**: `fuzz_conductor_example.py:261-280`

```python
def cleanup(self):
    if self.qemu_process:
        # 8.1.1 发送退出命令
        try:
            os.write(self.cmd_pipe_write, b'Q')
            self.qemu_process.wait(timeout=5)
        except:
            self.qemu_process.kill()
    
    # 8.1.2 关闭管道
    os.close(self.cmd_pipe_read)
    os.close(self.cmd_pipe_write)
    os.close(self.status_pipe_read)
    os.close(self.status_pipe_write)
    
    # 8.1.3 清理共享内存
    self.shm.close()
    
    print("[Conductor] Cleanup completed")
}
```

### 步骤8.2: QEMU接收'Q'命令

```c
// rr_fork_server.c:303-305
case 'Q':  // 退出命令
    RR_INFO("Received quit command");
    return -1;  // 返回-1表示退出
```

**返回到rr_do_syscall()**:

```c
// rr_main.c:380-383
int fork_result = rr_fork_server_loop();
// fork_result = -1

if (fork_result < 0) {
    exit(0);  // ← QEMU进程退出
}
```

### 步骤8.3: rr_framework_cleanup()

**文件**: `rr_main.c:221-292`

```c
void rr_framework_cleanup(void) {
    if (!g_rr_framework) {
        return;
    }
    
    RR_INFO("Starting RR-Fuzz framework cleanup");
    
    // 8.3.1 停止当前模式
    switch (g_rr_framework->mode) {
        case RR_MODE_FUZZING:
            rr_stop_fork_server();
            
            if (rr_strace_replay_enabled()) {
                rr_strace_replay_cleanup();
            }
            break;
    }
    
    // 8.3.2 清理子系统
    rr_ipc_cleanup();
    rr_fuzz_cleanup();
    rr_snapshot_cleanup();
    rr_debug_cleanup();
    rr_config_cleanup();
    
    // 8.3.3 清理哈希表
    if (g_rr_framework->fd_map) {
        g_hash_table_destroy(g_rr_framework->fd_map);
    }
    
    if (g_rr_framework->addr_map) {
        g_hash_table_destroy(g_rr_framework->addr_map);
    }
    
    // 8.3.4 清理轨迹
    syscall_record_t *record = g_rr_framework->trace_head;
    while (record) {
        syscall_record_t *next = record->next;
        
        for (int i = 0; i < 8; i++) {
            if (record->arg_data[i]) {
                g_free(record->arg_data[i]);
            }
        }
        
        g_free(record);
        record = next;
    }
    
    // 8.3.5 释放框架结构
    g_free(g_rr_framework);
    g_rr_framework = NULL;
    
    RR_INFO("RR-Fuzz framework cleanup completed");
}
```

**rr_ipc_cleanup()详解**:

```c
void rr_ipc_cleanup(void) {
    // 8.3.2.1 解除共享内存映射
    if (g_rr_framework->shared_memory) {
        munmap(g_rr_framework->shared_memory, 
              g_rr_config.shared_memory_size);
        g_rr_framework->shared_memory = NULL;
    }
    
    // 8.3.2.2 关闭管道FD
    if (g_rr_framework->cmd_pipe_fd >= 0) {
        close(g_rr_framework->cmd_pipe_fd);
        g_rr_framework->cmd_pipe_fd = -1;
    }
    
    if (g_rr_framework->status_pipe_fd >= 0) {
        close(g_rr_framework->status_pipe_fd);
        g_rr_framework->status_pipe_fd = -1;
    }
}
```

### 步骤8.4: Python清理共享内存

**文件**: `fuzz_conductor_example.py:103-113`

```python
def close(self):
    # 8.4.1 解除映射
    if self.mem:
        self.mem.close()
    
    # 8.4.2 关闭FD
    if self.shm_fd:
        os.close(self.shm_fd)
    
    # 8.4.3 删除共享内存文件
    shm_path = f"/dev/shm/{self.shm_name}"
    if os.path.exists(shm_path):
        os.unlink(shm_path)
}
```

**资源清理检查表**:
```
✓ QEMU进程退出
✓ 共享内存解除映射 (Python端)
✓ 共享内存解除映射 (QEMU端)
✓ 共享内存文件删除
✓ 命令管道关闭 (Python端)
✓ 命令管道关闭 (QEMU端)
✓ 状态管道关闭 (Python端)
✓ 状态管道关闭 (QEMU端)
✓ 哈希表销毁
✓ trace记录释放
✓ 配置字符串释放
```

---

## 完整时序图

```
时间轴  Python Conductor          管道/共享内存           QEMU进程
  │
  ├─ 创建管道和共享内存
  │      │
  │      ├─ pipe() × 2
  │      ├─ shm_open()
  │      └─ mmap()
  │
  ├─ 启动QEMU
  │      │
  │      └─ Popen(pass_fds=[5,8])
  │                                                          │
  │                                                          ├─ rr_config_init()
  │                                                          ├─ rr_framework_init()
  │                                                          ├─ rr_ipc_init()
  │                                                          ├─ rr_strace_parser_load()
  │                                                          ├─ rr_start_fork_server()
  │                                                          │
  │      ┌──────────────────────────────────────────────────┤
  │      │                  write(8, {1}, 4)                │
  │      │                  "Ready"                          │
  │      │←─────────────────────────────────────────────────┤
  │      │
  ├─ read(7) → status=1
  │
  │                                                          │
  │                                                          ├─ 执行系统调用1-5
  │                                                          │  (brk, arch_prctl, ...)
  │                                                          │
  │                                                          ├─ 执行系统调用6: openat
  │                                                          ├─ rr_check_fork_point()
  │                                                          │  → g_at_fork_point=true
  │      ┌──────────────────────────────────────────────────┤
  │      │                  write(8, {2}, 4)                │
  │      │                  "At Fork Point"                 │
  │      │←─────────────────────────────────────────────────┤
  │      │                                                   │
  ├─ read(7) → status=2                                     ├─ rr_fork_server_loop()
  │                                                          ├─ read(5) ← 阻塞等待
  │
  ├─ 写入Fuzz指令到共享内存
  │      │
  │      ├─ mem.write(header)
  │      └─ mem.write(instructions)
  │
  ├─ write(6, 'F')
  │      │
  │      ├────────────────────────────────────────────────→ │
  │      │                                                   ├─ read(5) → 'F'
  │      │                                                   ├─ rr_fuzz_load_from_shared_memory()
  │      │                                                   ├─ fork()
  │      │                                                   │
  │      │                                                   ├─ 父进程: waitpid()
  │      │                                                   │
  │      │                                                   └─ 子进程:
  │      │                                                      ├─ replay系统调用7-100
  │      │                                                      ├─ 应用fuzz变异
  │      │                                                      ├─ trace耗尽
  │      │                                                      └─ exit(0)
  │      │                                                   │
  │      │                                                   ├─ waitpid()返回
  │      ┌──────────────────────────────────────────────────┤
  │      │                  write(8, {3}, 4)                │
  │      │                  "Normal Exit"                   │
  │      │←─────────────────────────────────────────────────┤
  │      │                                                   │
  ├─ read(7) → status=3                                     ├─ read(5) ← 再次阻塞
  │
  ├─ (重复N次fuzzing)
  │
  ├─ write(6, 'Q')
  │      │
  │      ├────────────────────────────────────────────────→ │
  │      │                                                   ├─ read(5) → 'Q'
  │      │                                                   ├─ return -1
  │      │                                                   ├─ exit(0)
  │      │                                                   └─ rr_framework_cleanup()
  │
  ├─ cleanup()
  │      │
  │      ├─ close(pipes)
  │      ├─ munmap()
  │      └─ unlink("/dev/shm/...")
  │
  └─ 结束
```

---

## 总结

这份详细的执行流程分析涵盖了：

1. **每个阶段的详细步骤** - 从Python启动到最终清理
2. **每个函数的详细逻辑** - 包括参数、返回值、状态变化
3. **系统调用级别的分析** - fork(), pipe(), mmap()等
4. **内存布局和数据结构** - 共享内存、FD表、进程状态
5. **IPC通信的完整流程** - 管道读写、状态同步
6. **关键修复的详细说明** - 为什么需要、如何工作
7. **完整的时序图** - 可视化整个执行流程

每个步骤都包含：
- 代码位置
- 详细逻辑
- 状态变化
- 数据流
- 潜在问题

这应该是一份非常详尽的执行流程分析文档了！


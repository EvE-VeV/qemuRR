# Python Conductor 与 QEMU 交互机制说明

## 🔄 交互流程

### 完整的Fuzzing执行周期

```
1. Python启动QEMU
   ├─ 创建两个管道（命令管道、状态管道）
   ├─ 创建共享内存
   ├─ 通过环境变量传递配置
   └─ 使用subprocess.Popen启动QEMU，传递FD

2. QEMU初始化
   ├─ 读取环境变量(RR_MODE=fuzzing, RR_CMD_PIPE, RR_STATUS_PIPE, etc.)
   ├─ 初始化RR框架
   ├─ 映射共享内存
   ├─ 加载strace trace文件
   ├─ 启动Fork Server
   └─ 发送状态码1 (Ready) ✅

3. Python等待Ready
   └─ 从status_pipe读取状态码 = 1 ✅

4. Python发送第1个'F'命令
   └─ 向cmd_pipe写入字符'F'

5. QEMU执行系统调用直到Fork点
   ├─ replay trace中的系统调用
   ├─ 每个系统调用检查是否匹配fork条件(openat)
   ├─ 找到第一个openat
   ├─ 设置g_at_fork_point = true
   └─ 发送状态码2 (At Fork Point) ✅

6. Python收到"At Fork Point"
   └─ 状态码 = 2 ✅

7. Python写入Fuzz指令到共享内存
   └─ 将mutate指令写入/dev/shm/rr_fuzz_{pid}

8. Python发送第2个'F'命令
   └─ 向cmd_pipe写入字符'F'

9. QEMU Fork Server执行fork ⚠️
   ├─ 从共享内存读取Fuzz指令
   ├─ 调用fork()创建子进程
   ├─ 子进程：继续replay trace
   │   ├─ 执行后续系统调用
   │   ├─ 应用mutate指令
   │   └─ ❌ trace耗尽后没有退出，卡住
   └─ 父进程：waitpid()等待子进程
       └─ ⏳ 永远等待，因为子进程不退出

10. Python等待响应
    └─ ❌ TIMEOUT - 永远收不到状态码
```

---

## 📡 IPC机制详解

### 1. 命令管道 (Command Pipe)

**用途**: Python向QEMU发送命令

**实现**:
```python
# Python端
cmd_read, cmd_write = os.pipe()
env['RR_CMD_PIPE'] = str(cmd_read)  # 传递读取端FD给QEMU
os.write(cmd_write, b'F')           # 发送命令
```

```c
// C端 (rr_ipc.c)
int rr_ipc_receive_command(void) {
    char cmd;
    read(g_rr_framework->cmd_pipe_fd, &cmd, 1);
    return cmd;  // 返回'F', 'Q', 'S', 'L'
}
```

**命令协议**:
- `'F'` (Fork) - 触发一次fuzzing执行
- `'Q'` (Quit) - 退出QEMU
- `'S'` (Save) - 保存快照
- `'L'` (Load) - 加载快照

---

### 2. 状态管道 (Status Pipe)

**用途**: QEMU向Python报告状态

**实现**:
```python
# Python端
status_read, status_write = os.pipe()
env['RR_STATUS_PIPE'] = str(status_write)  # 传递写入端FD给QEMU
status_bytes = os.read(status_read, 4)     # 读取4字节整数
status = struct.unpack('i', status_bytes)[0]
```

```c
// C端 (rr_ipc.c)
int rr_ipc_send_status(int status) {
    write(g_rr_framework->status_pipe_fd, &status, sizeof(status));
    return 0;
}
```

**状态码协议**:
```c
1  - Ready          // 框架初始化完成
2  - At Fork Point  // 到达fork点
3  - Normal Exit    // 子进程正常退出
4  - Crash          // 发现崩溃(SIGSEGV等)
5  - Signal         // 其他信号
-1 - Error          // 错误
```

---

### 3. 共享内存 (Shared Memory)

**用途**: 传递Fuzz指令（批量变异信息）

**实现**:
```python
# Python端
shm_path = f"/dev/shm/rr_fuzz_{os.getpid()}"
shm_fd = os.open(shm_path, os.O_CREAT | os.O_RDWR, 0o666)
os.ftruncate(shm_fd, 65536)
mem = mmap.mmap(shm_fd, 65536)

# 写入指令
header = struct.pack('IIII', FUZZ_MAGIC, num_instructions, 0, 0)
mem.write(header)
for instr in instructions:
    mem.write(instr.pack())  # 每个指令265字节
```

```c
// C端 (rr_ipc.c)
shm_fd = shm_open(g_rr_config.shared_memory_name, O_RDWR, 0666);
g_rr_framework->shared_memory = mmap(NULL, size, 
    PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

// 读取指令 (rr_fuzz_engine.c)
int rr_fuzz_load_from_shared_memory(void *shm) {
    uint32_t magic = *(uint32_t*)shm;
    uint32_t count = *((uint32_t*)shm + 1);
    // ... 加载指令数组
}
```

**数据结构**:
```c
struct FuzzSharedMemory {
    uint32_t magic;        // 0x46555A5A ("FUZZ")
    uint32_t count;        // 指令数量 (0-32)
    uint32_t flags;
    uint32_t reserved;
    struct FuzzInstruction {
        uint32_t syscall_index;  // 第几个系统调用
        uint32_t cmd;            // mutate类型
        uint8_t  arg_index;      // 哪个参数
        uint16_t data_len;       // 数据长度
        uint8_t  data[256];      // 变异数据
    } instructions[32];
} __attribute__((packed));
```

---

## 🎯 当前问题

### ✅ 正常工作的部分

1. ✅ **管道通信** - 双向通信完全正常
2. ✅ **环境变量传递** - QEMU正确接收所有配置
3. ✅ **共享内存** - 映射和读写都正常
4. ✅ **Fork点检测** - 正确识别openat系统调用
5. ✅ **第一次F命令** - 成功到达fork点并响应
6. ✅ **Fuzz指令加载** - 从共享内存读取指令成功

### ❌ 存在问题的部分

**第二次F命令后卡住** - 原因：

```
Fork流程:
  fork()
   ├─ 子进程 (继续replay)
   │   ├─ 执行系统调用 #7, #8, #9...
   │   ├─ Trace文件只有100条记录
   │   ├─ 执行到记录末尾
   │   └─ ❌ 没有exit()，继续等待下一个系统调用
   │       → 陷入死循环或阻塞状态
   │
   └─ 父进程 (Fork Server主循环)
       └─ waitpid(child, &status, 0);  ⏳ 永远阻塞
           → 无法发送状态给Python
           → 无法继续接收下一个F命令
```

**根本原因**: 
- 子进程缺少明确的退出条件
- Trace replay完成后应该调用`exit(0)`
- 但当前代码只是返回-1继续循环

---

## 🔧 修复方案

### 方案1: Trace耗尽时退出 (推荐)

```c
// rr_replay_strace_optimized.c
abi_long rr_replay_syscall_strace_optimized(CPUArchState *env, int num, abi_long *args) {
    // ...
    
    // 检查trace是否已耗尽
    if (g_strace_state.trace_exhausted) {
        RR_INFO("Trace exhausted in child process, exiting");
        
        // 如果是子进程（fuzzing模式），退出
        if (g_rr_framework->mode == RR_MODE_FUZZING && 
            g_rr_framework->child_pid == 0) {
            exit(0);  // 正常退出
        }
        
        return -1;  // 父进程继续
    }
    
    // ...
}
```

### 方案2: 检测最后一条记录

```c
// rr_syscallparser.c
rr_strace_record_t* rr_strace_parser_get_next_record(rr_strace_parser_t *parser) {
    if (parser->current_index >= parser->record_count - 1) {
        // 这是最后一条记录
        parser->last_record = true;
    }
    // ...
}

// rr_replay_strace_optimized.c
if (record && record == last_record) {
    RR_INFO("Last record executed, child exiting");
    if (is_child_process()) {
        exit(0);
    }
}
```

### 方案3: 添加超时保护

```c
// rr_fork_server.c
int rr_fork_server_loop(void) {
    // ...
    pid_t pid = fork();
    
    if (pid > 0) {
        /* 父进程：带超时的等待 */
        int timeout_seconds = 5;
        alarm(timeout_seconds);
        
        int status;
        pid_t result = waitpid(pid, &status, 0);
        
        alarm(0);  // 取消alarm
        
        if (result == -1 && errno == EINTR) {
            RR_WARN("Child process timeout, killing");
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            rr_ipc_send_status(-1);  // Error
        } else {
            // 正常处理...
        }
    }
}
```

---

## 📊 通信时序图

```
Python Conductor          Command Pipe    Status Pipe         QEMU Process
      │                       │                │                    │
      │ subprocess.Popen      │                │                    │
      ├───────────────────────┼────────────────┼───────────────────>│
      │                       │                │                    │ rr_framework_init()
      │                       │                │<───────────────────┤ send_status(1)
      │<──────────────────────┼────────────────┤                    │
      │ read status = 1       │                │                    │
      │                       │                │                    │
      │ write('F')            │                │                    │
      ├───────────────────────>│                │                    │
      │                       ├───────────────────────────────────>│ receive_command()
      │                       │                │                    │ execute until fork point
      │                       │                │<───────────────────┤ send_status(2)
      │<──────────────────────┼────────────────┤                    │
      │ read status = 2       │                │                    │
      │                       │                │                    │
      │ write fuzz instr      │                │                    │
      │ to shared memory      │                │                    │
      │ write('F')            │                │                    │
      ├───────────────────────>│                │                    │
      │                       ├───────────────────────────────────>│ receive_command()
      │                       │                │                    │ fork()
      │                       │                │                    ├─> child: replay
      │                       │                │                    │   (should exit)
      │                       │                │                    │   ❌ hangs
      │                       │                │                    │
      │                       │                │                    │ parent: waitpid()
      │ read status           │                │                    │ ⏳ blocked forever
      │ ⏳ TIMEOUT            │                │                    │
```

---

## 🧪 验证测试

使用提供的测试脚本验证IPC：

```bash
# 测试1: 基本IPC功能
python3 debug_ipc_test.py
# ✅ 管道通信正常
# ✅ QEMU启动正常
# ✅ 收到Ready状态
# ✅ 第一次F命令响应正常

# 测试2: 多次Fork测试
python3 debug_multiple_forks.py
# ✅ 第一次F命令成功
# ❌ 第二次F命令超时（预期行为，问题已确认）
```

---

## 💡 关键要点

1. **IPC机制设计合理**: 管道+共享内存的组合高效且可靠
2. **通信协议简单明确**: 单字符命令 + 整数状态码
3. **FD传递方式正确**: 通过环境变量传递，subprocess.Popen的pass_fds参数
4. **问题不在通信**: IPC本身工作完美，问题在子进程生命周期管理
5. **修复相对简单**: 只需在replay完成时添加exit(0)

---

**总结**: Python Conductor和QEMU之间的IPC通信机制**完全正常**，真正的问题是Fork Server的子进程没有正确的退出逻辑。修复建议是在trace replay耗尽时让子进程调用`exit(0)`。


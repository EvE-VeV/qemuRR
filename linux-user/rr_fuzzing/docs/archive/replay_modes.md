# RR-Fuzz Replay模式对比分析

**生成时间**: 2025-10-29  
**文档类型**: 技术对比分析  
**分析范围**: Binary Replay vs Strace Replay

---

## 目录

1. [两种Replay模式概述](#两种replay模式概述)
2. [Binary Replay模式详解](#binary-replay模式详解)
3. [Strace Replay模式详解](#strace-replay模式详解)
4. [对比分析](#对比分析)
5. [使用建议](#使用建议)
6. [实现状态](#实现状态)

---

## 两种Replay模式概述

RR-Fuzz支持**两种Replay模式**，它们在数据来源、处理方式和适用场景上有根本区别：

```
┌──────────────────────────────────────────────────────────────┐
│                    RR-Fuzz Replay模式                          │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  1️⃣ Binary Replay 模式（主要模式）                            │
│     ├─ 数据源: .dat二进制trace文件                            │
│     ├─ 特点: EnvFuzz风格，完整数据捕获                        │
│     ├─ 路径: Pure Replay + Hybrid Replay                     │
│     └─ 适合: Fuzzing、确定性重放                              │
│                                                               │
│  2️⃣ Strace Replay 模式（辅助模式）                            │
│     ├─ 数据源: .txt strace文本文件                            │
│     ├─ 特点: 真实执行 + 句柄映射                              │
│     ├─ 路径: 真实系统调用执行                                 │
│     └─ 适合: 调试、快速原型、人工分析                         │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## Binary Replay模式详解

### 1.1 核心设计

**设计理念**: EnvFuzz风格的完全确定性重放

```c
// 数据结构: syscall_record_t (完整150字节固定字段)
typedef struct syscall_record {
    uint32_t index;                     // 系统调用序号
    int syscall_nr;                     // 系统调用号
    abi_long args[8];                   // 参数
    abi_long retval;                    // 返回值
    
    // 完整数据捕获
    uint8_t *arg_data[8];               // 参数指向的数据
    size_t arg_size[8];                 // 数据大小
    struct rr_aux_data *aux_data;       // 辅助数据链表
    bool has_aux_data;                  // 是否有aux_data
    
    // 元数据
    bool creates_fd;
    bool uses_fd;
    int32_t created_fd;
    
    struct syscall_record *next;
} syscall_record_t;
```

### 1.2 Trace文件格式

**文件结构** (.dat文件):
```
┌─────────────────────────────────────────┐
│ Header (12 bytes)                       │
│ ├─ magic:   0x52524644 ("RRFD")        │
│ ├─ version: 1                           │
│ └─ count:   记录数量                     │
├─────────────────────────────────────────┤
│ Record 1 (固定150字节)                  │
│ ├─ index, syscall_nr, args[8], retval  │
│ ├─ arg_size[8], has_aux_data, ...      │
│ │                                       │
│ ├─ Variable arg_data section           │
│ │  └─ 字符串、缓冲区数据                 │
│ │                                       │
│ └─ aux_data section (可选)              │
│    ├─ aux_count (4 bytes)               │
│    ├─ aux_data 1                        │
│    │  ├─ arg_mask, kind, size           │
│    │  └─ data                            │
│    ├─ aux_data 2                        │
│    └─ ...                                │
├─────────────────────────────────────────┤
│ Record 2                                │
│ ...                                     │
└─────────────────────────────────────────┘
```

### 1.3 双路径重放策略

#### Pure Replay路径

**特点**: 完全不执行真实syscall，从aux_data恢复

```c
// rr_replay.c: Pure Replay判断
if (g_current_record->has_aux_data && !is_memory_management) {
    ret = rr_replay_syscall_pure(env, num, args, g_current_record);
    if (ret != -1) {
        return ret;  // Pure Replay成功
    }
}
```

**实现** (rr_replay_pure.c):
```c
abi_long rr_replay_syscall_pure(CPUArchState *env, int num, abi_long *args,
                                syscall_record_t *record) {
    switch (num) {
        case TARGET_NR_read: {
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                // 直接写入guest内存
                cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1);
                return record->retval;  // 返回recorded retval
            }
            break;
        }
        case TARGET_NR_getrandom: {
            // 恢复随机数
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 0);
            if (aux && aux->data) {
                cpu_memory_rw_debug(env_cpu(env), args[0], aux->data, aux->size, 1);
                return record->retval;
            }
            break;
        }
        // ... 6个syscall实现
    }
    return -1;  // 回退到Hybrid
}
```

**支持的syscall** (6个):
- ✅ read / pread64
- ✅ recv / recvfrom
- ✅ getrandom
- ✅ ioctl (输出缓冲区)

#### Hybrid Replay路径

**特点**: 执行真实syscall，应用FD映射

```c
// rr_replay.c: Hybrid Replay
apply_fd_mapping(args, num);  // 映射FD

// mmap特殊处理: 强制使用recorded地址
if (is_mmap && record->has_aux_data) {
    rr_aux_mmap_info_t *mmap_info = ...;
    args[0] = mmap_info->addr;  // 修改地址参数
    args[3] |= MAP_FIXED;       // 添加MAP_FIXED标志
}

return -1;  // 执行真实syscall
```

**FD映射机制**:
```c
// 记录时: open("/etc/passwd") = 3
// 重放时: open("/etc/passwd") = 5  (实际FD)
// 映射: record_fd(3) → real_fd(5)
// 后续: read(3, ...) → read(5, ...)
```

### 1.4 优缺点

#### 优点 ✅

1. **完全确定性**: aux_data保证可重复性
2. **数据完整**: 捕获所有输入/输出数据
3. **支持Fuzzing**: 可精确变异syscall参数和缓冲区
4. **性能优化**: 二进制格式，解析快速
5. **跨环境**: 可在不同环境重放（数据来自trace）

#### 缺点 ❌

1. **文件较大**: 包含完整数据，trace文件可能>100MB
2. **不可读**: 二进制格式，人工分析困难
3. **实现复杂**: 需要复杂的aux_data捕获逻辑
4. **部分syscall未实现**: readv/writev/sendmsg/recvmsg等缺失

---

## Strace Replay模式详解

### 2.1 核心设计

**设计理念**: 真实执行 + 句柄映射

```
传统Binary模式: 记录数据 → 重放时返回记录数据 (不执行真实syscall)
Strace模式:     记录轨迹 → 重放时真实执行 + 映射句柄
```

**关键区别**:
- Binary模式的Pure Replay **不执行**真实syscall
- Strace模式**总是执行**真实syscall

### 2.2 数据来源

**Strace文本文件格式**:
```
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0", 832) = 832
close(3) = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0", 832) = 832
```

**启用方式**:
```bash
# 1. 生成strace文件 (使用QEMU自带-strace)
qemu-x86_64 -strace /usr/bin/ls > trace.txt 2>&1

# 2. Strace Replay
export RR_FUZZING_ENABLED=True
export RR_MODE=replay
export RR_TRACE_FILE=trace.txt
export RR_STRACE_MODE=True  # 关键：启用strace模式
./qemu-x86_64 /usr/bin/ls
```

### 2.3 工作流程

**完整流程**:
```
┌─────────────────────────────────────────────────────────────┐
│ PRE-HOOK: rr_replay_syscall_strace()                       │
│ ├─ 1. 从strace文件读取下一条记录                           │
│ ├─ 2. 匹配系统调用名称 (允许前瞻20条)                      │
│ ├─ 3. 映射输入句柄 (FD)                                    │
│ │    例: read(3, ...) → read(5, ...)                       │
│ ├─ 4. 保存当前记录到g_current_record                       │
│ └─ 5. 返回-1 (让QEMU真实执行syscall)                       │
│                                                             │
│ QEMU执行真实系统调用                                        │
│ ├─ 真实的open(), read(), write()等                         │
│ └─ 返回真实的FD、数据、状态                                 │
│                                                             │
│ POST-HOOK: rr_strace_syscall_post_hook()                   │
│ ├─ 1. 获取真实syscall返回值                                │
│ ├─ 2. 建立输出句柄映射                                      │
│ │    例: open() = 5 (实际)，recorded = 3                   │
│ │        → 建立映射 {3 → 5}                                │
│ ├─ 3. 对于close()，删除映射                                │
│ └─ 4. 清理g_current_record                                 │
└─────────────────────────────────────────────────────────────┘
```

### 2.4 实现细节

#### FD映射表

```c
// 简单哈希表实现
#define FD_MAPPING_TABLE_SIZE 256

typedef struct fd_mapping_entry {
    int recorded_fd;              // strace文件中的FD
    int actual_fd;                // 实际执行得到的FD
    struct fd_mapping_entry *next;
} fd_mapping_entry_t;

static fd_mapping_entry_t *g_fd_mapping_table[FD_MAPPING_TABLE_SIZE] = {0};
```

#### 匹配算法

```c
static rr_strace_record_t *find_matching_record(const char *syscall_name, abi_long *args) {
    // 从当前位置开始，前瞻最多20条
    for (int lookahead = 0; lookahead <= 20; lookahead++) {
        rr_strace_record_t *record = rr_strace_parser_peek_record(parser, lookahead);
        if (!record) break;
        
        // 精确匹配
        if (strcmp(record->syscall_name, syscall_name) == 0) {
            rr_strace_parser_consume_records(parser, lookahead + 1);
            return record;
        }
        
        // 等价syscall匹配
        if (are_equivalent_syscalls(record->syscall_name, syscall_name)) {
            return record;
        }
    }
    return NULL;  // 未匹配，跳过
}
```

#### POST-HOOK实现

```c
void rr_strace_syscall_post_hook(CPUArchState *env, int num, abi_long ret, abi_long *args) {
    if (!g_current_record) return;
    
    const char *syscall_name = g_current_record->syscall_name;
    
    // openat成功: 建立FD映射
    if (strcmp(syscall_name, "openat") == 0) {
        if (ret >= 0 && g_current_record->ret_value >= 0) {
            add_fd_mapping_simple(g_current_record->ret_value, ret);
            // recorded_fd=3 → actual_fd=5
        }
    }
    
    // close成功: 删除FD映射
    else if (strcmp(syscall_name, "close") == 0) {
        if (ret == 0) {
            remove_fd_mapping_simple((int)g_current_record->args[0].value);
        }
    }
    
    g_current_record = NULL;
}
```

### 2.5 优缺点

#### 优点 ✅

1. **人类可读**: 文本格式，易于调试和分析
2. **实现简单**: 不需要复杂的aux_data捕获
3. **兼容QEMU**: 使用QEMU原生-strace输出
4. **真实执行**: 保证功能完全正确
5. **环境适应**: 适应文件系统变化

#### 缺点 ❌

1. **非确定性**: 依赖真实系统状态，可能每次不同
2. **不支持Fuzzing**: 无法精确控制输入数据
3. **匹配率低**: 测试显示只有61.8%的syscall匹配
4. **数据丢失**: strace不捕获输出缓冲区内容
5. **性能开销**: 文本解析较慢

---

## 对比分析

### 3.1 功能对比

| 特性 | Binary Replay | Strace Replay |
|------|---------------|---------------|
| **数据来源** | .dat二进制文件 | .txt strace文本 |
| **数据捕获** | ✅ 完整 (aux_data) | ❌ 仅参数和返回值 |
| **确定性** | ✅ 100%确定 | ⚠️ 依赖环境 |
| **执行方式** | Pure/Hybrid双路径 | 总是真实执行 |
| **FD处理** | 映射表 + Pure恢复 | 仅映射表 |
| **Fuzzing支持** | ✅ 完整支持 | ❌ 不支持 |
| **文件大小** | 大 (>100MB) | 小 (<10MB) |
| **可读性** | ❌ 二进制 | ✅ 文本 |
| **解析速度** | 快 | 慢 |
| **实现复杂度** | 高 | 中 |

### 3.2 适用场景对比

#### Binary Replay最适合:

1. **Fuzzing场景** ⭐⭐⭐
   - 需要精确控制syscall参数
   - 需要变异输入数据
   - 需要coverage-guided fuzzing

2. **确定性重放** ⭐⭐⭐
   - 漏洞复现
   - 回归测试
   - 行为分析

3. **跨环境重放** ⭐⭐⭐
   - 不同机器间重放
   - 不同时间重放
   - 文件内容变化情况

#### Strace Replay最适合:

1. **快速调试** ⭐⭐⭐
   - 快速查看syscall序列
   - 人工分析程序行为
   - 理解控制流

2. **原型开发** ⭐⭐⭐
   - 快速验证想法
   - 不需要完整实现
   - 简化开发流程

3. **兼容性测试** ⭐⭐
   - 验证环境差异影响
   - 测试适应性

### 3.3 性能对比

**Binary Replay性能**:
```
┌──────────────────────────────────┐
│ Trace生成: 较慢 (需要捕获数据)   │
│ Trace大小: 大 (10-100MB)         │
│ Replay速度: 快 (二进制解析)      │
│ Pure Replay: 极快 (无真实syscall)│
│ Hybrid Replay: 中等 (有真实syscall)│
└──────────────────────────────────┘
```

**Strace Replay性能**:
```
┌──────────────────────────────────┐
│ Trace生成: 快 (QEMU原生)         │
│ Trace大小: 小 (1-10MB)           │
│ Replay速度: 中等 (文本解析)      │
│ 真实执行: 中等 (总是执行syscall) │
└──────────────────────────────────┘
```

### 3.4 实现完整度对比

**Binary Replay** (主要模式):
- ✅ Record模块: 70%
- ✅ Hybrid Replay: 90%
- ✅ Pure Replay: 85%
- ✅ aux_data系统: 100%
- ✅ FD映射: 80%
- ❌ readv/writev: 未实现
- ❌ sendmsg/recvmsg: 未实现

**Strace Replay** (辅助模式):
- ✅ Strace解析: 100%
- ✅ 基础匹配: 100%
- ✅ FD映射: 90%
- ⚠️ POST-HOOK: 框架就绪，待完善
- ❌ PID映射: 未实现
- ❌ 地址映射: 未实现

---

## 使用建议

### 4.1 选择决策树

```
┌────────────────────────────────────────┐
│ 我需要做什么？                          │
└────┬───────────────────────────────────┘
     │
     ├─→ 我要Fuzzing
     │   └─→ 【Binary Replay】必选
     │
     ├─→ 我要调试/分析程序行为
     │   └─→ 【Strace Replay】更方便
     │
     ├─→ 我要精确复现漏洞
     │   └─→ 【Binary Replay】Pure路径
     │
     ├─→ 我要快速原型验证
     │   └─→ 【Strace Replay】快速迭代
     │
     └─→ 我要跨环境重放
         └─→ 【Binary Replay】确定性
```

### 4.2 混合使用策略

**推荐工作流**:
```
Phase 1: 开发阶段
   └─→ 使用Strace Replay进行快速调试
       (人类可读，易于理解)

Phase 2: 测试阶段
   └─→ 使用Binary Replay进行功能测试
       (确定性，可重复)

Phase 3: Fuzzing阶段
   └─→ 使用Binary Replay进行Fuzzing
       (精确控制，coverage-guided)

Phase 4: 生产阶段
   └─→ 使用Binary Replay进行漏洞复现
       (完整数据，跨环境)
```

### 4.3 实际案例

#### 案例1: 调试网络程序

**场景**: 理解程序的网络交互逻辑

**选择**: Strace Replay
```bash
# 1. 生成strace
qemu-x86_64 -strace /path/to/server > trace.txt 2>&1

# 2. 人工分析
cat trace.txt | grep -E 'socket|bind|listen|accept'

# 3. Strace Replay验证
export RR_STRACE_MODE=True
export RR_MODE=replay
export RR_TRACE_FILE=trace.txt
./qemu-x86_64 /path/to/server
```

**优势**: 可以直接看到syscall序列，理解逻辑

#### 案例2: Fuzzing文件解析器

**场景**: 发现文件解析器的漏洞

**选择**: Binary Replay
```bash
# 1. Record阶段
export RR_MODE=record
export RR_TRACE_FILE=trace.dat
./qemu-x86_64 /path/to/parser input.file

# 2. Fuzzing阶段
python3 fuzz_conductor.py --trace trace.dat --iterations 10000
```

**优势**: 可以精确变异read()读取的文件内容

#### 案例3: 混合使用

**场景**: 先调试后Fuzzing

```bash
# Step 1: 快速调试 (Strace)
qemu-x86_64 -strace /path/to/target > trace.txt 2>&1
# 分析strace输出，理解程序逻辑

# Step 2: Binary Record
export RR_MODE=record
export RR_TRACE_FILE=trace.dat
./qemu-x86_64 /path/to/target

# Step 3: Fuzzing
python3 fuzz_conductor.py --trace trace.dat
```

---

## 实现状态

### 5.1 当前状态总结

**Binary Replay** (主要实现):
- ✅ 核心框架完整
- ✅ Pure/Hybrid双路径工作
- ✅ aux_data系统完善
- ✅ 基础Fuzzing可用
- ⚠️ 部分syscall未实现
- ⚠️ Coverage未集成

**Strace Replay** (辅助实现):
- ✅ 基础框架完整
- ✅ 文本解析正确
- ✅ PRE-HOOK完整
- ⚠️ POST-HOOK未完全集成
- ❌ PID/地址映射未实现

### 5.2 优先级建议

**Binary Replay** (P0-P1):
1. P0: Coverage TCG集成
2. P0: 反馈循环实现
3. P1: readv/writev/sendmsg/recvmsg
4. P1: 完善FD检测

**Strace Replay** (P2):
1. P2: POST-HOOK完整集成
2. P2: PID映射实现
3. P2: 改进匹配算法

### 5.3 未来规划

**短期** (1-2个月):
- Binary Replay达到production-ready
- Strace Replay基础完善

**中期** (3-6个月):
- 混合模式实现 (Strace + 选择性数据恢复)
- 智能路径选择

**长期** (6-12个月):
- 统一框架
- 自适应模式选择

---

## 总结

### 两种模式的定位

```
Binary Replay:  Production-Ready的核心功能
                ├─ Fuzzing的基础
                ├─ 确定性重放的保证
                └─ 当前开发重点

Strace Replay:  辅助调试工具
                ├─ 快速原型验证
                ├─ 人工分析辅助
                └─ 兼容性测试
```

### 关键建议

1. **Fuzzing任务**: 必须使用Binary Replay
2. **调试分析**: 优先使用Strace Replay
3. **生产环境**: Binary Replay (Pure路径)
4. **混合使用**: 发挥各自优势

### 文档版本

**版本**: 1.0  
**最后更新**: 2025-10-29  
**下次更新**: 待Strace POST-HOOK完整集成后

---

**相关文档**:
- `phase4_replay_module_analysis.md` - Binary Replay详细分析
- `old-archive/09_strace_replay_implementation.md` - Strace实现文档
- `old-archive/08_replay_methods_comparison.md` - 旧版对比
- `COMPREHENSIVE_ISSUES_AND_DEFICIENCIES.md` - 问题总结


# RR-Fuzz 改进指南

**最后更新**: 2025-10-13  
**基于**: EnvFuzz 技术分析  
**目标**: 提升 Fuzzing 效率 5-10 倍

---

## 📑 目录

1. [核心改进思路](#1-核心改进思路)
2. [优先级排序](#2-优先级排序)
3. [Phase 1: 系统调用分类](#3-phase-1-系统调用分类p0)
4. [Phase 2: 覆盖率机制](#4-phase-2-覆盖率机制p0)
5. [Phase 3: 虚拟 FD](#5-phase-3-虚拟-fdp1)
6. [快速开始](#6-快速开始)

---

## 1. 核心改进思路

### 1.1 当前问题

```
❌ 问题 1: 手动配置 fork point
  • 需要分析程序找合适的系统调用
  • 容易遗漏关键路径

❌ 问题 2: 无覆盖率机制
  • 盲目变异，重复测试相同路径
  • 效率仅为有覆盖率的 10-20%

❌ 问题 3: Replay 隔离性不够
  • 仍打开真实文件
  • 确定性不如 EnvFuzz
```

### 1.2 EnvFuzz 的解决方案

```
✅ 解决方案 1: P_IO 分类 + 自动 fork
  • 将系统调用分为 8 类
  • 只对 18 个 I/O 类系统调用 fork
  • 零配置

✅ 解决方案 2: 系统调用树覆盖率
  • 基于 Hamming 距离判断新颖性
  • 不依赖代码覆盖率
  • 智能探索新路径

✅ 解决方案 3: 虚拟 FD + 消息队列
  • 不打开真实文件
  • 完全隔离
```

---

## 2. 优先级排序

| 优先级 | 改进项 | 预期效果 | 工作量 | 难度 |
|-------|--------|---------|--------|------|
| **P0** | 系统调用分类 + 自动 Fork | 零配置 | 1 周 | ⭐⭐ |
| **P0** | 系统调用树覆盖率 | 效率提升 5-10x | 2-3 周 | ⭐⭐⭐⭐ |
| **P1** | 虚拟 FD + 消息队列 | 更强隔离 | 2-3 周 | ⭐⭐⭐⭐ |
| **P2** | 二进制记录格式 | 解析快 5-10x | 1-2 周 | ⭐⭐⭐ |

---

## 3. Phase 1: 系统调用分类（P0）

### 3.1 核心理念

**EnvFuzz 的智慧**: 只对 18 个 P_IO 类系统调用进行 fork

```c
// 系统调用分类
#define SYSCALL_CLASS_MISC  0   // 杂项 - 不 fork
#define SYSCALL_CLASS_FD    1   // 文件管理 - 不 fork
#define SYSCALL_CLASS_IO    2   // I/O - fork！✅
#define SYSCALL_CLASS_INFO  3   // 信息查询 - 不 fork
#define SYSCALL_CLASS_MEM   4   // 内存管理 - 不 fork
#define SYSCALL_CLASS_SIG   5   // 信号 - 不 fork
#define SYSCALL_CLASS_THR   6   // 线程 - 不 fork
#define SYSCALL_CLASS_PROC  7   // 进程 - 不 fork

// P_IO 类（18个，只占 5.6%）:
// read, write, pread64, pwrite64, readv, writev
// sendto, recvfrom, sendmsg, recvmsg
// ioctl, getdents, getdents64
// sendmmsg, recvmmsg, copy_file_range
// preadv, pwritev
```

**Fork 充要条件**:
```c
bool should_fork(syscall_nr, args, ret) {
    return (class == SYSCALL_CLASS_IO)  // ✅ I/O 类
        && is_input                     // ✅ inbound (read, 不是 write)
        && ret > 0;                     // ✅ 有数据
}
```

### 3.2 实现步骤

#### 步骤 1: 创建分类表

**新文件**: `linux-user/rr_fuzzing/rr_syscall_info.h`

```c
#ifndef RR_SYSCALL_INFO_H
#define RR_SYSCALL_INFO_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    SYSCALL_CLASS_MISC = 0,
    SYSCALL_CLASS_FD   = 1,
    SYSCALL_CLASS_IO   = 2,  // ← 只有这个 fork!
    SYSCALL_CLASS_INFO = 3,
    SYSCALL_CLASS_MEM  = 4,
    SYSCALL_CLASS_SIG  = 5,
    SYSCALL_CLASS_THR  = 6,
    SYSCALL_CLASS_PROC = 7,
} syscall_class_t;

typedef struct {
    int nr;
    const char *name;
    syscall_class_t class;
    bool is_input;  // read: true, write: false
} syscall_info_t;

const syscall_info_t *rr_get_syscall_info(int syscall_nr);
bool rr_should_auto_fork(int syscall_nr, const abi_long *args, abi_long ret);

#endif
```

**新文件**: `linux-user/rr_fuzzing/rr_syscall_info.c`

```c
#include "rr_syscall_info.h"
#include <syscall.h>

static const syscall_info_t g_syscall_table[] = {
    // ===== P_IO 类（18个）- fuzzing 目标 =====
    {__NR_read,      "read",      SYSCALL_CLASS_IO, true},
    {__NR_write,     "write",     SYSCALL_CLASS_IO, false},
    {__NR_pread64,   "pread64",   SYSCALL_CLASS_IO, true},
    {__NR_pwrite64,  "pwrite64",  SYSCALL_CLASS_IO, false},
    {__NR_readv,     "readv",     SYSCALL_CLASS_IO, true},
    {__NR_writev,    "writev",    SYSCALL_CLASS_IO, false},
    {__NR_sendto,    "sendto",    SYSCALL_CLASS_IO, false},
    {__NR_recvfrom,  "recvfrom",  SYSCALL_CLASS_IO, true},
    {__NR_sendmsg,   "sendmsg",   SYSCALL_CLASS_IO, false},
    {__NR_recvmsg,   "recvmsg",   SYSCALL_CLASS_IO, true},
    {__NR_ioctl,     "ioctl",     SYSCALL_CLASS_IO, true},
    {__NR_getdents,  "getdents",  SYSCALL_CLASS_IO, true},
    {__NR_getdents64,"getdents64",SYSCALL_CLASS_IO, true},
    
    // ===== P_FD 类 - 不 fork =====
    {__NR_open,      "open",      SYSCALL_CLASS_FD, false},
    {__NR_openat,    "openat",    SYSCALL_CLASS_FD, false},
    {__NR_close,     "close",     SYSCALL_CLASS_FD, false},
    {__NR_socket,    "socket",    SYSCALL_CLASS_FD, false},
    
    // ===== PMEM 类 - 不 fork =====
    {__NR_mmap,      "mmap",      SYSCALL_CLASS_MEM, false},
    {__NR_munmap,    "munmap",    SYSCALL_CLASS_MEM, false},
    {__NR_brk,       "brk",       SYSCALL_CLASS_MEM, false},
    
    // ===== PINF 类 - 不 fork =====
    {__NR_stat,      "stat",      SYSCALL_CLASS_INFO, false},
    {__NR_fstat,     "fstat",     SYSCALL_CLASS_INFO, false},
    {__NR_getpid,    "getpid",    SYSCALL_CLASS_INFO, false},
    
    {-1, NULL, SYSCALL_CLASS_MISC, false}
};

const syscall_info_t *rr_get_syscall_info(int syscall_nr) {
    for (int i = 0; g_syscall_table[i].nr != -1; i++) {
        if (g_syscall_table[i].nr == syscall_nr) {
            return &g_syscall_table[i];
        }
    }
    static const syscall_info_t default_info = {
        -1, "unknown", SYSCALL_CLASS_MISC, false
    };
    return &default_info;
}

bool rr_should_auto_fork(int syscall_nr, const abi_long *args, abi_long ret) {
    const syscall_info_t *info = rr_get_syscall_info(syscall_nr);
    
    // 充要条件（EnvFuzz 策略）
    return (info->class == SYSCALL_CLASS_IO)  // I/O 类
        && info->is_input                     // inbound
        && ret > 0;                           // 有数据
}
```

#### 步骤 2: 集成到 Fork Server

**修改**: `linux-user/rr_fuzzing/rr_fork_server.c`

```c
#include "rr_syscall_info.h"

// 在系统调用后调用（需要返回值）
void rr_check_auto_fork_post(int syscall_nr, const abi_long *args, abi_long ret) {
    if (g_at_fork_point) {
        return;  // 已在 fork server loop
    }
    
    if (rr_should_auto_fork(syscall_nr, args, ret)) {
        g_at_fork_point = true;
        
        const syscall_info_t *info = rr_get_syscall_info(syscall_nr);
        RR_INFO("✅ Auto fork: %s (ret=%ld)", info->name, ret);
        
        rr_ipc_send_status(2);
        rr_fork_server_loop();
    }
}
```

#### 步骤 3: 测试

```bash
# 零配置模式（自动检测）
qemu-arm -rr-mode fuzzing \
         -auto-fork \
         -strace-file app.strace \
         ./target_app

# 预期: 自动在 read/recvfrom 等处 fork
```

---

## 4. Phase 2: 覆盖率机制（P0）

### 4.1 核心理念

**EnvFuzz 的系统调用树**:

```
branches[msg_id] = BRANCH {
    input_hash: hash(syscall 参数)
    output_partition: [
        KEY0 (128-bit) → 输出 1
        KEY1 (128-bit) → 输出 2
        KEY2 (128-bit) → 输出 3
    ]
}

KEY = hash(输入 + 输出 + 退出状态)

新颖性判断:
  for each existing_key:
      if hamming_distance(new_key, existing_key) <= 5:
          reject  // 太相似
  accept  // 新颖！
```

### 4.2 实现步骤

#### 步骤 1: 数据结构

**新文件**: `linux-user/rr_fuzzing/rr_coverage.h`

```c
#ifndef RR_COVERAGE_H
#define RR_COVERAGE_H

#include <stdint.h>
#include <stdbool.h>

// 128-bit KEY
typedef __uint128_t rr_coverage_key_t;

// PARTITION
typedef struct {
    uint8_t threshold;      // Hamming 阈值
    uint8_t len;            // 当前数量
    uint8_t size;           // 最大容量
    rr_coverage_key_t *keys;  // KEY 数组
} rr_coverage_partition_t;

// BRANCH
typedef struct {
    uint64_t input_hash;
    rr_coverage_partition_t *partition;
} rr_coverage_branch_t;

void rr_coverage_init(void);
rr_coverage_branch_t *rr_coverage_get_branch(uint32_t msg_id);
rr_coverage_key_t rr_coverage_compute_key(
    const uint8_t *output, size_t len, int status
);
bool rr_coverage_is_novel(rr_coverage_branch_t *branch, rr_coverage_key_t key);
size_t rr_coverage_hamming_distance(rr_coverage_key_t k1, rr_coverage_key_t k2);

#endif
```

#### 步骤 2: Hamming 距离

**新文件**: `linux-user/rr_fuzzing/rr_coverage.c`

```c
#include "rr_coverage.h"
#include <glib.h>

static GHashTable *g_branch_table = NULL;

void rr_coverage_init(void) {
    g_branch_table = g_hash_table_new(g_direct_hash, g_direct_equal);
}

// Hamming 距离（使用 x86 popcnt 指令）
size_t rr_coverage_hamming_distance(rr_coverage_key_t k1, rr_coverage_key_t k2) {
    rr_coverage_key_t xor = k1 ^ k2;
    size_t dist = 0;
    dist += __builtin_popcountll((uint64_t)(xor >> 64));
    dist += __builtin_popcountll((uint64_t)xor);
    return dist;
}

// 判断新颖性
bool rr_coverage_is_novel(rr_coverage_branch_t *branch, rr_coverage_key_t key) {
    rr_coverage_partition_t *p = branch->partition;
    
    for (uint8_t i = 0; i < p->len; i++) {
        size_t dist = rr_coverage_hamming_distance(key, p->keys[i]);
        if (dist <= p->threshold) {
            return false;  // 太相似
        }
    }
    
    // 新颖！添加
    if (p->len < p->size) {
        p->keys[p->len++] = key;
        return true;
    }
    
    return false;
}
```

#### 步骤 3: Python 集成

**修改**: `fuzz_conductor.py`

```python
class FuzzConductorWithCoverage:
    def __init__(self):
        self.coverage_db = {}
        self.corpus = []
    
    def run_with_coverage(self, iterations=1000):
        for i in range(iterations):
            # 1. 生成变异
            mutations = self._generate_mutations()
            
            # 2. 执行
            status, output = self.execute(mutations)
            
            # 3. 计算 KEY
            key = self._compute_key(output, status)
            
            # 4. 判断新颖性
            if self._is_novel(key):
                self.corpus.append(mutations)
                print(f"✅ Iteration {i}: New path!")
            
            if status > 128:
                print(f"🐛 Crash: signal {status - 128}")
    
    def _is_novel(self, key):
        threshold = 5
        for existing_key in self.coverage_db.get('keys', []):
            if self._hamming_distance(key, existing_key) <= threshold:
                return False
        
        if 'keys' not in self.coverage_db:
            self.coverage_db['keys'] = []
        self.coverage_db['keys'].append(key)
        return True
    
    def _hamming_distance(self, k1, k2):
        return bin(k1 ^ k2).count('1')
```

---

## 5. Phase 3: 虚拟 FD（P1）

### 5.1 核心理念

**当前问题**: Replay 时仍打开真实文件

**EnvFuzz 方案**: 虚拟 FD + 消息队列

```c
// Replay 时
int vfd = rr_virtual_fd_create("/etc/passwd");  // 不打开真实文件
ssize_t n = rr_virtual_fd_read(vfd, buf, 100);  // 从消息队列读取
```

### 5.2 实现（简化）

**新文件**: `linux-user/rr_fuzzing/rr_virtual_fd.c`

```c
typedef struct {
    int vfd;
    char path[256];
    uint8_t *msg_data;
    size_t msg_len;
    size_t msg_pos;
} rr_virtual_fd_t;

static GHashTable *g_vfd_table = NULL;
static int g_vfd_counter = 100;

int rr_virtual_fd_create(const char *path) {
    rr_virtual_fd_t *vfd = g_malloc0(sizeof(*vfd));
    vfd->vfd = g_vfd_counter++;
    strncpy(vfd->path, path, sizeof(vfd->path) - 1);
    
    g_hash_table_insert(g_vfd_table, GINT_TO_POINTER(vfd->vfd), vfd);
    return vfd->vfd;
}

ssize_t rr_virtual_fd_read(int vfd, void *buf, size_t count) {
    rr_virtual_fd_t *entry = g_hash_table_lookup(g_vfd_table, GINT_TO_POINTER(vfd));
    if (!entry || !entry->msg_data) {
        return 0;  // EOF
    }
    
    size_t remaining = entry->msg_len - entry->msg_pos;
    size_t len = MIN(count, remaining);
    
    memcpy(buf, entry->msg_data + entry->msg_pos, len);
    entry->msg_pos += len;
    
    return len;
}
```

---

## 6. 快速开始

### 6.1 最小实现（1 周）

**只实现 Phase 1（系统调用分类）**:

```bash
# 1. 创建文件
touch linux-user/rr_fuzzing/rr_syscall_info.{h,c}

# 2. 复制上面的代码

# 3. 修改 meson.build
# 添加: 'rr_syscall_info.c'

# 4. 编译
cd build && ninja

# 5. 测试
qemu-arm -rr-mode fuzzing -auto-fork ./app
```

### 6.2 验证效果

```python
# 运行 1000 次迭代，对比:
# - 手动模式: 固定 fork point
# - 自动模式: P_IO 自动检测

# 预期:
# - 自动模式 fork 次数减少 50-70%
# - 发现相同数量的路径
```

---

## 7. 总结

### 7.1 核心价值

```
✅ 学习自 EnvFuzz:
  1. P_IO 分类 → 智能 fork（零配置）
  2. 系统调用树 → 覆盖率引导（效率提升 5-10x）
  3. 虚拟 FD → 完全隔离（更强确定性）

✅ 保持 RR-Fuzz 优势:
  1. 跨架构支持（ARM/MIPS/RISC-V）
  2. QEMU 动态拦截
  3. Python 灵活控制

✅ 改进后达到:
  • 零配置 fuzzing
  • 效率提升 5-10 倍
  • 在 IoT 领域与 EnvFuzz 同等水平
```

### 7.2 实施时间线

```
Week 1:       Phase 1 (P0) - 系统调用分类
Week 2-4:     Phase 2 (P0) - 覆盖率机制
Week 5-7:     Phase 3 (P1) - 虚拟 FD（可选）
Week 8-9:     Phase 4 (P2) - 二进制格式（可选）
```

---

**相关文档**:
- `architecture_analysis.md` - RR-Fuzz 架构详细分析
- `envfuzz_analysis_and_insights.md` - EnvFuzz 技术深度分析
- `execution_flow_analysis.md` - 执行流程详解

**创建日期**: 2025-10-13  
**维护者**: RR-Fuzz 开发团队


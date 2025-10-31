# RR-Fuzz 漏洞测试程序 v2.0

## 📋 概述

这是一个专门为 RR-Fuzz 设计的多漏洞测试程序，包含 5 种常见的漏洞类型，用于验证 RR-Fuzz 的漏洞发现能力。

---

## 🎯 设计特点

### 1. **系统调用输入** ✅
- 使用 `read(STDIN_FILENO, ...)` 获取输入
- RR-Fuzz 可以变异 `read()` 的返回数据和返回值
- 兼容 AFL/LibFuzzer 的输入方式

### 2. **多种漏洞类型** 🐛
- 涵盖 5 种常见漏洞
- 每种漏洞都易于触发
- 适合演示和测试 fuzzer 能力

### 3. **智能路径选择** 🔀
- 根据输入的第一个字节选择漏洞类型
- `input[0] % 5` 决定执行哪个漏洞函数
- 最大化代码覆盖率

---

## 🐛 包含的漏洞类型

### 漏洞 1: 经典缓冲区溢出

**触发条件**: 输入第一字节 `% 5 == 0`

```c
void vuln_buffer_overflow(const char *input, size_t len) {
    char buffer[16];  // 16字节缓冲区
    memcpy(buffer, input, len);  // 当 len > 16 时溢出
}
```

**触发方式**:
- 输入: `\x00` + `AAAAAAAAAAAAAAAAAAA` (20个A)
- 效果: 写入超过16字节导致栈溢出

**难度**: ⭐ (容易)

---

### 漏洞 2: 基于长度的溢出

**触发条件**: 输入第一字节 `% 5 == 1`

```c
void vuln_length_based(const char *input, uint32_t len) {
    char buffer[32];
    if (len > 0 && len < 1000) {  // 弱检查
        memcpy(buffer, input, len);  // 当 len > 32 时溢出
    }
}
```

**输入格式**:
```
[0] 类型字节 = 0x01
[1-4] 长度参数 (uint32_t, 小端序)
[5+] 数据内容
```

**触发方式**:
- 输入: `\x01\x40\x00\x00\x00AAAAAA...` (长度=64)
- 效果: 信任用户提供的长度，导致溢出

**难度**: ⭐⭐ (中等)

---

### 漏洞 3: Off-by-One 错误

**触发条件**: 输入第一字节 `% 5 == 2`

```c
void vuln_off_by_one(const char *input, size_t len) {
    char buffer[20];
    for (i = 0; i <= len && i < sizeof(buffer); i++) {  // <= 错误
        buffer[i] = input[i];
    }
}
```

**触发方式**:
- 输入: `\x02` + 20 个字符
- 效果: 循环多执行一次，写入 `buffer[20]`

**难度**: ⭐⭐⭐ (困难，需要精确的长度)

---

### 漏洞 4: 整数溢出导致的缓冲区溢出

**触发条件**: 输入第一字节 `% 5 == 3`

```c
void vuln_integer_overflow(const char *input, uint32_t count, uint32_t size) {
    char buffer[64];
    uint32_t total = count * size;  // 整数溢出
    if (total < sizeof(buffer)) {   // 检查被绕过
        memcpy(buffer, input, total);
    }
}
```

**输入格式**:
```
[0] 类型字节 = 0x03
[1-4] count (uint32_t)
[5-8] size (uint32_t)
[9+] 数据内容
```

**触发方式**:
- 输入: `\x03\x00\x00\x00\x80\x02\x00\x00\x00AAAA...`
- count = 0x80000000 (2^31)
- size = 2
- total = 0 (溢出)，绕过检查

**难度**: ⭐⭐⭐⭐ (很困难，需要特定的整数组合)

---

### 漏洞 5: 栈溢出（深度递归）

**触发条件**: 输入第一字节 `% 5 == 4`

```c
int vuln_stack_overflow(const char *input, int depth) {
    char local_buffer[256];  // 每次递归256字节
    if (depth > 0 && depth < 10000) {
        memset(local_buffer, 'A', sizeof(local_buffer));
        return vuln_stack_overflow(input, depth - 1) + 1;
    }
    return 0;
}
```

**输入格式**:
```
[0] 类型字节 = 0x04
[1-4] depth (int32_t)
[5+] 数据内容
```

**触发方式**:
- 输入: `\x04\x00\x10\x00\x00DATA` (depth = 4096)
- 效果: 4096 × 256 = 1MB 栈消耗，栈溢出

**难度**: ⭐⭐ (中等，但需要较大的递归深度)

---

## 🧪 使用方法

### 快速测试

```bash
cd /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests

# 运行完整测试套件
./test_vuln_v2.sh
```

### 手动测试特定漏洞

```bash
# 编译
gcc -o vuln_v2 vuln_stdin.c -g -no-pie -O0 -fno-stack-protector

# 测试漏洞类型 0 (缓冲区溢出)
printf '\x00AAAAAAAAAAAAAAAAAAA' | ./vuln_v2

# 测试漏洞类型 1 (长度溢出)
printf '\x01\x40\x00\x00\x00AAAAAAAAAAAAAAAA' | ./vuln_v2

# 测试漏洞类型 4 (栈溢出)
printf '\x04\x00\x10\x00\x00DATA' | ./vuln_v2
```

### RR-Fuzz 测试

```bash
QEMU="/path/to/qemu-x86_64"
VULN="./vuln_v2"

# 1. 录制 trace
printf '\x00hello' | RR_FUZZING_ENABLED=1 RR_MODE=record \
    RR_TRACE_FILE=vuln.dat $QEMU $VULN

# 2. 单进程 fuzzing
cd ../fuzzing
python3 fuzz_conductor.py \
    --qemu $QEMU \
    --target $VULN \
    --trace vuln.dat \
    --iterations 1000

# 3. 多进程 fuzzing
python3 multiprocess/fuzz_master.py \
    -n 4 \
    -p $VULN \
    -q $QEMU \
    -t ./traces/ \
    -s ./sync_dir/
```

---

## 📊 预期结果

### 单进程模式 (100 次迭代/类型)

| 漏洞类型 | 预期崩溃 | 难度 | 备注 |
|---------|---------|------|------|
| 类型 0 | ✅ 高 | 容易 | 简单长度变异即可触发 |
| 类型 1 | ✅ 中 | 中等 | 需要变异长度参数 |
| 类型 2 | ⚠️ 低 | 困难 | 需要精确的 off-by-one |
| 类型 3 | ⚠️ 低 | 很困难 | 需要特定整数组合 |
| 类型 4 | ✅ 中 | 中等 | 需要大递归深度值 |

### 多进程模式 (4 workers × 60秒)

- **预期**: 更高的崩溃发现率
- **加速比**: 3-4x
- **Seeds 增长**: +200-300%

---

## 🔧 编译选项说明

```bash
gcc -o vuln_v2 vuln_stdin.c \
    -g              # 调试信息
    -no-pie         # 禁用 PIE（位置无关可执行）
    -O0             # 禁用优化
    -fno-stack-protector  # 禁用栈保护（更容易触发）
```

**为什么禁用保护机制？**
- 栈保护会检测缓冲区溢出，导致程序崩溃前终止
- 禁用后更容易观察到真正的内存损坏
- 模拟没有现代保护机制的旧程序

---

## 📈 RR-Fuzz 能力展示

### ✅ 可以发现的漏洞

1. **简单缓冲区溢出** (类型 0, 1)
   - 通过变异 `read()` 的返回值（`nread`）
   - 通过变异输入数据的长度字段

2. **基于输入的漏洞** (类型 1, 3)
   - 通过 `aux_data` 变异输入内容
   - 变异结构化输入（长度字段、计数器）

3. **深度状态漏洞** (类型 4)
   - 通过变异控制流参数（递归深度）

### ⚠️ 较难发现的漏洞

1. **Off-by-One** (类型 2)
   - 需要非常精确的长度控制
   - 可能需要更多迭代或 recipe-based mutations

2. **复杂整数溢出** (类型 3)
   - 需要特定的整数组合
   - 可能需要符号执行或约束求解

---

## 🎓 学习要点

### 1. 系统调用输入的重要性

**错误做法** ❌:
```c
int main(int argc, char *argv[]) {
    vulnerable_function(argv[1]);  // RR-Fuzz 无法变异
}
```

**正确做法** ✅:
```c
int main() {
    char input[1024];
    read(STDIN_FILENO, input, 1024);  // RR-Fuzz 可以变异
    vulnerable_function(input);
}
```

### 2. 结构化输入

程序根据输入结构选择代码路径：
- `input[0]` → 选择漏洞类型
- `input[1-4]` → 长度/计数参数
- `input[5+]` → 实际数据

这种设计：
- ✅ 最大化代码覆盖率
- ✅ 测试多种漏洞类型
- ✅ 演示 fuzzer 的路径探索能力

### 3. 为什么有些漏洞更难发现？

- **简单漏洞**: 任何"不正常"的输入都能触发
- **复杂漏洞**: 需要特定的输入模式或值组合
- **解决方案**: 
  - 增加迭代次数
  - 使用 PathFinder (CFG 分析)
  - Recipe-based mutations

---

## 📚 相关文档

- **设计原理**: `/linux-user/rr_fuzzing/为什么vuln程序没有崩溃.md`
- **多进程测试**: `/linux-user/rr_fuzzing/多进程模式测试报告.md`
- **Fuzzing 架构**: `/linux-user/rr_fuzzing/fuzzing/README.md`

---

## 🚀 下一步

1. **运行测试**: `./test_vuln_v2.sh`
2. **查看结果**: 检查生成的日志和崩溃
3. **调整参数**: 增加迭代次数，尝试多进程模式
4. **添加新漏洞**: 扩展程序，添加更多漏洞类型

---

*文档创建时间: 2025-10-31*  
*程序版本: v2.0*  
*设计目标: 演示 RR-Fuzz 的多种漏洞发现能力* 🎯


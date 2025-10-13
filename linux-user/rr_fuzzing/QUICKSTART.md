# RR-Fuzz 快速教程

## 🎯 5分钟学会使用

### 步骤1：验证系统

```bash
cd /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/test
./quick_verify.sh
```

**预期输出：**
```
========================================
  ✓ 所有验证通过！
  RR-Fuzz框架工作正常
========================================
```

### 步骤2：准备你的程序

```bash
# 记录trace
strace -f -o my_program.strace ./my_program input_file

# 检查trace
head -20 my_program.strace
```

### 步骤3：开始Fuzzing

```bash
# 🔥 使用新的Fork点配置
python3 fuzz_conductor_example.py \
    --target ./my_program \
    --trace my_program.strace \
    --fork-syscall openat \
    --fork-pattern "*/input*" \
    --iterations 100
```

## 🔧 Fork点配置

### 常用配置

| 程序类型 | 配置 | 说明 |
|----------|------|------|
| 文件处理 | `--fork-syscall openat --fork-pattern "*/input*"` | 打开输入文件时fork |
| 网络服务 | `--fork-syscall accept` | 接受连接时fork |
| 配置解析 | `--fork-syscall openat --fork-pattern "*.conf"` | 打开配置文件时fork |

### 环境变量方式

```bash
export RR_FORK_SYSCALL=openat
export RR_FORK_PATTERN="*/input*"
qemu-x86_64 ./my_program
```

## 🔍 如何判断成功

### 验证脚本通过
```
✓ 所有验证通过！
```

### Fuzzing日志正常
```bash
grep "🎯\|🔧\|💥" fuzz_output.log
```

**预期输出：**
```
[RR-INFO] 🎯 Reached fork point: openat matching pattern '*/input*'
[RR-INFO] 🔧 MUTATE_ARG: openat[0] 3 → -1
[RR-INFO] 💥 CRASH DETECTED: Child crashed with signal 11
```

## ❌ 常见问题

### 问题1：验证脚本失败
```bash
# 重新编译
cd /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing
make clean && make all
```

### 问题2：找不到QEMU
```bash
sudo apt-get install qemu-user-static
```

### 问题3：共享内存权限
```bash
rm -f /dev/shm/rr_fuzz_*
```

## 📚 更多信息

- **中文指引：** `cat 开始验证.txt`
- **详细文档：** `doc/FUZZING_GUIDE.md`
- **示例代码：** `fuzz_conductor_example.py`

## 🎉 就是这么简单！

1. 运行 `./test/quick_verify.sh` 验证
2. 用 `strace` 记录你的程序
3. 用 `fuzz_conductor_example.py` 开始Fuzzing

**Happy Fuzzing!** 🚀
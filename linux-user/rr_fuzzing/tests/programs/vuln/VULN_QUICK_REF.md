
# 漏洞程序快速参考

## 🚀 快速开始

```bash
cd /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests
./test_vuln_v2.sh
```

## 📝 漏洞类型速查表

| 类型 | 输入首字节 | 触发输入示例 | 难度 |
|------|-----------|-------------|------|
| 0 | `\x00` | `\x00AAAAAAAAAAAAAAAAAAA` (20字节) | ⭐ 容易 |
| 1 | `\x01` | `\x01\x40\x00\x00\x00AAAA...` (len=64) | ⭐⭐ 中等 |
| 2 | `\x02` | `\x02` + 20字节数据 | ⭐⭐⭐ 困难 |
| 3 | `\x03` | `\x03\x00\x00\x00\x80\x02\x00\x00\x00` | ⭐⭐⭐⭐ 很困难 |
| 4 | `\x04` | `\x04\x00\x10\x00\x00DATA` (深度4096) | ⭐⭐ 中等 |

## 📋 输入格式

```
漏洞 0: [type] + data
漏洞 1: [type][len:4bytes] + data
漏洞 2: [type] + data
漏洞 3: [type][count:4bytes][size:4bytes] + data
漏洞 4: [type][depth:4bytes] + data
```

## 🧪 手动测试

```bash
# 编译
gcc -o vuln_v2 vuln_stdin.c -g -no-pie -O0 -fno-stack-protector

# 测试漏洞 0 (应该崩溃)
printf '\x00AAAAAAAAAAAAAAAAAAA' | ./vuln_v2

# 测试漏洞 1 (应该崩溃)
printf '\x01\x40\x00\x00\x00AAAAAAAAAAAAAAAAAAAAAAAA' | ./vuln_v2
```

## 🔧 RR-Fuzz 测试

```bash
# 录制
printf '\x00hello' | RR_FUZZING_ENABLED=1 RR_MODE=record \
    RR_TRACE_FILE=vuln.dat qemu-x86_64 vuln_v2

# 单进程 fuzzing
python3 ../fuzzing/fuzz_conductor.py \
    --qemu qemu-x86_64 \
    --target vuln_v2 \
    --trace vuln.dat \
    --iterations 1000
```

## 📊 文件位置

```
tests/
├── vuln_stdin.c          ← 源代码
├── test_vuln_v2.sh       ← 自动化测试
├── VULN_V2_README.md     ← 详细文档
└── VULN_QUICK_REF.md     ← 本文档
```


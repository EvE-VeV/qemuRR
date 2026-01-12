# RR-Fuzz Quick Start Guide

## 快速开始

### 前提条件

1. 已编译的 QEMU: `../qemu-x86_64` (支持 RR-Fuzz)
2. 目标程序和 Trace 文件可自动生成

### 1. 快速验证 (单进程)

最简单的方式是运行预置的测试脚本，它会自动录制 trace 并开始 fuzzing：

```bash
# 位于 linux-user/rr_fuzzing/ 目录下
./run_ls_fuzz_test.sh
```

该脚本会：
1. 使用 `/bin/ls` 录制初始 seed trace
2. 启动单进程 Fuzzer
3. 运行 1000 次迭代 (约 20秒)
4. 输出结果到 `fuzzing_output_ls/`

### 2. 多进程压力测试 (推荐)

在生产环境中，使用多进程模式可以显著提高效率（线性扩展）：

```bash
# 位于 linux-user/rr_fuzzing/ 目录下
./run_ls_fuzz_multiprocess.sh
```

该脚本会：
1. 自动检测 CPU 核心数
2. 启动 N 个 Worker 进程
3. 使用共享内存同步覆盖率和语料库
4. 运行 90秒后自动停止

### 3. 批量测试 (Full Suite)

验证所有 15 个目标（包括标准工具和 LAVA-M）：

```bash
./run_multiple_targets.sh
```

---

## 核心命令参数详解

如果您想手动运行 Fuzzer (而非使用上述 Helper Scripts)，请参考以下参数：

### 单进程模式 (`fuzz_main.py`)

```bash
python3 fuzzing/fuzz_main.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/example.trace.bin \
    --target /bin/ls \
    --iterations 1000
```

- `--qemu`: QEMU 可执行文件路径
- `--trace`: 录制的初始 Trace 文件
- `--target`: 目标程序路径
- `--smart`: 启用智能变异模式 (配合 PathFinder)

### 多进程模式 (`fuzz_multiprocess.py`)

```bash
python3 fuzzing/fuzz_multiprocess.py \
    --qemu ../qemu-x86_64 \
    --trace seeds/example.trace.bin \
    --target /bin/ls \
    --workers 4 \
    --timeout 3600
```

- `--workers`: Worker 进程数量 (默认: CPU 核心数)
- `--sync-dir`: 同步目录 (默认: `sync_dir`)
- `--timeout`: 运行时间限制 (秒)

---

## 常见问题

### Q: 为什么 Worker 启动这么快？
**A**: 我们在 v7.0 中引入了 **IPC Caching**。首次运行时会解析 Trace 并缓存为 `.pkl` 文件，后续启动直接加载缓存，启动时间从 5s 降低到 <0.1s。

### Q: 如何查看覆盖率详情？
**A**: 每次运行结束后，会生成 `final_stats.json`。对于详细的测试报告，请参考根目录下的 **`FINAL_SUMMARY_REPORT.md`**。

### Q: 支持哪些目标程序？
**A**: 支持几乎所有 Linux 用户态程序，包括 IO 密集型程序 (`cp`, `cat`) 和交互式程序。我们通过完整 hook `pread64`, `recvfrom` 等 syscall 确保了确定性。

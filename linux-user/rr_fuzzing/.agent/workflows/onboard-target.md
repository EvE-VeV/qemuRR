---
description: 如何为一个新的固件目标建立 Fuzzing 环境并生成初始轨迹
---

本文档描述了将一个全新的 IoT 固件集成到 RR-Fuzz 系统的标准流程。

### 1. 准备 Target Profile
在 `fuzzing/config/targets/` 下创建一个 `[target_name].json` 文件。
参考 [target_profile.schema.json](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/config/target_profile.schema.json)。

### 2. 执行自动化探测 (Discovery)
运行以下命令利用通用解析器发现端点：
```bash
python3 tests/scripts/tools/target_discoverer.py --profile fuzzing/config/targets/[target_name].json
```

### 3. 生成初始轨迹集 (Bulk Recording)
// turbo
运行批量录制工具生成 Master Seeds：
```bash
python3 tests/scripts/tools/bulk_recorder.py --profile fuzzing/config/targets/[target_name].json --discovery-results targets.json
```

### 4. 启动演进式 Fuzzing
一旦有了初始轨迹，启动核心引擎。引擎将自动根据变异发现的新路径，**自动自我录制 (Auto Re-recording)** 并在运行时扩展轨迹集合。
```bash
python3 fuzz_master.py --config [target_config].json --enable-evolution
```

### 5. 轨迹演进监控
监控 `sync_dir/evolved_traces`。系统会自动将覆盖率突破的变异种子提升为新的全功能轨迹。

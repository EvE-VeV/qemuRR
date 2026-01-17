# RAX30 模拟与 Fuzzing 方案 [DONE]

目标是复现 Netgear RAX30 固件上的 CVE-2023-27357。我们已成功搭建针对 `rex_cgi` 的 ARM 模拟环境，并触发了初步崩溃。

## 已实现的更改

### [RAX30 模拟环境]

- [x] **Mock 库**: `libnvram_mock.c` 已实现，涵盖了 NVRAM 和 CMS 消息初始化。
- [x] **模拟环境**: `setup_rax30.sh` 搭建了完整的 RootFS 模拟环境，并配置了最小化 `lighttpd`。
- [x] **CGI 兼容性**: 通过 Shell 包装器解决了 ARM 本地执行和库路径问题。

### [漏洞复现]

- [x] **直接轨迹录制**: `record_rex_cgi_direct.py` 成功记录了 `rex_cgi` 的执行。
- [x] **崩溃触发**: 使用包含 `wizWifi` 和 `serialNumber` 的 Payload 成功触发了段错误。

## 验证结论

1. **模拟环境测试**: `lighttpd` 和 `rex_cgi` 在模拟环境中运行正常，通过 Mock 库绕过了硬件依赖。
2. **崩溃复现成功**: 录制的 `rax30_cgi.trace` 显示了由于栈破坏导致的非法系统调用，这是一个强力的漏洞利用点。
3. **Fuzzing 启动**: `run_rax30_fuzz.sh` 已准备就绪，可以开始大规模探索。

## [/] 成果归档与后续扩展
- [x] 整理真实案例至 `linux-user/rr_fuzzing/crashes/real_world_repro/`，添加 README 标注。
- [x] 制定 [效果测试扩展计划](file:///home/webfuzz/.gemini/antigravity/brain/a3be7e27-df57-4f18-9531-a68b4f64259c/effectiveness_expansion_plan.md)。
- [/] **水平扩展：多厂商搜寻与分析**
    - [x] 检索文件系统中的 D-Link (DIR), TP-Link (Archer), Tenda (AC) 固件。
    - [x] **发现目标**: `DIR-820L` (RevA) 中的 `smbd` (MIPS-MSB)。
    - [/] 建立 `smbd` 模拟环境与 Mock。
        - [x] 识别 `libapmib.so` 为 NVRAM 等核心库依托。
        - [x] **新目标**: `jjhttpd` 和 `miniupnpd` 同样依赖于 `libapmib.so`。
        - [ ] 编写针对 `libapmib.so` 的 Mock 逻辑。
- [/] **垂直扩展：跨协议 Fuzzing**
    - [x] **UPnP/SSDP (RAX30)**: 分析 `bin/upnp` 和 `usr/sbin/ssd` (ARM)。
    - [ ] 为 RAX30 的 `upnp` 开发初始 Trace 录制脚本。
    - [ ] (可选) 若找到 TOTOLINK `snmpd` 则继续 SNMP 分析。

# RR-Fuzz Debugging: Multi-Target Coverage and Trace Sync

This plan addresses recent issues found during the RAX30 `upnp` and DIR-820L `jjhttpd` fuzzing campaigns.

## Proposed Changes

### [QEMU Engine / Core]

#### [MODIFY] [elfload.c](file:///home/webfuzz/Documents/qemu/linux-user/elfload.c)
- **Fix Range Calculation**: Remove double addition of `load_bias` if `start_code` is already absolute.
- **Fix Logging**: Ensure `fprintf` shows the actual range being used.

#### [MODIFY] [rr_framework.h](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/core/rr_framework.h)
- **Universal Trace Format**: Updated `syscall_record_t` to use `uint64_t` for `args` and `arg_size` to ensure cross-architecture compatibility.
- **Cache Consistency**: Added `rr_flush_tb_cache()` to ensure TCG translation blocks are updated when range settings change.

#### [MODIFY] [rr_record.c](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/record/rr_record.c)
- **Standardized Writing**: Use fixed 8-byte width for all header and payload fields.
- **Index Guard**: Only increment `trace_length` if `g_trace_file` is open to ensure 0-start indexing.
- **Arg Promotion**: Fix 32-bit to 64-bit argument promotion by using explicit loop copies instead of `memcpy`.
- **Endian Standardization**: Force all multi-byte fields to Little Endian using `cpu_to_leXX`.


#### [MODIFY] [rr_main.c](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/core/rr_main.c)
- **Header Refactor**: Include `user-internals.h` to resolve `thread_cpu` visibility for TB flushing.

#### [MODIFY] [rr_replay.c](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/replay/rr_replay.c)
- **Standardized Reading**: Match 8-byte width reading with the standardized recorder.

#### [MODIFY] [trace_analyzer.py](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/trace_analyzer.py)
- **Universal Parser**: Updated Python-side parsing logic to use fixed 64-bit sizes for all record fields.

### [RR-Fuzz / Utils]

#### [MODIFY] [rr_ipc.c](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/utils/rr_ipc.c)
- **FD Relocation**: Move `RR_SAFE_IPC_FD_START` to 180 to avoid potential conflicts with target FD usage.
- **Error Reporting**: Include `strerror(errno)` in IPC failure messages.

## [DONE] Dictionary Mutation Support

### [DONE] [afl_enhanced_mutator.py](file:///home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/conductor/afl_enhanced_mutator.py)
- [x] **Implement EXTRAS_AO**: Added `_generate_extras_ao_instructions` in `AFLEnhancedMutator`.
- [x] **Auto-Extraction**: `__init__` now runs `strings` on the target binary to populate the dictionary.
- [x] **Mutation Strategy**: Implemented `_extras_ao` method to insert/overwrite dictionary tokens.
- [x] **SmartMutator Integration**: Ported dictionary logic to `SmartMutator` (default class) to fix blind fuzzing.

## Phase 5: Result Consolidation [IN PROGRESS]

### [EXECUTION]
- [x] **Launch JJHTTPD Campaign**: Started long-duration session (PID: 2107284).
- [x] **Fix JJHTTPD Trace**: Re-recorded trace with HTTP payload to resolve EOF instability.
- [x] **Launch UPNP Campaign**: Started long-duration session (PID: 2107288).
- [x] **Fix UPNP Stagnation**: Hot-patched `SmartMutator` to enable dictionary support.

### [PENDING]
- [ ] Monitor crash directories.
- [ ] Triage unique crashes.

## Verification Plan

### Automated Tests
1. **Rebuild QEMU**: `cd build && make -j$(nproc)`
2. **RAX30 upnp Verification**: Run `run_upnp_fuzz.sh` and verify non-zero coverage in `/dev/shm/rr_coverage_*`.
3. **DIR-820L jjhttpd Verification**: Run `run_jjhttpd_fuzz.sh` and verify that "EOF at 48 / 110" errors are resolved.

### Manual Verification
- Check `qemu_debug.log` for correct `[RRFUZZ-RANGE]` and `[RR-COVERAGE]` output.
- Verify seed generation in `corpus/seeds`.

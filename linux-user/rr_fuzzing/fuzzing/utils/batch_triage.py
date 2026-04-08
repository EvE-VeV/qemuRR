#!/usr/bin/env python3
"""
batch_triage.py — 对已有 crash JSON 文件做批量 triage

对每个 crash 的 mutation_recipe 重放两个变体：
  net_only  — 只保留 network-fd 的 mutation
  file_only — 只保留 file-fd 的 mutation

判定：
  NETWORK-EXPLOITABLE  — net_only 复现 crash  → 真实漏洞
  FILE-FD-ONLY         — file_only 复现       → 配置依赖，不可远程利用
  COMBINED-STATE       — 只有全部 mutation 才崩 → 假阳性
  NOT-REPRODUCED       — 全部不崩              → 不稳定
"""
import sys
import os
import json
import glob
import time
import struct
import ast
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))
sys.path.insert(0, str(Path(__file__).parent.parent.parent.resolve()))

from conductor.qemu_executor import QEMUExecutor
from conductor.trace_analyzer import TraceAnalyzer
from conductor.fuzzing_core import FuzzingCore

# ── FuzzInstruction 导入（用于 eval mutation string）─────────────────────
try:
    from conductor.mutator import FuzzInstruction
except ImportError:
    # 手动定义最小版本（兼容旧 crash 文件）
    import struct as _struct
    class FuzzInstruction:
        def __init__(self, syscall_index, cmd, arg_index, data, offset, size, mutation_type='unknown'):
            self.syscall_index = syscall_index
            self.cmd = cmd
            self.arg_index = arg_index
            self.data = data if isinstance(data, bytes) else data.encode()
            self.offset = offset
            self.size = size
            self.mutation_type = mutation_type
        def __repr__(self):
            return f"FuzzInstruction(syscall_index={self.syscall_index}, cmd={self.cmd})"


def parse_mutations(mutation_recipe: dict) -> list:
    """从 mutation_recipe 字段解析 FuzzInstruction 列表"""
    if not mutation_recipe:
        return []
    muts_raw = mutation_recipe.get('mutations', [])
    if not muts_raw:
        return []
    # 旧格式：mutations 是一个包含单个字符串的列表，字符串是 list repr
    raw = muts_raw[0] if isinstance(muts_raw, list) else muts_raw
    if isinstance(raw, str):
        try:
            result = eval(raw, {"FuzzInstruction": FuzzInstruction, "__builtins__": {}})
            return result if isinstance(result, list) else [result]
        except Exception as e:
            print(f"  [WARN] eval mutations failed: {e}")
            return []
    return []


def triage_crash(crash_file: str, cfg: dict, network_fd_map: dict) -> str:
    """
    对单个 crash JSON 文件做 triage.
    返回 verdict 字符串，并将结果 patch 回文件。
    """
    try:
        d = json.load(open(crash_file))
    except Exception as e:
        return f"ERROR:{e}"

    if 'triage' in d:
        existing = d['triage'].get('verdict', '')
        if existing and existing not in ('UNKNOWN', 'NO-TRIAGE', ''):
            print(f"  [SKIP] already triaged: {existing}")
            return existing

    mutations = parse_mutations(d.get('mutation_recipe', {}))
    if not mutations:
        verdict = 'NO-MUTATIONS'
        d['triage'] = {'verdict': verdict}
        _write_json(crash_file, d)
        return verdict

    # 分离 net vs file mutations
    net_instrs  = [m for m in mutations if network_fd_map.get(m.syscall_index, False)]
    file_instrs = [m for m in mutations if not network_fd_map.get(m.syscall_index, False)]

    trace_file = cfg['trace']
    qemu = cfg['qemu']
    binary = cfg['binary']
    ld_prefix = cfg.get('ld_prefix', '')
    target_args = cfg.get('target_args', '')

    def _run(instrs, label):
        if not instrs:
            return False
        executor = None
        try:
            executor = QEMUExecutor(
                qemu_path=qemu,
                target_binary=binary,
                ld_prefix=ld_prefix or None,
                target_args=target_args,
                persistent_mode=True,
                timeout=15.0,
            )
            # Use execute_fork with fork_point=0 (replay from start), single variant
            results = executor.execute_fork(
                trace_file=trace_file,
                fork_point=0,
                mutation_variants=[instrs],
                depth=0,
                iteration_id=0,
            )
            crashed = False
            if results:
                r = results[0]
                crashed = getattr(r, 'crashed', False)
                print(f"    [{label}] crashed={crashed} signal={getattr(r,'signal_number',0)} pc={hex(getattr(r,'pc',0) or 0)}")
            return crashed
        except Exception as e:
            print(f"    [{label}] error: {e}")
            return False
        finally:
            if executor:
                try:
                    executor.stop_persistent_qemu()
                except Exception:
                    pass

    crashed_net  = _run(net_instrs,  'net_only')
    crashed_file = _run(file_instrs, 'file_only')
    original_crashed = bool(mutations)  # 原始带所有 mutation 才崩

    if crashed_net:
        verdict = 'NETWORK-EXPLOITABLE'
    elif crashed_file:
        verdict = 'FILE-FD-ONLY'
    elif original_crashed:
        verdict = 'COMBINED-STATE'
    else:
        verdict = 'NOT-REPRODUCED'

    triage_data = {
        'verdict': verdict,
        'crashed_net_only': crashed_net,
        'crashed_file_only': crashed_file,
        'net_syscall_indices': [m.syscall_index for m in net_instrs],
        'file_syscall_indices': [m.syscall_index for m in file_instrs],
        'timestamp': time.time(),
    }
    d['triage'] = triage_data
    _write_json(crash_file, d)
    return verdict


def _write_json(path: str, data: dict):
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


# ── Target 配置表 ─────────────────────────────────────────────────────────
SIM = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
BUILD = "/home/webfuzz/Documents/qemu/build"

TARGET_CONFIGS = {
    "rtac68u": {
        "qemu":        f"{BUILD}/qemu-arm",
        "binary":      f"{SIM}/tests/verified_targets/Asus_RTAC68U/rootfs/usr/sbin/httpd",
        "trace":       f"{SIM}/tests/seeds/Asus_RTAC68U.trace",
        "ld_prefix":   f"{SIM}/tests/verified_targets/Asus_RTAC68U/rootfs",
        "crash_dir":   f"{SIM}/fuzz_output_rtac68u/crashes",
        "arch":        "arm",
        "target_args": "",
    },
    "rtac68u_post": {
        "qemu":        f"{BUILD}/qemu-arm",
        "binary":      f"{SIM}/tests/verified_targets/Asus_RTAC68U/rootfs/usr/sbin/httpd",
        "trace":       f"{SIM}/tests/seeds/Asus_RTAC68U_post.trace",
        "ld_prefix":   f"{SIM}/tests/verified_targets/Asus_RTAC68U/rootfs",
        "crash_dir":   f"{SIM}/fuzz_output_rtac68u_post/crashes",
        "arch":        "arm",
        "target_args": "-p 8089",
    },
    "a720r": {
        "qemu":        f"{BUILD}/qemu-mips",
        "binary":      f"{SIM}/tests/images/Totolink/extracted_firmware/sim_root/bin/boa",
        "trace":       f"{SIM}/tests/seeds/TOTOLINK/boa_totolink_v2.trace",
        "ld_prefix":   f"{SIM}/tests/images/Totolink/extracted_firmware/sim_root",
        "crash_dir":   f"{SIM}/fuzz_output_a720r/crashes",
        "arch":        "mips",
        "target_args": "-c . -d",
    },
    "e1200": {
        "qemu":        f"{BUILD}/qemu-mipsel",
        "binary":      f"{SIM}/tests/images/Linksys/rootfs/usr/sbin/httpd",
        "trace":       f"{SIM}/tests/seeds/Linksys_E1200_auth.trace",
        "ld_prefix":   f"{SIM}/tests/images/Linksys/rootfs",
        "crash_dir":   f"{SIM}/fuzz_output_e1200/crashes",
        "arch":        "mips",
        "target_args": "-p 8093",
    },
    "e1200_post": {
        "qemu":        f"{BUILD}/qemu-mipsel",
        "binary":      f"{SIM}/tests/images/Linksys/rootfs/usr/sbin/httpd",
        "trace":       f"{SIM}/tests/seeds/Linksys_E1200_post.trace",
        "ld_prefix":   f"{SIM}/tests/images/Linksys/rootfs",
        "crash_dir":   f"{SIM}/fuzz_output_e1200_post/crashes",
        "arch":        "mips",
        "target_args": "-p 8093",
    },
    "lightftp": {
        "qemu":        f"{BUILD}/qemu-x86_64",
        "binary":      f"{SIM}/tests/realworld/LightFTP/src/Release/fftp",
        "trace":       f"{SIM}/tests/realworld/LightFTP/auto_retr.trace",
        "ld_prefix":   "",
        "crash_dir":   f"{SIM}/fuzz_output_lightftp/crashes",
        "arch":        "x86_64",
        "target_args": f"{SIM}/tests/realworld/LightFTP/data/fftp.conf",
    },
    "rtax88u": {
        "qemu":        f"{BUILD}/qemu-arm",
        "binary":      f"{SIM}/tests/images/Asus/RT-AX88U/rootfs/usr/sbin/httpd",
        "trace":       f"{SIM}/tests/images/Asus/RT-AX88U/traces/ax88u_init.trace",
        "ld_prefix":   f"{SIM}/tests/images/Asus/RT-AX88U/rootfs",
        "crash_dir":   f"{SIM}/fuzz_output_rtax88u/crashes",
        "arch":        "arm",
        "target_args": "",
    },
    "dir842": {
        "qemu":        f"{BUILD}/qemu-mips",
        "binary":      f"{SIM}/tests/images/DLink/DIR-842/DIR842A1_FW105B02.bin.extracted/_DIR842A1_FW105B02.bin.extracted/squashfs-root/sbin/jjhttpd",
        "trace":       f"{SIM}/tests/seeds/DLink_DIR842_RevA.trace",
        "ld_prefix":   f"{SIM}/tests/images/DLink/DIR-842/DIR842A1_FW105B02.bin.extracted/_DIR842A1_FW105B02.bin.extracted/squashfs-root",
        "crash_dir":   f"{SIM}/fuzz_output_dir842/crashes",
        "arch":        "mips",
        "target_args": "",
    },
    "tplink": {
        "qemu":        f"{BUILD}/qemu-arm",
        "binary":      f"{SIM}/tests/verified_targets/TPLink_AXE75/rootfs/usr/bin/httpd",
        "trace":       f"{SIM}/tests/seeds/TPLink_AXE75.trace",
        "ld_prefix":   f"{SIM}/tests/verified_targets/TPLink_AXE75/rootfs",
        "crash_dir":   f"{SIM}/fuzz_output_tplink/crashes",
        "arch":        "arm",
        "target_args": "",
    },
    "tew827_post": {
        "qemu":        f"{BUILD}/qemu-mipsel",
        "binary":      f"{SIM}/tests/verified_targets/Trendnet_TEW827DRU/rootfs/usr/sbin/uhttpd",
        "trace":       f"{SIM}/tests/seeds/Trendnet_TEW827_post.trace",
        "ld_prefix":   f"{SIM}/tests/verified_targets/Trendnet_TEW827DRU/rootfs",
        "crash_dir":   f"{SIM}/fuzz_output_tew827_post/crashes",
        "arch":        "mipsel",
        "target_args": "",
    },
    "rtax88u": {
        "qemu":        f"{BUILD}/qemu-arm",
        "binary":      f"{SIM}/tests/verified_targets/Asus_RTAX88U/sim_root/usr/sbin/httpd",
        "trace":       f"{SIM}/tests/seeds/Asus_RTAX88U.trace",
        "ld_prefix":   f"{SIM}/tests/verified_targets/Asus_RTAX88U/sim_root",
        "crash_dir":   f"{SIM}/fuzz_output_rtax88u/crashes",
        "arch":        "arm",
        "target_args": "",
    },
}


def build_network_fd_map(cfg: dict) -> dict:
    """用 SmartMutator 构建 syscall_index → is_network 映射"""
    arch = FuzzingCore._derive_arch(cfg['qemu'])
    try:
        from conductor.mutator import SmartMutator
        # SmartMutator.__init__ 会自动做 FD tracking
        m = SmartMutator(
            trace_file=cfg['trace'],
            target_binary=cfg['binary'],
            word_size=0,
            endian='auto',
            arch=arch,
            auth_boundary=0,
        )
        return m.syscall_network_fd_map
    except Exception as e:
        print(f"  [WARN] FD tracking failed: {e}, 返回空 map")
        return {}


def run_target(name: str, cfg: dict, max_crashes: int = 50):
    print(f"\n{'='*60}")
    print(f"Target: {name}")
    print(f"{'='*60}")

    crash_dir = cfg['crash_dir']
    crash_files = sorted(glob.glob(os.path.join(crash_dir, 'crash_w*.json')))
    if not crash_files:
        print("  无 crash JSON 文件，跳过")
        return {}

    print(f"  找到 {len(crash_files)} 个 crash，最多处理 {max_crashes} 个")

    # 检查 binary/trace 是否存在
    for key in ['qemu', 'binary', 'trace']:
        if not os.path.exists(cfg[key]):
            print(f"  [SKIP] {key} 不存在: {cfg[key]}")
            return {}

    network_fd_map = build_network_fd_map(cfg)
    print(f"  network_fd_map: {len(network_fd_map)} 条目，网络FD: {[k for k,v in network_fd_map.items() if v][:10]}")

    verdicts = {}
    for i, f in enumerate(crash_files[:max_crashes]):
        fname = os.path.basename(f)
        print(f"\n  [{i+1}/{min(len(crash_files), max_crashes)}] {fname}")
        verdict = triage_crash(f, cfg, network_fd_map)
        print(f"  → {verdict}")
        verdicts[verdict] = verdicts.get(verdict, 0) + 1

    return verdicts


def print_summary(all_results: dict):
    print(f"\n{'='*60}")
    print("TRIAGE 汇总")
    print(f"{'='*60}")
    total_net = 0
    for target, verdicts in sorted(all_results.items()):
        total = sum(verdicts.values())
        net = verdicts.get('NETWORK-EXPLOITABLE', 0)
        file_fd = verdicts.get('FILE-FD-ONLY', 0)
        combined = verdicts.get('COMBINED-STATE', 0)
        no_repro = verdicts.get('NOT-REPRODUCED', 0)
        no_mut = verdicts.get('NO-MUTATIONS', 0)
        total_net += net
        print(f"  {target:<20} total={total:2d}  "
              f"NET={net}  FILE={file_fd}  COMBINED={combined}  "
              f"NO-REPRO={no_repro}  NO-MUT={no_mut}")
    print(f"\n  ★ NETWORK-EXPLOITABLE 合计: {total_net} 个")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Batch crash triage')
    parser.add_argument('--targets', nargs='+', default=list(TARGET_CONFIGS.keys()),
                        help='要处理的 target（默认全部）')
    parser.add_argument('--max', type=int, default=30,
                        help='每个 target 最多 triage 几个 crash（默认30）')
    args = parser.parse_args()

    all_results = {}
    for name in args.targets:
        if name not in TARGET_CONFIGS:
            print(f"[!] 未知 target: {name}")
            continue
        cfg = TARGET_CONFIGS[name]
        verdicts = run_target(name, cfg, max_crashes=args.max)
        if verdicts:
            all_results[name] = verdicts

    print_summary(all_results)

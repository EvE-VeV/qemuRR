#!/usr/bin/env python3
"""
verify_crashes.py — 逐个 crash signature 做隔离重放验证

对每个 crash signature 生成三种变体：
  1. all_muts  : 原始全部 mutations（基线，已知崩溃）
  2. net_only  : 只保留 socket-fd mutations（idx=81 等攻击者可控）
  3. file_only : 只保留 file-fd mutations（idx=77/78/92 等攻击者不可控）

结论：
  net_only 崩溃  → ✅ 真实网络可利用 bug
  file_only 崩溃 → ⚠️  配置文件依赖，不可远程利用
  两个都不崩溃   → 🔶 需要组合状态（fuzzer 制造的假阳性）

Usage:
  python3 verify_crashes.py \\
    --crash-dir fuzz_output_e1200/crashes \\
    --trace     tests/seeds/Linksys_E1200_auth.trace \\
    --target    tests/images/Linksys/rootfs/usr/sbin/httpd \\
    --qemu      ../../build/qemu-mipsel \\
    --ld-prefix tests/images/Linksys/rootfs \\
    --args      "-p 8093" \\
    --net-indices 81 \\
    --top-n 10
"""
import argparse
import ast
import glob
import json
import os
import re
import sys
import time
from pathlib import Path

SCRIPT_DIR   = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]   # rr_fuzzing/
FUZZING_DIR  = PROJECT_ROOT / "fuzzing"

sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(FUZZING_DIR))

from conductor.conductor_types import FuzzInstruction
from conductor.qemu_executor import QEMUExecutor, STATUS_CRASH


# ── mutation string parser ────────────────────────────────────────────────────

def parse_instruction_string(raw: str) -> list:
    """
    Parse the Python repr stored in crash JSON mutation_recipe.mutations[0].
    Format: "[FuzzInstruction(syscall_index=N, cmd=N, ...), ...]"
    Returns list of FuzzInstruction.
    """
    instrs = []
    for m in re.finditer(r'FuzzInstruction\(([^)]+)\)', raw):
        kv_str = m.group(1)
        kv = {}
        for field in ('syscall_index', 'cmd', 'arg_index', 'offset', 'size'):
            fm = re.search(rf'{field}=(-?\d+)', kv_str)
            if fm:
                kv[field] = int(fm.group(1))
        mt = re.search(r"mutation_type='([^']+)'", kv_str)
        if mt:
            kv['mutation_type'] = mt.group(1)
        # bytes literal – may contain escaped sequences
        dm = re.search(r'data=(b(?:\'(?:[^\'\\]|\\.)*\'|"(?:[^"\\]|\\.)*"))', kv_str)
        if dm:
            try:
                kv['data'] = ast.literal_eval(dm.group(1))
            except Exception:
                kv['data'] = b''
        else:
            kv['data'] = b''
        try:
            instrs.append(FuzzInstruction(
                syscall_index=kv.get('syscall_index', 0),
                cmd=kv.get('cmd', 0),
                arg_index=kv.get('arg_index', 0),
                data=kv.get('data', b''),
                offset=kv.get('offset', 0),
                size=kv.get('size', None),
                mutation_type=kv.get('mutation_type', 'unknown'),
            ))
        except Exception as e:
            print(f"  [warn] parse error: {e}")
    return instrs


# ── crash loader ─────────────────────────────────────────────────────────────

def load_crash_samples(crash_dir: Path) -> dict:
    """Returns {hash8 -> first crash_dict found}."""
    samples = {}
    for f in sorted(crash_dir.glob("crash_w*.json")):
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        h8 = d.get('crash_hash', '')[:8]
        if h8 and h8 not in samples:
            samples[h8] = d
    return samples


# ── single variant runner ────────────────────────────────────────────────────

def run_variant(qemu_path: str, target_binary: str, ld_prefix: str, timeout: float,
                trace_file: str, instrs: list, label: str,
                target_args: str = '', fork_point: int = 0) -> tuple:
    """
    Run one variant using execute_fork() — the only path that propagates crash signals.
    Each call uses a fresh executor to prevent state pollution between runs.
    """
    if not instrs:
        return False, "skipped (no mutations)"
    executor = QEMUExecutor(
        qemu_path=qemu_path,
        target_binary=target_binary,
        target_args=target_args,
        ld_prefix=ld_prefix or None,
        timeout=timeout,
    )
    try:
        results = executor.execute_fork(
            trace_file=trace_file,
            fork_point=fork_point,
            mutation_variants=[instrs],
            depth=0,
            iteration_id=0,
        )
        if not results:
            return False, "no result"
        result = results[0]
        crashed = getattr(result, 'crashed', False)
        sig = getattr(result, 'signal_number', '')
        status_name = getattr(result, 'status_name', 'unknown')
        desc = f"status={status_name} sig={sig}"
        return crashed, desc
    except Exception as e:
        return False, f"error: {e}"
    finally:
        executor.stop_persistent_qemu()


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crash-dir",    required=True)
    ap.add_argument("--trace",        required=True)
    ap.add_argument("--target",       required=True)
    ap.add_argument("--qemu",         required=True)
    ap.add_argument("--ld-prefix",    default="")
    ap.add_argument("--args",         default="",
                    help="Target args as single string, e.g. '-p 8093'")
    ap.add_argument("--net-indices",  default="81",
                    help="Comma-separated socket-fd syscall indices")
    ap.add_argument("--fork-point",   type=int, default=0,
                    help="Fork point (auth_boundary) for execute_fork replay")
    ap.add_argument("--top-n",        type=int, default=10)
    ap.add_argument("--timeout",      type=float, default=8.0)
    ap.add_argument("--output",       default="verify_results.json")
    args = ap.parse_args()

    crash_dir   = Path(args.crash_dir)
    net_indices = {int(x.strip()) for x in args.net_indices.split(',')}

    print(f"[*] Crash dir    : {crash_dir}")
    print(f"[*] Trace        : {args.trace}")
    print(f"[*] Network idx  : {net_indices}  (attacker-controlled)")
    print(f"[*] Top-N        : {args.top_n}")
    print()

    # Load crash DB (for counts)
    db_path = crash_dir / "crash_db.json"
    db = json.loads(db_path.read_text()) if db_path.exists() else {}
    top_hashes = [h[:8] for h, _ in
                  sorted(db.items(), key=lambda x: x[1].get('count', 0), reverse=True)
                  ][:args.top_n]

    samples = load_crash_samples(crash_dir)

    # Each variant gets its own fresh executor to prevent state pollution.
    # Uses execute_fork() — the only path that propagates crash signals via IPC.
    run_kwargs = dict(
        qemu_path=args.qemu,
        target_binary=args.target,
        ld_prefix=args.ld_prefix,
        timeout=args.timeout,
        target_args=args.args,
        fork_point=args.fork_point,
    )

    results = {}
    header = f"{'Hash':8s}  {'Count':>7s}  {'all':>5s}  {'net_only':>8s}  {'file_only':>9s}  Verdict"
    print(header)
    print("-" * len(header))

    for h8 in top_hashes:
        info = db.get(h8) or db.get(next((k for k in db if k[:8] == h8), ''), {})
        count = info.get('count', 0)
        crash  = samples.get(h8)
        if not crash:
            print(f"{h8}  {count:7d}  (no sample json found)")
            continue

        mut_strings = crash.get('mutation_recipe', {}).get('mutations', [])
        raw = str(mut_strings[0]) if mut_strings else ''
        all_instrs = parse_instruction_string(raw)

        if not all_instrs:
            print(f"{h8}  {count:7d}  (cannot parse mutations)")
            continue

        net_instrs  = [i for i in all_instrs if i.syscall_index in net_indices]
        file_instrs = [i for i in all_instrs if i.syscall_index not in net_indices]

        crashed_all,  desc_all  = run_variant(**run_kwargs, trace_file=args.trace, instrs=all_instrs,  label="all")
        crashed_net,  desc_net  = run_variant(**run_kwargs, trace_file=args.trace, instrs=net_instrs,  label="net")
        crashed_file, desc_file = run_variant(**run_kwargs, trace_file=args.trace, instrs=file_instrs, label="file")

        if crashed_net:
            verdict = "✅ NETWORK-EXPLOITABLE"
        elif crashed_file:
            verdict = "⚠️  FILE-FD (not remote)"
        elif crashed_all:
            verdict = "🔶 COMBINED-STATE (fuzzer artifact)"
        else:
            verdict = "❓ NOT REPRODUCED"

        c_a = "CRASH" if crashed_all  else "ok"
        c_n = "CRASH" if crashed_net  else "ok"
        c_f = "CRASH" if crashed_file else "ok"
        print(f"{h8}  {count:7d}  {c_a:5s}  {c_n:8s}  {c_f:9s}  {verdict}")

        results[h8] = {
            "count":             count,
            "crashed_all":       crashed_all,
            "crashed_net":       crashed_net,
            "crashed_file":      crashed_file,
            "verdict":           verdict,
            "net_indices_used":  [i.syscall_index for i in net_instrs],
            "file_indices_used": [i.syscall_index for i in file_instrs],
            "desc_all":          desc_all,
            "desc_net":          desc_net,
            "desc_file":         desc_file,
        }

    out = Path(args.output)
    out.write_text(json.dumps(results, indent=2))
    print(f"\n[*] Results saved to {out}")

    real  = sum(1 for r in results.values() if r['crashed_net'])
    file_ = sum(1 for r in results.values() if not r['crashed_net'] and r['crashed_file'])
    combo = sum(1 for r in results.values() if r['crashed_all'] and not r['crashed_net'] and not r['crashed_file'])
    norep = sum(1 for r in results.values() if not r['crashed_all'])

    print(f"\n=== Summary (top {args.top_n}) ===")
    print(f"  ✅ Network-exploitable  : {real}")
    print(f"  ⚠️  File-fd only         : {file_}")
    print(f"  🔶 Requires combo       : {combo}")
    print(f"  ❓ Not reproduced       : {norep}")


if __name__ == "__main__":
    main()

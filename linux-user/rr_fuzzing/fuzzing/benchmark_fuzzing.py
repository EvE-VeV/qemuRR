#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import json
import psutil
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class BenchmarkConfig:
    name: str
    env_vars: Dict[str, str]
    description: str

def get_cpu_count():
    try:
        return psutil.cpu_count(logical=True)
    except:
        return 4

CPU_COUNT = get_cpu_count()
print(f"[Benchmark] Detected {CPU_COUNT} logical CPUs")

CONFIGS = [
    BenchmarkConfig(
        name="Baseline (Conservative)",
        env_vars={
            "RR_MAX_DEPTH": "2",
            "RR_MAX_VARIANTS": "2",
            "RR_TRIGGER_PROB": "0.2",
            "RR_BATCH_SIZE": "5"
        },
        description="Current default settings (Depth=2, Variants=2)"
    )
]

RESULTS = []

def run_benchmark(config: BenchmarkConfig, duration: int = 15):
    print(f"\n{'='*60}")
    print(f"🚀 Running Config: {config.name}")
    print(f"   Description: {config.description}")
    print(f"   Env Vars: {config.env_vars}")
    print(f"{'='*60}")

    target_bin = "mutation_test" 
    if not os.path.exists(target_bin):
        target_bin = "fork_test"
    
    qemu_path = "/home/webfuzz/Documents/qemu/build/qemu-x86_64"
    if not os.path.exists(qemu_path):
        qemu_path = "../../build/qemu-x86_64"

    cmd = [sys.executable, "fuzz_multiprocess.py", 
           "--qemu", qemu_path,
           "--target", f"./{target_bin}",
           "--trace", "tests/mock_trace.bin",  # ✅ Valid trace
           "--smart"
    ]
    
    env = os.environ.copy()
    env.update(config.env_vars)
    env["RR_MODE"] = "fuzzing"
    
    # Start process
    start_time = time.time()
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True
        )
        
        print(f"   Process started (PID={process.pid}). Running for {duration}s...")
        
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            pass
            
        print("   Stopping process...")
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            
        # Parse output for stats
        total_execs = 0
        full_log = stdout + "\n" + stderr
        
        # Heuristic extraction
        import re
        stats_matches = re.findall(r'total_execs[=:]\s*(\d+)', full_log)
        for val in stats_matches:
            total_execs = max(total_execs, int(val))

        if total_execs == 0:
             count_forks = full_log.count("Fork execution completed")
             count_variants = full_log.count("variants processed")
             if count_variants > 0:
                 total_execs = count_variants
             else:
                 total_execs = count_forks * 2 # Crude estimate
        
        elapsed = time.time() - start_time
        tps = total_execs / elapsed if elapsed > 0 else 0
        
        print(f"\n   ✅ Result: {total_execs} execs, {tps:.2f} execs/sec")
        
        if total_execs == 0:
            print("   ⚠️  Zero execs found. Logging snippet:")
            print("\n".join(full_log.splitlines()[-20:]))

    except Exception as e:
        print(f"   ❌ Benchmark failed: {e}")

def main():
    if not os.path.exists("mutation_test") and not os.path.exists("fork_test"):
        if os.path.exists("mutation_test.c"):
             subprocess.run(["gcc", "mutation_test.c", "-o", "mutation_test", "-g"])
    
    for config in CONFIGS:
        run_benchmark(config)

if __name__ == "__main__":
    main()

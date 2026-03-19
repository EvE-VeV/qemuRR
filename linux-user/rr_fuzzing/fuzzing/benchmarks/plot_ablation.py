#!/usr/bin/env python3
import os
import sys
import argparse
import glob
import re
import datetime
import matplotlib.pyplot as plt
import pandas as pd

def parse_rrfuzz_log(log_path):
    data = []
    start_time = None
    time_pattern = re.compile(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*')
    cov_pattern = re.compile(r'.*Coverage:\s+(\d+) edges')
    
    current_cov = None
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                time_match = time_pattern.match(line)
                if time_match:
                    time_str = time_match.group(1)
                    try: t = datetime.datetime.strptime(time_str, "%H:%M:%S.%f")
                    except ValueError: continue
                        
                    if start_time is None: start_time = t
                    rel_time = (t - start_time).total_seconds()
                    if rel_time < 0: rel_time += 86400

                    cov_match = cov_pattern.match(line)
                    if cov_match:
                        current_cov = int(cov_match.group(1))
                        data.append({'time_sec': rel_time, 'coverage': current_cov})
                        current_cov = None
                        
    except FileNotFoundError:
        return pd.DataFrame()
        
    if not data: return pd.DataFrame()
    df = pd.DataFrame(data)
    df['time_sec'] = df['time_sec'].round().astype(int)
    return df.groupby('time_sec').last().reset_index()

def parse_afl_plot_data(data_path):
    try:
        df = pd.read_csv(data_path, sep=',', skipinitialspace=True, comment='#', 
                         names=['relative_time', 'cycles_done', 'cur_path', 'paths_total', 
                                'pending_total', 'pending_favs', 'map_size', 'unique_crashes', 
                                'unique_hangs', 'max_depth', 'execs_per_sec', 'edges_found'])
        if len(df) == 0: return pd.DataFrame()
        df['time_sec'] = df['relative_time']
        df['coverage'] = df['edges_found'] if 'edges_found' in df.columns and not df['edges_found'].isnull().all() else df['map_size']
        return df[['time_sec', 'coverage']]
    except Exception:
        return pd.DataFrame()

def process_and_plot(benchmark_dir, ablation_dir):
    print(f"[*] Processing Benchmark Dir: {benchmark_dir}")
    print(f"[*] Processing Ablation Dir: {ablation_dir}")
    
    # 1. Full RR-Fuzz
    full_log = os.path.join(benchmark_dir, "rrfuzz_out", "worker0", "fuzzing.log")
    df_full = parse_rrfuzz_log(full_log)
    
    # 2. Cfg-1 (-RR) -> AFL++
    afl_log = os.path.join(benchmark_dir, "afl_out", "main_node", "plot_data")
    df_cfg1 = parse_afl_plot_data(afl_log)
    
    # 3. Cfg-2 (-SmartDict)
    cfg2_log = os.path.join(ablation_dir, "cfg2_no_smartdict_out", "worker0", "fuzzing.log")
    df_cfg2 = parse_rrfuzz_log(cfg2_log)
    
    # 4. Cfg-3 (-PathFinder)
    cfg3_log = os.path.join(ablation_dir, "cfg3_no_pathfinder_out", "worker0", "fuzzing.log")
    df_cfg3 = parse_rrfuzz_log(cfg3_log)

    plt.figure(figsize=(10, 6))
    plt.title("Ablation Study: Component Impact on Coverage", fontsize=14)
    plt.xlabel("Time (Hours)", fontsize=12)
    plt.ylabel("Edge Coverage", fontsize=12)
    
    if len(df_full) > 0:
        plt.plot(df_full['time_sec'] / 3600.0, df_full['coverage'], label='Full RR-Fuzz', linewidth=2.5, color='#e74c3c')
    if len(df_cfg2) > 0:
        plt.plot(df_cfg2['time_sec'] / 3600.0, df_cfg2['coverage'], label='Cfg-2 (-SmartDict)', linewidth=2, color='#f39c12', linestyle='--')
    if len(df_cfg3) > 0:
        plt.plot(df_cfg3['time_sec'] / 3600.0, df_cfg3['coverage'], label='Cfg-3 (-PathFinder)', linewidth=2, color='#27ae60', linestyle='-.')
    if len(df_cfg1) > 0:
        plt.plot(df_cfg1['time_sec'] / 3600.0, df_cfg1['coverage'], label='Cfg-1 (-RR / AFL++)', linewidth=2, color='#3498db', linestyle=':')

    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(fontsize=12)
    plt.tight_layout()
    
    out_file = "ablation_coverage_comparison.png"
    plt.savefig(out_file, dpi=300)
    print(f"[+] Saved ablation plot to {out_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", help="Benchmark results directory")
    parser.add_argument("--ablation", help="Ablation results directory")
    args = parser.parse_args()
    
    bench_dir = args.benchmark
    abl_dir = args.ablation
    
    if not bench_dir:
        b_dirs = sorted([d for d in glob.glob("benchmark_results_*") if os.path.isdir(d)])
        if b_dirs: bench_dir = b_dirs[-1]
        else: sys.exit("No benchmark dir found.")
        
    if not abl_dir:
        a_dirs = sorted([d for d in glob.glob("ablation_results_*") if os.path.isdir(d)])
        if a_dirs: abl_dir = a_dirs[-1]
        else: sys.exit("No ablation dir found.")
        
    process_and_plot(bench_dir, abl_dir)

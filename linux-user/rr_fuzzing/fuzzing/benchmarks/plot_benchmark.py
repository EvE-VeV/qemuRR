#!/usr/bin/env python3
import os
import sys
import glob
import re
import datetime
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

def parse_rrfuzz_log(log_path):
    """Parses RR-Fuzz log to extract time, coverage, and exec speed."""
    data = []
    start_time = None
    
    # Regex to match log lines
    # Example: [08:41:51.710] INFO    [STATS] Coverage:    0 edges
    # Example: [08:41:51.710] INFO    [STATS] Exec speed:  0.0 exec/s
    time_pattern = re.compile(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*')
    cov_pattern = re.compile(r'.*Coverage:\s+(\d+) edges')
    speed_pattern = re.compile(r'.*Exec speed:\s+([\d\.]+)\s+exec/s')
    
    current_time = None
    current_cov = None
    current_speed = None
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                time_match = time_pattern.match(line)
                if time_match:
                    time_str = time_match.group(1)
                    # We don't have full date in each line, assume same day
                    # We only care about relative seconds anyway
                    try:
                        t = datetime.datetime.strptime(time_str, "%H:%M:%S.%f")
                    except ValueError:
                        continue
                        
                    if start_time is None:
                        start_time = t
                    
                    rel_time = (t - start_time).total_seconds()
                    # Handle day wrapping
                    if rel_time < 0:
                        rel_time += 86400

                    cov_match = cov_pattern.match(line)
                    if cov_match:
                        current_cov = int(cov_match.group(1))
                    
                    speed_match = speed_pattern.match(line)
                    if speed_match:
                        current_speed = float(speed_match.group(1))
                        
                    if current_cov is not None and current_speed is not None:
                        # Record a data point
                        data.append({
                            'time_sec': rel_time,
                            'coverage': current_cov,
                            'speed': current_speed
                        })
                        current_cov = None
                        current_speed = None
                        
    except FileNotFoundError:
        print(f"Warning: RRFuzz log not found at {log_path}")
        return pd.DataFrame()
        
    if not data:
        return pd.DataFrame()
        
    df = pd.DataFrame(data)
    # Deduplicate and keep last stats for a given second
    df['time_sec'] = df['time_sec'].round().astype(int)
    df = df.groupby('time_sec').last().reset_index()
    return df

def parse_afl_plot_data(data_path):
    """Parses AFL++ plot_data file."""
    try:
        # AFL++ plot_data columns start with # relative_time, cycles_done...
        # sometimes comma separated, sometimes space
        df = pd.read_csv(data_path, sep=',', skipinitialspace=True, comment='#', 
                         names=['relative_time', 'cycles_done', 'cur_path', 'paths_total', 
                                'pending_total', 'pending_favs', 'map_size', 'unique_crashes', 
                                'unique_hangs', 'max_depth', 'execs_per_sec', 'edges_found'])
        if len(df) == 0:
             return pd.DataFrame()
             
        # Time is usually in seconds
        df['time_sec'] = df['relative_time']
        # AFL map_size or edges_found can be used for coverage
        # Let's use edges_found if available, otherwise map_size
        if 'edges_found' in df.columns and not df['edges_found'].isnull().all():
            df['coverage'] = df['edges_found']
        else:
            df['coverage'] = df['map_size']
            
        df['speed'] = df['execs_per_sec']
        return df[['time_sec', 'coverage', 'speed']]
        
    except Exception as e:
        print(f"Warning: Failed to parse AFL plot_data at {data_path}: {e}")
        return pd.DataFrame()

def smooth_data(df, column, window=5):
    """Applies a moving average to smooth the data."""
    if len(df) == 0:
        return df
    df[column] = df[column].rolling(window=window, min_periods=1).mean()
    return df

def plot_benchmark(result_dir):
    print(f"[*] Processing benchmark data in {result_dir}")
    
    rrfuzz_log = os.path.join(result_dir, "rrfuzz_out", "worker0", "fuzzing.log")
    afl_plot = os.path.join(result_dir, "afl_out", "main_node", "plot_data")
    
    df_rr = parse_rrfuzz_log(rrfuzz_log)
    df_afl = parse_afl_plot_data(afl_plot)
    
    if len(df_rr) == 0 and len(df_afl) == 0:
        print("[-] No valid data found for either fuzzer.")
        return
    
    # Pre-process
    if len(df_rr) > 0:
        df_rr = smooth_data(df_rr, 'speed')
    if len(df_afl) > 0:
        df_afl = smooth_data(df_afl, 'speed')

    # Convert time to hours
    if len(df_rr) > 0: df_rr['time_hrs'] = df_rr['time_sec'] / 3600.0
    if len(df_afl) > 0: df_afl['time_hrs'] = df_afl['time_sec'] / 3600.0

    # 1. Plot Coverage over Time
    plt.figure(figsize=(10, 6))
    plt.title("Edge Coverage over Time (Tenda AC15 httpd)", fontsize=14)
    plt.xlabel("Time (Hours)", fontsize=12)
    plt.ylabel("Edge Coverage", fontsize=12)
    
    if len(df_rr) > 0:
        plt.plot(df_rr['time_hrs'], df_rr['coverage'], label='RR-Fuzz', linewidth=2.5, color='#e74c3c')
    if len(df_afl) > 0:
        plt.plot(df_afl['time_hrs'], df_afl['coverage'], label='AFL++ (QEMU-Mode)', linewidth=2.5, color='#3498db')
        
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(fontsize=12)
    plt.tight_layout()
    cov_out = os.path.join(result_dir, "coverage_comparison.png")
    plt.savefig(cov_out, dpi=300)
    print(f"[+] Saved coverage plot to {cov_out}")
    
    # 2. Plot Real-time Throughput (Exec/sec)
    plt.figure(figsize=(10, 6))
    plt.title("Execution Throughput (Tenda AC15 httpd)", fontsize=14)
    plt.xlabel("Time (Hours)", fontsize=12)
    plt.ylabel("Executions per second", fontsize=12)
    
    if len(df_rr) > 0:
        plt.plot(df_rr['time_hrs'], df_rr['speed'], label='RR-Fuzz', alpha=0.8, color='#e74c3c')
    if len(df_afl) > 0:
        plt.plot(df_afl['time_hrs'], df_afl['speed'], label='AFL++ (QEMU-Mode)', alpha=0.8, color='#3498db')
        
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(fontsize=12)
    plt.tight_layout()
    speed_out = os.path.join(result_dir, "throughput_comparison.png")
    plt.savefig(speed_out, dpi=300)
    print(f"[+] Saved throughput plot to {speed_out}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]
    else:
        # Find latest benchmark result
        dirs = glob.glob("benchmark_results_*")
        dirs = [d for d in dirs if os.path.isdir(d)]
        if not dirs:
            print("[-] No benchmark_results found.")
            sys.exit(1)
        target_dir = sorted(dirs)[-1]
        
    plot_benchmark(target_dir)

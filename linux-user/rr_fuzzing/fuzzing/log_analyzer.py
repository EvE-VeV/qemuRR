#!/usr/bin/env python3
"""
RR-Fuzz Log Analysis Tool
Extract statistics from QEMU logs
"""

import re
import sys
from collections import defaultdict, Counter

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.stats = {
            'total_syscalls': 0,
            'deviations': 0,
            'deviation_details': [],
            'pure_replay': 0,
            'hybrid_replay': 0,
            'syscall_counts': Counter(),
            'fd_mappings': [],
            'checksum_failures': 0,
            'fork_events': 0,
        }
    
    def analyze(self):
        """Analyze log file"""
        with open(self.log_file, 'r', errors='ignore') as f:
            for line in f:
                self._process_line(line)
        
        return self.stats
    
    def _process_line(self, line):
        """Process a single log line"""
        # Deviation detection
        if 'UNEXPECTED DEVIATION' in line:
            self.stats['deviations'] += 1
            # Extract details
            match = re.search(r'syscall=(\d+) \((\w+)\), recorded_ret=(\S+), actual_ret=(\S+)', line)
            if match:
                self.stats['deviation_details'].append({
                    'syscall_nr': match.group(1),
                    'syscall_name': match.group(2),
                    'recorded': match.group(3),
                    'actual': match.group(4),
                })
        
        # Pure replay
        if 'Pure replay succeeded' in line:
            self.stats['pure_replay'] += 1
        
        # Hybrid replay
        if 'Hybrid mode' in line or 'Hybrid replay' in line:
            self.stats['hybrid_replay'] += 1
        
        # FD Mapping
        if 'FD_MAPPING: Adding mapping' in line:
            match = re.search(r'recorded_fd=(\d+) -> actual_fd=(\d+)', line)
            if match:
                self.stats['fd_mappings'].append((match.group(1), match.group(2)))
        
        # Checksum failure
        if 'checksum mismatch' in line:
            self.stats['checksum_failures'] += 1
        
        # Fork Event
        if 'Dynamic trace: fork' in line or 'Fork Server' in line:
            self.stats['fork_events'] += 1
        
        # Syscall count
        match = re.search(r'REPLAY_SYSCALL.*syscall[= ](\d+)', line)
        if match:
            self.stats['total_syscalls'] += 1
            self.stats['syscall_counts'][match.group(1)] += 1
    
    def print_report(self):
        """Print statistics report"""
        print("=" * 60)
        print("RR-Fuzz Execution Statistics Report")
        print("=" * 60)
        
        print(f"\nTotal syscalls: {self.stats['total_syscalls']}")
        print(f"Pure Replay: {self.stats['pure_replay']}")
        print(f"Hybrid Replay: {self.stats['hybrid_replay']}")
        
        if self.stats['total_syscalls'] > 0:
            pure_ratio = (self.stats['pure_replay'] / self.stats['total_syscalls']) * 100
            print(f"Pure Coverage: {pure_ratio:.1f}%")
        
        print(f"\nDeviation Detection:")
        print(f"  Total Deviations: {self.stats['deviations']}")
        if self.stats['deviations'] > 0:
            print(f"  Deviation Details (showing first 5):")
            for detail in self.stats['deviation_details'][:5]:
                print(f"    - {detail['syscall_name']}({detail['syscall_nr']}): "
                      f"{detail['recorded']} -> {detail['actual']}")
        
        print(f"\nIPC & Safety:")
        print(f"  Shared memory checksum failures: {self.stats['checksum_failures']}")
        print(f"  Fork events: {self.stats['fork_events']}")
        
        if self.stats['fd_mappings']:
            print(f"\nFD Mappings:")
            print(f"  Total mappings: {len(self.stats['fd_mappings'])}")
            if len(self.stats['fd_mappings']) <= 5:
                for recorded, actual in self.stats['fd_mappings']:
                    print(f"    {recorded} -> {actual}")
            else:
                print(f"    (showing first 5 only)")
                for recorded, actual in list(self.stats['fd_mappings'])[:5]:
                    print(f"    {recorded} -> {actual}")
        
        if self.stats['syscall_counts']:
            print(f"\nHot Syscalls (Top 5):")
            for syscall_nr, count in self.stats['syscall_counts'].most_common(5):
                print(f"  syscall {syscall_nr}: {count} times")
        
        print("\n" + "=" * 60)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <log_file>")
        print("\nExample:")
        print(f"  {sys.argv[0]} qemu_debug.log")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    try:
        analyzer = LogAnalyzer(log_file)
        analyzer.analyze()
        analyzer.print_report()
    except FileNotFoundError:
        print(f"Error: Log file not found: {log_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()


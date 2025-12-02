#!/usr/bin/env python3
"""
IPC Communication Overhead Profiler
分析Python-C通信的性能开销
"""

import time
import os
import struct
import select
from typing import Dict, List

class IPCProfiler:
    """
    IPC性能分析器

    测量各个IPC操作的耗时:
    1. write_fork_request() - 共享内存写入
    2. os.write(cmd_pipe) - 命令管道写入
    3. _wait_for_status() - 状态等待（最可能的瓶颈）
    4. _read_coverage() - Coverage读取
    """

    def __init__(self):
        self.measurements = {
            'shm_write': [],           # 共享内存写入耗时
            'cmd_write': [],           # 命令管道写入耗时
            'status_wait': [],         # 状态等待耗时
            'select_calls': [],        # select调用次数（每次等待）
            'coverage_read': [],       # Coverage读取耗时
            'total_roundtrip': [],     # 总往返耗时
        }

        self.current_exec_start = None
        self.current_phase_start = None

    def start_execution(self):
        """开始一次执行"""
        self.current_exec_start = time.time()

    def measure_phase(self, phase_name: str):
        """测量某个阶段开始"""
        self.current_phase_start = time.time()

    def record_phase(self, phase_name: str):
        """记录某个阶段结束"""
        if self.current_phase_start:
            elapsed = time.time() - self.current_phase_start
            if phase_name in self.measurements:
                self.measurements[phase_name].append(elapsed)
            self.current_phase_start = None

    def record_select_count(self, count: int):
        """记录select调用次数"""
        self.measurements['select_calls'].append(count)

    def end_execution(self):
        """结束一次执行"""
        if self.current_exec_start:
            total = time.time() - self.current_exec_start
            self.measurements['total_roundtrip'].append(total)
            self.current_exec_start = None

    def get_statistics(self) -> Dict:
        """获取统计信息"""
        stats = {}

        for key, values in self.measurements.items():
            if not values:
                continue

            stats[key] = {
                'count': len(values),
                'total_ms': sum(values) * 1000,
                'avg_ms': (sum(values) / len(values)) * 1000,
                'min_ms': min(values) * 1000,
                'max_ms': max(values) * 1000,
            }

            # 计算百分比（相对总往返时间）
            if 'total_roundtrip' in self.measurements and self.measurements['total_roundtrip']:
                total_time = sum(self.measurements['total_roundtrip'])
                stats[key]['percentage'] = (sum(values) / total_time) * 100

        return stats

    def print_report(self):
        """打印性能报告"""
        stats = self.get_statistics()

        print("\n" + "="*70)
        print("IPC Communication Overhead Analysis")
        print("="*70)

        if not stats:
            print("No measurements recorded.")
            return

        # 总览
        if 'total_roundtrip' in stats:
            total = stats['total_roundtrip']
            print(f"\n📊 Total Executions: {total['count']}")
            print(f"   Average Round-trip: {total['avg_ms']:.2f} ms")
            print(f"   Total Time: {total['total_ms']:.0f} ms")

        print("\n📈 Phase Breakdown:")

        # 按耗时百分比排序
        sorted_phases = sorted(
            [(k, v) for k, v in stats.items() if k != 'total_roundtrip'],
            key=lambda x: x[1].get('percentage', 0),
            reverse=True
        )

        for phase, data in sorted_phases:
            phase_name = {
                'shm_write': '共享内存写入',
                'cmd_write': '命令管道写入',
                'status_wait': '状态等待',
                'coverage_read': 'Coverage读取',
                'select_calls': 'select调用次数',
            }.get(phase, phase)

            print(f"\n  {phase_name} ({phase}):")
            print(f"    Count: {data['count']}")
            print(f"    Avg: {data['avg_ms']:.2f} ms")
            print(f"    Total: {data['total_ms']:.0f} ms")

            if 'percentage' in data:
                print(f"    % of Total: {data['percentage']:.1f}%")

            if phase == 'select_calls':
                avg_calls = sum(self.measurements['select_calls']) / len(self.measurements['select_calls'])
                print(f"    Avg select() calls per wait: {avg_calls:.1f}")

        # 瓶颈分析
        print("\n🔥 Bottleneck Analysis:")

        if 'status_wait' in stats and 'percentage' in stats['status_wait']:
            wait_pct = stats['status_wait']['percentage']
            if wait_pct > 40:
                print(f"  ⚠️  状态等待占比过高 ({wait_pct:.1f}%) - 主要瓶颈!")
                print(f"      建议: 批量命令减少往返次数")
            elif wait_pct > 25:
                print(f"  ⚠️  状态等待占比较高 ({wait_pct:.1f}%)")
                print(f"      建议: 考虑非阻塞I/O或批量命令")

        if 'select_calls' in self.measurements:
            avg_selects = sum(self.measurements['select_calls']) / len(self.measurements['select_calls'])
            if avg_selects > 10:
                print(f"  ⚠️  平均select调用次数过多 ({avg_selects:.1f}次/等待)")
                print(f"      建议: 减少轮询频率或使用事件驱动")

        print("\n" + "="*70)


# 全局profiler实例
_profiler = None

def get_profiler() -> IPCProfiler:
    """获取全局profiler"""
    global _profiler
    if _profiler is None:
        _profiler = IPCProfiler()
    return _profiler

def reset_profiler():
    """重置profiler"""
    global _profiler
    _profiler = IPCProfiler()

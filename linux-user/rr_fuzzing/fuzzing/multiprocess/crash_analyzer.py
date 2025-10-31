#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Crash分析和Triaging模块

负责：
1. 收集crash信息
2. 计算crash hash进行去重
3. 分类crash优先级
4. 保存crash数据库
"""

import hashlib
import json
import struct
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
from datetime import datetime


# 信号名称映射
SIGNAL_NAMES = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGUSR1",
    11: "SIGSEGV",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
}


@dataclass
class CrashInfo:
    """Crash信息"""
    crash_id: str                    # 唯一ID
    signal: int                      # 信号编号
    signal_name: str                 # 信号名称
    pc: int                          # Program Counter
    fault_address: Optional[int]     # 故障地址（SIGSEGV等）
    backtrace: List[str]             # 调用栈
    syscall_index: int               # 触发crash的syscall索引
    mutation_recipe: Dict            # 使用的mutation配方
    timestamp: str                   # 发生时间
    crash_hash: str                  # 用于去重的hash
    priority: str                    # 优先级: HIGH/MEDIUM/LOW
    exploitability: str              # 可利用性评估
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: Dict) -> 'CrashInfo':
        """从字典创建"""
        return CrashInfo(**data)


class CrashAnalyzer:
    """Crash分析器"""
    
    def __init__(self, output_dir: Path):
        """
        初始化Crash分析器
        
        Args:
            output_dir: 输出目录
        """
        self.output_dir = Path(output_dir)
        self.crashes_dir = self.output_dir / "crashes"
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        
        self.crash_db_file = self.crashes_dir / "crash_db.json"
        self.crashes: Dict[str, Dict] = self._load_crash_db()
        
        self.unique_hashes: Set[str] = set(self.crashes.keys())
    
    def _load_crash_db(self) -> Dict:
        """加载已知crash数据库"""
        if self.crash_db_file.exists():
            try:
                with open(self.crash_db_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[CrashAnalyzer] Warning: Failed to load crash DB: {e}")
                return {}
        return {}
    
    def _save_crash_db(self):
        """保存crash数据库"""
        try:
            with open(self.crash_db_file, 'w') as f:
                json.dump(self.crashes, f, indent=2)
        except Exception as e:
            print(f"[CrashAnalyzer] Error: Failed to save crash DB: {e}")
    
    def analyze_crash(self, qemu_status: Dict, mutation_recipe: Dict, 
                     iteration: int = 0) -> CrashInfo:
        """
        分析crash
        
        Args:
            qemu_status: QEMU返回的状态信息
            mutation_recipe: 使用的mutation配方
            iteration: fuzzing迭代次数
        
        Returns:
            CrashInfo对象
        """
        # 提取信号信息
        signal = qemu_status.get('signal', 0)
        signal_name = self._get_signal_name(signal)
        
        # 提取PC
        pc = qemu_status.get('pc', 0)
        
        # 提取故障地址（对于SIGSEGV/SIGBUS）
        fault_address = qemu_status.get('fault_address', None)
        
        # 提取调用栈
        backtrace = qemu_status.get('backtrace', [])
        if isinstance(backtrace, str):
            backtrace = [backtrace]
        
        # 提取syscall索引
        syscall_index = qemu_status.get('syscall_index', 
                                       mutation_recipe.get('syscall_index', -1))
        
        # 生成crash hash（用于去重）
        crash_hash = self._compute_crash_hash(signal, pc, backtrace)
        
        # 确定优先级
        priority = self._classify_priority(signal, pc, fault_address)
        
        # 评估可利用性
        exploitability = self._assess_exploitability(signal, pc, fault_address, backtrace)
        
        # 生成唯一ID
        crash_id = f"crash_{iteration:06d}_{crash_hash[:8]}"
        
        # 创建crash info
        crash_info = CrashInfo(
            crash_id=crash_id,
            signal=signal,
            signal_name=signal_name,
            pc=pc,
            fault_address=fault_address,
            backtrace=backtrace[:10],  # 只保留前10层
            syscall_index=syscall_index,
            mutation_recipe=mutation_recipe,
            timestamp=datetime.now().isoformat(),
            crash_hash=crash_hash,
            priority=priority,
            exploitability=exploitability
        )
        
        return crash_info
    
    def _compute_crash_hash(self, signal: int, pc: int, backtrace: List[str]) -> str:
        """
        计算crash hash用于去重
        
        使用信号 + PC + 前3层调用栈的hash
        """
        hash_components = [
            f"sig:{signal}",
            f"pc:{pc:#x}" if pc else "pc:unknown",
        ]
        
        # 添加调用栈的前3层
        for i, frame in enumerate(backtrace[:3]):
            if isinstance(frame, str):
                hash_components.append(f"frame{i}:{frame}")
            elif isinstance(frame, int):
                hash_components.append(f"frame{i}:{frame:#x}")
        
        hash_input = ":".join(hash_components)
        return hashlib.sha256(hash_input.encode()).hexdigest()
    
    def _classify_priority(self, signal: int, pc: int, fault_address: Optional[int]) -> str:
        """
        分类crash优先级
        
        HIGH:   可能可利用的crash
        MEDIUM: 普通crash
        LOW:    不太可能可利用
        """
        # HIGH优先级条件
        if signal == 11 and fault_address is not None:  # SIGSEGV
            # NULL pointer附近（可能控制）
            if fault_address < 0x10000:
                return "HIGH"
            # 在stack/heap边界附近
            if 0x7fff00000000 <= fault_address <= 0x7fffffffffff:
                return "HIGH"
        
        if signal == 6:  # SIGABRT
            # 通常表示heap corruption或assertion failure
            return "HIGH"
        
        if signal == 4:  # SIGILL
            # 非法指令，可能是代码覆盖
            return "HIGH"
        
        if pc == 0 or (pc is not None and pc < 0x1000):
            # PC跳转到NULL附近
            return "HIGH"
        
        # MEDIUM优先级
        if signal == 11:  # SIGSEGV
            return "MEDIUM"
        
        if signal == 7:  # SIGBUS
            return "MEDIUM"
        
        if signal == 8:  # SIGFPE
            return "MEDIUM"
        
        # LOW优先级
        return "LOW"
    
    def _assess_exploitability(self, signal: int, pc: int, 
                               fault_address: Optional[int], 
                               backtrace: List[str]) -> str:
        """
        评估可利用性
        
        Returns:
            "EXPLOITABLE", "PROBABLY_EXPLOITABLE", "PROBABLY_NOT_EXPLOITABLE", "UNKNOWN"
        """
        # EXPLOITABLE: 明显可利用
        if signal == 11 and fault_address is not None:
            # 可控的小地址（可能是指针覆盖）
            if 0 < fault_address < 0x10000:
                return "EXPLOITABLE"
        
        if pc == 0 or (pc is not None and pc < 0x1000):
            # PC被覆盖为NULL
            return "EXPLOITABLE"
        
        if signal == 6:  # SIGABRT from heap corruption
            # Heap corruption通常可利用
            if any('heap' in str(frame).lower() or 'malloc' in str(frame).lower() 
                   for frame in backtrace):
                return "PROBABLY_EXPLOITABLE"
        
        # PROBABLY_EXPLOITABLE
        if signal in [4, 11]:  # SIGILL, SIGSEGV
            return "PROBABLY_EXPLOITABLE"
        
        # PROBABLY_NOT_EXPLOITABLE
        if signal in [8, 13]:  # SIGFPE, SIGPIPE
            return "PROBABLY_NOT_EXPLOITABLE"
        
        # UNKNOWN
        return "UNKNOWN"
    
    def _get_signal_name(self, signal: int) -> str:
        """信号编号转名称"""
        return SIGNAL_NAMES.get(signal, f"SIG{signal}")
    
    def is_duplicate(self, crash_info: CrashInfo) -> bool:
        """检查是否重复crash"""
        return crash_info.crash_hash in self.unique_hashes
    
    def save_crash(self, crash_info: CrashInfo, save_details: bool = True):
        """
        保存crash
        
        Args:
            crash_info: Crash信息
            save_details: 是否保存详细信息到单独文件
        """
        if self.is_duplicate(crash_info):
            # 更新计数
            self.crashes[crash_info.crash_hash]['count'] += 1
            self.crashes[crash_info.crash_hash]['last_seen'] = crash_info.timestamp
            self.crashes[crash_info.crash_hash]['crash_ids'].append(crash_info.crash_id)
        else:
            # 新crash
            self.crashes[crash_info.crash_hash] = {
                'count': 1,
                'first_seen': crash_info.timestamp,
                'last_seen': crash_info.timestamp,
                'crash_ids': [crash_info.crash_id],
                'info': crash_info.to_dict()
            }
            self.unique_hashes.add(crash_info.crash_hash)
            
            # 保存详细信息到单独文件
            if save_details:
                crash_file = self.crashes_dir / f"{crash_info.crash_id}.json"
                try:
                    with open(crash_file, 'w') as f:
                        json.dump(crash_info.to_dict(), f, indent=2)
                except Exception as e:
                    print(f"[CrashAnalyzer] Warning: Failed to save crash details: {e}")
        
        # 保存数据库
        self._save_crash_db()
    
    def get_unique_crashes(self, sort_by: str = 'priority') -> List[Dict]:
        """
        获取去重后的crash列表
        
        Args:
            sort_by: 排序方式，可选 'priority', 'count', 'time', 'exploitability'
        
        Returns:
            排序后的crash列表
        """
        crashes = list(self.crashes.values())
        
        if sort_by == 'priority':
            priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
            crashes.sort(key=lambda c: (
                priority_order.get(c['info']['priority'], 99),
                -c['count']  # 相同优先级按count降序
            ))
        elif sort_by == 'exploitability':
            exploit_order = {
                'EXPLOITABLE': 0,
                'PROBABLY_EXPLOITABLE': 1,
                'PROBABLY_NOT_EXPLOITABLE': 2,
                'UNKNOWN': 3
            }
            crashes.sort(key=lambda c: (
                exploit_order.get(c['info']['exploitability'], 99),
                -c['count']
            ))
        elif sort_by == 'count':
            crashes.sort(key=lambda c: -c['count'])
        elif sort_by == 'time':
            crashes.sort(key=lambda c: c['first_seen'], reverse=True)
        
        return crashes
    
    def get_crash_by_hash(self, crash_hash: str) -> Optional[Dict]:
        """根据hash获取crash信息"""
        return self.crashes.get(crash_hash)
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        unique_count = len(self.crashes)
        total_count = sum(c['count'] for c in self.crashes.values())
        
        # 按优先级统计
        priority_stats = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for crash_data in self.crashes.values():
            priority = crash_data['info']['priority']
            priority_stats[priority] = priority_stats.get(priority, 0) + 1
        
        # 按可利用性统计
        exploit_stats = {
            'EXPLOITABLE': 0,
            'PROBABLY_EXPLOITABLE': 0,
            'PROBABLY_NOT_EXPLOITABLE': 0,
            'UNKNOWN': 0
        }
        for crash_data in self.crashes.values():
            exploit = crash_data['info']['exploitability']
            exploit_stats[exploit] = exploit_stats.get(exploit, 0) + 1
        
        # 按信号统计
        signal_stats = {}
        for crash_data in self.crashes.values():
            signal_name = crash_data['info']['signal_name']
            signal_stats[signal_name] = signal_stats.get(signal_name, 0) + 1
        
        return {
            'unique_crashes': unique_count,
            'total_crashes': total_count,
            'dedup_rate': (total_count - unique_count) / total_count * 100 if total_count > 0 else 0,
            'priority_distribution': priority_stats,
            'exploitability_distribution': exploit_stats,
            'signal_distribution': signal_stats
        }
    
    def print_summary(self, top_n: int = 10, verbose: bool = False):
        """
        打印crash汇总
        
        Args:
            top_n: 显示前N个crash
            verbose: 是否显示详细信息
        """
        stats = self.get_statistics()
        
        print(f"\n{'='*80}")
        print(f"Crash Analysis Summary")
        print(f"{'='*80}")
        
        print(f"\n📊 总体统计:")
        print(f"  唯一crashes:    {stats['unique_crashes']}")
        print(f"  总crashes:      {stats['total_crashes']}")
        print(f"  去重率:         {stats['dedup_rate']:.1f}%")
        
        print(f"\n🎯 优先级分布:")
        for priority, count in stats['priority_distribution'].items():
            pct = count / stats['unique_crashes'] * 100 if stats['unique_crashes'] > 0 else 0
            print(f"  {priority:8s}: {count:3d} ({pct:5.1f}%)")
        
        print(f"\n💥 可利用性分布:")
        for exploit, count in stats['exploitability_distribution'].items():
            pct = count / stats['unique_crashes'] * 100 if stats['unique_crashes'] > 0 else 0
            print(f"  {exploit:28s}: {count:3d} ({pct:5.1f}%)")
        
        print(f"\n🔍 信号分布:")
        for signal, count in sorted(stats['signal_distribution'].items(), 
                                    key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {signal:12s}: {count:3d}")
        
        if stats['unique_crashes'] > 0:
            print(f"\n🏆 Top {min(top_n, stats['unique_crashes'])} Unique Crashes:")
            print(f"{'#':<4} {'Priority':<8} {'Exploit':<28} {'Signal':<10} {'PC':>18} {'Count':>6}")
            print("-"*80)
            
            for i, crash_data in enumerate(self.get_unique_crashes()[:top_n], 1):
                info = crash_data['info']
                count = crash_data['count']
                
                pc_str = f"0x{info['pc']:x}" if info['pc'] else "unknown"
                
                print(f"{i:<4} {info['priority']:<8} {info['exploitability']:<28} "
                      f"{info['signal_name']:<10} {pc_str:>18} {count:>6}")
                
                if verbose:
                    print(f"     Hash: {info['crash_hash'][:16]}...")
                    print(f"     Syscall: #{info['syscall_index']}")
                    if info['fault_address'] is not None:
                        print(f"     Fault addr: 0x{info['fault_address']:x}")
                    if info['backtrace']:
                        print(f"     Backtrace: {info['backtrace'][:2]}")
                    print()
        
        print(f"{'='*80}\n")
    
    def export_to_file(self, output_file: Path, format: str = 'json'):
        """
        导出crash数据到文件
        
        Args:
            output_file: 输出文件路径
            format: 输出格式 ('json' or 'csv')
        """
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump({
                    'statistics': self.get_statistics(),
                    'crashes': self.get_unique_crashes()
                }, f, indent=2)
        elif format == 'csv':
            import csv
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Hash', 'Priority', 'Exploitability', 'Signal', 'PC', 
                                'Fault Addr', 'Count', 'First Seen', 'Last Seen'])
                
                for crash_data in self.get_unique_crashes():
                    info = crash_data['info']
                    writer.writerow([
                        info['crash_hash'][:16],
                        info['priority'],
                        info['exploitability'],
                        info['signal_name'],
                        f"0x{info['pc']:x}" if info['pc'] else "",
                        f"0x{info['fault_address']:x}" if info['fault_address'] else "",
                        crash_data['count'],
                        crash_data['first_seen'],
                        crash_data['last_seen']
                    ])
        
        print(f"[CrashAnalyzer] Exported crash data to {output_file}")


def main():
    """测试入口"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Crash Analyzer Tool')
    parser.add_argument('crash_dir', help='Crashes directory')
    parser.add_argument('--top', type=int, default=10, help='Show top N crashes')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--export', help='Export to file (JSON or CSV)')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Export format')
    
    args = parser.parse_args()
    
    # 加载crash analyzer
    analyzer = CrashAnalyzer(Path(args.crash_dir))
    
    # 打印摘要
    analyzer.print_summary(top_n=args.top, verbose=args.verbose)
    
    # 导出（如果指定）
    if args.export:
        analyzer.export_to_file(Path(args.export), format=args.format)


if __name__ == "__main__":
    main()


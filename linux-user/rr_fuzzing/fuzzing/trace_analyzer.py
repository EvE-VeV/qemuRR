#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RR-Fuzz Trace Analyzer

功能:
1. 解析 binary trace 文件
2. 识别每个系统调用的类型 (Pure/Hybrid)
3. 提取系统调用序列和参数信息
4. 为 Conductor 提供元信息

作者: RR-Fuzz Team
日期: 2025-10-26
"""

import struct
import os
import sys
from enum import IntEnum
from typing import List, Dict, Tuple, Optional

# 添加analysis目录到path以导入bb_trace_parser
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'analysis'))
try:
    from bb_trace_parser import BBTraceParser, BBEntry
    BB_TRACE_AVAILABLE = True
except ImportError:
    BB_TRACE_AVAILABLE = False
    # BB trace 是可选功能，静默失败


class AuxDataType(IntEnum):
    """aux_data 类型枚举 (与 rr_aux_data.h 保持一致)"""
    AUX_TYPE_BUFFER = 1
    AUX_TYPE_STRING = 2
    AUX_TYPE_RANDOM = 3
    AUX_TYPE_STRUCT = 4


class SyscallRecord:
    """系统调用记录"""
    def __init__(self, index: int, syscall_nr: int, retval: int, 
                 has_aux_data: bool, aux_data_size: int = 0):
        self.index = index
        self.syscall_nr = syscall_nr
        self.retval = retval
        self.has_aux_data = has_aux_data
        self.aux_data_size = aux_data_size
        self.name = self._nr_to_name(syscall_nr)
        self.category = self._categorize()
    
    def _nr_to_name(self, nr: int) -> str:
        """将系统调用号转换为名称 (x86_64)"""
        # 常见系统调用映射 (x86_64)
        syscall_map = {
            0: 'read',
            1: 'write',
            2: 'open',
            3: 'close',
            4: 'stat',
            5: 'fstat',
            8: 'lseek',
            9: 'mmap',
            10: 'mprotect',
            11: 'munmap',
            12: 'brk',
            21: 'access',
            41: 'socket',
            42: 'connect',
            43: 'accept',
            44: 'sendto',
            45: 'recvfrom',
            56: 'clone',
            57: 'fork',
            59: 'execve',
            60: 'exit',
            72: 'fcntl',
            79: 'getcwd',
            80: 'chdir',
            96: 'gettimeofday',
            102: 'getuid',
            104: 'getgid',
            158: 'arch_prctl',
            186: 'gettid',
            202: 'futex',
            218: 'set_tid_address',
            228: 'clock_gettime',
            231: 'exit_group',
            257: 'openat',
            262: 'newfstatat',
            318: 'getrandom',
        }
        return syscall_map.get(nr, f'syscall_{nr}')
    
    def _categorize(self) -> str:
        """分类系统调用 - 返回功能类别，不是pure/hybrid分类"""
        # ✅ FIX: Pure syscalls也应该根据功能分类，不要返回'pure_replay'
        # 'pure_replay'和'hybrid_replay'是统计字段，不是category
        
        # 根据系统调用名称分类
        if self.name in ['read', 'pread64', 'readv', 'preadv',
                         'recv', 'recvfrom', 'recvmsg',
                         'getrandom']:
            return 'input_io'
        elif self.name in ['write', 'pwrite64', 'writev', 'pwritev',
                           'send', 'sendto', 'sendmsg']:
            return 'output_io'
        elif self.name in ['open', 'openat', 'creat',
                           'stat', 'fstat', 'lstat', 'newfstatat',
                           'access', 'faccessat', 'close']:
            return 'file_ops'
        elif self.name in ['mmap', 'mmap2', 'munmap', 'mprotect', 'brk']:
            return 'memory_mgmt'
        elif self.name in ['socket', 'connect', 'bind', 'listen', 'accept']:
            return 'network'
        elif self.name in ['gettimeofday', 'clock_gettime', 'time']:
            return 'time'
        elif self.name in ['fork', 'clone', 'vfork', 'execve', 'exit', 'exit_group']:
            return 'process'
        else:
            # ✅ FIX: 未知syscall返回'unknown'，不是'hybrid_replay'
            return 'unknown'
    
    def __repr__(self):
        return (f"SyscallRecord(index={self.index}, name={self.name}, "
                f"nr={self.syscall_nr}, retval={self.retval}, "
                f"aux_data={self.has_aux_data}, category={self.category})")


class TraceAnalyzer:
    """Binary Trace 分析器"""
    
    # 支持多种 trace 格式的 magic numbers
    VALID_TRACE_MAGICS = {
        0x52525452: "RTRR",  # 旧格式或文档中的格式
        0x52525254: "TRRR",  # QEMU 实际生成的格式 (当前)
    }
    TRACE_VERSION = 1
    
    def __init__(self, trace_file: str):
        self.trace_file = trace_file
        self.syscalls: List[SyscallRecord] = []
        self.pure_syscalls: List[SyscallRecord] = []
        self.hybrid_syscalls: List[SyscallRecord] = []
        self.stats = {
            'total': 0,
            'pure_replay': 0,
            'hybrid_replay': 0,
            'input_io': 0,
            'output_io': 0,
            'file_ops': 0,
            'memory_mgmt': 0,
            'network': 0,
            'time': 0,
            'process': 0,
            'unknown': 0  # ✅ FIX: 添加unknown类别
        }
        
        # BB trace相关
        self.bb_trace_parser: Optional[BBTraceParser] = None
        self.bb_trace_available = False
        self.merged_execution_sequence = []  # 合并的执行序列
        
        # ✅ FIX: Track if already analyzed to prevent re-analysis
        self._analyzed = False
        
        # 自动解析trace文件
        self.analyze()
    
    def analyze(self) -> bool:
        """分析 trace 文件"""
        # ✅ FIX: Skip if already analyzed (for cached analyzers)
        if self._analyzed:
            return True
        
        # 处理None或空trace_file
        if self.trace_file is None:
            print(f"[TraceAnalyzer] ⚠️  No trace file provided, skipping analysis")
            return False
        
        if not os.path.exists(self.trace_file):
            print(f"[TraceAnalyzer] ❌ Trace file not found: {self.trace_file}")
            return False
        
        try:
            with open(self.trace_file, 'rb') as f:
                # 读取 header
                if not self._read_header(f):
                    return False
                
                # 读取所有 syscall records
                self._read_syscall_records(f)
                
                # 分类和统计
                self._classify_and_stats()
                
                # 尝试加载BB trace
                self._load_bb_trace()
                
                print(f"[TraceAnalyzer] ✅ Analysis completed:")
                print(f"  Total syscalls: {self.stats['total']}")
                print(f"  Pure Replay:    {self.stats['pure_replay']} "
                      f"({self.stats['pure_replay'] * 100 // max(self.stats['total'], 1)}%)")
                print(f"  Hybrid Replay:  {self.stats['hybrid_replay']} "
                      f"({self.stats['hybrid_replay'] * 100 // max(self.stats['total'], 1)}%)")
                if self.bb_trace_available:
                    print(f"  BB Trace:       ✅ Available ({self.bb_trace_parser.stats['total_bbs']} BBs)")
                # BB trace 是可选的，不显示 "Not available" 避免误解
                
                # ✅ FIX: Mark as analyzed
                self._analyzed = True
                return True
                
        except Exception as e:
            print(f"[TraceAnalyzer] ❌ Failed to analyze trace: {e}")
            return False
    
    def _read_header(self, f) -> bool:
        """读取 trace header"""
        # 魔数 (4 bytes)
        magic = struct.unpack('I', f.read(4))[0]
        if magic not in self.VALID_TRACE_MAGICS:
            valid_magics_str = ", ".join([f"0x{m:08X} ({n})" for m, n in self.VALID_TRACE_MAGICS.items()])
            print(f"[TraceAnalyzer] ❌ Invalid trace magic: 0x{magic:08X}")
            print(f"[TraceAnalyzer]    Expected one of: {valid_magics_str}")
            return False
        
        # 记录实际使用的格式
        format_name = self.VALID_TRACE_MAGICS[magic]
        print(f"[TraceAnalyzer] Detected trace format: {format_name} (0x{magic:08X})")
        
        # 版本 (4 bytes)
        version = struct.unpack('I', f.read(4))[0]
        if version != self.TRACE_VERSION:
            print(f"[TraceAnalyzer] ⚠️  Trace version mismatch: {version} (expected {self.TRACE_VERSION})")
        
        # 记录数量 (4 bytes)
        count = struct.unpack('I', f.read(4))[0]
        self.stats['total'] = count
        
        print(f"[TraceAnalyzer] Trace header:")
        print(f"  Magic:   0x{magic:08X}")
        print(f"  Version: {version}")
        print(f"  Count:   {count}")
        
        return True
    
    def _read_syscall_records(self, f):
        """读取所有系统调用记录 - 修复版，正确解析完整的trace格式"""
        index = 0
        
        while True:
            # ===== Step 1: 读取固定字段 (150字节) =====
            # [A] Record header (8 bytes): index + syscall_nr
            header_data = f.read(8)
            if len(header_data) < 8:
                break  # EOF
            
            rec_index, syscall_nr = struct.unpack('<Ii', header_data)
            
            # [B] Args and retval (72 bytes): args[8] (64) + retval (8)
            args_retval = f.read(72)
            if len(args_retval) < 72:
                print(f"[TraceAnalyzer] ⚠️  EOF at record {index} args_retval")
                break
            
            retval = struct.unpack('<q', args_retval[64:72])[0]
            
            # [C] Arg sizes (64 bytes): arg_sizes[8]
            arg_sizes = f.read(64)
            if len(arg_sizes) < 64:
                print(f"[TraceAnalyzer] ⚠️  EOF at record {index} arg_sizes")
                break
            
            # [D] Flags (6 bytes): creates_fd + uses_fd + created_fd
            flags = f.read(6)
            if len(flags) < 6:
                print(f"[TraceAnalyzer] ⚠️  EOF at record {index} flags")
                break
            
            creates_fd = struct.unpack('<?', flags[0:1])[0]
            uses_fd = struct.unpack('<?', flags[1:2])[0]
            created_fd = struct.unpack('<i', flags[2:6])[0]
            
            # ===== Step 2: 读取variable arg_data section =====
            while True:
                arg_idx_bytes = f.read(4)
                if len(arg_idx_bytes) < 4:
                    print(f"[TraceAnalyzer] ⚠️  EOF at record {index} arg_idx")
                    break
                
                arg_idx = struct.unpack('<i', arg_idx_bytes)[0]
                if arg_idx == -1:  # End marker
                    break
                
                # Read size and data
                size_bytes = f.read(8)
                if len(size_bytes) < 8:
                    print(f"[TraceAnalyzer] ⚠️  EOF at record {index} arg_size")
                    break
                
                size = struct.unpack('<Q', size_bytes)[0]
                if size > 1000000:  # Sanity check
                    print(f"[TraceAnalyzer] ⚠️  Record {index}: suspicious arg_size={size}")
                    break
                
                data = f.read(size)
                if len(data) < size:
                    print(f"[TraceAnalyzer] ⚠️  EOF at record {index} arg_data")
                    break
            
            # ===== Step 3: 读取aux_data section =====
            has_aux_data = False
            aux_data_size = 0
            
            marker_bytes = f.read(4)
            if len(marker_bytes) >= 4:
                marker = struct.unpack('<I', marker_bytes)[0]
                
                if marker == 0x41555844:  # "AUXD" (little-endian)
                    has_aux_data = True
                    aux_cnt_bytes = f.read(4)
                    if len(aux_cnt_bytes) < 4:
                        print(f"[TraceAnalyzer] ⚠️  EOF at record {index} aux_count")
                        break
                    
                    aux_count = struct.unpack('<I', aux_cnt_bytes)[0]
                    
                    # ✅ 关键修复：遍历所有aux_data（不要break！）
                    for j in range(aux_count):
                        kind_bytes = f.read(1)
                        arg_mask_bytes = f.read(1)
                        size_bytes = f.read(4)
                        
                        if len(kind_bytes) < 1 or len(arg_mask_bytes) < 1 or len(size_bytes) < 4:
                            print(f"[TraceAnalyzer] ⚠️  EOF at record {index} aux[{j}] header")
                            break
                        
                        kind = struct.unpack('<B', kind_bytes)[0]
                        arg_mask = struct.unpack('<B', arg_mask_bytes)[0]
                        size = struct.unpack('<I', size_bytes)[0]
                        
                        if size > 1000000:  # Sanity check
                            print(f"[TraceAnalyzer] ⚠️  Record {index}: suspicious aux_size={size}")
                            break
                        
                        data = f.read(size)
                        if len(data) < size:
                            print(f"[TraceAnalyzer] ⚠️  EOF at record {index} aux[{j}] data")
                            break
                        
                        aux_data_size += size
            
            # ===== Step 4: 创建记录 =====
            record = SyscallRecord(
                index=rec_index,
                syscall_nr=syscall_nr,
                retval=retval,
                has_aux_data=has_aux_data,
                aux_data_size=aux_data_size
            )
            
            self.syscalls.append(record)
            index += 1
        
        print(f"[TraceAnalyzer] ✅ Read {len(self.syscalls)} syscall records")
    
    def _classify_and_stats(self):
        """分类和统计"""
        # ✅ FIX: Clear lists before classifying (in case called multiple times)
        self.pure_syscalls = []
        self.hybrid_syscalls = []
        # Reset stats counters (pure_replay and hybrid_replay are separate from categories)
        self.stats['pure_replay'] = 0
        self.stats['hybrid_replay'] = 0
        for cat in ['input_io', 'output_io', 'file_ops', 'memory_mgmt', 'network', 'time', 'process', 'unknown']:
            self.stats[cat] = 0
        
        for record in self.syscalls:
            # 分类 Pure/Hybrid (这是一个维度)
            if record.has_aux_data:
                self.pure_syscalls.append(record)
                self.stats['pure_replay'] += 1
            else:
                self.hybrid_syscalls.append(record)
                self.stats['hybrid_replay'] += 1
            
            # ✅ FIX: 按功能类别统计 (另一个维度，与pure/hybrid正交)
            # Category现在只包含功能类别（input_io, file_ops等），不包含pure_replay/hybrid_replay
            if record.category in self.stats:
                self.stats[record.category] += 1
    
    def _load_bb_trace(self):
        """加载并解析BB trace文件"""
        if not BB_TRACE_AVAILABLE:
            return
        
        # 构造BB trace文件路径 (trace_file + ".bbl")
        bb_trace_file = self.trace_file + ".bbl"
        
        if not os.path.exists(bb_trace_file):
            print(f"[TraceAnalyzer] BB trace file not found: {bb_trace_file}")
            return
        
        try:
            self.bb_trace_parser = BBTraceParser(bb_trace_file)
            if self.bb_trace_parser.parse():
                self.bb_trace_available = True
                # 合并执行序列
                self._merge_execution_sequence()
        except Exception as e:
            print(f"[TraceAnalyzer] Failed to load BB trace: {e}")
    
    def _merge_execution_sequence(self):
        """合并syscall trace和BB trace，生成完整执行序列"""
        if not self.bb_trace_available or not self.bb_trace_parser:
            return
        
        # 简化版：按syscall索引组织BB
        self.merged_execution_sequence = []
        current_syscall_idx = 0
        
        for entry in self.bb_trace_parser.entries:
            # 当syscall索引变化时，插入syscall标记
            if entry.syscall_idx > current_syscall_idx:
                # 查找对应的syscall记录
                for syscall in self.syscalls:
                    if syscall.index == entry.syscall_idx:
                        self.merged_execution_sequence.append(('syscall', syscall))
                        break
                current_syscall_idx = entry.syscall_idx
            
            # 添加BB
            self.merged_execution_sequence.append(('bb', entry.pc))
    
    def classify_syscalls(self, syscalls):
        """分类系统调用"""
        pure = [s for s in syscalls if s['has_aux_data']]
        hybrid = [s for s in syscalls if not s['has_aux_data']]
        return pure, hybrid

    def get_pure_candidates(self):
        if not self.syscalls:
            self.analyze()
            self.classify_syscalls(self.syscalls)
        return self.pure_syscalls

    def get_hybrid_candidates(self):
        if not self.syscalls:
            self.analyze()
            self.classify_syscalls(self.syscalls)
        return self.hybrid_syscalls
    
    def get_pure_syscalls(self) -> List[SyscallRecord]:
        """获取 Pure Replay 系统调用"""
        return self.pure_syscalls
    
    def get_hybrid_syscalls(self) -> List[SyscallRecord]:
        """获取 Hybrid Replay 系统调用"""
        return self.hybrid_syscalls
    
    def get_syscalls_by_category(self, category: str) -> List[SyscallRecord]:
        """按类别获取系统调用"""
        return [sc for sc in self.syscalls if sc.category == category]
    
    def print_summary(self):
        """打印分析摘要"""
        print("\n" + "━" * 60)
        print("📊 Trace Analysis Summary")
        print("━" * 60)
        
        print(f"\n📈 Overall Statistics:")
        print(f"  Total syscalls:  {self.stats['total']}")
        print(f"  Pure Replay:     {self.stats['pure_replay']} "
              f"({self.stats['pure_replay'] * 100 // max(self.stats['total'], 1)}%)")
        print(f"  Hybrid Replay:   {self.stats['hybrid_replay']} "
              f"({self.stats['hybrid_replay'] * 100 // max(self.stats['total'], 1)}%)")
        
        print(f"\n🔍 Category Breakdown:")
        categories = ['input_io', 'output_io', 'file_ops', 'memory_mgmt', 
                      'network', 'time', 'process']
        for cat in categories:
            count = self.stats.get(cat, 0)
            if count > 0:
                pct = count * 100 // max(self.stats['total'], 1)
                print(f"  {cat:15s}: {count:4d} ({pct:2d}%)")
        
        print(f"\n📝 Top 10 Syscalls:")
        syscall_counts = {}
        for sc in self.syscalls:
            syscall_counts[sc.name] = syscall_counts.get(sc.name, 0) + 1
        
        sorted_syscalls = sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)
        for name, count in sorted_syscalls[:10]:
            pct = count * 100 // max(self.stats['total'], 1)
            print(f"  {name:20s}: {count:4d} ({pct:2d}%)")
        
        print("━" * 60 + "\n")
    
    def export_to_json(self, output_file: str):
        """导出分析结果为 JSON"""
        import json
        
        data = {
            'trace_file': self.trace_file,
            'stats': self.stats,
            'syscalls': [
                {
                    'index': sc.index,
                    'name': sc.name,
                    'nr': sc.syscall_nr,
                    'retval': sc.retval,
                    'has_aux_data': sc.has_aux_data,
                    'category': sc.category
                }
                for sc in self.syscalls
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[TraceAnalyzer] ✅ Exported to {output_file}")
    
    # ========== BB Trace相关方法 ==========
    
    def has_bb_trace(self) -> bool:
        """检查是否有BB trace数据"""
        return self.bb_trace_available and self.bb_trace_parser is not None
    
    def get_bb_sequence(self) -> List[int]:
        """获取完整的BB执行序列（PC地址列表）"""
        if not self.has_bb_trace():
            return []
        return self.bb_trace_parser.get_bb_sequence()
    
    def get_bb_between_syscalls(self, start_syscall_idx: int, end_syscall_idx: int) -> List[int]:
        """获取两个syscall之间的BB序列"""
        if not self.has_bb_trace():
            return []
        return self.bb_trace_parser.get_bb_between_syscalls(start_syscall_idx, end_syscall_idx)
    
    def get_merged_execution_sequence(self) -> List[Tuple[str, any]]:
        """
        获取合并的执行序列
        
        返回: [('bb', pc), ('syscall', SyscallRecord), ...]
        """
        return self.merged_execution_sequence
    
    def get_bb_coverage_summary(self) -> Dict[str, any]:
        """获取BB覆盖率摘要"""
        if not self.has_bb_trace():
            return {'error': 'BB trace not available'}
        return self.bb_trace_parser.get_coverage_summary()
    
    def export_bb_trace_to_json(self, output_file: str):
        """导出BB trace为JSON格式（用于离线分析）"""
        if not self.has_bb_trace():
            print("[TraceAnalyzer] ❌ No BB trace available")
            return
        
        import json
        
        data = {
            'trace_file': self.trace_file,
            'bb_trace_file': self.trace_file + ".bbl",
            'stats': self.bb_trace_parser.stats,
            'bb_sequence': [
                {
                    'pc': hex(entry.pc),
                    'syscall_idx': entry.syscall_idx,
                    'flags': entry.flags
                }
                for entry in self.bb_trace_parser.entries
            ],
            'syscall_bb_map': {
                str(k): [hex(pc) for pc in v]
                for k, v in self.bb_trace_parser.get_syscall_bb_map().items()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[TraceAnalyzer] ✅ BB trace exported to {output_file}")


def main():
    """测试入口"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: trace_analyzer.py <trace_file>")
        sys.exit(1)
    
    trace_file = sys.argv[1]
    
    analyzer = TraceAnalyzer(trace_file)
    if analyzer.analyze():
        analyzer.print_summary()
        
        # 可选: 导出 JSON
        if len(sys.argv) >= 3:
            analyzer.export_to_json(sys.argv[2])


if __name__ == '__main__':
    main()


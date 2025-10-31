#!/usr/bin/env python3
"""
BB Trace 功能测试和逻辑验证脚本
"""
import sys
import os
import struct

# 添加路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analysis.bb_trace_parser import BBTraceParser
from fuzzing.trace_analyzer import TraceAnalyzer

def test_bb_trace_parser(bb_file):
    """测试BB Trace解析器"""
    print(f"\n{'='*60}")
    print(f"测试1: BB Trace Parser - {bb_file}")
    print(f"{'='*60}")
    
    parser = BBTraceParser(bb_file)
    parser.parse()
    
    # 基本统计
    print(f"✅ 总BB数: {parser.stats['total_bbs']}")
    print(f"✅ 唯一PC数: {parser.stats['unique_pcs']}")
    print(f"✅ 涉及Syscall数: {parser.stats['syscalls_covered']}")
    
    # 显示前20个BB
    print(f"\n前20个BB:")
    for i, entry in enumerate(parser.entries[:20]):
        print(f"  [{i}] PC=0x{entry.pc:x}, syscall_idx={entry.syscall_idx}, flags=0x{entry.flags:x}")
    
    # 检查syscall分组
    syscalls = set(e.syscall_idx for e in parser.entries)
    print(f"\n✅ 涉及的Syscall索引: {sorted(syscalls)}")
    
    return parser

def test_trace_analyzer(dat_file):
    """测试Trace Analyzer（包含BB trace）"""
    print(f"\n{'='*60}")
    print(f"测试2: Trace Analyzer - {dat_file}")
    print(f"{'='*60}")
    
    analyzer = TraceAnalyzer(dat_file)
    
    print(f"✅ Syscall记录数: {len(analyzer.syscalls)}")
    print(f"✅ 是否有BB trace: {analyzer.has_bb_trace()}")
    
    if analyzer.has_bb_trace():
        # 显示前10个syscall及其关联的BB
        print(f"\n前10个Syscall及其BB:")
        for i in range(min(10, len(analyzer.syscalls))):
            record = analyzer.syscalls[i]
            bbs = analyzer.get_bb_between_syscalls(i, i+1)
            print(f"  Syscall[{i}]: num={record.syscall_nr}, BBs={len(bbs)}")
            if bbs and len(bbs) <= 5:
                for bb_pc in bbs[:5]:
                    print(f"    - 0x{bb_pc:x}")
        
        # 测试合并执行序列
        merged = analyzer.get_merged_execution_sequence()
        print(f"\n✅ 合并执行序列长度: {len(merged)}")
        print(f"  前10项:")
        for item in merged[:10]:
            if isinstance(item, tuple) and len(item) == 2:
                item_type, data = item
                if item_type == 'syscall':
                    print(f"    SYSCALL[{data.index}]: nr={data.syscall_nr}")
                else:  # 'bb'
                    print(f"    BB: 0x{data:x}")
    
    return analyzer

def test_logic_correctness(bb_file, dat_file):
    """测试逻辑正确性"""
    print(f"\n{'='*60}")
    print(f"测试3: 逻辑正确性验证")
    print(f"{'='*60}")
    
    parser = BBTraceParser(bb_file)
    parser.parse()
    analyzer = TraceAnalyzer(dat_file)
    
    # 验证1: BB的syscall_idx应该在有效范围内
    print("\n[验证1] BB的syscall_idx范围")
    max_syscall_idx = len(analyzer.syscalls)
    invalid_bb_count = 0
    for entry in parser.entries:
        if entry.syscall_idx > max_syscall_idx:
            invalid_bb_count += 1
    
    if invalid_bb_count == 0:
        print(f"  ✅ 所有BB的syscall_idx都在有效范围内 (0-{max_syscall_idx})")
    else:
        print(f"  ❌ 发现{invalid_bb_count}个BB的syscall_idx超出范围")
    
    # 验证2: 检查BB到Syscall的关联
    print("\n[验证2] BB到Syscall关联正确性")
    for syscall_idx in range(min(5, len(analyzer.syscalls))):
        bbs = analyzer.get_bb_between_syscalls(syscall_idx, syscall_idx + 1)
        # 从parser中统计属于该syscall的BB数
        parser_count = sum(1 for e in parser.entries if e.syscall_idx == syscall_idx)
        print(f"  Syscall[{syscall_idx}]: Analyzer报告{len(bbs)}个BB, Parser统计{parser_count}个BB")
        if len(bbs) == parser_count:
            print(f"    ✅ 一致")
        else:
            print(f"    ⚠️ 不一致")
    
    # 验证3: PC地址的合理性
    print("\n[验证3] PC地址合理性")
    pc_values = [e.pc for e in parser.entries]
    min_pc = min(pc_values) if pc_values else 0
    max_pc = max(pc_values) if pc_values else 0
    print(f"  PC范围: 0x{min_pc:x} - 0x{max_pc:x}")
    
    # 检查是否有异常的PC（如0x0）
    zero_pcs = sum(1 for pc in pc_values if pc == 0)
    if zero_pcs > 0:
        print(f"  ⚠️ 发现{zero_pcs}个PC=0的条目（可能是初始化问题）")
    else:
        print(f"  ✅ 没有异常的PC=0")
    
    # 验证4: 文件大小一致性
    print("\n[验证4] 文件大小一致性")
    file_size = os.path.getsize(bb_file)
    expected_size = len(parser.entries) * 20  # 每个entry 20字节
    print(f"  文件大小: {file_size} 字节")
    print(f"  预期大小: {expected_size} 字节 ({len(parser.entries)} entries × 20)")
    if file_size == expected_size:
        print(f"  ✅ 大小一致")
    else:
        print(f"  ⚠️ 大小不一致（差异: {abs(file_size - expected_size)} 字节）")

def main():
    if len(sys.argv) < 2:
        print("用法: test_bb_analysis.py <trace_file_prefix>")
        print("示例: test_bb_analysis.py /tmp/test_trace2.dat")
        sys.exit(1)
    
    dat_file = sys.argv[1]
    bb_file = dat_file + ".bbl"
    
    if not os.path.exists(bb_file):
        print(f"错误: BB trace文件不存在: {bb_file}")
        sys.exit(1)
    
    if not os.path.exists(dat_file):
        print(f"错误: Syscall trace文件不存在: {dat_file}")
        sys.exit(1)
    
    print(f"🧪 RR-Fuzz BB Trace 功能测试")
    print(f"📁 文件: {dat_file}")
    
    # 运行测试
    try:
        parser = test_bb_trace_parser(bb_file)
        analyzer = test_trace_analyzer(dat_file)
        test_logic_correctness(bb_file, dat_file)
        
        print(f"\n{'='*60}")
        print(f"✅ 所有测试完成！")
        print(f"{'='*60}")
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()


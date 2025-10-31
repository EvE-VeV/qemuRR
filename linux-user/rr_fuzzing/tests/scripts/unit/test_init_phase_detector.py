#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""InitPhaseDetector验证测试

测试InitPhaseDetector在不同类型程序上的准确性
"""

import sys
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# 添加父目录到path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "analysis"))
sys.path.insert(0, str(Path(__file__).parent.parent / "fuzzing"))

from trace_analyzer import TraceAnalyzer
from fuzz_conductor import InitPhaseDetector


class InitPhaseTestCase:
    """Init Phase测试案例"""
    def __init__(self, name: str, trace_file: str, expected_init_end: int, tolerance: int = 5, description: str = ""):
        self.name = name
        self.trace_file = trace_file
        self.expected_init_end = expected_init_end
        self.tolerance = tolerance
        self.description = description


# 定义测试案例集合
TEST_CASES = [
    InitPhaseTestCase(
        name="simple_hello",
        trace_file="/tmp/rr_test_simple/trace.dat",
        expected_init_end=8,
        tolerance=3,
        description="简单Hello World程序"
    ),
    InitPhaseTestCase(
        name="file_reader",
        trace_file="/tmp/rr_test_file/trace.dat",
        expected_init_end=12,
        tolerance=4,
        description="读取文件的程序"
    ),
    InitPhaseTestCase(
        name="network_client",
        trace_file="/tmp/rr_test_network/trace.dat",
        expected_init_end=20,
        tolerance=6,
        description="网络客户端程序"
    ),
]


# Syscall名称映射（简化版）
SYSCALL_NAMES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    21: "access",
    41: "socket",
    42: "connect",
    257: "openat",
}


def visualize_init_phase(syscalls: List, detected_end: int, expected_end: Optional[int] = None):
    """可视化初始化阶段检测结果"""
    print("\n" + "="*80)
    print("Syscall Timeline Visualization")
    print("="*80)
    
    for i, syscall in enumerate(syscalls[:min(50, len(syscalls))]):
        # 确定标记
        if i == detected_end:
            marker = "┃"
            phase_marker = "DETECTED"
        elif expected_end is not None and i == expected_end:
            marker = "┋"
            phase_marker = "EXPECTED"
        else:
            marker = "│"
            phase_marker = ""
        
        # 系统调用信息
        nr = syscall.get('syscall_nr', -1)
        name = SYSCALL_NAMES.get(nr, f"sys_{nr}")
        
        # 分类标记
        if nr in [9, 10, 11, 12]:  # mmap, mprotect, munmap, brk
            category = "🗺️  MEM"
        elif nr in [2, 257, 3, 21]:  # open, openat, close, access
            category = "📁 FILE"
        elif nr in [0, 1]:  # read, write
            category = "📝 I/O"
        elif nr in [41, 42, 43]:  # socket, connect, accept
            category = "🌐 NET"
        else:
            category = "⚙️  SYS"
        
        # 阶段标记
        if i < detected_end:
            phase = "INIT"
        else:
            phase = "WORK"
        
        # 打印行
        line = f"{marker} {i:3d} [{phase:4s}] {category} {name:15s}"
        if phase_marker:
            line += f"  ← {phase_marker}"
        print(line)
        
        # 在边界处打印分隔线
        if phase_marker == "DETECTED":
            print("━"*80)
    
    if len(syscalls) > 50:
        print(f"│ ... ({len(syscalls) - 50} more syscalls) ...")
    
    print("="*80)


def print_strategy_details(detector: InitPhaseDetector):
    """打印各策略的详细结果"""
    print("\n" + "-"*60)
    print("Strategy Voting Details:")
    print("-"*60)
    
    strategies = [
        ('mmap_burst', '内存映射突发'),
        ('first_io', '首次I/O操作'),
        ('init_burst', '初始化突发'),
        ('pattern_change', '模式变化'),
        ('loop_start', '循环开始'),
        ('statistical', '统计分析'),
    ]
    
    for strategy_key, strategy_name in strategies:
        vote = detector.strategy_votes.get(strategy_key, None)
        if vote is not None:
            print(f"  {strategy_name:15s}: syscall #{vote:3d}")
        else:
            print(f"  {strategy_name:15s}: N/A")
    
    # 打印权重
    if hasattr(detector, 'config') and 'weights' in detector.config:
        print("\n策略权重:")
        for strategy_key, strategy_name in strategies:
            weight = detector.config['weights'].get(strategy_key, 1.0)
            print(f"  {strategy_name:15s}: {weight:.2f}")
    
    print("-"*60)


def run_test_case(test_case: InitPhaseTestCase) -> Tuple[bool, int, int]:
    """
    运行单个测试案例
    
    Returns:
        (passed, detected_end, difference)
    """
    print("\n" + "="*80)
    print(f"测试案例: {test_case.name}")
    print("="*80)
    print(f"描述: {test_case.description}")
    print(f"Trace文件: {test_case.trace_file}")
    
    # 检查文件是否存在
    if not Path(test_case.trace_file).exists():
        print(f"❌ Trace文件不存在，跳过测试")
        return False, -1, -1
    
    try:
        # 加载trace
        print(f"\n正在加载trace...")
        analyzer = TraceAnalyzer(test_case.trace_file)
        syscalls = analyzer.get_syscall_sequence()
        print(f"✓ 加载了 {len(syscalls)} 个syscalls")
        
        # 运行detector
        print(f"\n正在运行InitPhaseDetector...")
        detector = InitPhaseDetector(syscalls, trace_file=test_case.trace_file)
        detected_end = detector.detect_init_phase_end()
        
        # 计算差异
        diff = abs(detected_end - test_case.expected_init_end)
        within_tolerance = diff <= test_case.tolerance
        
        # 打印结果
        print(f"\n结果:")
        print(f"  预期init结束: syscall #{test_case.expected_init_end}")
        print(f"  检测init结束: syscall #{detected_end}")
        print(f"  差异:         {diff} syscalls")
        print(f"  容差范围:     ±{test_case.tolerance} syscalls")
        print(f"  测试状态:     {'✅ PASS' if within_tolerance else '❌ FAIL'}")
        
        # 打印策略详情
        print_strategy_details(detector)
        
        # 可视化
        visualize_init_phase(syscalls, detected_end, test_case.expected_init_end)
        
        return within_tolerance, detected_end, diff
        
    except Exception as e:
        print(f"❌ 测试执行失败: {e}")
        import traceback
        traceback.print_exc()
        return False, -1, -1


def generate_sample_traces():
    """生成示例trace文件（用于测试）"""
    print("\n" + "="*80)
    print("生成示例Trace文件")
    print("="*80)
    
    # 这里可以添加生成trace的逻辑
    # 例如：编译简单程序并使用RR-Fuzz record模式
    
    print("\n⚠️  示例trace生成功能未实现")
    print("请手动创建测试trace文件，或使用现有的trace文件")
    print("\n建议步骤:")
    print("1. 编写测试程序（如 test_simple.c）")
    print("2. 使用RR-Fuzz record模式录制:")
    print("   RR_MODE=record RR_TRACE_FILE=/tmp/rr_test_simple/trace.dat qemu-x86_64 ./test_simple")
    print("3. 更新 TEST_CASES 中的路径")


def run_all_tests() -> Tuple[int, int]:
    """
    运行所有测试
    
    Returns:
        (passed_count, total_count)
    """
    print("="*80)
    print("InitPhaseDetector 验证测试套件")
    print("="*80)
    
    # 检查哪些测试文件存在
    available_tests = []
    missing_tests = []
    
    for test_case in TEST_CASES:
        if Path(test_case.trace_file).exists():
            available_tests.append(test_case)
        else:
            missing_tests.append(test_case)
    
    # 报告缺失的测试
    if missing_tests:
        print(f"\n⚠️  警告: {len(missing_tests)} 个测试trace文件缺失:")
        for test_case in missing_tests:
            print(f"  - {test_case.name}: {test_case.trace_file}")
    
    # 如果没有可用测试，提示生成
    if not available_tests:
        print(f"\n❌ 没有可用的测试trace文件")
        generate_sample_traces()
        return 0, 0
    
    print(f"\n✓ 找到 {len(available_tests)} 个可用测试")
    
    # 运行所有可用测试
    results = []
    for test_case in available_tests:
        passed, detected, diff = run_test_case(test_case)
        results.append({
            'name': test_case.name,
            'passed': passed,
            'expected': test_case.expected_init_end,
            'detected': detected,
            'diff': diff,
            'tolerance': test_case.tolerance
        })
    
    # 汇总结果
    print("\n" + "="*80)
    print("测试汇总")
    print("="*80)
    
    passed_count = sum(1 for r in results if r['passed'])
    total_count = len(results)
    
    # 打印每个测试的结果
    print(f"\n{'测试名称':<20} {'预期':>6} {'检测':>6} {'差异':>6} {'容差':>6} {'状态':>6}")
    print("-"*60)
    for r in results:
        status = "✅ PASS" if r['passed'] else "❌ FAIL"
        print(f"{r['name']:<20} {r['expected']:>6} {r['detected']:>6} {r['diff']:>6} "
              f"±{r['tolerance']:<5} {status:>6}")
    
    print("-"*60)
    print(f"总计: {passed_count}/{total_count} 通过 ({passed_count/total_count*100:.1f}%)")
    
    # 统计分析
    if results:
        avg_diff = sum(r['diff'] for r in results if r['diff'] >= 0) / len([r for r in results if r['diff'] >= 0])
        print(f"\n统计:")
        print(f"  平均差异: {avg_diff:.1f} syscalls")
        print(f"  通过率:   {passed_count/total_count*100:.1f}%")
    
    print("="*80)
    
    return passed_count, total_count


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='InitPhaseDetector验证测试')
    parser.add_argument('--generate', action='store_true', help='生成示例trace文件')
    parser.add_argument('--test', type=str, help='运行特定测试案例')
    parser.add_argument('--list', action='store_true', help='列出所有测试案例')
    
    args = parser.parse_args()
    
    if args.list:
        print("可用测试案例:")
        for i, test_case in enumerate(TEST_CASES, 1):
            exists = "✓" if Path(test_case.trace_file).exists() else "✗"
            print(f"  {i}. [{exists}] {test_case.name:20s} - {test_case.description}")
            print(f"      Trace: {test_case.trace_file}")
        return
    
    if args.generate:
        generate_sample_traces()
        return
    
    if args.test:
        # 运行特定测试
        test_case = next((tc for tc in TEST_CASES if tc.name == args.test), None)
        if not test_case:
            print(f"❌ 测试案例 '{args.test}' 不存在")
            print("使用 --list 查看所有测试案例")
            sys.exit(1)
        
        passed, _, _ = run_test_case(test_case)
        sys.exit(0 if passed else 1)
    
    # 运行所有测试
    passed, total = run_all_tests()
    
    # 返回适当的退出码
    if total == 0:
        print("\n⚠️  没有执行任何测试")
        sys.exit(2)
    elif passed == total:
        print(f"\n🎉 所有 {total} 个测试通过!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {total - passed}/{total} 个测试失败")
        sys.exit(1)


if __name__ == "__main__":
    main()


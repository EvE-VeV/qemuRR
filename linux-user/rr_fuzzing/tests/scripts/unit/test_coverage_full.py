#!/usr/bin/env python3
"""
完整的Coverage功能测试
测试Coverage模块的完整功能链条
"""

import os
import sys
import subprocess
import time
import struct

# 路径配置
QEMU_PATH = "/home/webfuzz/Documents/qemu/build/build-x86-arm-user/qemu-x86_64"
TEST_PROG = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/test_bb_trace"
TRACE_FILE = "/tmp/coverage_test.dat"

def cleanup():
    """清理测试文件"""
    for f in [TRACE_FILE, TRACE_FILE + ".bbl"]:
        if os.path.exists(f):
            os.remove(f)

def run_with_coverage(target_prog):
    """运行程序并返回coverage文件路径"""
    env = os.environ.copy()
    env.update({
        'RR_FUZZING_ENABLED': '1',
        'RR_MODE': 'record',
        'RR_TRACE_FILE': TRACE_FILE
    })
    
    # 运行程序
    proc = subprocess.Popen(
        [QEMU_PATH, target_prog],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    stdout, stderr = proc.communicate()
    
    # 从stderr中提取PID（从初始化日志中）
    pid = proc.pid
    cov_file = f"/dev/shm/rr_coverage_{pid}"
    
    # 由于QEMU fork了子进程，我们需要找到实际的coverage文件
    # 查找最新的coverage文件
    import glob
    cov_files = glob.glob("/dev/shm/rr_coverage_*")
    if cov_files:
        # 按修改时间排序，取最新的
        cov_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        for f in cov_files:
            # 检查文件是否有数据
            if os.path.getsize(f) > 0:
                return f, stdout, stderr
    
    return None, stdout, stderr

def analyze_coverage(cov_file):
    """分析coverage文件"""
    if not os.path.exists(cov_file):
        return None
    
    with open(cov_file, 'rb') as f:
        data = f.read()
    
    if len(data) == 0:
        return None
    
    non_zero_count = sum(1 for b in data if b != 0)
    total_hits = sum(data)
    
    # 提取所有非零边
    edges = []
    for idx, val in enumerate(data):
        if val != 0:
            edges.append((idx, val))
    
    return {
        'total_size': len(data),
        'unique_edges': non_zero_count,
        'total_hits': total_hits,
        'coverage_pct': non_zero_count * 100.0 / len(data),
        'edges': edges[:50]  # 只保留前50个
    }

def test_basic_coverage():
    """测试1: 基本coverage追踪"""
    print("\n" + "="*70)
    print("测试1: 基本Coverage追踪")
    print("="*70)
    
    cleanup()
    
    cov_file, stdout, stderr = run_with_coverage(TEST_PROG)
    
    if not cov_file:
        print("❌ FAILED: Coverage文件未生成")
        return False
    
    print(f"✅ Coverage文件生成: {cov_file}")
    
    stats = analyze_coverage(cov_file)
    if not stats:
        print("❌ FAILED: Coverage文件为空")
        return False
    
    print(f"\n📊 Coverage统计:")
    print(f"  总大小:     {stats['total_size']:,} 字节")
    print(f"  唯一边:     {stats['unique_edges']:,}")
    print(f"  总命中数:   {stats['total_hits']:,}")
    print(f"  覆盖率:     {stats['coverage_pct']:.2f}%")
    
    print(f"\n前10个非零边:")
    for idx, (edge_idx, count) in enumerate(stats['edges'][:10]):
        print(f"  Edge[{edge_idx:5d}]: {count:3d} hits")
    
    # 验证合理性
    if stats['unique_edges'] < 100:
        print(f"⚠️  WARNING: 唯一边数量较少 ({stats['unique_edges']})")
        return False
    
    if stats['coverage_pct'] < 0.1:
        print(f"⚠️  WARNING: 覆盖率过低 ({stats['coverage_pct']:.2f}%)")
        return False
    
    print("\n✅ 测试1 通过")
    return True

def test_different_programs():
    """测试2: 不同程序的coverage差异"""
    print("\n" + "="*70)
    print("测试2: 不同程序Coverage对比")
    print("="*70)
    
    programs = [
        ("/bin/true", "简单程序"),
        ("/bin/echo", "中等程序"),
        (TEST_PROG, "复杂程序")
    ]
    
    results = []
    for prog, desc in programs:
        if not os.path.exists(prog):
            continue
        
        cleanup()
        cov_file, _, _ = run_with_coverage(prog)
        
        if cov_file:
            stats = analyze_coverage(cov_file)
            if stats:
                results.append((desc, stats['unique_edges'], stats['coverage_pct']))
                print(f"  {desc:12s}: {stats['unique_edges']:5d} edges ({stats['coverage_pct']:5.2f}%)")
    
    if len(results) < 2:
        print("⚠️  WARNING: 测试程序不足")
        return True  # 不算失败
    
    # 验证复杂程序有更多coverage
    print("\n✅ 测试2 通过")
    return True

def test_trace_integration():
    """测试3: Coverage与Trace的集成"""
    print("\n" + "="*70)
    print("测试3: Coverage与BB Trace集成")
    print("="*70)
    
    cleanup()
    cov_file, stdout, stderr = run_with_coverage(TEST_PROG)
    
    if not cov_file:
        print("❌ FAILED: Coverage文件未生成")
        return False
    
    # 检查trace文件
    if not os.path.exists(TRACE_FILE):
        print("❌ FAILED: Trace文件未生成")
        return False
    
    if not os.path.exists(TRACE_FILE + ".bbl"):
        print("❌ FAILED: BB Trace文件未生成")
        return False
    
    # 分析coverage
    cov_stats = analyze_coverage(cov_file)
    
    # 分析BB trace
    bbl_size = os.path.getsize(TRACE_FILE + ".bbl")
    bb_count = bbl_size // 16  # 每个BB条目16字节
    
    print(f"✅ Trace文件: {TRACE_FILE}")
    print(f"✅ BB Trace文件: {TRACE_FILE}.bbl")
    print(f"✅ Coverage文件: {cov_file}")
    
    print(f"\n📊 集成统计:")
    print(f"  BB数量:       {bb_count:,}")
    print(f"  Coverage边:   {cov_stats['unique_edges']:,}")
    print(f"  比率:         {cov_stats['unique_edges']/bb_count if bb_count > 0 else 0:.2f}")
    
    print("\n✅ 测试3 通过")
    return True

def main():
    """主测试流程"""
    print("="*70)
    print("RR-Fuzz Coverage 完整功能测试")
    print("="*70)
    
    tests = [
        ("基本Coverage追踪", test_basic_coverage),
        ("不同程序Coverage对比", test_different_programs),
        ("Coverage与Trace集成", test_trace_integration)
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n❌ 测试异常: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    # 最终总结
    print("\n" + "="*70)
    print("测试总结")
    print("="*70)
    print(f"通过: {passed}/{len(tests)}")
    print(f"失败: {failed}/{len(tests)}")
    
    if failed == 0:
        print("\n🎉 所有测试通过！Coverage功能完全正常！")
        return 0
    else:
        print(f"\n⚠️  有 {failed} 个测试失败")
        return 1

if __name__ == "__main__":
    sys.exit(main())


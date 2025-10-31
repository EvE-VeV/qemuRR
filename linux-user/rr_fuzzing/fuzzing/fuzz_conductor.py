#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RR-Fuzz Conductor - 单进程模糊测试指挥器

⚠️  注意: 这是单进程模式的入口脚本，适用于：
    - 调试和学习
    - 快速原型验证
    - 单核环境

    生产环境请使用多进程模式: python3 multiprocess/fuzz_master.py

本脚本展示了如何使用重组后的模块化结构进行模糊测试。

用法:
    # 基础用法
    python3 fuzz_conductor.py --qemu ./qemu --trace ./trace.bin --target ./program
    
    # 带配方的用法
    python3 fuzz_conductor.py --qemu ./qemu --trace ./trace.bin --target ./program --recipe recipes.json
    
    # 生产环境（多进程）
    python3 multiprocess/fuzz_master.py -n 8 -p ./program -q ./qemu -t ./trace.bin

详细文档: USAGE_GUIDE.md
"""

import os
import sys
import signal
import argparse
import subprocess
import threading
import select
import struct
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List

# 导入 conductor 模块的所有核心组件
from conductor import (
    InitPhaseDetector,
    FuzzInstruction,
    CoverageTracker,
    FuzzSharedMemory,
    SmartMutator,
    FUZZ_FLAG_CAPTURE_SEED
)

# 导入 trace 分析器
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from trace_analyzer import TraceAnalyzer


# ========== 全局变量 ==========
_shutdown_requested = False
_conductor_instance = None


def signal_handler(signum, frame):
    """信号处理器（Ctrl+C 优雅退出）"""
    global _shutdown_requested, _conductor_instance
    print(f"\n[Conductor] 收到信号 {signum}，准备退出...")
    _shutdown_requested = True
    
    if _conductor_instance:
        _conductor_instance.cleanup()
    
    sys.exit(0)


# ========== 主指挥器类 ==========
class FuzzConductor:
    """
    Fuzz 指挥器 - 单进程模式
    
    负责:
    1. 与 QEMU 通过 IPC 通信
    2. 发送模糊测试指令
    3. 接收执行结果
    4. 追踪覆盖率
    """
    
    def __init__(
        self,
        qemu_path: str,
        target_binary: str,
        trace_file: str,
        recipe_file: Optional[str] = None,
        init_mode: str = 'adaptive'
    ):
        """
        初始化指挥器
        
        Args:
            qemu_path: QEMU 可执行文件路径
            target_binary: 目标二进制文件路径
            trace_file: trace 文件路径
            recipe_file: 配方文件路径（可选）
            init_mode: 初始化检测模式 ('adaptive', 'static', 'disabled')
        """
        self.qemu_path = qemu_path
        self.target_binary = target_binary
        self.trace_file = trace_file
        self.recipe_file = recipe_file
        
        print(f"[Conductor] 初始化 RR-Fuzz 指挥器...")
        print(f"[Conductor]   QEMU: {qemu_path}")
        print(f"[Conductor]   目标: {target_binary}")
        print(f"[Conductor]   Trace: {trace_file}")
        
        # 初始化阶段检测器
        self.init_detector = InitPhaseDetector(mode=init_mode)
        print(f"[Conductor]   初始化检测: {init_mode} 模式")
        
        # 智能变异器
        self.mutator = SmartMutator(trace_file, recipe_file=recipe_file)
        
        # IPC 管道
        self.cmd_pipe_read, self.cmd_pipe_write = os.pipe()
        self.status_pipe_read, self.status_pipe_write = os.pipe()
        
        # 共享内存
        self.shm = FuzzSharedMemory(f"rr_fuzz_{os.getpid()}")
        self.shm.create()
        
        # 覆盖率追踪
        self.coverage_tracker = CoverageTracker(os.getpid())
        
        # QEMU 进程
        self.qemu_process = None
        self.qemu_stderr_thread = None
        
        # 统计信息
        self.total_executions = 0
        self.crashes = []
        self.new_seeds = []
        self.start_time = None
        
        print(f"[Conductor] ✅ 初始化完成")
    
    def _read_qemu_stderr(self):
        """在单独线程中读取 QEMU 的 stderr 输出"""
        if not self.qemu_process or not self.qemu_process.stderr:
            return
        
        try:
            while True:
                line = self.qemu_process.stderr.readline()
                if not line:
                    break
                print(f"[QEMU] {line.decode('utf-8', errors='ignore').rstrip()}")
        except Exception as e:
            print(f"[Conductor] 读取 QEMU stderr 出错: {e}")
    
    def start_qemu(self):
        """启动 QEMU 进程（Fuzzing 模式）"""
        env = os.environ.copy()
        env.update({
            'RR_DEBUG_LEVEL': '3',
            'RR_FUZZING_ENABLED': 'True',
            'RR_MODE': 'fuzzing',
            'RR_TRACE_FILE': self.trace_file,
            'RR_CMD_PIPE': str(self.cmd_pipe_read),
            'RR_STATUS_PIPE': str(self.status_pipe_write),
            'RR_SHARED_MEMORY': self.shm.shm_name,
        })
        
        cmd = [self.qemu_path, self.target_binary]
        
        print(f"[Conductor] 启动 QEMU: {' '.join(cmd)}")
        
        self.qemu_process = subprocess.Popen(
            cmd,
            env=env,
            pass_fds=[self.cmd_pipe_read, self.status_pipe_write],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        print(f"[Conductor] QEMU 已启动 (PID={self.qemu_process.pid})")
        
        # 启动线程读取 stderr
        self.qemu_stderr_thread = threading.Thread(
            target=self._read_qemu_stderr,
            daemon=True
        )
        self.qemu_stderr_thread.start()
        
        # 等待 QEMU Ready 信号
        print("[Conductor] 等待 QEMU Ready 信号...")
        ready, _, _ = select.select([self.status_pipe_read], [], [], 10.0)
        if ready:
            status_bytes = os.read(self.status_pipe_read, 4)
            if status_bytes:
                status = struct.unpack('i', status_bytes)[0]
                if status == 1:  # Ready
                    print("[Conductor] QEMU 已就绪，发送初始命令")
                    os.write(self.cmd_pipe_write, b'F')
                else:
                    print(f"[Conductor] 收到意外状态: {status}")
        else:
            print("[Conductor] ⚠️  等待 QEMU Ready 信号超时")
    
    def send_fuzz_command(self, instructions: List[FuzzInstruction]) -> Optional[str]:
        """
        发送 Fuzz 命令并等待结果
        
        Args:
            instructions: 指令列表
        
        Returns:
            执行状态字符串，失败返回 None
        """
        # 写入共享内存
        self.shm.write_instructions(instructions)
        
        # 发送 'F' 命令
        os.write(self.cmd_pipe_write, b'F')
        
        # 等待执行结果（最多等待 30 秒）
        timeout = 30.0
        start = time.time()
        
        while time.time() - start < timeout:
            ready, _, _ = select.select([self.status_pipe_read], [], [], 1.0)
            if not ready:
                continue
            
            status_bytes = os.read(self.status_pipe_read, 4)
            if not status_bytes:
                return None
            
            status = struct.unpack('i', status_bytes)[0]
            
            # 状态码映射
            if status == 2:  # At Fork Point
                print('[Conductor] 到达 Fork 点，继续执行...')
                os.write(self.cmd_pipe_write, b'F')
                continue
            elif status == 1:  # Ready
                continue
            elif status == 3:  # Normal Exit
                return "正常退出"
            elif status == 4:  # Crash
                self.crashes.append(self.total_executions + 1)
                print(f"[Conductor] 💥 崩溃！ (执行 #{self.total_executions + 1})")
                return "崩溃"
            elif status == 5:  # Other Signal
                return "其他信号"
            else:
                return f"未知状态({status})"
        
        print("[Conductor] ⚠️  执行超时")
        return None
    
    def run(self, rounds: int):
        """
        运行模糊测试主循环
        
        Args:
            rounds: 迭代轮数
        """
        self.start_time = time.time()
        print(f"\n{'='*60}")
        print(f"[Conductor] 开始模糊测试: {rounds} 轮")
        print(f"{'='*60}\n")
        
        for i in range(rounds):
            if _shutdown_requested:
                break
            
            print(f"\n[Conductor] ===== 第 {i+1}/{rounds} 轮 =====")
            
            # 生成变异指令
            instructions = self.mutator.build_instructions(i)
            if not instructions:
                print("[Conductor] 未生成指令，跳过本轮")
                continue
            
            # 执行模糊测试
            status = self.send_fuzz_command(instructions)
            if status is None:
                print("[Conductor] QEMU 意外终止")
                break
            
            self.total_executions += 1
            print(f"[Conductor] 执行结果: {status}")
            
            # 检查覆盖率
            current_coverage = self.coverage_tracker.read_coverage()
            if current_coverage and self.coverage_tracker.has_new_coverage(current_coverage):
                print(f"[Conductor] 🎯 发现新覆盖率！")
                self.new_seeds.append(i + 1)
            
            # 崩溃立即停止
            if status == "崩溃":
                print("[Conductor] 发现崩溃，停止模糊测试")
                break
        
        self._print_statistics()
    
    def _print_statistics(self):
        """打印统计信息"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        cov_stats = self.coverage_tracker.get_stats()
        
        print(f"\n{'='*60}")
        print(f"模糊测试统计")
        print(f"{'='*60}")
        print(f"总执行次数:   {self.total_executions}")
        print(f"发现崩溃:     {len(self.crashes)}")
        print(f"新种子数:     {len(self.new_seeds)}")
        print(f"总边数:       {cov_stats['total_edges']}")
        print(f"新边数:       {cov_stats['new_edges_this_run']}")
        print(f"位图密度:     {cov_stats['bitmap_density']:.2f}%")
        print(f"总耗时:       {elapsed:.2f}s")
        if self.total_executions > 0:
            print(f"平均迭代耗时: {elapsed/self.total_executions:.3f}s")
        print(f"{'='*60}\n")
    
    def cleanup(self):
        """清理资源"""
        print("[Conductor] 清理资源...")
        
        # 终止 QEMU
        if self.qemu_process and self.qemu_process.poll() is None:
            try:
                os.write(self.cmd_pipe_write, b'Q')
                self.qemu_process.wait(timeout=5)
            except:
                self.qemu_process.terminate()
                try:
                    self.qemu_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.qemu_process.kill()
        
        # 关闭管道
        for fd in [self.cmd_pipe_read, self.cmd_pipe_write, 
                   self.status_pipe_read, self.status_pipe_write]:
            try:
                os.close(fd)
            except:
                pass
        
        # 清理共享内存
        self.shm.close()
        
        print("[Conductor] ✅ 清理完成")
        

# ========== 主函数 ==========
def main():
    """主函数"""
    global _conductor_instance
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='RR-Fuzz 单进程模糊测试指挥器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基础用法
  python3 fuzz_conductor.py --qemu ./qemu --trace trace.bin --target ./program
  
  # 使用配方
  python3 fuzz_conductor.py --qemu ./qemu --trace trace.bin --target ./program --recipe recipes.json
  
  # 生产环境（推荐多进程）
  python3 multiprocess/fuzz_master.py -n 8 -p ./program -q ./qemu -t ./trace.bin

更多信息请查看: USAGE_GUIDE.md
        """
    )
    
    parser.add_argument('--qemu', required=True,
                        help='QEMU 可执行文件路径')
    parser.add_argument('--target', required=True,
                        help='目标程序路径')
    parser.add_argument('--trace', required=True,
                        help='Trace 文件路径')
    parser.add_argument('--iterations', type=int, default=100,
                        help='迭代次数（默认: 100）')
    parser.add_argument('--recipe', default=None,
                        help='配方文件路径（可选）')
    parser.add_argument('--init-mode', default='adaptive',
                       choices=['adaptive', 'static', 'disabled'],
                        help='初始化检测模式（默认: adaptive）')
    
    args = parser.parse_args()
    
    # 检查文件存在
    if not os.path.exists(args.trace):
        print(f"❌ 错误: Trace 文件不存在: {args.trace}")
        return 1
    
    if not os.path.exists(args.target):
        print(f"❌ 错误: 目标程序不存在: {args.target}")
        return 1
    
    if not os.path.exists(args.qemu):
        print(f"❌ 错误: QEMU 不存在: {args.qemu}")
        return 1
    
    # 创建指挥器
    try:
        conductor = FuzzConductor(
            qemu_path=args.qemu,
            target_binary=args.target,
            trace_file=args.trace,
            recipe_file=args.recipe,
            init_mode=args.init_mode
        )
        _conductor_instance = conductor
        
        # 启动 QEMU
        conductor.start_qemu()
        
        # 运行模糊测试
        conductor.run(args.iterations)
        
        # 清理
        conductor.cleanup()
        print("\n✅ 模糊测试完成！")
        return 0
        
    except KeyboardInterrupt:
        print("\n[Conductor] 用户中断")
        if _conductor_instance:
            _conductor_instance.cleanup()
        return 130
    
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        if _conductor_instance:
            _conductor_instance.cleanup()
        return 1


if __name__ == '__main__':
    sys.exit(main())


#!/usr/bin/env python3
"""
RR-Fuzz Conductor 示例脚本

演示如何通过IPC与QEMU进行通信，发送Fuzz指令并接收执行结果

使用方法:
    python3 fuzz_conductor_example.py --trace trace.strace --target ./target_program
"""

import os
import sys
import struct
import mmap
import subprocess
import argparse
import select
import threading
import signal
from pathlib import Path

# ===== Fuzz指令类型定义（与C端保持一致）=====
FUZZ_CMD_NONE = 0
FUZZ_CMD_MUTATE_ARG = 1
FUZZ_CMD_REPLACE_BUFFER = 2
FUZZ_CMD_MUTATE_FLAGS = 3
FUZZ_CMD_BOUNDARY_VALUE = 4

FUZZ_MAGIC = 0x46555A5A  # "FUZZ"
FUZZ_MAX_INSTRUCTIONS = 32

# 全局变量用于信号处理
_conductor_instance = None
_shutdown_requested = False


def signal_handler(signum, frame):
    """处理Ctrl+C等信号"""
    global _shutdown_requested, _conductor_instance
    print(f"\n[Conductor] ⚠️  Signal {signum} received, shutting down gracefully...")
    _shutdown_requested = True
    
    # 不在这里cleanup，让主循环自然退出后在finally中cleanup
    # 这样避免重复cleanup和异常处理问题


class FuzzInstruction:
    """单个Fuzz指令"""
    def __init__(self, syscall_index, cmd, arg_index, data):
        self.syscall_index = syscall_index
        self.cmd = cmd
        self.arg_index = arg_index
        self.data = data
    
    def pack(self):
        """打包成二进制格式（对应C结构体）"""
        # struct FuzzInstruction {
        #     uint32_t syscall_index;
        #     uint32_t cmd;           // fuzz_cmd_type_t (enum)
        #     uint8_t arg_index;
        #     uint16_t data_len;
        #     uint8_t data[256];
        # }
        data_bytes = self.data if isinstance(self.data, bytes) else struct.pack('q', self.data)
        data_len = len(data_bytes)
        
        # 填充到256字节
        padded_data = data_bytes + b'\x00' * (256 - data_len)
        
        return struct.pack('IIBH256s', 
                          self.syscall_index,
                          self.cmd,
                          self.arg_index,
                          data_len,
                          padded_data)


class FuzzSharedMemory:
    """共享内存管理器"""
    def __init__(self, shm_name, size=64 * 1024):
        self.shm_name = shm_name
        self.size = size
        self.shm_fd = None
        self.mem = None
    
    def create(self):
        """创建共享内存"""
        # 使用 /dev/shm （Linux共享内存）
        shm_path = f"/dev/shm/{self.shm_name}"
        
        # 创建或打开共享内存文件
        self.shm_fd = os.open(shm_path, os.O_CREAT | os.O_RDWR, 0o666)
        os.ftruncate(self.shm_fd, self.size)
        
        # 映射到内存
        self.mem = mmap.mmap(self.shm_fd, self.size)
        
        print(f"[Conductor] Created shared memory: {shm_path} ({self.size} bytes)")
        return self
    
    def write_instructions(self, instructions):
        """写入Fuzz指令到共享内存"""
        if not self.mem:
            raise RuntimeError("Shared memory not created")
        
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            raise ValueError(f"Too many instructions: {len(instructions)} (max {FUZZ_MAX_INSTRUCTIONS})")
        
        # 写入头部：magic + count + flags + reserved
        header = struct.pack('IIII', FUZZ_MAGIC, len(instructions), 0, 0)
        self.mem.seek(0)
        self.mem.write(header)
        
        # 写入指令数组
        for instr in instructions:
            self.mem.write(instr.pack())
        
        print(f"[Conductor] Wrote {len(instructions)} instructions to shared memory")
    
    def close(self):
        """关闭共享内存"""
        try:
            if self.mem:
                self.mem.close()
                self.mem = None
        except:
            pass
        
        try:
            if self.shm_fd:
                os.close(self.shm_fd)
                self.shm_fd = None
        except:
            pass
        
        # 清理共享内存文件
        try:
            shm_path = f"/dev/shm/{self.shm_name}"
            if os.path.exists(shm_path):
                os.unlink(shm_path)
        except:
            pass


class FuzzConductor:
    """Fuzz控制器 - 与QEMU进行IPC通信"""
    
    def __init__(self, qemu_path, target_binary, trace_file):
        self.qemu_path = qemu_path
        self.target_binary = target_binary
        self.trace_file = trace_file
        
        # IPC管道
        self.cmd_pipe_read, self.cmd_pipe_write = os.pipe()
        self.status_pipe_read, self.status_pipe_write = os.pipe()
        
        # 共享内存
        self.shm = FuzzSharedMemory(f"rr_fuzz_{os.getpid()}")
        self.shm.create()
        
        self.qemu_process = None
        self.total_executions = 0
        self.crashes = []
        self.qemu_stderr_thread = None
    
    def _read_qemu_stderr(self):
        """在单独线程中读取QEMU的stderr输出，防止管道缓冲区满导致死锁"""
        if not self.qemu_process or not self.qemu_process.stderr:
            return
        
        try:
            while True:
                line = self.qemu_process.stderr.readline()
                if not line:
                    break
                # 实时打印QEMU的调试输出
                print(f"[QEMU] {line.decode('utf-8', errors='ignore').rstrip()}")
        except Exception as e:
            print(f"[Conductor] Error reading QEMU stderr: {e}")
    
    def start_qemu(self):
        """启动QEMU进程（Fuzzing模式）"""
        env = os.environ.copy()
        env.update({
            'RR_DEBUG_LEVEL':'4',
            'RR_FUZZING_ENABLED': 'True',
            'RR_MODE': 'fuzzing',  # 关键：设置为fuzzing模式
            'RR_STRACE_MODE': 'True',  # 使用strace重放
            'RR_TRACE_FILE': self.trace_file,
            'RR_CMD_PIPE': str(self.cmd_pipe_read),
            'RR_STATUS_PIPE': str(self.status_pipe_write),
            'RR_SHARED_MEMORY': self.shm.shm_name,
        })
        # 注意：不设置 RR_FORK_SYSCALL，启用自动检测
        
        # 构建QEMU命令
        cmd = [self.qemu_path, self.target_binary]
        
        print(f"[Conductor] Starting QEMU: {' '.join(cmd)}")
        print(f"[Conductor] Trace file: {self.trace_file}")
        
        # 启动QEMU子进程
        self.qemu_process = subprocess.Popen(
            cmd,
            env=env,
            pass_fds=[self.cmd_pipe_read, self.status_pipe_write],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        print(f"[Conductor] QEMU started (PID={self.qemu_process.pid})")
        
        # 启动线程读取QEMU的stderr，防止管道缓冲区满导致死锁
        self.qemu_stderr_thread = threading.Thread(target=self._read_qemu_stderr, daemon=True)
        self.qemu_stderr_thread.start()
        
        # 等待QEMU发送Ready状态
        print("[Conductor] Waiting for QEMU Ready signal...")
        ready, _, _ = select.select([self.status_pipe_read], [], [], 10.0)
        if ready:
            status_bytes = os.read(self.status_pipe_read, 4)
            if status_bytes:
                status = struct.unpack('i', status_bytes)[0]
                if status == 1:  # Ready
                    print("[Conductor] QEMU is Ready, sending initial 'F' command")
                    os.write(self.cmd_pipe_write, b'F')  # 发送第一个'F'让QEMU开始执行
                else:
                    print(f"[Conductor] Unexpected status: {status}")
        else:
            print("[Conductor] ⚠️  Timeout waiting for QEMU Ready signal")
    
    def send_fuzz_command(self, instructions):
        """发送Fuzz命令"""
        # 1. 写入共享内存
        self.shm.write_instructions(instructions)
        
        # 2. 发送'F'命令触发fork
        os.write(self.cmd_pipe_write, b'F')
        print(f"[Conductor] ✅ Sent 'F' command to QEMU (pipe_fd={self.cmd_pipe_write})")
        
        # 3. 等待执行结果 (添加超时保护)
        # 使用select()实现超时读取 (30秒超时，给复杂执行更多时间)
        ready, _, _ = select.select([self.status_pipe_read], [], [], 30.0)
        
        if not ready:
            print("[Conductor] ⚠️  Timeout waiting for QEMU response (30s), retrying once...")
            # 给一次重试机会
            ready, _, _ = select.select([self.status_pipe_read], [], [], 10.0)
            
            if not ready:
                print("[Conductor] ⚠️  Second timeout, terminating QEMU...")
                if self.qemu_process and self.qemu_process.poll() is None:
                    self.qemu_process.terminate()
                    try:
                        self.qemu_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.qemu_process.kill()
                return None
        
        status_bytes = os.read(self.status_pipe_read, 4)
        if not status_bytes:
            return None
        
        status = struct.unpack('i', status_bytes)[0]
        self.total_executions += 1
        
        return self._parse_status(status)
    
    def _parse_status(self, status):
        """解析执行状态"""
        status_map = {
            1: "Ready",
            2: "At Fork Point",
            3: "Normal Exit",
            4: "Crash Found",  # 崩溃！
            5: "Other Signal",
            -1: "Error"
        }
        
        status_name = status_map.get(status, f"Unknown({status})")
        print(f"[Conductor] Execution #{self.total_executions}: {status_name}")
        
        if status == 4:
            self.crashes.append(self.total_executions)
            print(f"[Conductor] 💥 CRASH DETECTED in execution #{self.total_executions}")
        
        return status
    
    def run_fuzzing_campaign(self, num_iterations=100):
        """运行Fuzzing测试"""
        global _shutdown_requested
        print(f"\n[Conductor] Starting fuzzing campaign ({num_iterations} iterations)")
        
        consecutive_failures = 0
        max_consecutive_failures = 3  # 允许连续3次失败
        
        for i in range(num_iterations):
            # 检查是否请求停止
            if _shutdown_requested:
                print(f"[Conductor] Shutdown requested, stopping at iteration {i}")
                break
            
            # 生成变异指令（示例：对第15个系统调用的第2个参数进行变异）
            instructions = self._generate_mutations(i)
            
            # 发送并执行
            status = self.send_fuzz_command(instructions)
            
            if status is None:
                consecutive_failures += 1
                print(f"[Conductor] ⚠️  QEMU process issue (failure {consecutive_failures}/{max_consecutive_failures})")
                
                if consecutive_failures >= max_consecutive_failures:
                    print(f"[Conductor] ❌ Too many consecutive failures, stopping campaign")
                    break
                else:
                    print(f"[Conductor] 🔄 Continuing fuzzing campaign...")
                    continue
            else:
                consecutive_failures = 0  # 重置失败计数
            
            # 处理不同的执行结果
            if status == 4:
                print(f"[Conductor] 💥 CRASH FOUND in iteration #{i}! Saving testcase...")
                # 保存触发崩溃的指令
                crash_file = f"crash_{self.total_executions}_{i}.txt"
                try:
                    with open(crash_file, 'w') as f:
                        f.write(f"=== CRASH TESTCASE ===\n")
                        f.write(f"Iteration: {i}\n")
                        f.write(f"Execution: {self.total_executions}\n")
                        f.write(f"Timestamp: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"\n=== FUZZ INSTRUCTIONS ===\n")
                        for idx, instr in enumerate(instructions):
                            f.write(f"Instruction {idx}:\n")
                            f.write(f"  Command: {instr.cmd}\n")
                            f.write(f"  Syscall Index: {instr.syscall_index}\n")
                            f.write(f"  Arg Index: {instr.arg_index}\n")
                            f.write(f"  Value: {instr.value}\n")
                            f.write(f"  Size: {instr.size}\n")
                            f.write(f"\n")
                    print(f"[Conductor] 💾 Crash testcase saved: {crash_file}")
                except Exception as e:
                    print(f"[Conductor] ⚠️  Failed to save crash: {e}")
            elif status == 3:
                # Normal exit - 静默处理，避免日志噪音
                pass
            elif status == 5:
                print(f"[Conductor] ⚠️  Child terminated by signal (iteration #{i})")
            elif status == -1:
                print(f"[Conductor] ❌ Error status received (iteration #{i})")
        
        print(f"\n[Conductor] Fuzzing campaign completed")
        print(f"[Conductor] Total executions: {self.total_executions}")
        print(f"[Conductor] Crashes found: {len(self.crashes)}")
    
    def _generate_mutations(self, iteration):
        """生成变异指令（示例策略）"""
        # 简单策略：每次变异不同的系统调用
        syscall_index = 15 + (iteration % 10)  # 轮流变异第15-24个系统调用
        
        mutations = []
        
        # 变异1：参数边界值测试
        mutations.append(FuzzInstruction(
            syscall_index=syscall_index,
            cmd=FUZZ_CMD_BOUNDARY_VALUE,
            arg_index=2,
            data=-1  # 测试-1（常见的错误值）
        ))
        
        # 变异2：标志位翻转
        if iteration % 3 == 0:
            mutations.append(FuzzInstruction(
                syscall_index=syscall_index,
                cmd=FUZZ_CMD_MUTATE_FLAGS,
                arg_index=3,
                data=0xFFFF  # XOR掩码
            ))
        
        return mutations
    
    def cleanup(self):
        """清理资源"""
        # 发送退出命令
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
        
        # 关闭管道（添加异常保护）
        for fd in [self.cmd_pipe_read, self.cmd_pipe_write, 
                   self.status_pipe_read, self.status_pipe_write]:
            try:
                os.close(fd)
            except:
                pass
        
        # 清理共享内存
        self.shm.close()
        
        print("[Conductor] Cleanup completed")


def main():
    global _conductor_instance
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description='RR-Fuzz Conductor Example')
    parser.add_argument('--qemu', default='qemu-x86_64', help='QEMU binary path')
    parser.add_argument('--target', required=True, help='Target program to fuzz')
    parser.add_argument('--trace', required=True, help='Strace trace file')
    parser.add_argument('--iterations', type=int, default=100, help='Number of fuzz iterations')
    
    args = parser.parse_args()
    
    # 检查文件存在
    if not os.path.exists(args.trace):
        print(f"Error: Trace file not found: {args.trace}")
        return 1
    
    if not os.path.exists(args.target):
        print(f"Error: Target binary not found: {args.target}")
        return 1
    
    print("🚀 RR-Fuzz Conductor - Auto Detection Mode")
    print(f"  - Target: {args.target}")
    print(f"  - Trace: {args.trace}")
    print(f"  - Mode: AUTO (智能检测所有 P_IO 系统调用)")
    print(f"  - Iterations: {args.iterations}")
    print(f"  - Press Ctrl+C to stop gracefully")
    print()
    
    # 创建Conductor并运行
    conductor = FuzzConductor(args.qemu, args.target, args.trace)
    _conductor_instance = conductor  # 保存全局引用供信号处理器使用
    
    try:
        conductor.start_qemu()
        conductor.run_fuzzing_campaign(args.iterations)
    except KeyboardInterrupt:
        print("\n[Conductor] Interrupted by user")
    finally:
        conductor.cleanup()
        _conductor_instance = None
    
    return 0


if __name__ == '__main__':
    sys.exit(main())


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
from pathlib import Path

# ===== Fuzz指令类型定义（与C端保持一致）=====
FUZZ_CMD_NONE = 0
FUZZ_CMD_MUTATE_ARG = 1
FUZZ_CMD_REPLACE_BUFFER = 2
FUZZ_CMD_MUTATE_FLAGS = 3
FUZZ_CMD_BOUNDARY_VALUE = 4

FUZZ_MAGIC = 0x46555A5A  # "FUZZ"
FUZZ_MAX_INSTRUCTIONS = 32


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
        if self.mem:
            self.mem.close()
        if self.shm_fd:
            os.close(self.shm_fd)
        
        # 清理共享内存文件
        shm_path = f"/dev/shm/{self.shm_name}"
        if os.path.exists(shm_path):
            os.unlink(shm_path)


class FuzzConductor:
    """Fuzz控制器 - 与QEMU进行IPC通信"""
    
    def __init__(self, qemu_path, target_binary, trace_file, fork_syscall="openat", fork_pattern=None):
        self.qemu_path = qemu_path
        self.target_binary = target_binary
        self.trace_file = trace_file
        self.fork_syscall = fork_syscall      # 新增：fork系统调用
        self.fork_pattern = fork_pattern      # 新增：路径匹配模式
        
        # IPC管道
        self.cmd_pipe_read, self.cmd_pipe_write = os.pipe()
        self.status_pipe_read, self.status_pipe_write = os.pipe()
        
        # 共享内存
        self.shm = FuzzSharedMemory(f"rr_fuzz_{os.getpid()}")
        self.shm.create()
        
        self.qemu_process = None
        self.total_executions = 0
        self.crashes = []
    
    def start_qemu(self):
        """启动QEMU进程（Fuzzing模式）"""
        env = os.environ.copy()
        env.update({
            'RR_DEBUG_LEVEL':'4',
            'RR_FUZZING_ENABLED': 'True',
            'RR_MODE': 'fuzzing',  # 关键：设置为fuzzing模式
            'RR_STRACE_MODE': 'True',  # 使用strace重放
            'RR_TRACE_FILE': self.trace_file,
            'RR_FORK_SYSCALL': self.fork_syscall,   # 🔥 新增：基于系统调用的fork点
            'RR_CMD_PIPE': str(self.cmd_pipe_read),
            'RR_STATUS_PIPE': str(self.status_pipe_write),
            'RR_SHARED_MEMORY': self.shm.shm_name,
        })
        
        # 如果有路径模式，添加到环境变量
        if self.fork_pattern:
            env['RR_FORK_PATTERN'] = self.fork_pattern
        
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
    
    def send_fuzz_command(self, instructions):
        """发送Fuzz命令"""
        # 1. 写入共享内存
        self.shm.write_instructions(instructions)
        
        # 2. 发送'F'命令触发fork
        os.write(self.cmd_pipe_write, b'F')
        print(f"[Conductor] Sent 'F' command to QEMU")
        
        # 3. 等待执行结果
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
        print(f"\n[Conductor] Starting fuzzing campaign ({num_iterations} iterations)")
        
        for i in range(num_iterations):
            # 生成变异指令（示例：对第15个系统调用的第2个参数进行变异）
            instructions = self._generate_mutations(i)
            
            # 发送并执行
            status = self.send_fuzz_command(instructions)
            
            if status is None:
                print("[Conductor] QEMU process terminated unexpectedly")
                break
            
            if status == 4:
                print(f"[Conductor] Found crash! Saving testcase #{i}")
                # 这里可以保存触发崩溃的指令
        
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
        if self.qemu_process:
            # 发送退出命令
            try:
                os.write(self.cmd_pipe_write, b'Q')
                self.qemu_process.wait(timeout=5)
            except:
                self.qemu_process.kill()
        
        # 关闭管道
        os.close(self.cmd_pipe_read)
        os.close(self.cmd_pipe_write)
        os.close(self.status_pipe_read)
        os.close(self.status_pipe_write)
        
        # 清理共享内存
        self.shm.close()
        
        print("[Conductor] Cleanup completed")


def main():
    parser = argparse.ArgumentParser(description='RR-Fuzz Conductor Example')
    parser.add_argument('--qemu', default='qemu-x86_64', help='QEMU binary path')
    parser.add_argument('--target', required=True, help='Target program to fuzz')
    parser.add_argument('--trace', required=True, help='Strace trace file')
    parser.add_argument('--iterations', type=int, default=100, help='Number of fuzz iterations')
    
    # 🔥 新增：Fork点配置参数
    parser.add_argument('--fork-syscall', default='openat', 
                       help='System call to fork on (default: openat)')
    parser.add_argument('--fork-pattern', 
                       help='Path pattern to match (e.g., "*/input*", "/tmp/*")')
    
    args = parser.parse_args()
    
    # 检查文件存在
    if not os.path.exists(args.trace):
        print(f"Error: Trace file not found: {args.trace}")
        return 1
    
    if not os.path.exists(args.target):
        print(f"Error: Target binary not found: {args.target}")
        return 1
    
    print(f"🎯 Fork Configuration:")
    print(f"  - System call: {args.fork_syscall}")
    print(f"  - Path pattern: {args.fork_pattern or 'none (match all)'}")
    print()
    
    # 创建Conductor并运行
    conductor = FuzzConductor(args.qemu, args.target, args.trace, 
                             args.fork_syscall, args.fork_pattern)
    
    try:
        conductor.start_qemu()
        conductor.run_fuzzing_campaign(args.iterations)
    except KeyboardInterrupt:
        print("\n[Conductor] Interrupted by user")
    finally:
        conductor.cleanup()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())


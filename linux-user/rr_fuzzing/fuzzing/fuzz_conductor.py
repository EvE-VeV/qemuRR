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
import json
import time
from datetime import datetime
from pathlib import Path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../analysis'))
USE_FIXED_PARSER = False  # 暂时禁用，因为trace_parser_fixed不返回结构化数据
from trace_analyzer import TraceAnalyzer

# ===== Fuzz指令类型定义（与C端保持一致）=====
FUZZ_CMD_NONE = 0
FUZZ_CMD_MUTATE_ARG = 1
FUZZ_CMD_REPLACE_BUFFER = 2
FUZZ_CMD_MUTATE_FLAGS = 3
FUZZ_CMD_BOUNDARY_VALUE = 4

# === 常量定义（对应 rr_constants.h）===
# 注意：这些值必须与 C 端保持严格一致！

FUZZ_MAGIC = 0x46555A5A  # "FUZZ" - 共享内存魔数
FUZZ_MAX_INSTRUCTIONS = 32  # 指令队列最大长度
FUZZ_INSTRUCTION_DATA = 256  # 每条指令的数据负载大小
FUZZ_SHM_SIZE = 64 * 1024  # 共享内存大小：64KB（⚠️ 必须与 rr_constants.h 一致）

# === Phase 1: 初始化阶段过滤配置 ===
# 这些系统调用在初始化阶段不应被变异，以避免破坏内存布局
INIT_SYSCALLS = {'mmap', 'brk', 'set_tid_address', 'set_robust_list', 'arch_prctl',
                 'munmap', 'mprotect', 'rt_sigprocmask', 'rt_sigaction'}

# 初始化阶段阈值：前 N 个 syscall 中的初始化调用将被跳过
# 来源：rr_constants.h 中的 RR_INIT_PHASE_THRESHOLD
# 注意：这是一个启发式值，未来应该改为自适应检测
# TODO: 从配置文件读取，支持运行时覆盖
INIT_PHASE_THRESHOLD = 10

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
        # 🔥 修正：C端的结构体定义（rr_framework.h:68-74）：
        # typedef struct {
        #     fuzz_cmd_type_t cmd;        // 第1个字段 (uint32)
        #     uint32_t syscall_index;     // 第2个字段
        #     uint32_t arg_index;         // 第3个字段
        #     uint32_t data_len;          // 第4个字段
        #     uint8_t data[256];          // 第5个字段
        # } FuzzInstruction;
        data_bytes = self.data if isinstance(self.data, bytes) else struct.pack('q', self.data)
        data_len = len(data_bytes)
        
        # 填充到256字节
        padded_data = data_bytes + b'\x00' * (256 - data_len)
        
        # 按照C端的字段顺序打包
        return struct.pack('IIII256s', 
                          self.cmd,                # 第1个：cmd
                          self.syscall_index,      # 第2个：syscall_index  
                          self.arg_index,          # 第3个：arg_index
                          data_len,                # 第4个：data_len
                          padded_data)             # 第5个：data


class FuzzSharedMemory:
    """共享内存管理器"""
    def __init__(self, shm_name, size=FUZZ_SHM_SIZE):
        self.shm_name = shm_name
        self.size = size
        self.shm_fd = None
        self.mem = None
        self.sequence = 0  # 序列号计数器
    
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
        """写入Fuzz指令到共享内存，带序列号和校验"""
        if not self.mem:
            raise RuntimeError("Shared memory not created")
        
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            raise ValueError(f"Too many instructions: {len(instructions)} (max {FUZZ_MAX_INSTRUCTIONS})")
        
        # 递增序列号
        self.sequence += 1
        count = len(instructions)
        
        # 计算校验和：magic ^ sequence ^ count
        checksum = FUZZ_MAGIC ^ self.sequence ^ count
        
        # 写入头部：magic + sequence + count + checksum + flags + reserved[3]
        header = struct.pack('IIIIII', FUZZ_MAGIC, self.sequence, count, checksum, 0, 0)
        # reserved[3] 需要两个额外的 I (total 8 uint32_t)
        header += struct.pack('II', 0, 0)
        
        self.mem.seek(0)
        self.mem.write(header)
        
        # 写入指令数组
        for instr in instructions:
            self.mem.write(instr.pack())
        
        # 强制刷新到磁盘
        self.mem.flush()
        
        print(f"[Conductor] Wrote {count} instructions to shared memory (seq={self.sequence}, checksum=0x{checksum:x})")
    
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


class SmartMutator:
    def __init__(self, trace_file):
        # ✅ 修复：恢复自动解析，使用修复后的TraceAnalyzer
        print(f"[Mutator] Analyzing trace file: {trace_file}")
        
        # 导入并使用修复后的TraceAnalyzer
        from trace_analyzer import TraceAnalyzer
        
        analyzer = TraceAnalyzer(trace_file)
        if not analyzer.analyze():
            raise RuntimeError(f"Failed to analyze trace: {trace_file}")
        
        # 获取所有pure syscalls（有aux_data的syscalls）
        pure_syscalls = analyzer.get_pure_syscalls()
        
        # 定义Candidate类
        class Candidate:
            def __init__(self, index, name, nr):
                self.index = index
                self.name = name
                self.syscall_nr = nr
        
        # 转换为Candidate对象
        self.pure_candidates = [
            Candidate(sc.index, sc.name, sc.syscall_nr)
            for sc in pure_syscalls
        ]
        
        # 获取hybrid syscalls（无aux_data的syscalls）
        hybrid_syscalls = analyzer.get_hybrid_syscalls()
        self.hybrid_candidates = [
            Candidate(sc.index, sc.name, sc.syscall_nr)
            for sc in hybrid_syscalls
        ]
        
        # 保存所有syscalls供后续使用
        self.syscalls = analyzer.syscalls
        
        print(f"[Mutator] ✅ Found {len(self.pure_candidates)} pure replay syscalls:")
        for cand in self.pure_candidates[:10]:  # 只打印前10个
            print(f"[Mutator]   index={cand.index}, name={cand.name}, nr={cand.syscall_nr}")
        if len(self.pure_candidates) > 10:
            print(f"[Mutator]   ... and {len(self.pure_candidates) - 10} more")
        
        # Phase 1: 过滤不可变异的 syscall
        self.mutable_candidates = self._filter_mutable_candidates()
    
    def _parse_trace_for_candidates(self, trace_file):
        """手动解析trace文件，找到所有有aux_data的syscalls"""
        candidates = []
        
        # 简化的Candidate类
        class Candidate:
            def __init__(self, index, name, nr):
                self.index = index
                self.name = name
                self.syscall_nr = nr
        
        # 已知的系统调用号映射
        syscall_names = {
            0: 'read', 1: 'write', 9: 'mmap', 10: 'mprotect',
            12: 'brk', 44: 'sendto', 45: 'recvfrom'
        }
        
        try:
            with open(trace_file, 'rb') as f:
                # 读取头部
                header = f.read(12)
                if len(header) < 12:
                    print("[Mutator] ❌ Trace file too short")
                    return candidates
                
                magic, version, count = struct.unpack('<III', header)
                print(f"[Mutator] Trace: magic=0x{magic:x}, version={version}, count={count}")
                
                for i in range(count):
                    try:
                        # 读取record header
                        rec_header = f.read(8)
                        if len(rec_header) < 8:
                            break
                        
                        index, syscall_nr = struct.unpack('<Ii', rec_header)
                        
                        # 跳过args (72) + arg_sizes (64) + timestamps (16) + flags (6) = 158 bytes
                        f.read(158)
                        
                        # 读取arg_data (跳过直到-1标记)
                        while True:
                            arg_idx_bytes = f.read(4)
                            if len(arg_idx_bytes) < 4:
                                break
                            arg_idx = struct.unpack('<i', arg_idx_bytes)[0]
                            if arg_idx == -1:
                                break
                            # 跳过size(8) + data
                            size_bytes = f.read(8)
                            if len(size_bytes) < 8:
                                break
                            size = struct.unpack('<Q', size_bytes)[0]
                            f.read(size)
                        
                        # 读取aux marker
                        marker_bytes = f.read(4)
                        if len(marker_bytes) < 4:
                            break
                        
                        marker = struct.unpack('<I', marker_bytes)[0]
                        
                        if marker == 0x41555844:  # "AUXD"
                            # 有aux_data!
                            name = syscall_names.get(syscall_nr, f'syscall_{syscall_nr}')
                            cand = Candidate(index, name, syscall_nr)
                            candidates.append(cand)
                            print(f"[Mutator] ✅ Found candidate: index={index}, name={name}, nr={syscall_nr}")
                            
                            # 跳过aux_data
                            aux_count_bytes = f.read(4)
                            if len(aux_count_bytes) < 4:
                                break
                            aux_count = struct.unpack('<I', aux_count_bytes)[0]
                            for _ in range(aux_count):
                                # kind(1) + arg_mask(1) + size(4)
                                aux_header = f.read(6)
                                if len(aux_header) < 6:
                                    break
                                aux_size = struct.unpack('<I', aux_header[2:6])[0]
                                f.read(aux_size)  # 跳过data
                    
                    except Exception as e:
                        print(f"[Mutator] Error parsing record {i}: {e}")
                        break
        
        except Exception as e:
            print(f"[Mutator] Error opening trace file: {e}")
        
        print(f"[Mutator] Found {len(candidates)} pure candidates")
        return candidates
    
    def _should_skip_mutation(self, syscall_info, index):
        """判断是否应跳过该 syscall 的变异
        
        Args:
            syscall_info: 系统调用信息对象
            index: 在 trace 中的索引位置
        
        Returns:
            bool: True 表示应跳过，False 表示可以变异
        """
        syscall_name = getattr(syscall_info, 'name', '').lower()
        
        # 🔥 关键修复：重要的IO syscalls永远不跳过
        IMPORTANT_SYSCALLS = {'send', 'sendto', 'recv', 'recvfrom', 'write', 'read'}
        if syscall_name in IMPORTANT_SYSCALLS:
            print(f"[Mutator] ✅ Keeping important IO syscall: {syscall_name} (index={index})")
            return False  # 永不跳过
        
        # 1. 跳过初始化阶段的关键 syscall
        if index < INIT_PHASE_THRESHOLD:
            if any(init_sc in syscall_name for init_sc in INIT_SYSCALLS):
                print(f"[Mutator] ⏭️  Skipping init syscall: {syscall_name} (index={index})")
                return True
        
        # 2. 跳过没有可变异数据的 syscall（将来可扩展）
        # 目前 TraceAnalyzer 已经筛选出 pure/hybrid candidates
        
        return False
    
    def _filter_mutable_candidates(self):
        """过滤出真正可变异的 candidate
        
        Returns:
            list: 可安全变异的 syscall 候选列表
        """
        mutable = []
        
        # 合并 pure 和 hybrid candidates
        all_candidates = list(self.pure_candidates) + list(self.hybrid_candidates)
        
        print(f"[Mutator] 📋 Filtering {len(all_candidates)} candidates...")
        
        for candidate in all_candidates:
            if not self._should_skip_mutation(candidate, candidate.index):
                mutable.append(candidate)
        
        print(f"[Mutator] ✅ Filtered result: {len(mutable)} mutable candidates")
        print(f"[Mutator] 📝 Mutable candidates:")
        for i, cand in enumerate(mutable):
            print(f"[Mutator]   [{i}] index={cand.index}, name={cand.name}")
        
        return mutable
    
    def build_instructions(self, iteration):
        """构建 Fuzz 指令
        
        Phase 1 改进：单次变异策略（每次迭代只变异一个 syscall）
        
        Args:
            iteration: 当前迭代次数
        
        Returns:
            list: FuzzInstruction 列表
        """
        instrs = []
        
        if not self.mutable_candidates:
            print("[Mutator] ⚠️  No mutable candidates found!")
            return instrs
        
        # Phase 1: 单次变异 - 轮询选择一个 candidate
        target_candidate = self.mutable_candidates[iteration % len(self.mutable_candidates)]
        
        # 根据类型生成轻量级变异指令
        if target_candidate in self.pure_candidates:
            # Pure syscall: 轻量级缓冲区变异（少量数据）
            # 改为翻转几个字节，而不是完全替换
            mutation_data = bytes([0xFF ^ (iteration % 256)] * 4)  # 只变异 4 字节
            print(f"[Mutator] 🎯 Target: index={target_candidate.index}, name={target_candidate.name}, cmd=REPLACE_BUFFER({FUZZ_CMD_REPLACE_BUFFER})")
            instrs.append(FuzzInstruction(target_candidate.index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data))
        else:
            # Hybrid syscall: 标志位变异
            flag_mutation = struct.pack('q', (1 << (iteration % 32)))  # 单个 bit 翻转
            print(f"[Mutator] 🎯 Target: index={target_candidate.index}, name={target_candidate.name}, cmd=MUTATE_FLAGS({FUZZ_CMD_MUTATE_FLAGS})")
            instrs.append(FuzzInstruction(target_candidate.index, FUZZ_CMD_MUTATE_FLAGS, 0, flag_mutation))
        
        return instrs


class FuzzConductor:
    """Fuzz控制器 - 与QEMU进行IPC通信"""
    
    def __init__(self, qemu_path, target_binary, trace_file, output_format='all'):
        self.qemu_path = qemu_path
        self.target_binary = target_binary
        self.trace_file = trace_file
        self.output_format = output_format
        
        # 树可视化器（用于接收完整的 syscall 树）
        self.visualizer_proc = None
        self.trace_pipe_path = f"/tmp/rr_dynamic_trace_{os.getpid()}"
        self.tree_html_path = None
        
        # IPC管道
        self.cmd_pipe_read, self.cmd_pipe_write = os.pipe()
        self.status_pipe_read, self.status_pipe_write = os.pipe()
        
        # 共享内存
        self.shm = FuzzSharedMemory(f"rr_fuzz_{os.getpid()}")
        self.shm.create()
        
        self.smart_mutator = SmartMutator(trace_file)
        
        self.qemu_process = None
        self.total_executions = 0
        self.crashes = []
        self.qemu_stderr_thread = None
        
        # Fuzzing日志（用于输出摘要）
        self.fuzzing_log = []
        self.start_time = None
    
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
    
    def start_tree_visualizer(self):
        """启动实时树可视化器（后台进程）"""
        if self.output_format not in ['html', 'all']:
            return  # 只有需要 HTML 输出时才启动
        
        # 生成输出文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.tree_html_path = f"fuzzing_tree_{timestamp}.html"
        
        # 查找 realtime_tree_visualizer.py
        script_dir = os.path.dirname(os.path.abspath(__file__))
        visualizer_script = os.path.join(script_dir, "realtime_tree_visualizer.py")
        
        if not os.path.exists(visualizer_script):
            print(f"[Conductor] ⚠️  Tree visualizer not found: {visualizer_script}")
            return
        
        try:
            print(f"[Conductor] 🌳 Starting tree visualizer...")
            print(f"[Conductor]    Pipe: {self.trace_pipe_path}")
            print(f"[Conductor]    Output: {self.tree_html_path}")
            
            # 启动可视化器（后台进程）
            self.visualizer_proc = subprocess.Popen(
                [
                    sys.executable,
                    visualizer_script,
                    '--pipe', self.trace_pipe_path,
                    '--output', self.tree_html_path,
                    '--update-interval', '1.0'
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True  # 独立进程组
            )
            
            # 等待管道创建
            max_wait = 5
            for _ in range(max_wait * 10):
                if os.path.exists(self.trace_pipe_path):
                    print(f"[Conductor] ✅ Tree visualizer ready")
                    return
                time.sleep(0.1)
            
            print(f"[Conductor] ⚠️  Tree visualizer pipe not created")
        
        except Exception as e:
            print(f"[Conductor] ❌ Failed to start tree visualizer: {e}")
            self.visualizer_proc = None
    
    def stop_tree_visualizer(self):
        """停止树可视化器"""
        if self.visualizer_proc:
            try:
                print(f"[Conductor] Stopping tree visualizer...")
                self.visualizer_proc.terminate()
                self.visualizer_proc.wait(timeout=5)
                print(f"[Conductor] ✅ Tree visualizer stopped")
                
                # 修改HTML文件，添加fuzzing session统计信息
                if self.tree_html_path and os.path.exists(self.tree_html_path):
                    self._update_tree_html_stats()
                    print(f"[Conductor] 🌳 Tree visualization saved to: {self.tree_html_path}")
            
            except subprocess.TimeoutExpired:
                print(f"[Conductor] Killing tree visualizer (timeout)...")
                self.visualizer_proc.kill()
            except Exception as e:
                print(f"[Conductor] Error stopping tree visualizer: {e}")
            finally:
                self.visualizer_proc = None
    
    def _update_tree_html_stats(self):
        """更新树形HTML中的fuzzing统计信息"""
        try:
            with open(self.tree_html_path, 'r') as f:
                html_content = f.read()
            
            # 计算fuzzing统计
            duration = time.time() - self.start_time if self.start_time else 0
            mutable_count = len(self.smart_mutator.mutable_candidates)
            total_mutations = sum(1 for log in self.fuzzing_log if log.get('instructions'))
            
            # 在HTML中添加fuzzing session信息
            fuzzing_stats = f'''
        <div style="position: fixed; bottom: 20px; right: 20px; background: rgba(102, 126, 234, 0.95); color: white; padding: 15px 20px; border-radius: 10px; font-size: 13px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); z-index: 300;">
            <div style="font-weight: bold; margin-bottom: 8px; font-size: 14px;">🎯 Fuzzing Session</div>
            <div style="margin-bottom: 4px;">Iterations: <strong>{self.total_executions}</strong></div>
            <div style="margin-bottom: 4px;">Mutations: <strong>{total_mutations}</strong></div>
            <div style="margin-bottom: 4px;">Crashes: <strong>{len(self.crashes)}</strong></div>
            <div style="margin-bottom: 4px;">Duration: <strong>{duration:.2f}s</strong></div>
            <div>Mutable Syscalls: <strong>{mutable_count}</strong></div>
        </div>'''
            
            # 在 </body> 标签前插入
            html_content = html_content.replace('</body>', fuzzing_stats + '\n</body>')
            
            with open(self.tree_html_path, 'w') as f:
                f.write(html_content)
        
        except Exception as e:
            print(f"[Conductor] Warning: Failed to update tree HTML stats: {e}")
    
    def start_qemu(self):
        """启动QEMU进程（Fuzzing模式）"""
        env = os.environ.copy()
        env.update({
            'RR_DEBUG_LEVEL': '4',
            'RR_FUZZING_ENABLED': 'True',
            'RR_MODE': 'fuzzing',  # 关键：设置为fuzzing模式
            'RR_TRACE_FILE': self.trace_file,
            'RR_CMD_PIPE': str(self.cmd_pipe_read),
            'RR_STATUS_PIPE': str(self.status_pipe_write),
            'RR_SHARED_MEMORY': self.shm.shm_name,
        })
        
        # 如果树可视化器已启动，启用动态跟踪
        if self.visualizer_proc and os.path.exists(self.trace_pipe_path):
            env['RR_DYNAMIC_TRACE'] = '1'
            env['RR_TRACE_PIPE'] = self.trace_pipe_path
            print(f"[Conductor] ✅ Dynamic trace enabled -> {self.trace_pipe_path}")
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
        iteration_start = time.time()
        
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
                
                # 记录超时
                self.fuzzing_log.append({
                    'iteration': self.total_executions + 1,
                    'instructions': [{'syscall_index': i.syscall_index, 'cmd': i.cmd} for i in instructions],
                    'status': 'timeout',
                    'duration': time.time() - iteration_start
                })
                return None
        
        status_bytes = os.read(self.status_pipe_read, 4)
        if not status_bytes:
            self.fuzzing_log.append({
                'iteration': self.total_executions + 1,
                'instructions': [{'syscall_index': i.syscall_index, 'cmd': i.cmd} for i in instructions],
                'status': 'no_response',
                'duration': time.time() - iteration_start
            })
            return None
        
        status = struct.unpack('i', status_bytes)[0]
        self.total_executions += 1
        
        status_name = self._parse_status(status)
        
        # 记录本次迭代
        self.fuzzing_log.append({
            'iteration': self.total_executions,
            'instructions': [{'syscall_index': i.syscall_index, 'cmd': i.cmd} for i in instructions],
            'status': status_name,
            'duration': time.time() - iteration_start
        })
        
        return status_name
    
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
    
    def run(self, rounds):
        """运行Fuzz主循环"""
        self.start_time = time.time()
        print(f"[Conductor] Starting fuzzing loop for {rounds} rounds")
        for i in range(rounds):
            if _shutdown_requested:
                break
            print(f"\n[Conductor] ===== Round {i+1}/{rounds} =====")
            # self._drain_qemu_stdout()  # 方法不存在，暂时注释
            instructions = self.smart_mutator.build_instructions(i)
            if not instructions:
                print("[Conductor] No instructions generated, skipping round")
                continue
            status = self.send_fuzz_command(instructions)
            if status is None:
                print("[Conductor] QEMU terminated unexpectedly")
                break
            if status == "Crash Found":
                print("[Conductor] Crash detected! Stopping fuzzing loop")
                break
        print("[Conductor] Fuzzing loop completed")
    
    def save_trace_file(self, output_file=None):
        """保存可读的 syscall trace 文件"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"fuzzing_trace_{timestamp}.txt"
        
        analyzer = self.smart_mutator.analyzer
        
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("RR-Fuzz Syscall Trace\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:     {self.target_binary}\n")
            f.write(f"Trace File: {self.trace_file}\n")
            f.write(f"Timestamp:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Iterations: {self.total_executions}\n")
            f.write("=" * 80 + "\n\n")
            
            # 1. Original Trace Summary
            f.write("📋 ORIGINAL TRACE SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total syscalls: {len(analyzer.syscalls)}\n")
            f.write(f"Pure replay candidates: {len(self.smart_mutator.pure_candidates)}\n")
            f.write(f"Hybrid replay candidates: {len(self.smart_mutator.hybrid_candidates)}\n")
            f.write(f"Mutable syscalls: {len(self.smart_mutator.mutable_candidates)}\n\n")
            
            # 2. Syscall List with Details
            f.write("📜 SYSCALL SEQUENCE\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'Index':<6} {'Syscall':<20} {'Category':<12} {'Aux Data':<10} {'Mutable':<8}\n")
            f.write("-" * 80 + "\n")
            
            for sc in analyzer.syscalls:
                is_mutable = sc in self.smart_mutator.mutable_candidates
                aux_info = f"{sc.aux_data_size}B" if sc.has_aux_data else "No"
                f.write(f"{sc.index:<6} {sc.name:<20} {sc.category:<12} {aux_info:<10} {'✓' if is_mutable else '✗':<8}\n")
            
            f.write("\n")
            
            # 3. Fuzzing Iterations Detail
            if self.fuzzing_log:
                f.write("🎯 FUZZING ITERATIONS\n")
                f.write("-" * 80 + "\n")
                for log_entry in self.fuzzing_log:
                    f.write(f"\nIteration #{log_entry['iteration']} - Status: {log_entry['status']} - Duration: {log_entry['duration']:.3f}s\n")
                    
                    for instr in log_entry['instructions']:
                        syscall_idx = instr['syscall_index']
                        cmd_type = instr['cmd']
                        cmd_name_map = {
                            0: 'NONE',
                            1: 'MUTATE_ARG',
                            2: 'REPLACE_BUFFER',
                            3: 'MUTATE_FLAGS',
                            4: 'BOUNDARY_VALUE',
                            10: 'LIGHT_MUTATION'
                        }
                        cmd_name = cmd_name_map.get(cmd_type, f'UNKNOWN({cmd_type})')
                        
                        # Find syscall name
                        syscall_name = "unknown"
                        for sc in analyzer.syscalls:
                            if sc.index == syscall_idx:
                                syscall_name = sc.name
                                break
                        
                        f.write(f"  ⚡ Mutated: syscall[{syscall_idx}] {syscall_name} - Command: {cmd_name}\n")
            
            f.write("\n")
            f.write("=" * 80 + "\n")
            f.write("End of Trace\n")
            f.write("=" * 80 + "\n")
        
        print(f"[Conductor] 📝 Syscall trace saved to: {output_file}")
        return output_file
    
    def save_summary(self, output_file=None):
        """保存fuzzing摘要到JSON文件"""
        if output_file is None:
            # 默认输出到当前目录
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"fuzzing_summary_{timestamp}.json"
        
        duration = time.time() - self.start_time if self.start_time else 0
        
        summary = {
            'fuzzing_session': {
                'target': self.target_binary,
                'trace_file': self.trace_file,
                'start_time': datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
                'duration_seconds': round(duration, 2),
                'total_iterations': self.total_executions
            },
            'statistics': {
                'total_executions': self.total_executions,
                'crashes_found': len(self.crashes),
                'crash_iterations': self.crashes,
                'avg_iteration_time': round(duration / self.total_executions, 3) if self.total_executions > 0 else 0
            },
            'mutable_syscalls': {
                'total': len(self.smart_mutator.mutable_candidates),
                'pure_replay_total': len(self.smart_mutator.pure_candidates),
                'hybrid_replay_total': len(self.smart_mutator.hybrid_candidates)
            },
            'iterations': self.fuzzing_log
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n[Conductor] 📊 Fuzzing summary saved to: {output_file}")
        print(f"[Conductor]    Total iterations: {self.total_executions}")
        print(f"[Conductor]    Crashes found: {len(self.crashes)}")
        print(f"[Conductor]    Duration: {round(duration, 2)}s")
        
        return output_file
    
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
        
        # 停止树可视化器
        self.stop_tree_visualizer()
        
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
    parser.add_argument('--output-format', type=str, default='all', 
                       choices=['html', 'txt', 'json', 'all', 'none'],
                       help='Output format: html=tree only, txt=text only, json=summary only, all=everything, none=no output (default: all)')
    
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
    print(f"  - Output: {args.output_format}")
    print(f"  - Press Ctrl+C to stop gracefully")
    print()
    
    # 创建Conductor并运行
    conductor = FuzzConductor(args.qemu, args.target, args.trace, args.output_format)
    _conductor_instance = conductor  # 保存全局引用供信号处理器使用
    
    try:
        # 1. 启动树可视化器（如果需要HTML输出）
        conductor.start_tree_visualizer()
        
        # 2. 启动QEMU（会自动连接到树可视化器）
        conductor.start_qemu()
        
        # 3. 运行fuzzing
        conductor.run(args.iterations)
    except KeyboardInterrupt:
        print("\n[Conductor] Interrupted by user")
    finally:
        # 保存fuzzing摘要和trace（根据output_format配置）
        if conductor.total_executions > 0:
            output_fmt = args.output_format
            
            # 检查是否需要生成输出文件
            if output_fmt != 'none':
                # JSON summary
                if output_fmt in ['json', 'all']:
                    conductor.save_summary()
                
                # HTML tree已由 realtime_tree_visualizer.py 生成（在cleanup中停止）
                # 不再需要手动调用 save_html_trace()
                
                # Text trace
                if output_fmt in ['txt', 'all']:
                    conductor.save_trace_file()
            else:
                print("[Conductor] ⚠️  Output disabled (--output-format none)")
        
        conductor.cleanup()
        _conductor_instance = None
    
    return 0


if __name__ == '__main__':
    sys.exit(main())


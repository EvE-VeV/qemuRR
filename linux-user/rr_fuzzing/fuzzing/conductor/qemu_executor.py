#!/usr/bin/env python3
"""
QEMUExecutor - Layer 2: QEMU Execution Engine

Manages QEMU process lifecycle and handles execution of traces with mutations.
Implements the architecture described in DETAILED_ARCHITECTURE.md Layer 2.
"""

import os
import time
import signal
import struct
import select
import subprocess
import threading
from typing import List, Optional, Dict
from dataclasses import dataclass

from .instruction import FuzzInstruction
from .shared_memory import FuzzSharedMemory


# Status codes (must match C-side definitions in rr_constants.h)
STATUS_NONE = 0
STATUS_READY = 1
STATUS_AT_FORK_POINT = 2
STATUS_NORMAL_EXIT = 3
STATUS_CRASH = 4
STATUS_OTHER_SIGNAL = 5
STATUS_TIMEOUT = 6


@dataclass
class ExecutionResult:
    """
    Result of a single QEMU execution
    
    Contains status, coverage bitmap, and timing information.
    """
    status: int
    status_name: str
    coverage_bitmap: Optional[bytes]
    execution_time: float
    qemu_exit_code: Optional[int] = None
    signal_number: Optional[int] = None
    
    @property
    def crashed(self) -> bool:
        """Check if execution resulted in a crash"""
        return self.status == STATUS_CRASH
    
    @property
    def timeout(self) -> bool:
        """Check if execution timed out"""
        return self.status == STATUS_TIMEOUT
    
    @property
    def normal_exit(self) -> bool:
        """Check if execution completed normally"""
        return self.status == STATUS_NORMAL_EXIT


class QEMUExecutor:
    """
    Layer 2: QEMU Execution Engine
    
    Responsibilities:
    1. Manage QEMU process lifecycle (fork, exec, wait)
    2. Setup IPC channels (pipes, shared memory)
    3. Send mutations to QEMU via shared memory
    4. Receive execution results (status, coverage)
    5. Handle timeouts and crashes
    
    Architecture: DETAILED_ARCHITECTURE.md Line 108-137
    """
    
    def __init__(self, qemu_path: str, target_binary: str, timeout: float = 30.0):
        """
        Initialize QEMU Executor
        
        Args:
            qemu_path: Path to QEMU executable
            target_binary: Path to target program
            timeout: Execution timeout in seconds
        """
        self.qemu_path = qemu_path
        self.target_binary = target_binary
        self.timeout = timeout
        
        # IPC components (initialized per execution)
        self.cmd_pipe_read = None
        self.cmd_pipe_write = None
        self.status_pipe_read = None
        self.status_pipe_write = None
        self.shm: Optional[FuzzSharedMemory] = None
        
        # QEMU process
        self.qemu_process: Optional[subprocess.Popen] = None
        self.qemu_pid: Optional[int] = None
        
        # Statistics
        self.total_executions = 0
        self.total_crashes = 0
        self.total_timeouts = 0
        
        print(f"[QEMUExecutor] Initialized")
        print(f"  QEMU: {qemu_path}")
        print(f"  Target: {target_binary}")
        print(f"  Timeout: {timeout}s")
    
    def _setup_ipc(self):
        """Setup IPC channels (pipes and shared memory)"""
        # Create pipes
        self.cmd_pipe_read, self.cmd_pipe_write = os.pipe()
        self.status_pipe_read, self.status_pipe_write = os.pipe()
        
        # Create shared memory
        shm_name = f"rr_fuzz_{os.getpid()}_{self.total_executions}"
        self.shm = FuzzSharedMemory(shm_name)
        self.shm.create()
    
    def _cleanup_ipc(self):
        """Cleanup IPC channels"""
        # Close pipes
        for fd in [self.cmd_pipe_read, self.cmd_pipe_write,
                   self.status_pipe_read, self.status_pipe_write]:
            try:
                if fd is not None:
                    os.close(fd)
            except:
                pass
        
        # Cleanup shared memory
        if self.shm:
            self.shm.close()
            self.shm = None
        
        # Reset pipe descriptors
        self.cmd_pipe_read = None
        self.cmd_pipe_write = None
        self.status_pipe_read = None
        self.status_pipe_write = None
    
    def _fork_qemu(self, trace_file: str):
        """
        Fork and exec QEMU process
        
        Args:
            trace_file: Path to trace file to replay
        """
        env = os.environ.copy()
        env.update({
            'RR_FUZZING_ENABLED': '1',  # 关键！启用 RR-Fuzz
            'RR_MODE': 'fuzzing',
            'RR_TRACE_FILE': trace_file,
            'RR_CMD_PIPE': str(self.cmd_pipe_read),
            'RR_STATUS_PIPE': str(self.status_pipe_write),
            'RR_SHARED_MEMORY': self.shm.shm_name,
        })
        
        cmd = [self.qemu_path, self.target_binary]
        
        try:
            self.qemu_process = subprocess.Popen(
                cmd,
                env=env,
                pass_fds=[self.cmd_pipe_read, self.status_pipe_write],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            self.qemu_pid = self.qemu_process.pid
            
            # Close child's pipe ends in parent
            os.close(self.cmd_pipe_read)
            os.close(self.status_pipe_write)
            self.cmd_pipe_read = None
            self.status_pipe_write = None
            
        except Exception as e:
            raise RuntimeError(f"Failed to fork QEMU: {e}")
    
    def _wait_for_status(self, timeout: float) -> Optional[int]:
        """
        Wait for status update from QEMU
        
        Args:
            timeout: Timeout in seconds
        
        Returns:
            int: Status code or None if timeout
        """
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            ready, _, _ = select.select([self.status_pipe_read], [], [], 1.0)
            
            if ready:
                status_bytes = os.read(self.status_pipe_read, 4)
                if len(status_bytes) == 4:
                    status = struct.unpack('i', status_bytes)[0]
                    return status
            
            # Check if process is still alive
            if self.qemu_process and self.qemu_process.poll() is not None:
                # Process exited unexpectedly
                return None
        
        return None  # Timeout
    
    def _read_coverage(self) -> Optional[bytes]:
        """
        Read coverage bitmap from QEMU's coverage shared memory
        
        方案 3: 扫描最新的 rr_coverage_* 文件
        QEMU creates: /dev/shm/rr_coverage_{qemu_pid}
        
        Returns:
            bytes: Coverage bitmap or None if unavailable
        """
        try:
            import glob
            import time
            
            # 找到所有 rr_coverage_* 文件
            coverage_files = glob.glob("/dev/shm/rr_coverage_*")
            if not coverage_files:
                return None
            
            # 按修改时间排序，取最近修改的（1秒内）
            now = time.time()
            recent_files = [
                f for f in coverage_files
                if now - os.path.getmtime(f) < 1.0  # 最近1秒内修改的
            ]
            
            if not recent_files:
                # 如果没有最近的，就取最新的
                latest_file = max(coverage_files, key=os.path.getmtime)
            else:
                latest_file = max(recent_files, key=os.path.getmtime)
            
            # 读取 coverage
            with open(latest_file, 'rb') as f:
                coverage_bitmap = f.read(64 * 1024)  # 64KB coverage map
            
            # 统计非零字节数（用于调试）
            non_zero_count = sum(1 for b in coverage_bitmap if b != 0)
            if non_zero_count > 0:
                print(f"[QEMUExecutor] ✅ Read coverage: {non_zero_count} non-zero bytes from {latest_file}")
            
            return bytes(coverage_bitmap)
        except FileNotFoundError:
            return None
        except Exception as e:
            # 首次执行可能没有文件，这是正常的
            return None
    
    def _terminate_qemu(self):
        """Terminate QEMU process"""
        if not self.qemu_process:
            return
        
        try:
            # Try graceful termination first
            self.qemu_process.terminate()
            try:
                self.qemu_process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                # Force kill
                self.qemu_process.kill()
                self.qemu_process.wait()
        except:
            pass
        finally:
            self.qemu_process = None
            self.qemu_pid = None
    
    def execute(self, trace_file: str, mutations: List[FuzzInstruction]) -> ExecutionResult:
        """
        Execute trace with mutations
        
        This is the main execution method that:
        1. Sets up IPC
        2. Forks QEMU
        3. Writes mutations to shared memory
        4. Sends start command
        5. Waits for result
        6. Reads coverage
        7. Cleans up
        
        Args:
            trace_file: Path to trace file
            mutations: List of fuzzing instructions
        
        Returns:
            ExecutionResult: Execution result with status and coverage
        
        Architecture: DETAILED_ARCHITECTURE.md Line 608-811
        """
        start_time = time.time()
        self.total_executions += 1
        
        try:
            # Step 1: Setup IPC
            self._setup_ipc()
            
            # Step 2: Write mutations to shared memory
            self.shm.write_instructions(mutations)
            
            # Step 3: Fork QEMU process
            self._fork_qemu(trace_file)
            
            # Step 4: Wait for READY status
            status = self._wait_for_status(timeout=5.0)
            if status != STATUS_READY:
                return ExecutionResult(
                    status=STATUS_OTHER_SIGNAL,
                    status_name="qemu_init_failed",
                    coverage_bitmap=None,
                    execution_time=time.time() - start_time
                )
            
            # Step 5: Send start command 'F' (Fuzz)
            os.write(self.cmd_pipe_write, b'F')
            
            # Step 6: Wait for execution result
            status = self._wait_for_status(timeout=self.timeout)
            
            if status is None:
                # Timeout or unexpected exit
                self.total_timeouts += 1
                self._terminate_qemu()
                
                return ExecutionResult(
                    status=STATUS_TIMEOUT,
                    status_name="timeout",
                    coverage_bitmap=None,
                    execution_time=time.time() - start_time
                )
            
            # Step 7: Read coverage
            coverage_bitmap = self._read_coverage()
            
            # Step 8: Determine status name
            status_map = {
                STATUS_NORMAL_EXIT: "normal_exit",
                STATUS_CRASH: "crash",
                STATUS_OTHER_SIGNAL: "signal",
                STATUS_AT_FORK_POINT: "fork_point"
            }
            status_name = status_map.get(status, f"unknown_{status}")
            
            if status == STATUS_CRASH:
                self.total_crashes += 1
            
            # Wait for QEMU to exit
            try:
                exit_code = self.qemu_process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                self._terminate_qemu()
                exit_code = -1
            
            return ExecutionResult(
                status=status,
                status_name=status_name,
                coverage_bitmap=coverage_bitmap,
                execution_time=time.time() - start_time,
                qemu_exit_code=exit_code
            )
        
        except Exception as e:
            print(f"[QEMUExecutor] Execution failed: {e}")
            return ExecutionResult(
                status=STATUS_OTHER_SIGNAL,
                status_name="exception",
                coverage_bitmap=None,
                execution_time=time.time() - start_time
            )
        
        finally:
            # Step 9: Cleanup
            self._terminate_qemu()
            self._cleanup_ipc()
    
    def get_statistics(self) -> Dict:
        """Get execution statistics"""
        return {
            'total_executions': self.total_executions,
            'total_crashes': self.total_crashes,
            'total_timeouts': self.total_timeouts,
            'crash_rate': self.total_crashes / max(self.total_executions, 1),
            'timeout_rate': self.total_timeouts / max(self.total_executions, 1)
        }


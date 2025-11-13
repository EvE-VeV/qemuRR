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
import mmap
from pathlib import Path
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
    
    # Class-level shared coverage bitmap (all executors share)
    _shared_coverage_shm = None
    _coverage_shm_lock = threading.Lock()
    _coverage_env_value = "rr_coverage_global"
    
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
        
        # QEMU process (persistent fork server)
        self.qemu_process: Optional[subprocess.Popen] = None
        self.qemu_pid: Optional[int] = None
        self._qemu_ready = False  # ✅ FIX: Track if QEMU is in fork server loop
        self._trace_file = None   # ✅ FIX: Remember trace file for persistent mode
        
        # Statistics
        self.total_executions = 0
        self.total_crashes = 0
        self.total_timeouts = 0
        self._ipc_fallback_dir = Path(
            os.environ.get("RR_SHM_FALLBACK_DIR") or (Path.cwd() / ".rr_shm_fallback")
        )
        
        # Initialize shared coverage bitmap (once for all executors)
        self._init_shared_coverage()
        
        print(f"[QEMUExecutor] Initialized")
        print(f"  QEMU: {qemu_path}")
        print(f"  Target: {target_binary}")
        print(f"  Timeout: {timeout}s")
    
    class _FileBackedSharedMemory:
        """Minimal wrapper to mimic multiprocessing.SharedMemory API"""
        def __init__(self, path: Path, size: int):
            self.path = path
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
            os.ftruncate(self.fd, size)
            self._mmap = mmap.mmap(self.fd, size)
            self.buf = memoryview(self._mmap)
            print(f"[QEMUExecutor] ✅ Created file-backed coverage bitmap at {self.path}")
        
        def close(self):
            try:
                if self.buf:
                    self.buf.release()
            except AttributeError:
                pass
            self._mmap.close()
            os.close(self.fd)
        
        def unlink(self):
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass

    @classmethod
    def _coverage_fallback_path(cls) -> Path:
        base = Path(os.environ.get("RR_COVERAGE_FALLBACK_DIR") or (Path.cwd() / ".rr_cov_fallback"))
        return base / "rr_coverage_global.bin"

    @classmethod
    def _init_shared_coverage(cls):
        """Initialize shared coverage bitmap (AFL-style, once for all executors)"""
        with cls._coverage_shm_lock:
            if cls._shared_coverage_shm is None:
                try:
                    from multiprocessing import shared_memory
                    
                    # Try to create or open existing shared memory
                    try:
                        cls._shared_coverage_shm = shared_memory.SharedMemory(
                            name="rr_coverage_global",
                            create=True,
                            size=64 * 1024
                        )
                        # Initialize to zeros
                        cls._shared_coverage_shm.buf[:] = bytes(64 * 1024)
                        print("[QEMUExecutor] ✅ Created shared coverage bitmap (/dev/shm/rr_coverage_global)")
                    except FileExistsError:
                        # Already exists, just open it
                        cls._shared_coverage_shm = shared_memory.SharedMemory(
                            name="rr_coverage_global",
                            create=False,
                            size=64 * 1024
                        )
                        print("[QEMUExecutor] ✅ Opened existing shared coverage bitmap")
                    cls._coverage_env_value = "rr_coverage_global"
                except PermissionError as e:
                    print(f"[QEMUExecutor] ⚠️  SharedMemory permission error: {e}")
                    fallback_path = cls._coverage_fallback_path()
                    cls._shared_coverage_shm = cls._FileBackedSharedMemory(
                        fallback_path, 64 * 1024
                    )
                    cls._coverage_env_value = f"file:{fallback_path}"
                except Exception as e:
                    print(f"[QEMUExecutor] ⚠️  Failed to create shared coverage: {e}")
                    fallback_path = cls._coverage_fallback_path()
                    cls._shared_coverage_shm = cls._FileBackedSharedMemory(
                        fallback_path, 64 * 1024
                    )
                    cls._coverage_env_value = f"file:{fallback_path}"
    
    @classmethod
    def reset_shared_coverage(cls):
        """Reset shared coverage bitmap to zeros (call before each execution)"""
        if cls._shared_coverage_shm is not None:
            try:
                # Clear the entire bitmap
                cls._shared_coverage_shm.buf[:] = bytes(64 * 1024)
                return True
            except Exception as e:
                print(f"[QEMUExecutor] ⚠️  Failed to reset coverage: {e}")
                return False
        return False
    
    @classmethod
    def cleanup_shared_coverage(cls):
        """Cleanup shared coverage bitmap (call at program exit)"""
        with cls._coverage_shm_lock:
            if cls._shared_coverage_shm is not None:
                try:
                    cls._shared_coverage_shm.close()
                    if hasattr(cls._shared_coverage_shm, "unlink"):
                        cls._shared_coverage_shm.unlink()
                    print("[QEMUExecutor] ✅ Cleaned up shared coverage bitmap")
                except:
                    pass
                finally:
                    cls._shared_coverage_shm = None
    
    def _setup_ipc(self):
        """Setup IPC channels (pipes and shared memory)"""
        # Create pipes
        self.cmd_pipe_read, self.cmd_pipe_write = os.pipe()
        self.status_pipe_read, self.status_pipe_write = os.pipe()
        
        # Create shared memory
        shm_name = f"rr_fuzz_{os.getpid()}_{self.total_executions}"
        self.shm = FuzzSharedMemory(shm_name, fallback_dir=str(self._ipc_fallback_dir))
        self.shm.create()
    
    def stop_persistent_qemu(self):
        """
        Stop persistent QEMU fork server gracefully
        
        This should be called when fuzzing campaign finishes.
        """
        if not self._qemu_ready:
            return
        
        try:
            print("[QEMUExecutor] 🛑 Stopping persistent QEMU fork server...")
            # Send 'Q' command to quit
            if self.cmd_pipe_write is not None:
                os.write(self.cmd_pipe_write, b'Q')
            
            # Wait for graceful exit
            if self.qemu_process:
                try:
                    self.qemu_process.wait(timeout=2.0)
                    print("[QEMUExecutor] ✅ Fork server exited gracefully")
                except subprocess.TimeoutExpired:
                    print("[QEMUExecutor] ⚠️  Fork server didn't exit, killing...")
                    self._terminate_qemu()
        except Exception as e:
            print(f"[QEMUExecutor] ⚠️  Error stopping fork server: {e}")
            self._terminate_qemu()
        finally:
            self._qemu_ready = False
            # Now cleanup IPC
            self._cleanup_ipc()
    
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
            shm_descriptor = None
            try:
                shm_descriptor = self.shm.get_env_value()
                self.shm.close()
                self.shm.unlink()
            except Exception:
                pass
            finally:
                if shm_descriptor:
                    print(f"[Conductor] ✅ Cleaned IPC shared memory: {shm_descriptor}")
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
        
        # Note: Do NOT set RR_STRACE_MODE - it's for strace text format
        # Our trace files are TRRR binary format, use native replay module
        # which already supports silent_replay_mode
        
        # Set RR_TRACE_PIPE for dynamic trace visualization
        if 'RR_TRACE_PIPE' in os.environ:
            env['RR_TRACE_PIPE'] = os.environ['RR_TRACE_PIPE']
            print(f"[QEMUExecutor] Passing RR_TRACE_PIPE={env['RR_TRACE_PIPE']} to QEMU")
        else:
            # Default to /tmp/rr_dynamic_trace if not set
            default_pipe = '/tmp/rr_dynamic_trace'
            if os.path.exists(default_pipe):
                env['RR_TRACE_PIPE'] = default_pipe
                print(f"[QEMUExecutor] Using default RR_TRACE_PIPE={default_pipe}")
            else:
                print(f"[QEMUExecutor] Warning: RR_TRACE_PIPE not set and {default_pipe} not found - dynamic trace disabled")
        
        env.update({
            'RR_FUZZING_ENABLED': '1',
            'RR_MODE': 'fuzzing',
            'RR_TRACE_FILE': trace_file,
            'RR_CMD_PIPE': str(self.cmd_pipe_read),
            'RR_STATUS_PIPE': str(self.status_pipe_write),
            'RR_SHARED_MEMORY': self.shm.get_env_value(),
            'RR_COVERAGE_SHM': self.__class__._coverage_env_value,
            'RR_DEBUG_LEVEL': '4',
        })
        
        cmd = [self.qemu_path, self.target_binary]
        
        # ✅ FIX: Save pipe ends to close in case of error
        child_cmd_pipe = self.cmd_pipe_read
        child_status_pipe = self.status_pipe_write
        
        try:
            # ✅ FIX: 允许QEMU输出显示（用于调试和验证RR-Fuzz功能）
            # 在生产环境中可以改回DEVNULL以减少输出
            self.qemu_process = subprocess.Popen(
                cmd,
                env=env,
                pass_fds=[child_cmd_pipe, child_status_pipe],
                stdout=None,  # 继承父进程的stdout，显示QEMU输出
                stderr=None   # 继承父进程的stderr
            )
            
            self.qemu_pid = self.qemu_process.pid
            
        except Exception as e:
            # ✅ FIX: Ensure we don't leak pipe fds on failure
            raise RuntimeError(f"Failed to fork QEMU: {e}")
        finally:
            # ✅ FIX: Always close child's pipe ends in parent (success or failure)
            # These were passed to child, parent should close them
            try:
                if child_cmd_pipe is not None:
                    os.close(child_cmd_pipe)
                    self.cmd_pipe_read = None
            except:
                pass
            
            try:
                if child_status_pipe is not None:
                    os.close(child_status_pipe)
                    self.status_pipe_write = None
            except:
                pass
    
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
        Read coverage bitmap from shared memory (AFL-style)
        
        New design: Direct shared memory access (no file operations)
        QEMU writes to: /dev/shm/rr_coverage_global
        Python reads from: same shared memory
        
        Returns:
            bytes: Coverage bitmap or None if unavailable
        """
        # Try shared coverage first (new AFL-style approach)
        if self._shared_coverage_shm is not None:
            try:
                coverage_bitmap = bytes(self._shared_coverage_shm.buf[:])
                
                # Statistics (for debugging)
                non_zero_count = sum(1 for b in coverage_bitmap if b != 0)
                if non_zero_count > 0:
                    print(f"[QEMUExecutor] ✅ Read coverage: {non_zero_count} non-zero bytes from shared memory")
                
                return coverage_bitmap
            except Exception as e:
                print(f"[QEMUExecutor] ⚠️  Failed to read shared coverage: {e}")
                # Fall through to legacy file-based approach
        
        # Fallback: Legacy file-based approach (for compatibility with old QEMU)
        coverage_file = None
        try:
            import glob
            import time
            
            # Find all rr_coverage_* files
            coverage_files = glob.glob("/dev/shm/rr_coverage_*")
            if not coverage_files:
                return None
            
            # Get most recent file
            now = time.time()
            recent_files = [
                f for f in coverage_files
                if now - os.path.getmtime(f) < 1.0
            ]
            
            if not recent_files:
                latest_file = max(coverage_files, key=os.path.getmtime)
            else:
                latest_file = max(recent_files, key=os.path.getmtime)
            
            coverage_file = latest_file
            
            # Read coverage
            with open(latest_file, 'rb') as f:
                coverage_bitmap = f.read(64 * 1024)
            
            non_zero_count = sum(1 for b in coverage_bitmap if b != 0)
            if non_zero_count > 0:
                print(f"[QEMUExecutor] ✅ Read coverage: {non_zero_count} non-zero bytes from {latest_file}")
            
            return bytes(coverage_bitmap)
        except FileNotFoundError:
            return None
        except Exception as e:
            return None
        finally:
            # Clean up file-based coverage
            if coverage_file:
                try:
                    os.unlink(coverage_file)
                except:
                    pass
    
    def reset_coverage(self):
        """Reset coverage bitmap (clear all bytes to zero)"""
        if self._shared_coverage_shm is not None:
            try:
                # Clear all bytes in the coverage bitmap
                for i in range(len(self._shared_coverage_shm.buf)):
                    self._shared_coverage_shm.buf[i] = 0
                print(f"[QEMUExecutor] ✅ Coverage bitmap reset (cleared {len(self._shared_coverage_shm.buf)} bytes)")
            except Exception as e:
                print(f"[QEMUExecutor] ⚠️  Failed to reset coverage: {e}")
    
    def execute_baseline(self, trace_file: str, iteration_id: int = 0) -> ExecutionResult:
        """
        Execute baseline trace (full replay without fork, for displaying all syscalls)
        
        This is used for the first execution of an iteration to show the complete
        syscall sequence including the shared baseline [0-9] syscalls.
        
        Args:
            trace_file: Path to trace file
            iteration_id: Current iteration ID (for tree visualization)
        
        Returns:
            ExecutionResult: Execution result with status
        """
        start_time = time.time()
        print(f"[QEMUExecutor] 📜 Executing baseline trace (iteration {iteration_id})...")
        
        try:
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # PHASE 1: Initialize QEMU (if not ready)
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            if not self._qemu_ready:
                print("[QEMUExecutor] 🚀 Starting persistent QEMU fork server for baseline...")
                
                # Setup IPC
                self._setup_ipc()
                
                # Write iteration_id to shared memory
                self.shm.write_fork_request(fork_point=0, mutation_variants=[[]], depth=0, iteration_id=iteration_id)
                
                # Fork QEMU process
                self._fork_qemu(trace_file)
                self._trace_file = trace_file
                
                # Wait for initial READY status
                status = self._wait_for_status(timeout=5.0)
                if status != STATUS_READY:
                    raise RuntimeError(f"QEMU startup failed (status={status})")
                
                self._qemu_ready = True
                print("[QEMUExecutor] ✅ QEMU fork server ready for baseline")
            else:
                # Write iteration_id to shared memory
                self.shm.write_fork_request(fork_point=0, mutation_variants=[[]], depth=0, iteration_id=iteration_id)
            
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # PHASE 2: Send baseline execution command ('E')
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            print(f"[QEMUExecutor] 📤 Sending 'E' (baseline execution) command...")
            os.write(self.cmd_pipe_write, b'E')
            
            # Wait for execution to complete
            status = self._wait_for_status(timeout=30.0)
            
            execution_time = time.time() - start_time
            
            if status == 0:  # Success
                print(f"[QEMUExecutor] ✅ Baseline execution completed ({execution_time:.3f}s)")
                return ExecutionResult(
                    status=STATUS_NORMAL_EXIT,
                    status_name="NORMAL",
                    coverage_bitmap=None,
                    execution_time=execution_time
                )
            else:
                print(f"[QEMUExecutor] ⚠️ Baseline execution failed (status={status})")
                return ExecutionResult(
                    status=-1,
                    status_name="ERROR",
                    coverage_bitmap=None,
                    execution_time=execution_time
                )
        
        except Exception as e:
            execution_time = time.time() - start_time
            print(f"[QEMUExecutor] ❌ Baseline execution exception: {e}")
            import traceback
            traceback.print_exc()
            return ExecutionResult(
                status=-1,
                status_name="ERROR",
                coverage_bitmap=None,
                execution_time=execution_time
            )
    
    def _terminate_qemu(self):
        """Terminate QEMU process and ensure no zombie"""
        if not self.qemu_process:
            return
        
        try:
            # Check if already exited
            if self.qemu_process.poll() is not None:
                # Already exited, just wait to collect zombie
                try:
                    self.qemu_process.wait(timeout=0.1)
                except:
                    pass
                return
            
            # Try graceful termination first
            try:
                self.qemu_process.terminate()
                self.qemu_process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                # Force kill if not terminated
                try:
                    self.qemu_process.kill()
                    self.qemu_process.wait(timeout=1.0)  # ✅ FIX: Must wait after kill
                except:
                    pass
            except Exception:
                # If terminate fails, try kill
                try:
                    self.qemu_process.kill()
                    self.qemu_process.wait(timeout=1.0)  # ✅ FIX: Must wait
                except:
                    pass
        finally:
            # ✅ FIX: Final attempt to reap zombie if still exists
            if self.qemu_process:
                try:
                    self.qemu_process.wait(timeout=0.1)
                except:
                    pass
            
            self.qemu_process = None
            self.qemu_pid = None
    
    def execute(self, trace_file: str, mutations: List[FuzzInstruction], iteration_id: int = 0) -> ExecutionResult:
        """
        Execute trace with mutations (Persistent Fork Server Mode)
        
        First execution:
        1. Sets up IPC
        2. Forks QEMU
        3. Waits for QEMU to reach fork server loop (STATUS_READY → first 'F' → STATUS_READY)
        
        Subsequent executions (reusing QEMU):
        1. Writes mutations to shared memory
        2. Sends 'F' command to trigger fork
        3. Waits for result
        4. Reads coverage
        
        Args:
            trace_file: Path to trace file
            mutations: List of fuzzing instructions
            iteration_id: Current iteration ID (for tree visualization)
        
        Returns:
            ExecutionResult: Execution result with status and coverage
        """
        start_time = time.time()
        self.total_executions += 1
        
        # ✅ DEBUG: Track _qemu_ready状态
        print(f"[DEBUG-EXEC] execute() called (exec#{self.total_executions}), _qemu_ready={self._qemu_ready}, qemu_alive={self.qemu_process is not None and self.qemu_process.poll() is None if self.qemu_process else False}")
        
        # ✅ CRITICAL FIX: Reset coverage before each execution for accurate diff
        QEMUExecutor.reset_shared_coverage()
        
        try:
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # PHASE 1: Initialize QEMU (first time only)
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            if not self._qemu_ready:
                print("[QEMUExecutor] 🚀 Starting persistent QEMU fork server...")
                
                # Setup IPC
                self._setup_ipc()
                
                # Write initial empty mutations (will be overwritten later)
                self.shm.write_fork_request(fork_point=0, mutation_variants=[[]], depth=0, iteration_id=iteration_id)
                
                # Fork QEMU process
                self._fork_qemu(trace_file)
                self._trace_file = trace_file
                
                # Wait for initial READY status
                status = self._wait_for_status(timeout=5.0)
                if status != STATUS_READY:
                    print(f"[DEBUG-EXEC] ❌ QEMU init failed (status={status}), setting _qemu_ready=False")
                    self._qemu_ready = False
                    return ExecutionResult(
                        status=STATUS_OTHER_SIGNAL,
                        status_name="qemu_init_failed",
                        coverage_bitmap=None,
                        execution_time=time.time() - start_time
                    )
                
                # Send first 'F' to let QEMU execute to fork point
                print("[QEMUExecutor] 📤 Sending first 'F' to reach fork server loop...")
                os.write(self.cmd_pipe_write, b'F')
                
                # ✅ FIX: Fork server loop does NOT send status when entering!
                # It silently enters the loop and waits for commands.
                # Give it a moment to reach the fork point
                import time as time_module
                time_module.sleep(0.1)  # 100ms should be enough for simple_test
                
                print("[QEMUExecutor] ✅ QEMU should now be in fork server loop, ready for persistent fuzzing")
                self._qemu_ready = True
            
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # PHASE 2: Execute mutation (every time)
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            # Write mutations to shared memory (using unified interface)
            self.shm.write_fork_request(fork_point=0, mutation_variants=[mutations], depth=0, iteration_id=iteration_id)
            
            # Send 'F' command to trigger fork and execution
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
                STATUS_AT_FORK_POINT: "fork_point_ready"  # Fork server waiting for next command
            }
            status_name = status_map.get(status, f"unknown_{status}")
            
            if status == STATUS_CRASH:
                self.total_crashes += 1
            
            # ✅ FIX: In persistent mode, fork server returns AT_FORK_POINT (2) after each execution
            # indicating it's ready for the next round. Don't wait for exit!
            if status == STATUS_AT_FORK_POINT:
                # Fork server is ready for next command
                exit_code = None
            else:
                # Abnormal termination, wait for exit
                try:
                    exit_code = self.qemu_process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    print(f"[DEBUG-EXEC] ⏱️ QEMU wait timeout after abnormal exit, setting _qemu_ready=False")
                    self._terminate_qemu()
                    self._qemu_ready = False
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
            import traceback
            traceback.print_exc()
            # Error occurred, reset persistent state
            print(f"[DEBUG-EXEC] ❌ Exception caught, setting _qemu_ready=False")
            self._terminate_qemu()
            self._qemu_ready = False
            self._cleanup_ipc()
            return ExecutionResult(
                status=STATUS_OTHER_SIGNAL,
                status_name="exception",
                coverage_bitmap=None,
                execution_time=time.time() - start_time
            )
        
        # ✅ FIX: DON'T cleanup in finally block for persistent mode
        # Cleanup only when explicitly stopping (via stop_persistent_qemu)
    
    def execute_fork(self, 
                    trace_file: str,
                    fork_point: int = 0,
                    mutation_variants: List[List[FuzzInstruction]] = None,
                    depth: int = 0,
                    iteration_id: int = 0) -> List[ExecutionResult]:
        """
        统一的fork执行方法（替代所有旧方法）
        
        Args:
            trace_file: Trace文件路径
            fork_point: Fork点（0=从头，N=mid-point）
            mutation_variants: Mutation列表（None=单次执行）
            depth: Fork深度
            iteration_id: Iteration编号
        
        Returns:
            执行结果列表
        
        场景映射:
            - 旧execute(): fork(fork_point=0, variants=[[inst1,inst2]], depth=0)
            - 旧execute_batch(): fork(fork_point=0, variants=[v1,v2,v3], depth=0)
            - 旧execute_batch_at_checkpoint(): fork(fork_point=N, variants=[v1,v2,v3], depth=0)
            - 嵌套fork: fork(fork_point=N, variants=[v1,v2,v3], depth=1)
        """
        start_time = time.time()
        
        # 初始化fork server（如果未初始化）
        if not self._qemu_ready:
            self._setup_ipc()
            # 不需要写入共享内存，QEMU启动时会等待第一个命令
            # self.shm.write_fork_request(fork_point=0, mutation_variants=[[]], depth=0)
            self._fork_qemu(trace_file)
            self._trace_file = trace_file
            
            status = self._wait_for_status(timeout=5.0)
            if status != STATUS_READY:
                raise RuntimeError("QEMU init failed")
            
            # 不需要发送'F'命令，QEMU已经在fork server loop中等待
            # os.write(self.cmd_pipe_write, b'F')
            # time.sleep(0.1)
            self._qemu_ready = True
        
        # 处理mutation_variants
        if mutation_variants is None:
            mutation_variants = [[]]
        
        # 重置coverage
        QEMUExecutor.reset_shared_coverage()
        
        # 写入fork请求到共享内存
        self.shm.write_fork_request(
            fork_point=fork_point,
            mutation_variants=mutation_variants,
            depth=depth,
            iteration_id=iteration_id
        )
        
        # 发送统一命令：'C'
        print(f"[QEMUExecutor] Sending 'C' command (fork_point={fork_point}, "
              f"variants={len(mutation_variants)}, depth={depth}, iteration={iteration_id})")
        os.write(self.cmd_pipe_write, b'C')
        
        # 收集结果
        results = []
        extended_timeout = self.timeout * len(mutation_variants)
        
        for variant_idx in range(len(mutation_variants)):
            status = self._wait_for_status(timeout=extended_timeout)
            
            if status is None:
                # Timeout
                self.total_timeouts += 1
                results.append(ExecutionResult(
                    status=STATUS_TIMEOUT,
                    status_name="timeout",
                    coverage_bitmap=None,
                    execution_time=time.time() - start_time
                ))
                continue
            
            # 读取coverage
            coverage_bitmap = self._read_coverage()
            
            # Status name
            status_map = {
                STATUS_NORMAL_EXIT: "normal_exit",
                STATUS_CRASH: "crash",
                STATUS_OTHER_SIGNAL: "signal",
                STATUS_AT_FORK_POINT: "fork_point_ready",
                2: "batch_completed"
            }
            status_name = status_map.get(status, f"unknown_{status}")
            
            if status == STATUS_CRASH:
                self.total_crashes += 1
            
            results.append(ExecutionResult(
                status=status,
                status_name=status_name,
                coverage_bitmap=coverage_bitmap,
                execution_time=time.time() - start_time,
                qemu_exit_code=None
            ))
            
            self.total_executions += 1
        
        print(f"[QEMUExecutor] ✅ Fork execution completed: {len(results)} results")
        
        # ❌ 不要在这里关闭QEMU - 应该在iteration间关闭，而不是每次fork后关闭
        # 当前的并发fork需要串行化或完全隔离，暂时依赖fuzzing_core的cleanup
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get execution statistics"""
        return {
            'total_executions': self.total_executions,
            'total_crashes': self.total_crashes,
            'total_timeouts': self.total_timeouts,
            'crash_rate': self.total_crashes / max(self.total_executions, 1),
            'timeout_rate': self.total_timeouts / max(self.total_executions, 1)
        }

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
from .async_logger import alog


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
    
    def __init__(self, qemu_path: str, target_binary: str, timeout: float = 30.0, target_args: str = "", persistent_mode: bool = True, log_file: Optional[str] = None):
        """
        Initialize QEMU Executor
        
        Args:
            qemu_path: Path to QEMU executable
            target_binary: Path to target program
            timeout: Execution timeout in seconds
            target_args: Arguments to pass to target binary
            persistent_mode: Whether to keep QEMU process alive between executions (Default: True)
        """
        self.qemu_path = qemu_path
        self.target_binary = target_binary
        self.timeout = timeout
        self.target_args = target_args
        self.persistent_mode = persistent_mode
        self.log_file = log_file
        
        # IPC components (initialized per execution)
        self.cmd_pipe_read = None
        self.cmd_pipe_write = None
        self.status_pipe_read = None
        self.status_pipe_write = None
        self.shm: Optional[FuzzSharedMemory] = None
        
        # QEMU process (persistent fork server)
        self.qemu_process: Optional[subprocess.Popen] = None
        self.qemu_pid: Optional[int] = None
        self._qemu_ready = False  # Track if QEMU is in fork server loop
        self._trace_file = None   # Remember trace file for persistent mode
        self._last_fork_point = -1 # Track last fork point for reuse optimization
        
        self._init_stats()
        
    @property
    def process(self) -> Optional[subprocess.Popen]:
        """Expose QEMU process object for monitoring (Read-only)"""
        return self.qemu_process
        
        # Statistics
    def _init_stats(self):
         self.total_executions = 0
         self.total_crashes = 0
         self.total_timeouts = 0
         self._ipc_fallback_dir = Path(
             os.environ.get("RR_SHM_FALLBACK_DIR") or (Path.cwd() / ".rr_shm_fallback")
         )
         
         # Initialize shared coverage bitmap (once for all executors)
         self._init_shared_coverage()
         
         alog(f"Initialized (QEMU={self.qemu_path}, Target={self.target_binary})", "EXEC", "INFO")
    
    class _FileBackedSharedMemory:
        """Minimal wrapper to mimic multiprocessing.SharedMemory API"""
        def __init__(self, path: Path, size: int):
            self.path = path
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
            os.ftruncate(self.fd, size)
            self._mmap = mmap.mmap(self.fd, size)
            self.buf = memoryview(self._mmap)
            alog(f"Created file-backed coverage bitmap at {self.path}", "EXEC", "INFO")
        
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
                    
                    # Use a unique name per process to avoid multi-worker collision
                    # Logic: Logical coverage is global (mp.Array), but QEMU's raw SHM 
                    # must be isolated to allow per-execution reset without cross-process interference.
                    shm_name = f"rr_coverage_{os.getpid()}"
                    
                    # Try to create or open existing shared memory
                    try:
                        cls._shared_coverage_shm = shared_memory.SharedMemory(
                            name=shm_name,
                            create=True,
                            size=69672  # sizeof(rr_coverage_t)
                        )
                        # Initialize to zeros
                        cls._shared_coverage_shm.buf[:] = bytes(69672)
                        alog(f"Created isolated coverage SHM ({shm_name})", "EXEC", "INFO")
                    except FileExistsError:
                        # Already exists, just open it
                        cls._shared_coverage_shm = shared_memory.SharedMemory(
                            name=shm_name,
                            create=False,
                            size=69672
                        )
                        alog(f"Opened existing isolated coverage SHM ({shm_name})", "EXEC", "INFO")
                    cls._coverage_env_value = shm_name
                except PermissionError as e:
                    alog(f"⚠️  SharedMemory permission error: {e}", "EXEC", "WARN")
                    fallback_path = cls._coverage_fallback_path()
                    cls._shared_coverage_shm = cls._FileBackedSharedMemory(
                        fallback_path, 64 * 1024 + 4096
                    )
                    cls._coverage_env_value = f"file:{fallback_path}"
                except Exception as e:
                    alog(f"⚠️  Failed to create shared coverage: {e}", "EXEC", "WARN")
                    fallback_path = cls._coverage_fallback_path()
                    cls._shared_coverage_shm = cls._FileBackedSharedMemory(
                        fallback_path, 69672
                    )
                    cls._coverage_env_value = f"file:{fallback_path}"
    
    @classmethod
    def reset_shared_coverage(cls):
        """Reset shared coverage bitmap to zeros (call before each execution)"""
        if cls._shared_coverage_shm is not None:
            try:
                # 🔥 FIX: Preserve the first byte (enabled flag)
                # Structure: [enabled(1)] [coverage_map(64K)]
                # The map starts at offset 1 or 4 depending on alignment, but we clear from 1 to end to be safe/simple.
                # However, strict slice assignment requires equal sizes.
                
                # Check actual buffer size
                buf_len = len(cls._shared_coverage_shm.buf)
                if buf_len > 1:
                    # Create a zero-filled bytes object of the exact needed length
                    reset_len = buf_len - 1
                    cls._shared_coverage_shm.buf[1:] = bytes(reset_len)
                return True
            except Exception as e:
                alog(f"⚠️ Failed to reset coverage SHM: {e}", "EXEC", "WARN")
                return False
        return True
    
    @classmethod
    def cleanup_shared_coverage(cls):
        """Cleanup shared coverage bitmap (call at program exit)"""
        with cls._coverage_shm_lock:
            if cls._shared_coverage_shm is not None:
                try:
                    # ✅ FIX: Avoid KeyError in resource_tracker by not calling unlink 
                    # if the tracker has already marked it for deletion or it's gone.
                    cls._shared_coverage_shm.close()
                    if hasattr(cls._shared_coverage_shm, "unlink"):
                        try:
                            cls._shared_coverage_shm.unlink()
                        except (FileNotFoundError, KeyError, Exception):
                            # Silently ignore cleanup errors to avoid resource_tracker noise
                            pass
                    # alog("Cleaned up isolated coverage SHM", "EXEC", "INFO")
                except Exception:
                    pass
                finally:
                    cls._shared_coverage_shm = None
    
    def _setup_ipc(self):
        """Setup IPC channels (pipes and shared memory)"""
        # 🔥 FIX: Cleanup old IPC resources before creating new ones to avoid leaks
        self._cleanup_ipc()
        
        # Create pipes
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        
        # Move pipes to high FDs to avoid collision with target program FDs
        # QEMU's align_fd_state might clobber low FDs if not relocated
        try:
            self.cmd_pipe_read = os.dup(r1) 
            # We don't control the target FD number easily in Python without os.dup2 to a specific int
            # But just duping usually finds the lowest available.
            # We want SPECIFIC high FDs.
            
            # Let's try to dup2 to 100, 101, 102, 103 manually
            TARGET_FD_BASE = 150
            
            os.dup2(r1, TARGET_FD_BASE)
            os.dup2(w1, TARGET_FD_BASE + 1)
            os.dup2(r2, TARGET_FD_BASE + 2)
            os.dup2(w2, TARGET_FD_BASE + 3)
            
            # Close originals
            os.close(r1); os.close(w1); os.close(r2); os.close(w2)
            
            self.cmd_pipe_read = TARGET_FD_BASE
            self.cmd_pipe_write = TARGET_FD_BASE + 1
            self.status_pipe_read = TARGET_FD_BASE + 2
            self.status_pipe_write = TARGET_FD_BASE + 3
            
        except Exception as e:
            alog(f"⚠️ Failed to relocate FDs, falling back to default: {e}", "EXEC", "WARN")
            self.cmd_pipe_read = r1
            self.cmd_pipe_write = w1
            self.status_pipe_read = r2
            self.status_pipe_write = w2

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
            alog("🛑 Stopping persistent QEMU fork server...", "EXEC", "INFO")
            # Send 'Q' command to quit
            if self.cmd_pipe_write is not None:
                os.write(self.cmd_pipe_write, b'Q')
            
            # Wait for graceful exit
            if self.qemu_process:
                try:
                    self.qemu_process.wait(timeout=2.0)
                    alog("Fork server exited gracefully", "EXEC", "INFO")
                except subprocess.TimeoutExpired:
                    alog("⚠️  Fork server didn't exit, killing...", "EXEC", "WARN")
                    self._terminate_qemu()
        except Exception as e:
            alog(f"⚠️  Error stopping fork server: {e}", "EXEC", "ERROR")
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
                    alog(f"Cleaned IPC shared memory: {shm_descriptor}", "EXEC", "INFO")
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
        # os.environ.copy() will be used below
        
        env = os.environ.copy()
        
        # Note: Do NOT set RR_STRACE_MODE - it's for strace text format
        # Our trace files are TRRR binary format, use native replay module
        # which already supports silent_replay_mode
        
        # QEMU may hang if RR_TRACE_PIPE is set but no visualizer is reading.
        # This prevents deadlock by ensuring we only pass it if active.
        if 'RR_TRACE_PIPE' in env:
             alog(f"RR_TRACE_PIPE active: {env['RR_TRACE_PIPE']}", "EXEC", "DEBUG")
             # print("[QEMUExecutor] 🛑 为了防止 QEMU 启动死锁（阻塞式打开），正在移除该变量")
             # del env['RR_TRACE_PIPE']
        
        # 同时禁用默认管道的自动检测逻辑，原因同上
        # default_pipe = '/tmp/rr_dynamic_trace'
        # if os.path.exists(default_pipe): ...

        
        env.update({
            'RR_FUZZING_ENABLED': '1',
            'RR_MODE': 'fuzzing',
            'RR_TRACE_FILE': trace_file,
            'RR_CMD_PIPE': str(self.cmd_pipe_read),
            'RR_STATUS_PIPE': str(self.status_pipe_write),
            'RR_SHARED_MEMORY': self.shm.get_env_value(),
            'RR_COVERAGE_SHM': self.__class__._coverage_env_value,
            'RR_BB_TRACE_ENABLED': '1', # Enable BB trace for PathFinder
            'RR_DEBUG_LEVEL': os.environ.get('RR_DEBUG_LEVEL', '1'),
            # ✅ FIX: Use unique BB trace file to avoid overwriting seed trace
            'RR_BB_TRACE_FILE': f"/tmp/qemu_bb_trace_{os.getpid()}_{self.total_executions}_{time.time()}.bbl",
        })
        
        if 'RR_TREE_OUTPUT' in env:
            alog(f"🌲 Env OK: RR_TREE_OUTPUT={env['RR_TREE_OUTPUT']}", "EXEC", "DEBUG")
        else:
            # Set default path to prevent C-side crash/error
            import tempfile
            default_tree = Path(tempfile.gettempdir()) / f"syscall_tree_{os.getpid()}_{self.total_executions}.html"
            env['RR_TREE_OUTPUT'] = str(default_tree)
            alog(f"⚠️ Env MISSING: RR_TREE_OUTPUT not found! Defaults to {default_tree}", "EXEC", "WARN")
        
        cmd = [self.qemu_path, self.target_binary]
        if self.target_args:
            # Simple splitting by space, assuming no complex quoting for now
            # For complex cases we might need shlex.split
            import shlex
            cmd.extend(shlex.split(self.target_args))
        
        # ✅ FIX: Save pipe ends to close in case of error
        child_cmd_pipe = self.cmd_pipe_read
        child_status_pipe = self.status_pipe_write
        
        try:
            # ✅ FIX: Redirect output to log file if configured, otherwise inherit stdout (visible in terminal)
            stdout_dest = None
            stderr_dest = None
            self._log_file_handle = None

            if self.log_file:
                try:
                    # Open in append mode
                    self._log_file_handle = open(self.log_file, "a")
                    stdout_dest = self._log_file_handle
                    stderr_dest = self._log_file_handle
                    alog(f"📝 Redirecting QEMU output to {self.log_file}", "EXEC", "INFO")
                except Exception as e:
                    alog(f"⚠️ Failed to open log file {self.log_file}: {e}. Falling back to terminal.", "EXEC", "WARN")

            self.qemu_process = subprocess.Popen(
                cmd,
                env=env,
                pass_fds=[child_cmd_pipe, child_status_pipe],
                stdout=stdout_dest,
                stderr=stderr_dest
            )
            
            # Close file handle in parent process immediately (Popen has enabled it for child)
            if self._log_file_handle:
                self._log_file_handle.close()
                self._log_file_handle = None
            
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
    
    def _wait_for_status(self, timeout: float) -> Optional[tuple]:
        """
        Wait for status update from QEMU

        Args:
            timeout: Timeout in seconds

        Returns:
            tuple: (status, exit_code, signal_number) or None if timeout
                  For non-crash statuses: (status, None, None)
                  For crashes: (STATUS_CRASH, exit_code, signal_number)

        # Performance optimization: reduce select timeout to minimize wait time
        """
        start_time = time.time()

        while (time.time() - start_time) < timeout:
            # Optimize: use small polling interval to reduce selection latency
            remaining = timeout - (time.time() - start_time)
            select_timeout = min(0.01, remaining) 

            ready, _, _ = select.select([self.status_pipe_read], [], [], select_timeout)

            if ready:
                # Read status (4 bytes)
                try:
                    status_bytes = os.read(self.status_pipe_read, 4)
                except OSError:
                    status_bytes = b''

                if not status_bytes:
                    # Pipe closed (EOF), process likely exited
                    if self.qemu_process:
                         # Wait briefly for process to update status
                         try:
                             self.qemu_process.wait(timeout=0.1)
                         except:
                             pass
                         
                         if self.qemu_process.poll() is not None:
                             exit_code = self.qemu_process.returncode
                             alog(f"❌ QEMU Process Exited Unexpectedly with Code: {exit_code}", "EXEC", "ERROR")
                             return None
                    return None
                    
                if len(status_bytes) == 4:
                    status = struct.unpack('i', status_bytes)[0]
                    
                    # Read additional exit code and signal for crashes
                    if status == STATUS_CRASH:
                        try:
                            extra_bytes = os.read(self.status_pipe_read, 8)
                            if len(extra_bytes) == 8:
                                exit_code, signal_number = struct.unpack('ii', extra_bytes)
                                return (status, exit_code, signal_number)
                            else:
                                alog(f"⚠️ Incomplete crash data: {len(extra_bytes)} bytes", "EXEC", "WARN")
                                return (status, None, None)
                        except Exception as e:
                            alog(f"⚠️ Failed to read crash details: {e}", "EXEC", "ERROR")
                            return (status, None, None)
                    else:
                        # Non-crash status, no extra data needed
                        return (status, None, None)

            # Check if process is still alive
            if self.qemu_process and self.qemu_process.poll() is not None:
                # Process exited unexpectedly
                exit_code = self.qemu_process.returncode
                alog(f"❌ QEMU Process Exited Unexpectedly with Code: {exit_code}", "EXEC", "ERROR")
                # Try to read stderr if available
                if self.qemu_process.stderr:
                   try:
                       err_out = self.qemu_process.stderr.read()
                       if err_out:
                           print(f"[QEMUExecutor] 📜 Last Stderr: {err_out.decode('utf-8', errors='replace')}")
                   except:
                       pass
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
                # 🔥 FIX: Slice exactly 64KB starting from offset 1 (skipping 'enabled' byte)
                # Structure: [enabled(1)] [coverage_map(64K)]
                start_offset = 1
                map_size = 64 * 1024
                raw_buf = self._shared_coverage_shm.buf
                coverage_bitmap = bytes(raw_buf[start_offset : start_offset + map_size])
                
                # Debug: Check first 16 bytes and non-zero count
                header = bytes(raw_buf[:16]).hex()
                nz_count = sum(1 for b in coverage_bitmap if b > 0)
                if nz_count > 0 or self.total_executions % 100 == 0:
                    alog(f"📊 [SHM-DEBUG] SHM Header: {header}, Map Non-Zero: {nz_count}", "EXEC", "DEBUG")

                return coverage_bitmap
            except Exception as e:
                alog(f"⚠️  Failed to read shared coverage: {e}", "EXEC", "WARN")
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
                alog(f"✅ Read coverage: {non_zero_count} non-zero bytes from {latest_file}", "EXEC", "INFO")
            
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
                alog(f"✅ Coverage bitmap reset (cleared {len(self._shared_coverage_shm.buf)} bytes)", "EXEC", "DEBUG")
            except Exception as e:
                alog(f"⚠️  Failed to reset coverage: {e}", "EXEC", "WARN")
    
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
        alog(f"📜 Executing baseline trace (iteration {iteration_id})...", "EXEC", "INFO")
        
        try:
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # PHASE 1: Initialize QEMU (if not ready)
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            if not self._qemu_ready:
                alog("🚀 Starting persistent QEMU fork server for baseline...", "EXEC", "INFO")
                
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
                alog("QEMU fork server ready for baseline", "EXEC", "DEBUG")
            else:
                # Write iteration_id to shared memory
                self.shm.write_fork_request(fork_point=0, mutation_variants=[[]], depth=0, iteration_id=iteration_id)
            
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # PHASE 2: Send baseline execution command ('E')
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            alog("📤 Sending 'E' (baseline execution) command...", "EXEC", "DEBUG")
            os.write(self.cmd_pipe_write, b'E')
            
            # Wait for execution to complete
            status = self._wait_for_status(timeout=30.0)
            
            execution_time = time.time() - start_time
            
            if status == 0:  # Success
                alog(f"Baseline execution completed ({execution_time:.3f}s)", "EXEC", "INFO")
                return ExecutionResult(
                    status=STATUS_NORMAL_EXIT,
                    status_name="NORMAL",
                    coverage_bitmap=None,
                    execution_time=execution_time
                )
            else:
                alog(f"⚠️ Baseline execution failed (status={status})", "EXEC", "WARN")
                return ExecutionResult(
                    status=-1,
                    status_name="ERROR",
                    coverage_bitmap=None,
                    execution_time=execution_time
                )
        
        except Exception as e:
            execution_time = time.time() - start_time
            alog(f"❌ Baseline execution exception: {e}", "EXEC", "ERROR")
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
                    self.qemu_process.wait(timeout=1.0)  # Must wait after kill
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
            # Final attempt to reap zombie if still exists
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
        
        # Track _qemu_ready state
        alog(f"execute() called (exec#{self.total_executions}), _qemu_ready={self._qemu_ready}, qemu_alive={self.qemu_process is not None and self.qemu_process.poll() is None if self.qemu_process else False}", "EXEC")
        
        # Coverage accumulation logic: Standardize reset for each execution 
        # to ensure accurate delta reporting in statistics.
        # Persistent mode handles accumulation on the C side if needed.
        QEMUExecutor.reset_shared_coverage() 
        
        try:
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # PHASE 1: Initialize QEMU (first time only)
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            if not self._qemu_ready:
                alog("🚀 Starting persistent QEMU fork server...", "EXEC", "INFO")
                
                # Setup IPC
                self._setup_ipc()
                
                # Write initial empty mutations (will be overwritten later)
                self.shm.write_fork_request(fork_point=0, mutation_variants=[[]], depth=0, iteration_id=iteration_id)
                
                # Fork QEMU process
                self._fork_qemu(trace_file)
                self._trace_file = trace_file
                
                # Wait for initial READY status
                status_data = self._wait_for_status(timeout=20.0)
                if status_data is None or status_data[0] != STATUS_READY:
                    alog(f"❌ QEMU init failed (data={status_data}), setting _qemu_ready=False", "EXEC", "ERROR")
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
                
                time_module.sleep(0.1)  
                
                print("[QEMUExecutor] QEMU in fork server loop, ready for persistent fuzzing")
                self._qemu_ready = True
            
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # PHASE 2: Execute mutation (every time)
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            # Write mutations to shared memory (using unified interface)
            self.shm.write_fork_request(fork_point=0, mutation_variants=[mutations], depth=0, iteration_id=iteration_id)
            
            # Send 'F' command to trigger fork and execution
            os.write(self.cmd_pipe_write, b'F')
            
            # Step 6: Wait for execution result
            status_data = self._wait_for_status(timeout=self.timeout)
            
            if status_data is None:
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
            
            # Step 8: Unpack status and crash details
            status, exit_code, signal_number = status_data
            
            # Step 9: Determine status name
            status_map = {
                STATUS_NORMAL_EXIT: "normal_exit",
                STATUS_CRASH: "crash",
                STATUS_OTHER_SIGNAL: "signal",
                STATUS_AT_FORK_POINT: "fork_point_ready"  # Fork server waiting for next command
            }
            # Ensure STATUS_NORMAL_EXIT (3) is explicitly handled
            if status == 3:
                status_name = "normal_exit"
            else:
                status_name = status_map.get(status, f"unknown_{status}")
            
            if status == STATUS_CRASH:
                self.total_crashes += 1
            
            # In persistent mode, fork server returns AT_FORK_POINT (2) after execution.
            if status == STATUS_AT_FORK_POINT:
                # Fork server is ready for next command
                pass
            else:
                # Abnormal termination, wait for exit
                try:
                    exit_code_wait = self.qemu_process.wait(timeout=1.0)
                    if exit_code is None:
                        exit_code = exit_code_wait
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
        Unified fork execution method (replaces all legacy methods)
        
        Args:
            trace_file: Path to trace file
            fork_point: Fork point (0=start, N=mid-point)
            mutation_variants: Mutation variants list (None=single execution)
            depth: Fork depth
            iteration_id: Iteration ID
        
        Returns:
            List of execution results
        
        Scenario Mapping:
            - Legacy execute(): fork(fork_point=0, variants=[[inst1,inst2]], depth=0)
            - Legacy execute_batch(): fork(fork_point=0, variants=[v1,v2,v3], depth=0)
            - Legacy execute_batch_at_checkpoint(): fork(fork_point=N, variants=[v1,v2,v3], depth=0)
            - Nested fork: fork(fork_point=N, variants=[v1,v2,v3], depth=1)
        """
        start_time = time.time()
        
        # 🔥 CRITICAL FIX: Each fork execution MUST use a fresh QEMU process
        # 
        # Problem: QEMU's CPU/memory state cannot be "rewound". After processing
        # one fork command (e.g., fork_point=10), the Parent's replay_index has
        # advanced. A subsequent fork command with fork_point=34 cannot work
        # because QEMU cannot go back to replay_index=0 and replay to 34.
        #
        # Solution: Always start a fresh QEMU process for each execute_fork call.
        # This ensures clean state and proper trace replay from the beginning.
        #
        # Performance Note: This is slower than true persistent mode, but correct.
        # For high performance, use multi-process mode instead.
        if self._qemu_ready:
            # ✅ OPTIMIZATION: Reuse QEMU if fork_point matches
            if self._last_fork_point == fork_point:
                 # alog(f"♻️ Reusing QEMU at fork_point={fork_point}", "EXEC", "DEBUG")
                 pass
            else:
                print(f"[QEMUExecutor] 🔄 Restarting QEMU for fresh fork state (fork_point={fork_point}, depth={depth})")
                # Use stop_persistent_qemu instead of _terminate_qemu to properly cleanup IPC
                self.stop_persistent_qemu()
                print(f"[QEMUExecutor] 🔄 After stop: _qemu_ready={self._qemu_ready}")
        
        # Initialize fork server (if not already initialized)
        if not self._qemu_ready:
            print(f"[QEMUExecutor] 🚀 Starting fresh QEMU (fork_point={fork_point}, depth={depth})")
            # If not persistent mode, we might need to restart, but here we just start if needed
            self._setup_ipc()
            # No need to write to shared memory, QEMU will wait for first command on start
            # self.shm.write_fork_request(fork_point=0, mutation_variants=[[]], depth=0)
            self._fork_qemu(trace_file)
            self._trace_file = trace_file
            
            print(f"[QEMUExecutor] ⏳ Waiting for READY status...")
            status_data = self._wait_for_status(timeout=20.0)
            if status_data is None or status_data[0] != STATUS_READY:
                print(f"[DEBUG-EXEC] ❌ QEMU init failed (data={status_data})")
                raise RuntimeError("QEMU init failed")
            
            print(f"[QEMUExecutor] ✅ QEMU ready!")
            # 不需要发送'F'命令，QEMU已经在fork server loop中等待
            # os.write(self.cmd_pipe_write, b'F')
            # time.sleep(0.1)
            self._qemu_ready = True
        
        if mutation_variants is None:
            mutation_variants = [[]]
        
        # Standardized reset
        QEMUExecutor.reset_shared_coverage()
        
        # Write fork request to shared memory
        self.shm.write_fork_request(
            fork_point=fork_point,
            mutation_variants=mutation_variants,
            depth=depth,
            iteration_id=iteration_id
        )
        
        # Update last fork point
        self._last_fork_point = fork_point
        
        # Send unified command: 'C'
        print(f"[QEMUExecutor] Sending 'C' command (fork_point={fork_point}, "
              f"variants={len(mutation_variants)}, depth={depth}, iteration={iteration_id})")
        os.write(self.cmd_pipe_write, b'C')
        
        # Collect results
        results = []
        extended_timeout = self.timeout * len(mutation_variants)
        
        for variant_idx in range(len(mutation_variants)):
            result_data = self._wait_for_status(timeout=extended_timeout)
            
            if result_data is None:
                if self.qemu_process and self.qemu_process.returncode == 0:
                     print(f"[QEMUExecutor] ℹ️  QEMU Exited Cleanly (Execution Finished due to Early Exit in Mutation)")
                else:
                     print(f"[QEMUExecutor] ❌ QEMU disconnected unexpectedly (EOF), setting _qemu_ready=False")
                
                self._qemu_ready = False
                # Try to restart QEMU to salvage subsequent iterations
                self._terminate_qemu()
                break
            
            # Unpack status and crash details
            status, exit_code, signal_number = result_data
            
            # Read coverage
            coverage_bitmap = self._read_coverage()
            
            # Status name
            status_map = {
                STATUS_NORMAL_EXIT: "normal_exit",
                STATUS_CRASH: "crash",
                STATUS_OTHER_SIGNAL: "signal",
                STATUS_AT_FORK_POINT: "fork_point_ready",
                2: "batch_completed"
            }
            # Ensure STATUS_NORMAL_EXIT (3) is explicitly handled
            if status == 3:
                status_name = "normal_exit"
            else:
                status_name = status_map.get(status, f"unknown_{status}")
            
            print(f"[QEMUExecutor] Read status={status}, name={status_name}")
            
            if status == STATUS_CRASH:
                self.total_crashes += 1
                print(f"[QEMUExecutor] CRASH DETECTED! exit_code={exit_code}, signal={signal_number}, Total crashes: {self.total_crashes}")
            
            result = ExecutionResult(
                status=status,
                status_name=status_name,
                coverage_bitmap=coverage_bitmap,
                execution_time=time.time() - start_time,
                qemu_exit_code=exit_code,
                signal_number=signal_number
            )
            # Initialize crash_info if it's a crash
            if status == STATUS_CRASH:
                result.crash_info = f"Signal {signal_number} (Exit Code: {exit_code})"
            
            results.append(result)
            
            self.total_executions += 1
        
        print(f"[QEMUExecutor] ✅ Fork execution completed: {len(results)} results")
        
        # ❌ Do NOT close QEMU here - it should be closed between iterations, not after every fork
        # Current concurrent forks require serialization or isolation, temporarily relying on FuzzingCore cleanup
        
        # If not persistent mode, ensure cleanup
        if not self.persistent_mode:
            self.stop_persistent_qemu()
        
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

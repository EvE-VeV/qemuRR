#!/usr/bin/env python3
"""
FuzzSharedMemory - Shared Memory Management

This module manages the shared memory region used for IPC between the
Python fuzzing conductor and the QEMU process.

The shared memory layout matches the C-side structure:
    - Header: magic, sequence, count, checksum, flags, reserved
    - Instructions: array of FuzzInstruction
"""

import os
import mmap
import struct
from pathlib import Path
from typing import List
from .constants import (
    FUZZ_MAGIC, FUZZ_MAX_INSTRUCTIONS, FUZZ_SHM_SIZE,
    FUZZ_FLAG_CAPTURE_SEED
)


class FuzzSharedMemory:
    """Shared Memory Manager"""
    
    def __init__(self, shm_name, size=FUZZ_SHM_SIZE, fallback_dir: str = None):
        # Ensure shm_name doesn't contain /dev/shm/ prefix
        # QEMU's shm_open() expects just the name, not the full path
        if shm_name.startswith("/dev/shm/"):
            shm_name = shm_name[9:]  # Remove "/dev/shm/" prefix
        elif shm_name.startswith("/"):
            shm_name = shm_name[1:]  # Remove leading "/"
        
        self.shm_name = shm_name
        self.shm_path = f"/dev/shm/{shm_name}"
        self.size = size
        self.shm_fd = None
        self.mem = None
        self.sequence = 0  # Sequence number counter
        self.mode = "posix"  # posix | file
        self.fallback_path: Path = None
        self._fallback_dir = Path(
            fallback_dir
            or os.environ.get("RR_SHM_FALLBACK_DIR")
            or (Path.cwd() / ".rr_shm_fallback")
        )
    
    def create(self):
        """Create shared memory"""
        # Use /dev/shm (Linux shared memory)
        # Use self.shm_path instead of recreating it
        
        try:
            # Create or open shared memory file
            self.shm_fd = os.open(self.shm_path, os.O_CREAT | os.O_RDWR, 0o666)
            os.ftruncate(self.shm_fd, self.size)
            
            # Map to memory
            self.mem = mmap.mmap(self.shm_fd, self.size)
            
            print(f"[Conductor] Created shared memory: {self.shm_path} ({self.size} bytes)")
            print(f"[Conductor] Shared memory name for QEMU: {self.shm_name}")
            self.mode = "posix"
        except PermissionError:
            # Sandboxed environments may forbid /dev/shm writes; fall back to file-backed mmap.
            self._create_file_backed_region()
        return self

    def _create_file_backed_region(self):
        """Create a regular file based shared memory fallback"""
        self.mode = "file"
        self._fallback_dir.mkdir(parents=True, exist_ok=True)
        self.fallback_path = (self._fallback_dir / f"{self.shm_name}.bin").resolve()
        fd = os.open(self.fallback_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.ftruncate(fd, self.size)
        self.shm_fd = fd
        self.mem = mmap.mmap(self.shm_fd, self.size)
        print(f"[Conductor] ⚠️  /dev/shm unavailable, using file-backed shared memory: {self.fallback_path}")

    def get_env_value(self) -> str:
        """Value to be passed via RR_SHARED_MEMORY for QEMU side."""
        if self.mode == "file" and self.fallback_path:
            return f"file:{self.fallback_path}"
        return self.shm_name
    
    def write_fork_request(self, 
                          fork_point: int = 0,
                          mutation_variants: List[List] = None,
                          depth: int = 0,
                          iteration_id: int = 0):
        """
        统一的fork请求写入方法（替代所有旧方法）
        
        Args:
            fork_point: 0=从头开始, N=mid-point fork
            mutation_variants: None/空=单次执行, [v1,v2,...]=批量fork
            depth: 嵌套深度（0=顶层，1=一级嵌套，...）
            iteration_id: 当前iteration编号（用于Visualizer）
        
        场景映射:
            - 旧write_instructions: fork_request(fork_point=0, variants=[[inst1,inst2]], depth=0)
            - 旧write_batch_variants: fork_request(fork_point=0, variants=[v1,v2,v3], depth=0)
            - 旧write_checkpoint_variants: fork_request(fork_point=N, variants=[v1,v2,v3], depth=0)
            - 嵌套fork: fork_request(fork_point=N, variants=[v1,v2,v3], depth=1)
        """
        if not self.mem:
            raise RuntimeError("Shared memory not created")
        
        if mutation_variants is None:
            mutation_variants = [[]]  # 空变异列表
        
        num_variants = len(mutation_variants)
        if num_variants > 10:
            raise ValueError(f"Too many variants: {num_variants} (max 10)")
        
        # Increment sequence
        self.sequence += 1
        
        # Checksum
        checksum = FUZZ_MAGIC ^ self.sequence ^ num_variants ^ fork_point ^ depth
        
        # Header: 包含所有必要信息
        # Layout: magic(4) + sequence(4) + num_variants(4) + checksum(4) + iteration_id(4) + reserved(4)
        #         + fork_point(4) + depth(4) + reserved(4)
        header = struct.pack('IIIIII', 
            FUZZ_MAGIC,      # magic
            self.sequence,   # sequence
            num_variants,    # num_variants（复用原instruction_count字段）
            checksum,        # checksum
            iteration_id,    # iteration_id（复用原flags字段）
            0)               # reserved
        header += struct.pack('III', 
            fork_point,      # fork_point
            depth,           # depth（新增）
            0)               # reserved
        
        self.mem.seek(0)
        self.mem.write(header)
        
        # 🔥 修复：写入variants的正确offset计算
        # Header: 9个uint32_t = 36字节
        # instructions[32]: 32 * 280字节(FuzzInstruction.struct_size) = 8960字节
        # variants[0]起始: 36 + 8960 = 8996字节
        offset = 36 + 32 * 280
        
        for variant_idx, instructions in enumerate(mutation_variants):
            # Variant header: instruction_count
            self.mem.seek(offset)
            self.mem.write(struct.pack('I', len(instructions)))
            offset += 4
            
            # Variant instructions
            for inst in instructions:
                self.mem.seek(offset)
                self.mem.write(inst.pack())
                # 🔥 修复：使用固定的C结构体大小而不是数据大小
                offset += inst.struct_size
        
        self.mem.flush()
        
        print(f"[SharedMemory] Fork request: fork_point={fork_point}, "
              f"variants={num_variants}, depth={depth}, iteration={iteration_id}")
        for i, variant in enumerate(mutation_variants):
            if variant:  # 只有非空variant才打印
                print(f"  Variant {i}: {len(variant)} instructions")
    
    def close(self):
        """Close shared memory"""
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
        
    def unlink(self):
        """Remove backing file (if any)"""
        target = None
        if self.mode == "file" and self.fallback_path:
            target = str(self.fallback_path)
        elif self.mode == "posix":
            target = self.shm_path
        
        if not target:
            return
        
        try:
            if os.path.exists(target):
                os.unlink(target)
        except FileNotFoundError:
            pass
        except Exception as exc:
            print(f"[Conductor] ⚠️  Failed to unlink shared memory '{target}': {exc}")

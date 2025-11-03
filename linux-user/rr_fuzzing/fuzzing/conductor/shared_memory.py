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
from .constants import (
    FUZZ_MAGIC, FUZZ_MAX_INSTRUCTIONS, FUZZ_SHM_SIZE,
    FUZZ_FLAG_CAPTURE_SEED
)


class FuzzSharedMemory:
    """Shared Memory Manager"""
    
    def __init__(self, shm_name, size=FUZZ_SHM_SIZE):
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
    
    def create(self):
        """Create shared memory"""
        # Use /dev/shm (Linux shared memory)
        # Use self.shm_path instead of recreating it
        
        # Create or open shared memory file
        self.shm_fd = os.open(self.shm_path, os.O_CREAT | os.O_RDWR, 0o666)
        os.ftruncate(self.shm_fd, self.size)
        
        # Map to memory
        self.mem = mmap.mmap(self.shm_fd, self.size)
        
        print(f"[Conductor] Created shared memory: {self.shm_path} ({self.size} bytes)")
        print(f"[Conductor] Shared memory name for QEMU: {self.shm_name}")
        return self
    
    def write_instructions(self, instructions, capture_seed=False):
        """
        Write Fuzz instructions to shared memory, with sequence number and checksum
        
        Args:
            instructions: Instruction list
            capture_seed: Phase 3 - Whether to request seed capture
        """
        if not self.mem:
            raise RuntimeError("Shared memory not created")
        
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            raise ValueError(f"Too many instructions: {len(instructions)} (max {FUZZ_MAX_INSTRUCTIONS})")
        
        # Increment sequence number
        self.sequence += 1
        count = len(instructions)
        
        # Calculate checksum: magic ^ sequence ^ count
        checksum = FUZZ_MAGIC ^ self.sequence ^ count
        
        # Phase 3: Set flags
        flags = 0
        if capture_seed:
            flags |= FUZZ_FLAG_CAPTURE_SEED
        
        # Write header: magic + sequence + count + checksum + flags + reserved[3]
        header = struct.pack('IIIIII', FUZZ_MAGIC, self.sequence, count, checksum, flags, 0)
        # reserved[3] needs two additional I (total 8 uint32_t)
        header += struct.pack('II', 0, 0)
        
        self.mem.seek(0)
        self.mem.write(header)
        
        # Write instruction array
        for instr in instructions:
            self.mem.write(instr.pack())
        
        # Force flush to disk
        self.mem.flush()
        
        print(f"[Conductor] Wrote {count} instructions to shared memory (seq={self.sequence}, checksum=0x{checksum:x})")
    
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
        
        # Clean up shared memory file
        try:
            if os.path.exists(self.shm_path):
                os.unlink(self.shm_path)
        except:
            pass


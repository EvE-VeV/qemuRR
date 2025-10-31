#!/usr/bin/env python3
"""
FuzzInstruction - Fuzzing Instruction Representation

This module provides the FuzzInstruction class that represents a single
fuzzing instruction to be sent to QEMU via shared memory.

The binary format matches the C-side structure defined in rr_framework.h:
    typedef struct {
        fuzz_cmd_type_t cmd;        // Command type (uint32)
        uint32_t syscall_index;     // Syscall index
        uint32_t arg_index;         // Argument index
        uint32_t offset;            // Offset (Phase 2)
        uint32_t size;              // Size (Phase 2)
        uint32_t data_len;          // Data length
        uint8_t data[256];          // Data payload
    } FuzzInstruction;
"""

import struct
from .constants import FUZZ_INSTRUCTION_DATA


class FuzzInstruction:
    """
    Single Fuzz Instruction (Phase 2 Enhanced)
    
    Represents one mutation command to apply during fuzzing.
    """
    
    def __init__(self, syscall_index, cmd, arg_index, data, offset=0, size=None):
        """
        Args:
            syscall_index: System call index
            cmd: Command type
            arg_index: Argument index
            data: Mutation data
            offset: Offset (Phase 2 new)
            size: Data size (Phase 2 new, if None uses data length)
        """
        self.syscall_index = syscall_index
        self.cmd = cmd
        self.arg_index = arg_index
        self.data = data
        self.offset = offset
        self.size = size if size is not None else (len(data) if isinstance(data, bytes) else 8)
    
    def pack(self):
        """
        Pack to binary format (matches C struct)
        
        🔥 Phase 2 Fix: C-side structure definition (rr_framework.h:70-78):
        typedef struct {
            fuzz_cmd_type_t cmd;        // Field 1 (uint32)
            uint32_t syscall_index;     // Field 2
            uint32_t arg_index;         // Field 3
            uint32_t offset;            // Field 4 (Phase 2 new)
            uint32_t size;              // Field 5 (Phase 2 new)
            uint32_t data_len;          // Field 6
            uint8_t data[256];          // Field 7
        } FuzzInstruction;
        
        Returns:
            bytes: Packed binary data
        """
        data_bytes = self.data if isinstance(self.data, bytes) else struct.pack('q', self.data)
        data_len = len(data_bytes)
        
        # Pad to 256 bytes
        padded_data = data_bytes + b'\x00' * (FUZZ_INSTRUCTION_DATA - data_len)
        
        # Pack in C-side field order (Phase 2: includes offset and size)
        return struct.pack('IIIIII256s', 
                          self.cmd,                # Field 1: cmd
                          self.syscall_index,      # Field 2: syscall_index  
                          self.arg_index,          # Field 3: arg_index
                          self.offset,             # Field 4: offset (Phase 2 new)
                          self.size,               # Field 5: size (Phase 2 new)
                          data_len,                # Field 6: data_len
                          padded_data)             # Field 7: data


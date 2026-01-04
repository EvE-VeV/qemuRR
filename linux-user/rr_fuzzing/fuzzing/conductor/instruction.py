#!/usr/bin/env python3
"""
FuzzInstruction - Fuzzing指令表示

本模块提供FuzzInstruction类，表示通过共享内存发送到QEMU的单个
fuzzing指令。

二进制格式与rr_framework.h中定义的C端结构匹配:
    typedef struct {
        fuzz_cmd_type_t cmd;        // 命令类型 (uint32)
        uint32_t syscall_index;     // 系统调用索引
        uint32_t arg_index;         // 参数索引
        uint32_t offset;            // 偏移 (第2阶段)
        uint32_t size;              // 大小 (第2阶段)
        uint32_t data_len;          // 数据长度
        uint8_t data[256];          // 数据负载
    } FuzzInstruction;
"""

import struct
from .constants import FUZZ_INSTRUCTION_DATA


class FuzzInstruction:
    """
    单条Fuzz指令 (第2阶段增强)
    单条Fuzz指令
    
    表示在fuzzing期间应用的一个变异命令。
    """
    
    def __init__(self, syscall_index, cmd, arg_index, data, offset=0, size=None, mutation_type='unknown'):
        """
        参数:
            cmd: 命令类型
            arg_index: 参数索引
            data: 变异数据
            offset: 偏移
            size: 数据大小 (如果为None则使用数据长度)
            mutation_type: Mutation类型 (用于统计，不pack到C端)
        """
        self.syscall_index = syscall_index
        self.cmd = cmd
        self.arg_index = arg_index
        self.data = data
        self.offset = offset
        self.size = size if size is not None else (len(data) if isinstance(data, bytes) else 8)
        self.mutation_type = mutation_type  # Tracking mutation type
    
    def pack(self):
        """
        打包为二进制格式 (与C结构体匹配)
        结构体定义 (rr_framework.h:70-78):
        typedef struct {
            fuzz_cmd_type_t cmd;        // 字段1 (uint32)
            uint32_t syscall_index;     // 字段2
            uint32_t arg_index;         // 字段3
            uint32_t offset;            // 字段4
            uint32_t size;              // 字段5
            uint32_t data_len;          // 字段6
            uint8_t data[256];          // 字段7
        } FuzzInstruction;
        
        返回:
            bytes: 打包后的二进制数据
        """
        data_bytes = self.data if isinstance(self.data, bytes) else struct.pack('q', self.data)
        data_len = len(data_bytes)
        
        # 填充到256字节
        padded_data = data_bytes + b'\x00' * (FUZZ_INSTRUCTION_DATA - data_len)
        
        # 按C端字段顺序打包 (包含offset和size)
        return struct.pack('IIIIII256s', 
                          self.cmd,                # 字段1: cmd
                          self.syscall_index,      # 字段2: syscall_index  
                          self.arg_index,          # 字段3: arg_index
                          self.offset,             # 字段4: offset
                          self.size,               # 字段5: size
                          data_len,                # 字段6: data_len
                          padded_data)             # 字段7: data

    @property
    def struct_size(self):
        """
        返回C结构体的固定大小
        6个uint32_t + data[256] = 24 + 256 = 280字节
        """
        return 280

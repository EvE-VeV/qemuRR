# RR-Fuzz Trace File Format Specification

**Version**: 1.0  
**Date**: 2025-10-29  
**Status**: Stable

---

## 概述

RR-Fuzz trace文件是一个二进制格式文件，用于存储程序执行期间的系统调用序列及其相关数据。本文档详细描述了trace文件的完整格式规范。

### 文件扩展名

- 推荐扩展名: `.dat`
- MIME类型: `application/octet-stream`

### 字节序

- **Little-Endian** (小端序)
- 所有多字节整数均使用小端序存储

---

## 文件结构

```
┌─────────────────────┐
│   File Header       │  12 bytes
├─────────────────────┤
│   Syscall Record 0  │  Variable size
├─────────────────────┤
│   Syscall Record 1  │  Variable size
├─────────────────────┤
│   ...               │
├─────────────────────┤
│   Syscall Record N  │  Variable size
└─────────────────────┘
```

---

## 1. File Header (12字节)

文件头部包含魔数、版本信息和记录数量。

| 偏移 | 大小 | 类型 | 名称 | 说明 | 值 |
|------|------|------|------|------|-----|
| 0 | 4 | uint32_t | magic | 魔数标识 | 0x52525254 ("TRRR") |
| 4 | 4 | uint32_t | version | 文件格式版本 | 1 |
| 8 | 4 | uint32_t | count | 系统调用记录数量 | N |

### Python解析示例

```python
import struct

with open('trace.dat', 'rb') as f:
    # 读取文件头
    header = f.read(12)
    magic, version, count = struct.unpack('<III', header)
    
    # 验证魔数
    assert magic == 0x52525254, f"Invalid magic: 0x{magic:08x}"
    assert version == 1, f"Unsupported version: {version}"
    
    print(f"Trace file contains {count} syscall records")
```

---

## 2. Syscall Record Format

每条系统调用记录由三部分组成：
1. **固定字段** (150字节)
2. **Variable arg_data section** (可变长度)
3. **aux_data section** (可变长度，可选)

### 2.1 固定字段 (150字节)

| 偏移 | 大小 | 类型 | 名称 | 说明 |
|------|------|------|------|------|
| 0 | 4 | uint32_t | index | 记录在trace中的序号 (从0开始) |
| 4 | 4 | int32_t | syscall_nr | 系统调用号 (x86_64架构) |
| 8 | 64 | abi_long[8] | args | 系统调用参数 (8个，每个8字节) |
| 72 | 8 | abi_long | retval | 系统调用返回值 |
| 80 | 64 | size_t[8] | arg_sizes | 每个参数数据的大小 (遗留字段) |
| 144 | 1 | bool | creates_fd | 是否创建文件描述符 |
| 145 | 1 | bool | uses_fd | 是否使用文件描述符 |
| 146 | 4 | int32_t | created_fd | 创建的文件描述符值 (-1表示无) |

**总计**: 150字节

### 数据类型定义

- `abi_long`: 64位有符号整数 (在x86_64上)
- `size_t`: 64位无符号整数 (在x86_64上)
- `bool`: 1字节布尔值 (0=false, 非0=true)

### Python解析示例

```python
# 读取固定字段 (150字节)
fixed_data = f.read(150)

# 解析各个字段
index = struct.unpack('<I', fixed_data[0:4])[0]
syscall_nr = struct.unpack('<i', fixed_data[4:8])[0]

# 解析args[8]
args = struct.unpack('<8q', fixed_data[8:72])

# 解析retval
retval = struct.unpack('<q', fixed_data[72:80])[0]

# 解析arg_sizes[8]
arg_sizes = struct.unpack('<8Q', fixed_data[80:144])

# 解析flags
creates_fd = struct.unpack('<?', fixed_data[144:145])[0]
uses_fd = struct.unpack('<?', fixed_data[145:146])[0]
created_fd = struct.unpack('<i', fixed_data[146:150])[0]

print(f"Record #{index}: syscall={syscall_nr}, retval={retval}")
```

---

### 2.2 Variable arg_data Section (可变长度)

此部分存储参数指向的数据内容（如字符串、缓冲区等）。采用链式结构，以 `arg_idx == -1` 作为结束标记。

#### 每个arg_data项

| 字段 | 大小 | 类型 | 说明 |
|------|------|------|------|
| arg_idx | 4 | int32_t | 参数索引 (0-7)，-1表示结束 |
| size | 8 | size_t | 数据大小（字节） |
| data | size | uint8_t[] | 实际数据内容 |

#### 读取流程

```python
# 循环读取arg_data项
while True:
    # 读取arg_idx
    arg_idx_bytes = f.read(4)
    if len(arg_idx_bytes) < 4:
        break
    
    arg_idx = struct.unpack('<i', arg_idx_bytes)[0]
    
    # 检查结束标记
    if arg_idx == -1:
        print("End of arg_data section")
        break
    
    # 读取size
    size = struct.unpack('<Q', f.read(8))[0]
    
    # 读取data
    data = f.read(size)
    
    print(f"  arg[{arg_idx}]: {size} bytes")
```

#### 示例

假设syscall是 `open("/tmp/test.txt", O_RDONLY)`，则arg_data包含：

```
arg_idx: 0
size: 14
data: "/tmp/test.txt\0"

arg_idx: -1  (结束标记)
```

---

### 2.3 aux_data Section (可变长度，可选)

此部分存储辅助数据，用于Pure Replay。只有当系统调用需要记录额外数据时才存在。

#### AUXD标记 (8字节)

| 字段 | 大小 | 类型 | 值 | 说明 |
|------|------|------|-----|------|
| marker | 4 | uint32_t | 0x41555844 | "AUXD"标记 (little-endian) |
| aux_count | 4 | uint32_t | N | aux_data项的数量 |

#### 每个aux_data项

| 字段 | 大小 | 类型 | 说明 |
|------|------|------|------|
| kind | 1 | uint8_t | 数据类型 (见下表) |
| arg_mask | 1 | uint8_t | 参数掩码 (bit mask，指示关联的参数) |
| size | 4 | uint32_t | 数据大小（字节） |
| data | size | uint8_t[] | 实际数据内容 |

#### aux_data类型 (kind)

| 值 | 名称 | 说明 |
|----|------|------|
| 1 | AUX_TYPE_BUFFER | 通用缓冲区数据 |
| 2 | AUX_TYPE_STRING | 字符串数据 |
| 3 | AUX_TYPE_RANDOM | 随机数据 |
| 4 | AUX_TYPE_STRUCT | 结构体数据 |

#### arg_mask说明

`arg_mask` 是一个位掩码，指示此aux_data关联哪个参数：
- bit 0: 关联 args[0]
- bit 1: 关联 args[1]
- ...
- bit 7: 关联 args[7]

例如：
- `arg_mask = 0x01` (0b00000001) → 关联 args[0]
- `arg_mask = 0x02` (0b00000010) → 关联 args[1]
- `arg_mask = 0x03` (0b00000011) → 关联 args[0] 和 args[1]

#### Python解析示例

```python
# 读取AUXD标记
marker_bytes = f.read(4)
if len(marker_bytes) >= 4:
    marker = struct.unpack('<I', marker_bytes)[0]
    
    if marker == 0x41555844:  # "AUXD"
        print("Found aux_data section")
        
        # 读取aux_count
        aux_count = struct.unpack('<I', f.read(4))[0]
        print(f"  aux_count: {aux_count}")
        
        # 遍历所有aux_data项
        for i in range(aux_count):
            kind = struct.unpack('<B', f.read(1))[0]
            arg_mask = struct.unpack('<B', f.read(1))[0]
            size = struct.unpack('<I', f.read(4))[0]
            data = f.read(size)
            
            print(f"  aux[{i}]: kind={kind}, mask=0x{arg_mask:02x}, size={size}")
            print(f"    data (hex): {data[:32].hex()}")
    else:
        # 不是AUXD，回退4字节
        f.seek(-4, 1)
```

#### 示例：sendto syscall

```
syscall: sendto(sock_fd, "Hello from client!", 18, 0, addr, addrlen)

固定字段:
  index: 39
  syscall_nr: 44 (sendto)
  args: [3, 0x7fff1234, 18, 0, 0x7fff5678, 16, 0, 0]
  retval: 18

arg_data section:
  (无，因为所有数据已在aux_data中)
  arg_idx: -1  (直接结束)

aux_data section:
  marker: 0x41555844 ("AUXD")
  aux_count: 1
  
  aux[0]:
    kind: 1 (AUX_TYPE_BUFFER)
    arg_mask: 0x02 (关联args[1])
    size: 18
    data: "Hello from client!"
```

---

## 3. 完整解析示例

```python
#!/usr/bin/env python3
"""
完整的RR-Fuzz trace文件解析器
"""

import struct
from typing import List, Dict, Any

class SyscallRecord:
    def __init__(self):
        self.index = 0
        self.syscall_nr = 0
        self.args = []
        self.retval = 0
        self.arg_sizes = []
        self.creates_fd = False
        self.uses_fd = False
        self.created_fd = -1
        self.arg_data = {}
        self.aux_data = []

def parse_trace_file(filename: str) -> List[SyscallRecord]:
    """解析trace文件，返回所有syscall记录"""
    records = []
    
    with open(filename, 'rb') as f:
        # ===== Step 1: 读取文件头 =====
        header = f.read(12)
        magic, version, count = struct.unpack('<III', header)
        
        if magic != 0x52525254:
            raise ValueError(f"Invalid magic: 0x{magic:08x}")
        if version != 1:
            raise ValueError(f"Unsupported version: {version}")
        
        print(f"Trace file: version={version}, count={count}")
        
        # ===== Step 2: 读取所有syscall记录 =====
        for i in range(count):
            record = SyscallRecord()
            
            # [A] 固定字段 (150字节)
            fixed = f.read(150)
            if len(fixed) < 150:
                print(f"Warning: Incomplete record {i}")
                break
            
            record.index = struct.unpack('<I', fixed[0:4])[0]
            record.syscall_nr = struct.unpack('<i', fixed[4:8])[0]
            record.args = list(struct.unpack('<8q', fixed[8:72]))
            record.retval = struct.unpack('<q', fixed[72:80])[0]
            record.arg_sizes = list(struct.unpack('<8Q', fixed[80:144]))
            record.creates_fd = struct.unpack('<?', fixed[144:145])[0]
            record.uses_fd = struct.unpack('<?', fixed[145:146])[0]
            record.created_fd = struct.unpack('<i', fixed[146:150])[0]
            
            # [B] Variable arg_data section
            while True:
                arg_idx_bytes = f.read(4)
                if len(arg_idx_bytes) < 4:
                    break
                
                arg_idx = struct.unpack('<i', arg_idx_bytes)[0]
                if arg_idx == -1:
                    break
                
                size = struct.unpack('<Q', f.read(8))[0]
                data = f.read(size)
                record.arg_data[arg_idx] = data
            
            # [C] aux_data section
            marker_bytes = f.read(4)
            if len(marker_bytes) >= 4:
                marker = struct.unpack('<I', marker_bytes)[0]
                
                if marker == 0x41555844:  # "AUXD"
                    aux_count = struct.unpack('<I', f.read(4))[0]
                    
                    for j in range(aux_count):
                        kind = struct.unpack('<B', f.read(1))[0]
                        arg_mask = struct.unpack('<B', f.read(1))[0]
                        size = struct.unpack('<I', f.read(4))[0]
                        data = f.read(size)
                        
                        record.aux_data.append({
                            'kind': kind,
                            'arg_mask': arg_mask,
                            'data': data
                        })
            
            records.append(record)
        
        print(f"Successfully parsed {len(records)} records")
    
    return records

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: parse_trace.py <trace_file>")
        sys.exit(1)
    
    records = parse_trace_file(sys.argv[1])
    
    # 打印摘要
    print("\n=== Trace Summary ===")
    for rec in records:
        has_aux = "✅" if rec.aux_data else "  "
        print(f"{has_aux} Record #{rec.index}: syscall={rec.syscall_nr}, retval={rec.retval}")
        
        if rec.aux_data:
            for aux in rec.aux_data:
                print(f"     aux: kind={aux['kind']}, mask=0x{aux['arg_mask']:02x}, "
                      f"size={len(aux['data'])} bytes")

if __name__ == '__main__':
    main()
```

---

## 4. 常见Syscall的aux_data结构

### 4.1 read/pread64

```
syscall_nr: 0 (read)
args: [fd, buf_addr, count, ...]

aux_data[0]:
  kind: AUX_TYPE_BUFFER
  arg_mask: 0x02 (args[1] - buf_addr)
  data: <读取的实际数据>
```

### 4.2 write/pwrite64

```
syscall_nr: 1 (write)
args: [fd, buf_addr, count, ...]

aux_data[0]:
  kind: AUX_TYPE_BUFFER
  arg_mask: 0x02 (args[1] - buf_addr)
  data: <写入的数据内容>
```

### 4.3 sendto

```
syscall_nr: 44 (sendto)
args: [sock_fd, buf_addr, len, flags, addr, addrlen, ...]

aux_data[0]:
  kind: AUX_TYPE_BUFFER
  arg_mask: 0x02 (args[1] - buf_addr)
  data: <发送的数据内容>
```

### 4.4 recvfrom

```
syscall_nr: 45 (recvfrom)
args: [sock_fd, buf_addr, len, flags, addr, addrlen_ptr, ...]

aux_data[0]:
  kind: AUX_TYPE_BUFFER
  arg_mask: 0x02 (args[1] - buf_addr)
  data: <接收的数据内容>
```

### 4.5 ioctl

```
syscall_nr: 16 (ioctl)
args: [fd, request, argp, ...]

aux_data[0]:
  kind: AUX_TYPE_STRUCT
  arg_mask: 0x04 (args[2] - argp)
  data: <ioctl参数结构体>
```

---

## 5. 文件大小估算

### 公式

```
文件大小 ≈ 12 + N × (150 + avg_arg_data_size + avg_aux_data_size)
```

其中：
- N: 系统调用记录数量
- avg_arg_data_size: 平均arg_data大小（通常0-100字节）
- avg_aux_data_size: 平均aux_data大小（通常0-1KB）

### 示例

- TCP客户端程序 (44个syscalls)
  - 文件大小: ~15KB
  - 平均每条记录: ~340字节

- 大型程序 (1000个syscalls)
  - 文件大小: ~500KB-2MB
  - 取决于I/O数据量

---

## 6. 最佳实践

### 6.1 写入端（C代码）

1. **始终刷新文件流**
   ```c
   fwrite(&record, sizeof(syscall_record_t), 1, g_trace_file);
   fflush(g_trace_file);  // 确保数据写入
   ```

2. **正确处理字节序**
   ```c
   // 使用 htole32/le32toh 确保little-endian
   uint32_t magic = htole32(0x52525254);
   ```

3. **验证数据完整性**
   ```c
   if (aux_data_size > RR_MAX_BUFFER_TOTAL) {
       // 截断过大的数据
       aux_data_size = RR_MAX_BUFFER_TOTAL;
   }
   ```

### 6.2 读取端（Python代码）

1. **边界检查**
   ```python
   if size > 1000000:  # 1MB sanity check
       raise ValueError(f"Suspicious size: {size}")
   ```

2. **EOF处理**
   ```python
   data = f.read(size)
   if len(data) < size:
       raise EOFError(f"Incomplete data: expected {size}, got {len(data)}")
   ```

3. **使用生成器**
   ```python
   def parse_records(f):
       while True:
           record = parse_one_record(f)
           if record is None:
               break
           yield record
   ```

---

## 7. 版本兼容性

### Version 1 (当前)

- 初始版本
- 固定字段150字节
- 支持多个aux_data项
- Little-endian

### 未来版本规划

- Version 2: 可能添加压缩支持
- Version 3: 可能添加加密/签名
- 向后兼容承诺：解析器应检查version字段并适配

---

## 8. 故障排查

### 问题1: 魔数不匹配

**症状**: `Invalid magic: 0xXXXXXXXX`

**原因**:
- 文件损坏
- 字节序错误
- 非trace文件

**解决**:
```python
# 检查文件头
hexdump -C trace.dat | head -n 3

# 应该看到: 54 52 52 52 01 00 00 00 XX XX XX XX
```

### 问题2: 解析到一半EOF

**症状**: `Incomplete record N`

**原因**:
- 写入端未正确flush
- 程序崩溃
- 磁盘满

**解决**:
- 检查C端代码是否有`fflush()`
- 使用 `fseek(f, 0, SEEK_END); size = ftell(f)` 检查文件大小

### 问题3: aux_count异常大

**症状**: `aux_count: 999999`

**原因**:
- 文件指针错位
- arg_data section未正确解析

**解决**:
```python
# 添加sanity check
if aux_count > 100:
    print(f"Warning: Suspicious aux_count={aux_count}")
    f.seek(-8, 1)  # 回退，可能不是AUXD标记
```

---

## 附录A: C结构体定义

```c
// 文件: rr_framework.h

typedef struct syscall_record {
    uint32_t index;                     // +0
    int syscall_nr;                     // +4
    abi_long args[8];                   // +8 (64 bytes)
    abi_long retval;                    // +72 (8 bytes)
    
    uint8_t *arg_data[8];               // 非序列化字段
    size_t arg_size[8];                 // +80 (64 bytes)
    
    struct rr_aux_data *aux_data;       // 非序列化字段
    bool has_aux_data;                  // 非序列化字段
    
    bool creates_fd;                    // +144 (1 byte)
    bool uses_fd;                       // +145 (1 byte)
    int32_t created_fd;                 // +146 (4 bytes)
    
    struct syscall_record *next;        // 非序列化字段
} syscall_record_t;

// 固定字段总计: 4+4+64+8+64+1+1+4 = 150 bytes
```

---

## 附录B: 参考资料

- [QEMU用户模式文档](https://qemu.readthedocs.io/en/latest/user/index.html)
- [Linux系统调用表 (x86_64)](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl)
- [RR-Fuzz架构文档](./architecture.md)
- [Python struct模块文档](https://docs.python.org/3/library/struct.html)

---

**文档版本**: 1.0  
**最后更新**: 2025-10-29  
**维护者**: RR-Fuzz Team


#!/usr/bin/env python3
"""
IO Return Value Mutator - 专门用于变异IO syscalls的返回值

这个mutator解决关键问题：
- buffer_overflow等程序的分支依赖于read()返回值的大小
- 当前random mutation只改变参数，不改变返回值
- 需要生成针对性的返回值来触发不同分支

Author: RR-Fuzz Team
Date: 2025-11-14
"""

import random
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

try:
    from .async_logger import alog
except ImportError:
    # Fallback if accessed via direct script run or path issues
    def alog(msg, *args, **kwargs):
        print(f"[{args[0] if args else 'LOG'}] {msg}")


@dataclass
class IOMutation:
    """IO系统调用的变异"""
    syscall_index: int
    mutation_type: str
    new_return_value: int
    buffer_content: Optional[bytes] = None
    description: str = ""


class IOReturnValueMutator:
    """IO返回值变异器

    核心功能:
    1. 识别IO syscalls (read, write, recv, send, etc.)
    2. 生成针对性的返回值变异
    3. 为不同返回值范围生成测试用例
    """

    def __init__(self):
        self.io_syscall_names = [
            'read', 'write', 'recv', 'send', 'recvfrom',
            'sendto', 'recvmsg', 'sendmsg', 'getrandom',
            'pread64', 'pwrite64', 'readv', 'writev', 
            'preadv', 'pwritev', 'sendmmsg', 'recvmmsg'
        ]

        # 典型的返回值策略
        self.return_value_strategies = {
            'boundary': [0, 1, 2, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256],
            'powers_of_2': [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024],
            'incremental': list(range(0, 100, 5)),  # 0, 5, 10, 15, ..., 95
            # Aggressive overflow values including boundary-adjacent and large offsets
            'buffer_overflow': [
                # 接近32字节边界
                28, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                # 明显溢出范围
                45, 50, 55, 60, 64, 70, 80, 90, 100,
                # 大幅溢出
                128, 150, 200, 250, 256, 300, 400, 500, 512, 600, 700, 800, 900, 1000,
                # 极端值
                1024, 2048, 4096
            ],
            'error_injection': [-1, -2, -9, -13, -14, -32, -104, -111] # EPERM, EIO, EBADF, EACCES, EFAULT, EPIPE, ECONNRESET, ECONNREFUSED
        }

    def identify_io_syscalls(self, trace, analyzer: Optional[Any] = None) -> List[Dict[str, Any]]:
        """识别trace中的IO syscalls
        
        Args:
            trace: Trace对象，包含file_path
            analyzer: Existing TraceAnalyzer instance (optional)
        
        Returns:
            IO syscall信息列表
        """
        io_syscalls = []

        # Parse trace file to retrieve syscall sequence
        if not analyzer:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent / "analysis"))
            import trace_analyzer
            # 解析trace文件
            analyzer = trace_analyzer.TraceAnalyzer(trace.file_path)

        if not analyzer or not analyzer.syscalls:
            return io_syscalls

        for idx, syscall in enumerate(analyzer.syscalls):
            # Access record attributes
            syscall_name = getattr(syscall, 'name', '')
            if syscall_name in self.io_syscall_names:
                retval = getattr(syscall, 'retval', 0)

                # Filter read() calls that are likely not user inputs
                # 启发式规则：
                # The 200-byte limit was harmful. Removed to allow fuzzing deep protocol logic.
                # Heuristic: only skip if it's explicitly identified as a library file by Mutator's FD tracking.
                # (But here we don't have the map yet, so we allow all and let Mutator.mutate filter if needed)
                pass

                io_syscalls.append({
                    'index': idx,
                    'name': syscall_name,
                    'original_return': retval,
                    'is_input': syscall_name in ['read', 'recv', 'recvfrom', 'recvmsg', 'getrandom']
                })

        return io_syscalls

    def generate_mutations_for_io(
        self,
        io_syscall: Dict[str, Any],
        strategy: str = 'buffer_overflow'
    ) -> List[IOMutation]:
        """为单个IO syscall生成变异

        Args:
            io_syscall: IO syscall信息
            strategy: 变异策略 ('boundary', 'powers_of_2', 'incremental', 'buffer_overflow')

        Returns:
            IOMutation列表
        """
        mutations = []
        syscall_index = io_syscall['index']
        syscall_name = io_syscall['name']
        original_return = io_syscall['original_return']

        # 选择返回值策略
        if strategy in self.return_value_strategies:
            return_values = self.return_value_strategies[strategy]
        else:
            return_values = self.return_value_strategies['boundary']

        # 对于输入syscall (read, recv等)，生成相应的buffer内容
        is_input = io_syscall['is_input']

        for new_ret in return_values:
            # 跳过与原始返回值相同的
            if new_ret == original_return:
                continue

            # 生成buffer内容（对于输入syscalls）
            buffer_content = None
            if is_input and new_ret > 0:
                # 生成指定大小的buffer
                # 使用多种填充模式
                fill_patterns = [
                    b'A' * new_ret,  # 全A
                    b'B' * new_ret,  # 全B
                    bytes(range(256)) * (new_ret // 256 + 1),  # 递增模式
                    bytes([random.randint(0, 255) for _ in range(new_ret)])  # 随机
                ]
                buffer_content = random.choice(fill_patterns)[:new_ret]

            mutation = IOMutation(
                syscall_index=syscall_index,
                mutation_type='io_return_value',
                new_return_value=new_ret,
                buffer_content=buffer_content,
                description=f"{syscall_name} @{syscall_index}: ret {original_return}→{new_ret}"
            )
            mutations.append(mutation)

        return mutations

    def generate_all_mutations(
        self,
        trace,
        max_mutations_per_io: int = 10,
        analyzer: Optional[Any] = None
    ) -> List[IOMutation]:
        """为trace中所有IO syscalls生成变异
        
        Args:
            trace: Trace对象
            max_mutations_per_io: 每个IO syscall的最大变异数
            analyzer: Existing TraceAnalyzer instance (optional)

        Returns:
            IOMutation列表
        """
        all_mutations = []

        # 识别IO syscalls
        io_syscalls = self.identify_io_syscalls(trace, analyzer=analyzer)

        if not io_syscalls:
            return all_mutations

        # 为每个IO syscall生成变异
        for io_syscall in io_syscalls:
            # 根据syscall类型选择策略
            if io_syscall['name'] in ['read', 'recv', 'recvfrom']:
                # 读取syscall - 使用buffer_overflow策略
                mutations = self.generate_mutations_for_io(io_syscall, 'buffer_overflow')
            else:
                # 其他IO syscall - 使用boundary策略
                mutations = self.generate_mutations_for_io(io_syscall, 'boundary')
            
            # 随机混入错误注入策略
            if random.random() < 0.3: # 30% chance to also inject errors
                mutations.extend(self.generate_mutations_for_io(io_syscall, 'error_injection'))

            # 限制每个IO的变异数量
            if len(mutations) > max_mutations_per_io:
                mutations = random.sample(mutations, max_mutations_per_io)

            all_mutations.extend(mutations)

        return all_mutations

    def prioritize_mutations(
        self,
        mutations: List[IOMutation],
        coverage_feedback: Optional[Dict] = None
    ) -> List[IOMutation]:
        """对变异进行优先级排序

        Args:
            mutations: 变异列表
            coverage_feedback: 覆盖率反馈（可选）

        Returns:
            排序后的变异列表
        """
        # Employ diverse strategies for testing various return value sizes
        #
        # 策略：将mutations分组，每组随机选择，确保覆盖所有范围
        #
        # 分组:
        # 1. 小值 (0-20): 测试边界、负数等
        # 2. 中值 (20-70): 接近缓冲区边界
        # 3. 大值 (70-200): 明显溢出
        # 4. 极大值 (200+): 极端溢出

        def priority_score(m: IOMutation) -> int:
            val = m.new_return_value

            # 使用随机偏移确保多样性
            base_score = random.randint(0, 30)

            # 根据值范围分配基础分数（确保每个范围都有机会）
            if val == 0 or val == 1:
                # 边界值 - 总是高优先级
                return 200 + base_score
            elif 1 < val <= 20:
                # 小值范围
                return 100 + base_score
            elif 20 < val <= 70:
                # 中值范围（接近缓冲区大小）
                return 150 + base_score
            elif 70 < val <= 200:
                # 大值范围（明显溢出）
                return 180 + base_score
            elif val < 0:
                # 错误注入 - 高优先级！
                return 190 + base_score
            else:
                # 极大值（极端溢出）
                return 160 + base_score

        return sorted(mutations, key=priority_score, reverse=True)


# 便利函数：与现有mutator接口兼容

def generate_io_mutations(trace, max_mutations: int = 50) -> List[Dict[str, Any]]:
    """生成IO变异（兼容现有接口）

    Args:
        trace: Trace对象
        max_mutations: 最大变异数

    Returns:
        变异字典列表（兼容现有mutator格式）
    """
    mutator = IOReturnValueMutator()

    # 生成所有变异
    io_mutations = mutator.generate_all_mutations(trace, max_mutations_per_io=10)

    # 优先级排序
    io_mutations = mutator.prioritize_mutations(io_mutations)

    # 限制总数
    if len(io_mutations) > max_mutations:
        io_mutations = io_mutations[:max_mutations]

    # 转换为字典格式（兼容现有接口）
    result = []
    for m in io_mutations:
        mut_dict = {
            'type': 'io_return_value',
            'syscall_index': m.syscall_index,
            'new_return_value': m.new_return_value,
            'description': m.description
        }

        if m.buffer_content:
            mut_dict['buffer_content'] = m.buffer_content

        result.append(mut_dict)

    return result


if __name__ == '__main__':
    # 测试代码
    print("IO Return Value Mutator")
    print("=" * 60)

    # 模拟一个简单的trace
    class MockSyscall:
        def __init__(self, name, ret):
            self.name = name
            self.ret = ret

    class MockTrace:
        def __init__(self):
            self.syscalls = [
                MockSyscall('brk', 0),
                MockSyscall('read', 11),  # seed trace: read返回11字节
                MockSyscall('write', 11),
                MockSyscall('close', 0)
            ]

    trace = MockTrace()

    # 测试mutator
    mutator = IOReturnValueMutator()

    print("1. 识别IO syscalls:")
    io_syscalls = mutator.identify_io_syscalls(trace)
    for io in io_syscalls:
        print(f"  - {io}")
    print()

    print("2. 生成变异:")
    mutations = mutator.generate_all_mutations(trace, max_mutations_per_io=8)
    print(f"  生成了 {len(mutations)} 个变异")
    for i, m in enumerate(mutations[:5]):
        print(f"  [{i+1}] {m.description}")
    print()

    print("3. 优先级排序:")
    mutations = mutator.prioritize_mutations(mutations)
    print(f"  排序后的前5个变异:")
    for i, m in enumerate(mutations[:5]):
        print(f"  [{i+1}] {m.description} (ret={m.new_return_value})")

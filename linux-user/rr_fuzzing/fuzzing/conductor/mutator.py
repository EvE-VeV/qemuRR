#!/usr/bin/env python3
"""
变异器 - 变异引擎 (第2层)

提供基础和智能变异能力:
- BaseMutator: 简单随机变异
- SmartMutator: 基于trace分析的智能变异和recipe支持
"""

import os
import json
import struct
import random
import sys
import time  # 🔥 修复: 用于生成recipe id
from pathlib import Path
from typing import List, Optional

# 将分析目录添加到路径以导入trace_analyzer
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "analysis"))

from .constants import (
    FUZZ_CMD_FLIP_BITS, FUZZ_CMD_LIGHT_MUTATION, FUZZ_CMD_INTERESTING_VALUES,
    FUZZ_CMD_BOUNDARY_VALUE, FUZZ_CMD_TRUNCATE, FUZZ_CMD_EXTEND,
    FUZZ_CMD_REPLACE_BUFFER, FUZZ_CMD_MUTATE_AUX_BUFFER, FUZZ_CMD_MUTATE_FLAGS,
    FUZZ_CMD_MUTATE_ARG, FUZZ_CMD_OVERWRITE_AT_OFFSET,
    INIT_SYSCALLS, INIT_PHASE_THRESHOLD, IMPORTANT_SYSCALLS,
    PRIMARY_IO_SYSCALLS, SECONDARY_IO_SYSCALLS, FORBIDDEN_MUTATION_SYSCALLS,
    FUZZ_MAX_INSTRUCTIONS
)
from .instruction import FuzzInstruction
from .io_mutator import IOReturnValueMutator
from .async_logger import alog


class BaseMutator:
    """
    基础变异引擎 (简单随机变异)
    
    提供不需要trace分析的基础随机变异。
    用作备用方案或独立fuzzing。
    
    架构: DETAILED_ARCHITECTURE.md 第87-106行
    """
    
    def __init__(self, use_io_mutation: bool = True):
        """初始化BaseMutator

        参数:
            use_io_mutation: 是否启用IO返回值变异 (默认True)
        """
        self.iteration_count = 0
        self.use_io_mutation = use_io_mutation
        self.io_mutator = IOReturnValueMutator() if use_io_mutation else None
        # ✅ 2025-11-17: 初始化 mutation type 跟踪
        self.last_mutation_type = 'unknown'

        mode_str = "随机变异 + IO返回值变异" if use_io_mutation else "随机变异模式"
        print(f"[BaseMutator] 已初始化 ({mode_str})")
    
    def mutate(self, trace, fork_point: int = None) -> List[FuzzInstruction]:
        """
        生成随机变异

        参数:
            trace: Trace对象 (对于BaseMutator可能为None)
            fork_point: Syscall index of fork point (for compatibility with SmartMutator)

        返回:
            FuzzInstruction列表
        """
        self.iteration_count += 1

        # 🔥 新特性：70%概率使用IO返回值变异（如果可用且有trace）
        if self.use_io_mutation and self.io_mutator and trace and random.random() < 0.7:
            # ✅ 2025-11-17: 设置 mutation type 用于跟踪
            self.last_mutation_type = 'io_mutation'
            instrs = self._generate_io_mutations(trace, fork_point)
            
            # ✅ 修复: 验证指令数量不超过限制
            if len(instrs) > FUZZ_MAX_INSTRUCTIONS:
                print(f"[BaseMutator] ⚠️  IO mutation generated {len(instrs)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}")
                instrs = instrs[:FUZZ_MAX_INSTRUCTIONS]
            return instrs

        # 否则使用传统随机变异
        # ✅ 2025-11-17: 设置 mutation type 用于跟踪
        self.last_mutation_type = 'random'
        # 生成1-3个随机变异
        num_mutations = random.randint(1, 3)
        instructions = []
        
        for i in range(num_mutations):
            # 🔥 修复：如果指定了fork_point，第一个mutation目标是fork_point
            if i == 0 and fork_point is not None:
                syscall_index = fork_point
                alog(f"Mutation {i+1} targeting fork_point={fork_point}", "MUTATOR")
            else:
                # 随机syscall索引，但确保 >= fork_point (如果指定)
                if fork_point is not None:
                    syscall_index = random.randint(fork_point, max(fork_point + 20, 99))
                else:
                    syscall_index = random.randint(0, 99)
                alog(f"Mutation {i+1} targeting random syscall_index={syscall_index}", "MUTATOR")
            
            # 随机变异类型 - ✅ 新增 Aux Data 变异命令
            mutation_types = [
                FUZZ_CMD_FLIP_BITS,
                FUZZ_CMD_INTERESTING_VALUES,
                FUZZ_CMD_BOUNDARY_VALUE,
                FUZZ_CMD_REPLACE_BUFFER,
                FUZZ_CMD_MUTATE_FLAGS,
                # ⭐ 新增: Aux Data Mutation Engine (460 lines C code)
                FUZZ_CMD_MUTATE_AUX_BUFFER,  # 核心功能：变异 aux_data 缓冲区
                FUZZ_CMD_TRUNCATE,            # 截断攻击
                FUZZ_CMD_EXTEND,              # 溢出攻击
                FUZZ_CMD_LIGHT_MUTATION       # 轻量级变异
            ]
            cmd = random.choice(mutation_types)

            # 生成随机数据 + ✅ 设置mutation_type
            if cmd == FUZZ_CMD_FLIP_BITS:
                data = struct.pack('I', random.randint(1, 8))
                mut_type = 'bitflip'
            elif cmd == FUZZ_CMD_INTERESTING_VALUES:
                value = random.choice([0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF])
                data = struct.pack('Q', value & 0xFFFFFFFFFFFFFFFF)
                mut_type = 'interesting_value'
            elif cmd == FUZZ_CMD_BOUNDARY_VALUE:
                value = random.choice([0, -1, 0x7FFFFFFF, 0xFFFFFFFF])
                data = struct.pack('q', value)
                mut_type = 'boundary_value'
            elif cmd == FUZZ_CMD_REPLACE_BUFFER:
                size = random.choice([4, 8, 16, 32])
                data = bytes([random.randint(0, 255) for _ in range(size)])
                mut_type = 'replace_buffer'
            elif cmd == FUZZ_CMD_MUTATE_AUX_BUFFER:
                # ⭐ Aux Data 变异：生成攻击模式数据
                attack_patterns = [
                    b'%s%s%s%s',           # 格式化字符串攻击
                    b'A' * 64,             # 缓冲区溢出
                    b'../../../etc/passwd', # 路径遍历
                    b'; cat /etc/passwd',  # 命令注入
                    b'\x00' * 8,           # NULL注入
                ]
                data = random.choice(attack_patterns)
                mut_type = 'aux_buffer'
            elif cmd == FUZZ_CMD_TRUNCATE:
                # 截断攻击：减少数据大小
                truncate_size = random.choice([0, 1, 2, 4, 8])
                data = struct.pack('I', truncate_size)
                mut_type = 'truncate'
            elif cmd == FUZZ_CMD_EXTEND:
                # 扩展攻击：增加数据大小触发溢出
                extend_size = random.choice([64, 128, 256, 512, 1024])
                data = struct.pack('I', extend_size)
                mut_type = 'extend'
            elif cmd == FUZZ_CMD_LIGHT_MUTATION:
                # 轻量级变异：只翻转1-2位
                data = struct.pack('I', random.randint(1, 2))
                mut_type = 'light_mutation'
            else:  # MUTATE_FLAGS
                data = struct.pack('q', random.randint(0, 0xFFFFFFFF))
                mut_type = 'flags'

            instruction = FuzzInstruction(
                syscall_index=syscall_index,
                cmd=cmd,
                arg_index=1,
                data=data,
                mutation_type=mut_type  # ✅ 2025-11-18: 设置mutation type
            )
            instructions.append(instruction)

        # ✅ 修复: 验证指令数量不超过限制
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            print(f"[BaseMutator] ⚠️  Generated {len(instructions)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions  # 这个是给Qemu读取的内容，以FuzzInstruction包装这样的一个Fuzz指令

    def _generate_io_mutations(self, trace, fork_point: int = None) -> List[FuzzInstruction]:
        """生成IO返回值变异指令

        参数:
            trace: Trace对象
            fork_point: Fork点syscall索引 (可选)

        返回:
            FuzzInstruction列表
        """
        alog(f"Attempting IO mutation, trace={trace}, fork_point={fork_point}", "MUTATOR")

        # 识别IO syscalls
        io_syscalls = self.io_mutator.identify_io_syscalls(trace)
        alog(f"Found {len(io_syscalls)} IO syscalls", "MUTATOR")

        if not io_syscalls:
            # 没有IO syscalls，返回普通随机变异
            print("[BaseMutator] 🚨 No IO syscalls found, falling back to random mutation")
            return self._generate_random_mutations(trace, fork_point)

        # 优先选择fork_point的IO syscall（如果指定）
        target_io = None
        if fork_point is not None:
            for io in io_syscalls:
                if io['index'] == fork_point:
                    target_io = io
                    break

        # 如果没有在fork_point找到IO syscall，随机选一个
        if target_io is None:
            target_io = random.choice(io_syscalls)

        # 为这个IO syscall生成变异
        mutations = self.io_mutator.generate_mutations_for_io(
            target_io,
            strategy='buffer_overflow' if target_io['is_input'] else 'boundary'
        )

        # 优先级排序
        mutations = self.io_mutator.prioritize_mutations(mutations)

        # ✅ 修复 2025-11-18: 增加mutation数量，确保测试各种大小的值
        # 取前3-6个高优先级变异（原来是1-2个，导致值分布单一）
        num_mutations = random.randint(3, 6)
        selected_mutations = mutations[:num_mutations]

        # 转换为FuzzInstruction
        instructions = []
        for m in selected_mutations:
            # 1️⃣ 返回值变异
            data = struct.pack('Q', m.new_return_value)  # 新返回值

            instruction = FuzzInstruction(
                syscall_index=m.syscall_index,
                cmd=FUZZ_CMD_MUTATE_ARG,  # 临时使用，后续可以定义专门的IO_RETURN命令
                arg_index=0xFF,  # 特殊标记：0xFF表示改变返回值
                data=data,
                mutation_type='io_return_value'  # ✅ 2025-11-18: 设置mutation type
            )
            instructions.append(instruction)

            alog(f"IO Mutation (retval): {m.description}", "MUTATOR")

            # 2️⃣ 如果有buffer_content，也生成REPLACE_BUFFER指令
            if m.buffer_content:
                # 获取buffer参数索引（read的第二个参数是buffer指针）
                # read(fd, buf, count) -> buf是args[1]
                buf_arg_index = 1

                buffer_instruction = FuzzInstruction(
                    syscall_index=m.syscall_index,
                    cmd=FUZZ_CMD_REPLACE_BUFFER,
                    arg_index=buf_arg_index,
                    data=m.buffer_content[:min(len(m.buffer_content), 256)]  # 限制256字节
                )
                instructions.append(buffer_instruction)

                alog(f"IO Mutation (buffer): Fill {len(m.buffer_content)} bytes", "MUTATOR")

        # ✅ 修复: 验证指令数量不超过限制
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            print(f"[BaseMutator] ⚠️  IO mutation generated {len(instructions)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions

    def _generate_random_mutations(self, trace, fork_point: int = None) -> List[FuzzInstruction]:
        """生成传统随机变异（辅助方法）"""
        # 这是原来mutate方法的实现，提取为独立方法
        num_mutations = random.randint(1, 3)
        instructions = []

        for i in range(num_mutations):
            if i == 0 and fork_point is not None:
                syscall_index = fork_point
            else:
                if fork_point is not None:
                    syscall_index = random.randint(fork_point, max(fork_point + 20, 99))
                else:
                    syscall_index = random.randint(0, 99)

            # ✅ 新增 Aux Data 变异命令（与mutate方法保持一致）
            mutation_types = [
                FUZZ_CMD_FLIP_BITS,
                FUZZ_CMD_INTERESTING_VALUES,
                FUZZ_CMD_BOUNDARY_VALUE,
                FUZZ_CMD_REPLACE_BUFFER,
                FUZZ_CMD_MUTATE_FLAGS,
                # ⭐ Aux Data Mutation Engine
                FUZZ_CMD_MUTATE_AUX_BUFFER,
                FUZZ_CMD_TRUNCATE,
                FUZZ_CMD_EXTEND,
                FUZZ_CMD_LIGHT_MUTATION
            ]
            cmd = random.choice(mutation_types)

            # ✅ 2025-11-18: 设置mutation_type（修复94% unknown问题）
            if cmd == FUZZ_CMD_FLIP_BITS:
                data = struct.pack('I', random.randint(1, 8))
                mut_type = 'bitflip'
            elif cmd == FUZZ_CMD_INTERESTING_VALUES:
                value = random.choice([0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF])
                data = struct.pack('Q', value & 0xFFFFFFFFFFFFFFFF)
                mut_type = 'interesting_value'
            elif cmd == FUZZ_CMD_BOUNDARY_VALUE:
                value = random.choice([0, -1, 0x7FFFFFFF, 0xFFFFFFFF])
                data = struct.pack('q', value)
                mut_type = 'boundary_value'
            elif cmd == FUZZ_CMD_REPLACE_BUFFER:
                size = random.choice([4, 8, 16, 32])
                data = bytes([random.randint(0, 255) for _ in range(size)])
                mut_type = 'replace_buffer'
            elif cmd == FUZZ_CMD_MUTATE_AUX_BUFFER:
                # ⭐ Aux Data 变异：生成攻击模式数据
                attack_patterns = [
                    b'%s%s%s%s',           # 格式化字符串攻击
                    b'A' * 64,             # 缓冲区溢出
                    b'../../../etc/passwd', # 路径遍历
                    b'; cat /etc/passwd',  # 命令注入
                    b'\x00' * 8,           # NULL注入
                ]
                data = random.choice(attack_patterns)
                mut_type = 'aux_buffer'
            elif cmd == FUZZ_CMD_TRUNCATE:
                truncate_size = random.choice([0, 1, 2, 4, 8])
                data = struct.pack('I', truncate_size)
                mut_type = 'truncate'
            elif cmd == FUZZ_CMD_EXTEND:
                extend_size = random.choice([64, 128, 256, 512, 1024])
                data = struct.pack('I', extend_size)
                mut_type = 'extend'
            elif cmd == FUZZ_CMD_LIGHT_MUTATION:
                data = struct.pack('I', random.randint(1, 2))
                mut_type = 'light_mutation'
            else:  # MUTATE_FLAGS
                data = struct.pack('q', random.randint(0, 0xFFFFFFFF))
                mut_type = 'flags'

            instruction = FuzzInstruction(
                syscall_index=syscall_index,
                cmd=cmd,
                arg_index=1,
                data=data,
                mutation_type=mut_type  # ✅ 2025-11-18: 添加mutation_type参数
            )
            instructions.append(instruction)

        # ✅ 修复: 验证指令数量不超过限制
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            print(f"[BaseMutator] ⚠️  Random mutation generated {len(instructions)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions


class SmartMutator:
    """
    智能变异引擎
    
    分析trace文件，过滤可变异的syscall，并使用多种策略
    生成智能变异指令。
    """
    
    # 类级别缓存，避免重复解析相同的trace
    _trace_cache = {}  # {trace_file: TraceAnalyzer}
    
    def __init__(self, trace_file, recipe_file=None, target_binary=None, path_finder=None):
        """
        初始化SmartMutator

        参数:
            trace_file: Trace文件路径
            recipe_file: Recipe文件路径 (可选, 第2阶段)
            target_binary: 目标二进制文件路径 (用于PathFinder CFG分析)
            path_finder: 现有的PathFinder实例 (可选, 避免重复初始化)
        """
        # 如果可用则使用缓存的TraceAnalyzer
        if trace_file in SmartMutator._trace_cache:
            print(f"[Mutator] 使用缓存的分析结果: {trace_file}")
            self.analyzer = SmartMutator._trace_cache[trace_file]
        else:
            # 使用修复后的TraceAnalyzer自动解析
            print(f"[Mutator] 分析trace文件: {trace_file}")
            
            # 导入并使用修复后的TraceAnalyzer
            from trace_analyzer import TraceAnalyzer
            
            # TraceAnalyzer在__init__中自动调用analyze()
            self.analyzer = TraceAnalyzer(trace_file)
            
            # 缓存以供将来使用
            SmartMutator._trace_cache[trace_file] = self.analyzer
        
        # 获取所有纯重放syscall (带aux_data的syscall)
        pure_syscalls = self.analyzer.get_pure_syscalls()
        
        # 保存所有syscall以备后用
        self.syscalls = self.analyzer.syscalls
        
        # 转换为Candidate对象 (带全量元数据)
        self.pure_candidates = [sc for sc in pure_syscalls]
        
        # 获取混合重放syscall (不带aux_data的syscall)
        hybrid_syscalls = self.analyzer.get_hybrid_syscalls()
        self.hybrid_candidates = [sc for sc in hybrid_syscalls]
        
        # ━━━━ 第0阶段: FD 追踪与环境过滤 ━━━━
        self._perform_fd_tracking()
        
        # 这些其实也需要删除
        print(f"[Mutator] 发现 {len(self.pure_candidates)} 个纯重放syscall:")
        for cand in self.pure_candidates[:10]:  # 只打印前10个
            print(f"[Mutator]   index={cand.index}, name={cand.name}, nr={cand.syscall_nr}")
        if len(self.pure_candidates) > 10:
            print(f"[Mutator]   ... 以及 {len(self.pure_candidates) - 10} 个更多")
        
        # 第1阶段: 延迟过滤，等待 PathFinder 就绪
        self.mutable_candidates = []
        
        # ━━━━ 第2阶段: PathFinder & Recipe驱动模式 ━━━━
        self.recipes = []
        self.recipe_mode = False
        self.path_finder = None
        self.target_binary = target_binary

        # PathFinder集成（自动recipe生成）
        if path_finder:
            self.path_finder = path_finder
            print(f"[Mutator] ✅ 使用外部传入的PathFinder实例")
        elif target_binary:
            self._init_pathfinder(trace_file, target_binary)
        else:
            self.path_finder = None

        # 手动recipe文件加载
        if recipe_file and os.path.exists(recipe_file):
            self._load_recipes(recipe_file)
            self.recipe_mode = True
            print(f"[Mutator] 🧪 Recipe驱动模式已启用 (手动:{len(self.recipes)}个recipes)")

        # 尝试从PathFinder自动生成recipes
        auto_recipes = self._generate_automatic_recipes()
        if auto_recipes:
            self.recipes.extend(auto_recipes)
            print(f"[Mutator] 🤖 自动生成{len(auto_recipes)}个recipes (总计:{len(self.recipes)}个)")

        if len(self.recipes) > 0:
            self.recipe_mode = True
            print(f"[Mutator] 🧪 Recipe驱动模式已启用 (总计:{len(self.recipes)}个recipes)")
        else:
            print(f"[Mutator] 🎲 随机变异模式 (未提供recipe文件且自动生成失败)")
        
        # 现在 PathFinder 已初始化，进行候选过滤
        self.mutable_candidates = self._filter_mutable_candidates()
        
        # P1修复: 停滞检测（Stagnation Detection）
        self.last_new_coverage_iter = 0  # 上次发现新coverage的迭代
        self.stagnation_threshold = 1000  # 🔥 提高阈值: 1000次迭代无新coverage = 停滞
        self.is_stagnant = False  # 当前是否停滞
        self.total_iterations = 0  # 总迭代次数
        # ✅ 2025-11-17: 初始化 mutation type 跟踪
        self.last_mutation_type = 'unknown'
        print(f"[Mutator] 🔍 停滞检测已启用 (阈值={self.stagnation_threshold} 次迭代)")
    
    def _perform_fd_tracking(self):
        """
        追踪追踪文件描述符 (FD) 的打开和关闭。
        识别加载库文件等系统级 FD，并在对应的 syscall 索引处标记为禁用。
        """
        active_forbidden_fds = set()
        self.syscall_forbidden_map = {} # index -> bool
        
        for sc in self.syscalls:
            # 1. 检查当前 syscall 是否使用了已被标记为禁止的 FD
            is_forbidden = False
            if sc.uses_fd and sc.args:
                fd = sc.args[0]
                if fd in active_forbidden_fds:
                    is_forbidden = True
            
            self.syscall_forbidden_map[sc.index] = is_forbidden
            
            # 2. 追踪 FD 打开并更新状态
            if sc.creates_fd and sc.created_fd > 2:
                filename = "unknown"
                if sc.name in ['open', 'openat']:
                    idx = 1 if sc.name == 'openat' else 0
                    if idx in sc.arg_data:
                        try:
                            filename = sc.arg_data[idx].split(b'\x00')[0].decode('utf-8', errors='ignore')
                        except:
                            filename = str(sc.arg_data[idx])
                
                # 如果是系统库，或者在初始化阶段且文件名未知，加入禁止集合
                is_library = "/lib/" in filename or "/usr/lib/" in filename or "ld.so.cache" in filename
                is_early_unknown = (sc.index < 30 and filename == "unknown")
                
                if is_library or is_early_unknown:
                    active_forbidden_fds.add(sc.created_fd)
                    reason = "library" if is_library else "early_init"
                    alog(f"FD {sc.created_fd} (index={sc.index}) marked FORBIDDEN ({reason}): {filename}", "MUTATOR")
                else:
                    # 如果 FD 被复用于普通文件，从禁止集合移除
                    if sc.created_fd in active_forbidden_fds:
                        active_forbidden_fds.discard(sc.created_fd)
                        alog(f"FD {sc.created_fd} (index={sc.index}) UNMARKED (reused): {filename}", "MUTATOR")
            
            # 3. 追踪 FD 关闭
            if sc.name == 'close' and sc.args:
                fd = sc.args[0]
                if fd in active_forbidden_fds:
                    active_forbidden_fds.discard(fd)
        
        forbidden_count = sum(1 for v in self.syscall_forbidden_map.values() if v)
        if forbidden_count > 0:
            print(f"[Mutator] 🛡️  环境过滤: 识别到 {forbidden_count} 个涉及系统库的 IO 调用已受保护")
    
    def _should_skip_mutation(self, syscall_info, index):
        """
        判断是否应该跳过该syscall的变异
        
        参数:
            syscall_info: 系统调用信息对象
            index: 在trace中的索引位置
        
        返回:
            bool: True表示跳过, False表示可以变异
        """
        # ━━━━ 核心保护 ━━━━
        # 1. 通用启动阶段保护: 前 40 个 syscall 通常属于 ld.so 和 libc 初始化
        # 1. 通用启动阶段保护: 前 40 个 syscall 通常属于 ld.so 和 libc 初始化
        # 🔥 FIX: 移除硬编码的 index < 40 检查，改用 PathFinder 的智能过滤
        # if index < 40:
        #    alog(f"[Mutator] 🛡️  启动阶段保护: 跳过早期启动 syscall (index={index})", "MUTATOR")
        #    return True
            
        syscall_name = getattr(syscall_info, 'name', '').lower()
        
        # 2. 已识别的 Forbidden FD 保护
        if self.syscall_forbidden_map.get(index, False):
            alog(f"[Mutator] ⏭️  跳过Forbidden IO: {syscall_name} (index={index})", "MUTATOR")
            return True
        
        # 重要的IO syscall永不跳过 (已经经过了 FD 和 启动阶段过滤)
        if syscall_name in IMPORTANT_SYSCALLS:
            return False  # 永不跳过
        
        # 在初始化阶段跳过关键syscall (使用动态阈值)
        # 注意: dynamic_threshold将在第一次fuzzing时由Conductor设置
        threshold = getattr(self, 'dynamic_threshold', INIT_PHASE_THRESHOLD)
        if index < threshold:
            if any(init_sc in syscall_name for init_sc in INIT_SYSCALLS):
                print(f"[Mutator] ⏭️  跳过初始化syscall: {syscall_name} (index={index}, threshold={threshold})")
                return True
        
        # 1. PathFinder 增强过滤:
        # 如果有 PathFinder，检查该 syscall 是否能被目标代码段到达
        if self.path_finder and hasattr(self.path_finder, 'bb_to_syscall'):
            # 查找是否有任何目标 BB 映射到这个 syscall
            is_target_reachable = False
            for bb_addr, sc_idx in self.path_finder.bb_to_syscall.items():
                if sc_idx == index:
                    is_target_reachable = True
                    break
            
            if not is_target_reachable:
                # 如果这个 syscall 在 trace 中，但从未被目标范围内的 BB 调用/覆盖，
                # 说明它极可能是 early loader 或 libc 初始化代码调用的。
                alog(f"[Mutator] 🛡️  PathFinder 过滤: 跳过非目标代码调用的 syscall (index={index}, {syscall_name})", "MUTATOR")
                return True
        
        return False
    
    def _filter_mutable_candidates(self):
        """
        过滤出真正可变异的候选 - 扩展策略保留更多候选

        🔥 P0修复: 扩展候选池 (4个 → 15个+)

        新设计原则：
        1. 只排除明确危险的syscalls (FORBIDDEN_MUTATION_SYSCALLS)
        2. 保留所有safe的syscalls，不只是IO
        3. 优先级分层：Important > Primary IO > Secondary IO > Others

        返回:
            list: 安全可变异的syscall候选列表
        """
        important = []   # 重要的syscalls (必须mutate)
        primary_io = []  # Primary IO syscalls
        secondary_io = [] # Secondary IO syscalls
        others = []      # 其他安全的syscalls

        all_candidates = list(self.pure_candidates) + list(self.hybrid_candidates)

        print(f"[Mutator] Filtering {len(all_candidates)} candidates (Enhanced mode)...")

        for candidate in all_candidates:
            syscall_name = candidate.name

            # 1. 跳过禁止的syscalls (内存管理、信号、进程控制)
            if syscall_name in FORBIDDEN_MUTATION_SYSCALLS:
                continue

            # 2. 跳过初始化阶段的关键syscalls
            if self._should_skip_mutation(candidate, candidate.index):
                continue

            # 3. 🔥 新策略: 按优先级分类，但保留所有safe的syscalls
            if syscall_name in IMPORTANT_SYSCALLS:
                important.append(candidate)
            elif syscall_name in PRIMARY_IO_SYSCALLS:
                primary_io.append(candidate)
            elif syscall_name in SECONDARY_IO_SYSCALLS:
                secondary_io.append(candidate)
            else:
                # 🔥 关键改进: 保留其他syscalls (之前被丢弃)
                others.append(candidate)

        # 🔥 按优先级合并，保留所有候选
        mutable = important + primary_io + secondary_io + others

        print(f"[Mutator] Enhanced syscall candidates:")
        print(f"  Important:    {len(important)} syscalls")
        if important:
            print(f"    Examples: {[f'{c.name}@{c.index}' for c in important[:3]]}")
        print(f"  Primary IO:   {len(primary_io)} syscalls")
        if primary_io:
            print(f"    Examples: {[f'{c.name}@{c.index}' for c in primary_io[:3]]}")
        print(f"  Secondary IO: {len(secondary_io)} syscalls")
        if secondary_io:
            print(f"    Examples: {[f'{c.name}@{c.index}' for c in secondary_io[:3]]}")
        print(f"  Others:       {len(others)} syscalls")
        if others:
            print(f"    Examples: {[f'{c.name}@{c.index}' for c in others[:3]]}")
        print(f"  Total mutable: {len(mutable)} syscalls (was {len(primary_io) + len(secondary_io)} in old version)")

        if len(mutable) == 0:
            print(f"[Mutator] WARNING: No syscalls found for mutation!")
            print(f"[Mutator] All candidates: {[(c.name, c.index) for c in all_candidates[:10]]}")

        return mutable

    def _init_pathfinder(self, trace_file, target_binary):
        """
        初始化PathFinder进行CFG分析
        """
        try:
            # 尝试导入PathFinder
            import sys
            from pathlib import Path

            # 添加multiprocess目录到路径
            multiprocess_dir = Path(__file__).parent.parent / "multiprocess"
            if str(multiprocess_dir) not in sys.path:
                sys.path.insert(0, str(multiprocess_dir))

            # 尝试导入PathFinder (DualLevel)
            from multiprocess.dual_level_path_finder import DualLevelPathFinder as PathFinder
            # Config is part of DB or params, maybe unnecessary or can use dummy
            # DualLevel uses different config, let's omit Config class import as it's not strictly needed if we pass dict or it handles it.
            # actually DualLevelPathFinder constructor signature might be different. 
            # Original: PathFinder(binary, config)
            # DualLevel: DualLevelPathFinder(binary, config_dict/obj)


            # 创建配置（保守设置）
            # 创建配置（保守设置）
            config = {
                "verbose": False,
                "timeout": 30,  # 30秒超时
                "max_cfg_nodes": 5000,  # 限制节点数
                "graceful_disable": True,  # 出错时禁用而不是抛异常
                "enable_auto_fast_mode": True  # 自动简化模式
            }

            # 初始化PathFinder
            self.path_finder = PathFinder(target_binary, config)
            print(f"[Mutator] ✅ PathFinder已初始化")

            # 尝试从trace构建动态CFG
            if self.path_finder.build_from_trace(trace_file):
                print(f"[Mutator] ✅ PathFinder动态CFG已构建")
            else:
                print(f"[Mutator] ⚠️  PathFinder动态CFG构建失败")

        except Exception as e:
            print(f"[Mutator] ⚠️  PathFinder初始化失败: {e}")
            self.path_finder = None

    def _generate_automatic_recipes(self):
        """
        从PathFinder自动生成recipes
        """
        if not self.path_finder or not self.path_finder.is_available():
            return []

        try:
            # 分析未覆盖的分支（简化版本，基于动态CFG）
            uncovered_branches = self._find_uncovered_branches()
            if not uncovered_branches:
                print(f"[Mutator] 📊 PathFinder未发现未覆盖分支")
                return []

            print(f"[Mutator] 📊 PathFinder发现{len(uncovered_branches)}个未覆盖分支")

            # 生成recipes
            raw_recipes = self.path_finder.generate_recipes(uncovered_branches, max_recipes=10)

            # 🔥 修复: PathFinder返回MutationRecipe对象，需要转换为字典
            auto_recipes = []
            for i, recipe in enumerate(raw_recipes):
                # PathFinder返回的是MutationRecipe对象，转换为字典
                recipe_dict = recipe.to_dict() if hasattr(recipe, 'to_dict') else recipe

                # 🔥 修复: 确保有id字段（recipe_pool要求）
                if 'id' not in recipe_dict or not recipe_dict['id']:
                    recipe_dict['id'] = f"pathfinder_auto_{i}_{int(time.time())}"

                # 转换为字符串id以确保兼容性
                if isinstance(recipe_dict['id'], int):
                    recipe_dict['id'] = f"pathfinder_{recipe_dict['id']}"

                auto_recipes.append(recipe_dict)

            return auto_recipes

        except Exception as e:
            print(f"[Mutator] ⚠️  PathFinder recipe生成失败: {e}")
            return []

    def _find_uncovered_branches(self):
        """
        基于动态CFG找到未覆盖的分支（简化实现）
        """
        if not self.path_finder or not hasattr(self.path_finder, 'dynamic_edges'):
            # 对于 DualLevelPathFinder, 我们在运行期根据覆盖率生成分支
            return []

        uncovered = []

        # 简化逻辑：遍历所有动态节点，寻找只有一个出边的节点
        # 这些节点可能有未探索的分支
        for node_id, edges in self.path_finder.dynamic_edges.items():
            if len(edges) == 1:  # 只有一个出边，可能有另一个分支未探索
                edge = list(edges)[0]
                # 构造一个假设的未覆盖分支
                uncovered_branch = {
                    'from': self.path_finder.dynamic_nodes.get(node_id, node_id),
                    'to': self.path_finder.dynamic_nodes.get(edge, edge),
                    'type': 'conditional',
                    'has_syscall': node_id in self.path_finder.dynamic_syscalls,
                    'distance': 1  # 简化距离计算
                }

                # 如果这个节点有syscall信息，添加到分支信息中
                if node_id in self.path_finder.dynamic_syscalls:
                    uncovered_branch['syscalls'] = self.path_finder.dynamic_syscalls[node_id]

                uncovered.append(uncovered_branch)

        # 限制数量，避免生成太多recipes
        return uncovered[:15]

    def _load_recipes(self, recipe_file):
        """
        从JSON文件加载recipe
        
        参数:
            recipe_file: Recipe文件路径 (recipes.json)
        """
        try:
            with open(recipe_file, 'r') as f:
                data = json.load(f)
            
            self.recipes = data.get('recipes', [])
            print(f"[Mutator] 从 {recipe_file} 加载了 {len(self.recipes)} 个recipe")
            
            # 打印前几个recipe, 这些需要删除后面
            for i, recipe in enumerate(self.recipes[:5]):
                print(f"[Mutator]   Recipe {i}: {recipe['source_branch']} -> {recipe['target_branch']}, "
                      f"syscall_idx={recipe['syscall_index']}, type={recipe['mutation_type']}")
            
        except Exception as e:
            print(f"[Mutator] ⚠️  加载recipe失败: {e}")
            self.recipes = []
    
    def _recipe_to_instruction(self, recipe):
        """
        将recipe转换为FuzzInstruction
        
        参数:
            recipe: Recipe字典 (来自recipes.json)
        
        返回:
            FuzzInstruction 或 None
        """
        try:
            syscall_index = recipe['syscall_index']
            mutation_type = recipe['mutation_type']
            offset = recipe.get('offset', 0)
            size = recipe.get('size', 4)
            data_template = recipe.get('data_template', 'RANDOM')
            
            # 基于data_template生成实际数据
            if data_template == 'RANDOM':
                mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            elif data_template == 'ZERO':
                mutation_data = b'\x00' * size
            elif data_template == 'FF':
                mutation_data = b'\xFF' * size
            elif data_template.startswith('ASCII:'):
                ascii_data = data_template.split(':', 1)[1]
                mutation_data = ascii_data.encode('utf-8')
                size = len(mutation_data)
            elif data_template.startswith('0x'):
                # 十六进制值
                val = int(data_template, 16)
                mutation_data = struct.pack('Q', val)[:size]
            else:
                # 默认随机
                mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            
            # 基于mutation_type选择命令
            if mutation_type == 'buffer_overwrite':
                # 第2阶段新功能: 使用FUZZ_CMD_OVERWRITE_AT_OFFSET
                # 使用recipe中的offset和size创建精确的覆写指令
                instr = FuzzInstruction(
                    syscall_index, 
                    FUZZ_CMD_OVERWRITE_AT_OFFSET, 
                    recipe.get('arg_index', 1), 
                    mutation_data,
                    offset=offset,
                    size=size
                )
                return instr
            elif mutation_type == 'value_change':
                return FuzzInstruction(syscall_index, FUZZ_CMD_MUTATE_ARG, 0, mutation_data, 0, size)
            elif mutation_type == 'size_modify':
                return FuzzInstruction(syscall_index, FUZZ_CMD_BOUNDARY_VALUE, 0, mutation_data, 0, size)
            else:
                # 默认使用缓冲区替换
                return FuzzInstruction(syscall_index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data, 0, size)
                
        except Exception as e:
            print(f"[Mutator] ⚠️  将recipe转换为指令失败: {e}")
            return None
    
    def _build_from_recipes(self, iteration):
        """
        从recipe生成Fuzz指令
        
        参数:
            iteration: 当前迭代次数
        
        返回:
            list: FuzzInstruction列表
        """
        instrs = []
        
        # 选择recipe (循环使用)
        recipe_idx = iteration % len(self.recipes)
        recipe = self.recipes[recipe_idx]
        
        # 记录使用的recipe（用于反馈）
        self.last_recipe_used = recipe
        
        print(f"[Mutator] 🧪 使用recipe {recipe_idx}/{len(self.recipes)}: "
              f"{recipe['source_branch']} -> {recipe['target_branch']}")
        
        # 转换为指令
        instr = self._recipe_to_instruction(recipe)
        if instr:
            instrs.append(instr)
            print(f"[Mutator]   生成指令: syscall_idx={recipe['syscall_index']}, "
                  f"cmd={recipe['mutation_type']}")
        
        return instrs
    
    def update_stagnation_status(self, iteration: int, has_new_coverage: bool):
        """
        P1修复: 更新停滞检测状态
        
        参数:
            iteration: 当前迭代次数
            has_new_coverage: 本次迭代是否发现新coverage
        """
        self.total_iterations = iteration
        
        if has_new_coverage:
            # 发现新coverage，重置停滞计数
            self.last_new_coverage_iter = iteration
            was_stagnant = self.is_stagnant
            self.is_stagnant = False
            
            if was_stagnant:
                print(f"[Mutator] 在迭代{iteration}从停滞中恢复!")
        else:
            # 检查是否进入停滞
            stagnation_duration = iteration - self.last_new_coverage_iter
            
            if stagnation_duration >= self.stagnation_threshold:
                if not self.is_stagnant:
                    # 首次进入停滞状态
                    self.is_stagnant = True
                    print(f"[Mutator] ⚠️  在迭代{iteration}检测到停滞!")
                    print(f"[Mutator]   已{stagnation_duration}次迭代无新coverage")
                    print(f"[Mutator]   切换到激进变异模式...")
    
    def _select_mutation_strategy(self):
        """
        使用平衡化概率选择变异策略

        新设计原则：
        1. 平衡各种漏洞类型的发现能力
        2. 避免过度偏向单一漏洞类型
        3. 支持多样化的变异模式

        返回:
            int: 策略类型 (0-10)
        """
        if self.is_stagnant:
            # 🔥 停滞模式：更激进的策略分布
            strategy_weights = [
                8,   # 0: FLIP_BITS (位翻转) - 减少轻量变异
                15,  # 1: INTERESTING_VALUES (特殊值) - 增强整数溢出发现
                12,  # 2: TRUNCATE (截断) - 平衡
                20,  # 3: EXTEND (扩展) - 保持缓冲区溢出能力但降低权重
                5,   # 4: LIGHT_MUTATION (轻量变异) - 减少
                10,  # 5: MUTATE_AUX_BUFFER (辅助缓冲区变异)
                8,   # 6: REPLACE_BUFFER (小缓冲区替换)
                12,  # 7: REPLACE_BUFFER (大缓冲区替换) - 显著降低
                12,  # 8: BOUNDARY_VALUE (边界值) - 增强
                10,  # 9: MUTATE_FLAGS (标志变异) - 增强
                8,   # 10: OVERWRITE_AT_OFFSET (偏移覆写)
            ]
        else:
            # 🎯 常规模式：平衡化策略分布
            strategy_weights = [
                12,  # 0: FLIP_BITS (位翻转) - 基础变异
                12,  # 1: INTERESTING_VALUES (特殊值) - 整数漏洞
                10,  # 2: TRUNCATE (截断) - 大小相关漏洞
                14,  # 3: EXTEND (扩展) - 缓冲区溢出，权重大幅降低
                8,   # 4: LIGHT_MUTATION (轻量变异) - 探索性变异
                9,   # 5: MUTATE_AUX_BUFFER (辅助缓冲区变异) - 数据完整性
                9,   # 6: REPLACE_BUFFER (小缓冲区替换) - 内容替换
                10,  # 7: REPLACE_BUFFER (大缓冲区替换) - 权重大幅降低
                10,  # 8: BOUNDARY_VALUE (边界值) - 边界条件漏洞
                9,   # 9: MUTATE_FLAGS (标志变异) - 逻辑漏洞
                7,   # 10: OVERWRITE_AT_OFFSET (偏移覆写) - 内存布局漏洞
            ]

        return random.choices(range(11), weights=strategy_weights)[0]
    
    def _generate_advanced_mutation(self, target_candidate, strategy_type, iteration):
        """
        生成高级变异指令 (充分利用11个C端变异命令)
        
        参数:
            target_candidate: 目标syscall候选
            strategy_type: 策略类型 (0-10)
            iteration: 迭代计数
        
        返回:
            FuzzInstruction: 生成的变异指令
        """
        index = target_candidate.index
        
        # 基于策略类型选择变异命令
        if strategy_type == 0:
            # FLIP_BITS - 位翻转 (轻量级, 保持大部分数据不变)
            num_flips = random.randint(1, 8)  # 翻转1-8个位
            mutation_data = struct.pack('I', num_flips)
            print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=FLIP_BITS({num_flips} bits)")
            return FuzzInstruction(index, FUZZ_CMD_FLIP_BITS, 1, mutation_data)
        
        elif strategy_type == 1:
            # INTERESTING_VALUES - 智能特殊值注入 (根据系统调用类型选择)
            syscall_name = target_candidate.name.lower()

            if 'read' in syscall_name or 'recv' in syscall_name:
                # 输入系统调用：使用多种攻击模式
                pattern_type = random.randint(0, 7)  # 8种模式 (对应C端switch)
                secondary_param = random.randint(0, 255)
                mutation_data = struct.pack('BB', pattern_type, secondary_param)
                print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=INTERESTING_VALUES(vuln_pattern={pattern_type})")
            else:
                # 其他系统调用：使用传统边界值
                interesting_values = [
                    0, 1, -1,                           # 基本边界
                    0x7F, 0x80, 0xFF,                   # 8位边界
                    0x7FFF, 0x8000, 0xFFFF,             # 16位边界
                    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, # 32位边界
                    0x100, 0x400, 0x1000,               # 页面大小相关
                ]
                value = random.choice(interesting_values)
                mutation_data = struct.pack('Q', value & 0xFFFFFFFFFFFFFFFF)
                print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=INTERESTING_VALUES(0x{value:x})")
            return FuzzInstruction(index, FUZZ_CMD_INTERESTING_VALUES, 1, mutation_data)
        
        elif strategy_type == 2:
            # TRUNCATE - 截断数据 (减少大小)
            truncate_to = random.choice([0, 1, 2, 4, 8, 16])
            mutation_data = struct.pack('I', truncate_to)
            print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=TRUNCATE(to {truncate_to})")
            return FuzzInstruction(index, FUZZ_CMD_TRUNCATE, 1, mutation_data)
        
        elif strategy_type == 3:
            # EXTEND - 扩展数据 (增加大小)
            # 🔥 增强扩展值以触发缓冲区溢出
            if self.is_stagnant or iteration % 10 == 0:
                # 停滞模式或每10次迭代使用更激进的扩展
                extend_by = random.choice([64, 128, 256, 512, 1024])
            else:
                # 常规模式使用温和的扩展
                extend_by = random.choice([1, 4, 16, 32, 64, 128])
            mutation_data = struct.pack('I', extend_by)
            print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=EXTEND(by {extend_by})")
            return FuzzInstruction(index, FUZZ_CMD_EXTEND, 1, mutation_data)
        
        elif strategy_type == 4:
            # LIGHT_MUTATION - 轻量变异 (只翻转1-2位)
            num_flips = random.randint(1, 2)
            mutation_data = struct.pack('I', num_flips)
            print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=LIGHT_MUTATION({num_flips} bits)")
            return FuzzInstruction(index, FUZZ_CMD_LIGHT_MUTATION, 1, mutation_data)
        
        elif strategy_type == 5:
            # MUTATE_AUX_BUFFER - 变异辅助缓冲区
            # 随机修改缓冲区中的几个字节
            num_changes = random.randint(1, 8)
            mutation_data = struct.pack('I', num_changes) + bytes([random.randint(0, 255) for _ in range(num_changes)])
            print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=MUTATE_AUX_BUFFER({num_changes} bytes)")
            return FuzzInstruction(index, FUZZ_CMD_MUTATE_AUX_BUFFER, 1, mutation_data)
        
        elif strategy_type == 6:
            # REPLACE_BUFFER - 完全替换缓冲区 (小数据)
            size = random.choice([4, 8, 16, 32])
            mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=REPLACE_BUFFER({size} bytes)")
            return FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data)
        
        elif strategy_type == 7:
            # REPLACE_BUFFER - 大数据替换 (测试溢出)
            # 🔥 增强大缓冲区变异以触发缓冲区溢出
            if self.is_stagnant or iteration % 15 == 0:
                # 停滞模式或周期性使用超大缓冲区
                size = random.choice([128, 256, 512, 1024])
                # 使用特定模式来增加崩溃几率 (重复字符)
                pattern = random.choice([b'A', b'B', b'X', b'\x41'])
                mutation_data = pattern * size
            else:
                # 常规模式
                size = random.choice([64, 128, 256])
                mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=REPLACE_BUFFER({size} bytes, large)")
            return FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data)
        
        elif strategy_type == 8:
            # BOUNDARY_VALUE - 边界值测试
            boundary_vals = [0, -1, 0x7FFFFFFF, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF]
            value = random.choice(boundary_vals)
            mutation_data = struct.pack('q', value)
            print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=BOUNDARY_VALUE(0x{value:x})")
            return FuzzInstruction(index, FUZZ_CMD_BOUNDARY_VALUE, 1, mutation_data)
        
        elif strategy_type == 9:
            # 🎯 多样化漏洞类型支持 - 特殊模式注入
            vuln_patterns = {
                'format_string': [
                    b'%s%s%s%s%n',           # 格式化字符串
                    b'%x%x%x%x%x%x',         # 堆栈泄露
                    b'%p%p%p%p',             # 指针泄露
                    b'%08x.%08x.%08x',       # 内存转储
                ],
                'injection': [
                    b"'; DROP TABLE users;--",  # SQL注入
                    b"' OR '1'='1",            # SQL绕过
                    b"$(id)",                  # 命令注入
                    b"`whoami`",               # 命令替换
                    b"|cat /etc/passwd",       # 管道注入
                ],
                'path_traversal': [
                    b'/../../../etc/passwd',    # 路径遍历
                    b'..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',  # Windows路径
                    b'/proc/self/environ',      # 环境变量读取
                    b'/dev/urandom',            # 特殊设备
                ],
                'overflow_patterns': [
                    b'A' * 256,                 # 经典缓冲区溢出
                    b'\x41' * 512 + b'\x42\x43\x44\x45',  # 带标记的溢出
                    b'%n' * 100,                # 格式化字符串溢出
                ],
                'special_chars': [
                    b'\x00' * 32,               # NULL字节注入
                    b'\xFF' * 32,               # 高位字节
                    b'\x0A\x0D' * 16,          # 换行符注入
                    b'\x80\x81\x82\x83',       # 非ASCII字符
                ],
                'unicode_attacks': [
                    b'\xC0\xAE\xC0\xAE\x2f',  # UTF-8溢出
                    b'\xEF\xBB\xBF',          # BOM注入
                    b'\x00\x41\x00\x42',      # 宽字符注入
                ],
                'race_condition': [
                    b'AAAAAAAAAAAAAAAA',        # 重复模式用于竞态
                    b'1234567890' * 10,        # 数字序列
                    b'test\x00test\x00',       # 分隔符注入
                ]
            }

            # 根据系统调用类型选择合适的漏洞模式
            syscall_name = target_candidate.name.lower()

            if 'read' in syscall_name or 'recv' in syscall_name:
                # 输入相关系统调用：使用各种注入模式
                pattern_type = random.choice(['format_string', 'injection', 'overflow_patterns', 'special_chars'])
            elif 'write' in syscall_name or 'send' in syscall_name:
                # 输出相关：测试格式化字符串和特殊字符
                pattern_type = random.choice(['format_string', 'special_chars', 'unicode_attacks'])
            elif 'open' in syscall_name:
                # 文件操作：路径遍历攻击
                pattern_type = random.choice(['path_traversal', 'special_chars'])
            else:
                # 其他系统调用：通用模式
                pattern_type = random.choice(['overflow_patterns', 'special_chars', 'race_condition'])

            mutation_data = random.choice(vuln_patterns[pattern_type])
            print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=VULN_PATTERN({pattern_type})")
            return FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data)
        
        else:
            # MUTATE_FLAGS - 标志位变异
            if iteration % 3 == 0:
                # 单位翻转
                flag_mutation = struct.pack('q', (1 << (iteration % 32)))
                print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=MUTATE_FLAGS(single bit)")
            else:
                # 多位翻转
                flag_mutation = struct.pack('q', random.randint(0, 0xFFFFFFFF))
                print(f"[Mutator]   🎯 目标: index={index}, name={target_candidate.name}, cmd=MUTATE_FLAGS(multi bits)")
            return FuzzInstruction(index, FUZZ_CMD_MUTATE_FLAGS, 0, flag_mutation)
    
    def mutate(self, trace, fork_point: int = None) -> List['FuzzInstruction']:
        """
        为trace生成变异 (接口兼容性)

        参数:
            trace: Trace对象 (使用metadata.exec_count作为迭代计数)
            fork_point: Fork点的syscall index (确保mutation目标>=fork_point)

        返回:
            list: FuzzInstruction列表
        """
        # 🔥 修复: 使用trace.metadata.exec_count而不是trace.exec_count
        iteration = getattr(trace.metadata, 'exec_count', 0) if hasattr(trace, 'metadata') else 0
        return self.build_instructions(iteration, fork_point=fork_point)
    
    def build_instructions(self, iteration, fork_point: int = None):
        """
        构建Fuzz指令
        
        ━━━━ 第2.1阶段增强: 充分利用11个变异命令 ━━━━
        - 如果有recipes: 使用recipes生成精确的变异指令
        - 如果没有recipes: 使用增强的随机变异模式
        
        增强策略 (随机模式):
        - P1: 基于停滞状态动态调整变异数量
        - P2: 只选择IO syscalls作为mutation目标
        - P3: 确保mutation目标 >= fork_point
        - P4: 如果指定fork_point，保证至少一个mutation目标是它
        - 使用所有11种变异策略:
          * FLIP_BITS, LIGHT_MUTATION - 轻量级变异
          * INTERESTING_VALUES, BOUNDARY_VALUE - 边界值测试
          * TRUNCATE, EXTEND - 大小变异
          * REPLACE_BUFFER, MUTATE_AUX_BUFFER - 缓冲区变异
          * MUTATE_FLAGS, MUTATE_ARG - 参数变异
          * 特殊模式 - 格式化字符串、注入攻击等
        
        参数:
            iteration: 当前迭代次数
            fork_point: Fork点的syscall index (可选)
        
        返回:
            list: FuzzInstruction列表
        """
        instrs = []

        # ━━━━ 第2阶段: Recipe驱动模式 (概率性) ━━━━
        # 🔥 P3 Fix 3.3: 改为概率性recipe选择，避免recipe完全主导
        #
        # 策略：
        # - 前期 (<100 iters): 70% recipe, 30% 系统化探索
        # - 中期 (100-500): 50% recipe, 50% 系统化探索
        # - 后期 (>500): 30% recipe, 70% 系统化探索
        #
        # 效果：增加path discovery rate，平衡directed vs. systematic fuzzing
        if self.recipe_mode and self.recipes:
            import random

            # 根据迭代次数调整recipe概率
            if iteration < 100:
                recipe_probability = 0.7  # 前期70%使用recipe
            elif iteration < 500:
                recipe_probability = 0.5  # 中期50%使用recipe
            else:
                recipe_probability = 0.3  # 后期30%使用recipe

            # 停滞时进一步降低recipe使用率（增加exploration）
            if self.is_stagnant:
                recipe_probability *= 0.6  # 停滞时降低recipe使用率

            if random.random() < recipe_probability:
                # ✅ 2025-11-17: 设置 mutation type 用于跟踪
                self.last_mutation_type = 'recipe'
                return self._build_from_recipes(iteration)
            else:
                # Fall through to systematic exploration
                print(f"[Mutator] ⚙️ 跳过recipe，使用系统化探索 (iteration={iteration}, prob={recipe_probability:.1%})")

        # ━━━━ 如果没有recipe或未命中recipe概率，使用系统化探索 ━━━━

        # ━━━━ 增强: 随机变异模式 ━━━━
        # ✅ 2025-11-17: 设置 mutation type 用于跟踪
        self.last_mutation_type = 'smart_random'

        if not self.mutable_candidates:
            print("[Mutator] ⚠️  未发现可变异候选!")
            return instrs
        
        num_candidates = len(self.mutable_candidates)
        
        # 🔥 P0修复: 增强变异强度 - 提高所有模式的mutation数量
        #
        # 新正常模式（有新coverage）:
        # - 候选<5个: mutate 2-3个 (提高)
        # - 候选5-10个: mutate 3-5个 (提高)
        # - 候选>10个: mutate 5-8个 (提高)
        #
        # 新停滞模式（长时间无新coverage）:
        # - 候选<5个: mutate 3-4个 (更激进)
        # - 候选5-10个: mutate 5-7个 (更激进)
        # - 候选>10个: mutate 8-15个 (非常激进)

        if self.is_stagnant:
            # 🔥 停滞模式：非常激进的mutation
            if num_candidates < 5:
                num_mutations = min(4, max(3, num_candidates))
            elif num_candidates < 10:
                num_mutations = min(7, max(5, num_candidates))
            else:
                num_mutations = min(15, max(8, num_candidates // 2))

            stagnation_duration = iteration - self.last_new_coverage_iter
            print(f"[Mutator] 🔥 停滞模式: 变异{num_mutations}个syscall "
                  f"(已停滞{stagnation_duration}次迭代)")
        else:
            # 🔥 正常模式：提高基础mutation数量
            if num_candidates < 5:
                num_mutations = min(3, max(2, num_candidates))
            elif num_candidates < 10:
                num_mutations = min(5, max(3, num_candidates))
            else:
                num_mutations = min(8, max(5, num_candidates // 3))
        
        # P2: 过滤出 >= fork_point 的候选
        valid_candidates = self.mutable_candidates
        if fork_point is not None:
            valid_candidates = [c for c in self.mutable_candidates if c.index >= fork_point]
            print(f"[Mutator] Fork point={fork_point}, valid candidates after filter: {len(valid_candidates)}/{len(self.mutable_candidates)}")
            if len(valid_candidates) == 0:
                print(f"[Mutator] WARNING: No candidates >= fork_point, using all candidates")
                valid_candidates = self.mutable_candidates
        
        num_candidates = len(valid_candidates)
        
        print(f"[Mutator] Iteration {iteration}: Mutating {num_mutations} from {num_candidates} IO candidates")
        
        # P3: 分类候选（所有候选都已经是IO syscalls了）
        primary_io = [c for c in valid_candidates if c.name in PRIMARY_IO_SYSCALLS]
        secondary_io = [c for c in valid_candidates if c.name in SECONDARY_IO_SYSCALLS]
        
        print(f"[Mutator]   Primary IO: {len(primary_io)}, Secondary IO: {len(secondary_io)}")
        
        # P4: 如果指定了fork_point，保证至少有一个mutation目标是它
        fork_point_candidate = None
        if fork_point is not None:
            for c in valid_candidates:
                if c.index == fork_point:
                    fork_point_candidate = c
                    break
            
            if fork_point_candidate:
                strategy_type = self._select_mutation_strategy()
                fork_instr = self._generate_advanced_mutation(fork_point_candidate, strategy_type, iteration)
                instrs.append(fork_instr)
                print(f"[Mutator] P4: Guaranteed mutation at fork_point={fork_point} ({fork_point_candidate.name})")
                num_mutations -= 1
            else:
                print(f"[Mutator] WARNING: fork_point={fork_point} not in valid candidates")
        
        # 🔥 修复：选择剩余的mutation目标，避免重复性targeting
        # 策略：基于迭代ID进行轮换选择，确保不同迭代探索不同syscalls
        selected = []

        # 合并所有候选，按索引排序以确保稳定的顺序
        all_io_candidates = sorted(primary_io + secondary_io, key=lambda c: c.index)

        if len(all_io_candidates) >= num_mutations:
            # 🔥 修复：实现轮换选择而不是纯随机
            selected = self._select_diverse_targets(all_io_candidates, num_mutations, iteration)
        else:
            # 如果候选数不够，使用所有候选
            selected = all_io_candidates.copy()
        
        # 生成mutations
        for target_candidate in selected:
            strategy_type = self._select_mutation_strategy()
            instr = self._generate_advanced_mutation(target_candidate, strategy_type, iteration)
            if instr:
                instrs.append(instr)
        
        # ✅ 2025-11-18: 记录mutation_type
        self.last_mutation_type = 'smart' if len(instrs) > 0 else 'none'
        
        # ✅ 修复: 验证指令数量不超过限制
        if len(instrs) > FUZZ_MAX_INSTRUCTIONS:
            print(f"[SmartMutator] ⚠️  Generated {len(instrs)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}")
            instrs = instrs[:FUZZ_MAX_INSTRUCTIONS]
        
        print(f"[Mutator] Generated {len(instrs)} mutation instructions")
        return instrs

    def _select_diverse_targets(self, candidates: list, num_targets: int, iteration: int) -> list:
        """
        🔥 修复：选择多样化的mutation目标，避免重复性targeting

        策略：
        1. 轮换算法：基于迭代ID在不同候选间循环
        2. 分散选择：确保选中的syscalls在索引上分散
        3. 随机扰动：一定概率的随机选择保持不可预测性
        4. 历史避免：避免连续迭代选择相同的目标

        Args:
            candidates: 可选候选列表 (已按索引排序)
            num_targets: 需要选择的目标数量
            iteration: 当前迭代ID

        Returns:
            选择的候选列表
        """
        if not candidates:
            return []

        if len(candidates) <= num_targets:
            return candidates.copy()

        selected = []

        # 策略1: 基于迭代的轮换起始点
        start_index = iteration % len(candidates)

        # 策略2: 分散选择 - 尽量选择距离较远的候选
        if num_targets == 1:
            # 单个选择：基于迭代轮换
            selected_index = start_index
            selected.append(candidates[selected_index])
        else:
            # 多个选择：使用步进算法确保分散
            step = max(1, len(candidates) // num_targets)
            for i in range(num_targets):
                index = (start_index + i * step) % len(candidates)
                selected.append(candidates[index])

        # 策略3: 随机扰动 (25%概率)
        if random.random() < 0.25:
            # 用随机候选替换一个选中的候选
            if selected:
                replace_idx = random.randint(0, len(selected) - 1)
                selected[replace_idx] = random.choice(candidates)

        # 去重处理（如果由于轮换产生重复）
        seen = set()
        unique_selected = []
        for candidate in selected:
            if candidate.index not in seen:
                unique_selected.append(candidate)
                seen.add(candidate.index)

        # 如果去重后数量不足，补充选择
        while len(unique_selected) < num_targets and len(unique_selected) < len(candidates):
            for candidate in candidates:
                if candidate.index not in seen:
                    unique_selected.append(candidate)
                    seen.add(candidate.index)
                    break

        return unique_selected[:num_targets]


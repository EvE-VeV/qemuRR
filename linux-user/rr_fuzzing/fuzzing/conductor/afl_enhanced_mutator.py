#!/usr/bin/env python3
"""
AFL Enhanced Mutator - AFL风格的系统化变异
在现有SmartMutator基础上添加AFL核心思想
"""

import struct
import random
from typing import List, Dict, Any, Optional, Tuple
from .mutator import SmartMutator
from .instruction import FuzzInstruction
from .constants import *

class AFLStage:
    """AFL变异阶段枚举"""
    BITFLIP_1_1 = "bitflip_1_1"     # 翻转每1位
    BITFLIP_2_1 = "bitflip_2_1"     # 翻转每2位
    BITFLIP_4_1 = "bitflip_4_1"     # 翻转每4位
    BITFLIP_8_8 = "bitflip_8_8"     # 翻转每字节
    BITFLIP_16_8 = "bitflip_16_8"   # 翻转每2字节
    BITFLIP_32_8 = "bitflip_32_8"   # 翻转每4字节

    ARITH_8 = "arith_8"             # 8位算术
    ARITH_16 = "arith_16"           # 16位算术
    ARITH_32 = "arith_32"           # 32位算术

    INTEREST_8 = "interest_8"       # 8位有趣值
    INTEREST_16 = "interest_16"     # 16位有趣值
    INTEREST_32 = "interest_32"     # 32位有趣值

    EXTRAS_UO = "extras_uo"         # 用户提供的extras
    EXTRAS_AO = "extras_ao"         # 自动提取的extras

    HAVOC = "havoc"                 # 随机变异（使用现有策略）
    SPLICE = "splice"               # 拼接模式

class AFLEnhancedMutator(SmartMutator):
    """
    AFL增强变异器

    核心思想：
    1. 保留SmartMutator的所有优势（系统调用语义、参数关联）
    2. 添加AFL的系统化探索阶段
    3. 在AFL阶段与智能变异之间找到平衡
    """

    def __init__(self, trace_file, recipe_file=None, target_binary=None):
        super().__init__(trace_file, recipe_file, target_binary)

        # AFL相关状态
        self.afl_enabled = True
        self.current_stage = AFLStage.BITFLIP_1_1
        self.stage_progress = 0
        self.stage_max = 0
        self.stage_finds = 0  # 本阶段发现的新路径数

        # AFL阶段统计
        self.stage_stats = {
            stage: {"executions": 0, "finds": 0, "time": 0.0}
            for stage in [
                AFLStage.BITFLIP_1_1, AFLStage.BITFLIP_2_1, AFLStage.BITFLIP_4_1,
                AFLStage.BITFLIP_8_8, AFLStage.BITFLIP_16_8, AFLStage.BITFLIP_32_8,
                AFLStage.ARITH_8, AFLStage.ARITH_16, AFLStage.ARITH_32,
                AFLStage.INTEREST_8, AFLStage.INTEREST_16, AFLStage.INTEREST_32,
                AFLStage.EXTRAS_UO, AFLStage.EXTRAS_AO,
                AFLStage.HAVOC, AFLStage.SPLICE
            ]
        }

        # AFL常量
        self.INTERESTING_8 = [
            -128, -1, 0, 1, 16, 32, 64, 100, 127
        ]

        self.INTERESTING_16 = [
            -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767
        ]

        self.INTERESTING_32 = [
            -2147483648, -100663046, -32769, 32768, 65535, 65536,
            100663045, 2147483647
        ]

        # 当前种子数据缓存
        self.current_seed_data = None
        self.current_target_index = None

        print("[AFLMutator] ✅ Initialized with AFL-style systematic exploration")

    def mutate(self, trace, fork_point: int = None) -> List[FuzzInstruction]:
        """
        主要的变异入口点，重写SmartMutator的mutate方法

        参数:
            trace: Trace对象 (未使用, 使用内部候选)
            fork_point: Syscall index of fork point (可选)
        """
        # 获取当前迭代数（简化实现：使用trace的某种标识）
        iteration = getattr(self, '_iteration_count', 0)
        self._iteration_count = iteration + 1

        return self.build_instructions_afl_enhanced(iteration, fork_point=fork_point)

    def build_instructions_afl_enhanced(self, iteration: int, fork_point: Optional[int] = None) -> List[FuzzInstruction]:
        """
        AFL增强的指令构建

        策略：
        1. 前80%迭代：使用AFL系统化探索
        2. 后20%迭代：使用SmartMutator的智能变异
        3. 停滞状态：混合使用两种方法
        """

        # 决定使用AFL还是智能变异
        use_afl = self._should_use_afl_stage(iteration)

        if use_afl and self.afl_enabled:
            return self._build_afl_instructions(iteration, fork_point)
        else:
            # 使用原有的SmartMutator逻辑
            return super().build_instructions(iteration, fork_point)

    def _should_use_afl_stage(self, iteration: int) -> bool:
        """判断是否应该使用AFL阶段"""

        # 停滞状态：50% AFL，50% 智能变异
        if self.is_stagnant:
            return random.choice([True, False])

        # 前期：主要使用AFL系统化探索
        if iteration < 100:
            return random.random() < 0.8  # 80% AFL

        # 中期：平衡使用
        elif iteration < 500:
            return random.random() < 0.6  # 60% AFL

        # 后期：主要使用智能变异
        else:
            return random.random() < 0.3  # 30% AFL

    def _filter_candidates_for_fork_point(self, fork_point: Optional[int]):
        """过滤适合当前fork point的候选"""
        # 简化：返回所有候选
        if hasattr(self, 'pure_candidates') and self.pure_candidates:
            return self.pure_candidates
        return []

    def _build_afl_instructions(self, iteration: int, fork_point: Optional[int] = None) -> List[FuzzInstruction]:
        """
        构建AFL风格的指令
        """

        # 选择目标候选
        valid_candidates = self._filter_candidates_for_fork_point(fork_point)
        if not valid_candidates:
            print("[AFLMutator] ⚠️  No valid candidates for AFL mutation")
            return []

        # 随机选择一个候选作为目标
        target_candidate = random.choice(valid_candidates)
        self.current_target_index = target_candidate.index

        # 获取种子数据（简化：使用固定种子）
        self.current_seed_data = self._get_seed_data_for_candidate(target_candidate)

        # 根据当前阶段生成变异
        afl_instructions = []

        if self.current_stage.startswith("bitflip"):
            afl_instructions = self._generate_bitflip_instructions(target_candidate)
        elif self.current_stage.startswith("arith"):
            afl_instructions = self._generate_arithmetic_instructions(target_candidate)
        elif self.current_stage.startswith("interest"):
            afl_instructions = self._generate_interesting_instructions(target_candidate)
        elif self.current_stage == AFLStage.HAVOC:
            # Havoc阶段：使用现有的智能变异策略
            afl_instructions = super().build_instructions(iteration, fork_point)

        # 推进阶段
        self._advance_afl_stage()

        return afl_instructions

    def _get_seed_data_for_candidate(self, candidate) -> bytes:
        """获取候选的种子数据"""
        # 简化实现：返回一些基础数据
        if candidate.name in ['read', 'recv', 'recvfrom']:
            # 输入类系统调用：返回典型输入数据
            return b"Hello, World! This is test input data for fuzzing."
        elif candidate.name in ['write', 'send', 'sendto']:
            # 输出类系统调用：返回格式化数据
            return b"Output data: %s %d %x"
        else:
            # 其他：返回通用数据
            return b"AAAABBBBCCCCDDDD"

    def _generate_bitflip_instructions(self, target_candidate) -> List[FuzzInstruction]:
        """生成位翻转指令（AFL核心）"""
        instructions = []
        seed_data = self.current_seed_data

        if self.current_stage == AFLStage.BITFLIP_1_1:
            # 1/1位翻转：翻转每一位
            instructions = self._bitflip_1_1(target_candidate, seed_data)
        elif self.current_stage == AFLStage.BITFLIP_2_1:
            # 2/1位翻转：翻转连续2位
            instructions = self._bitflip_2_1(target_candidate, seed_data)
        elif self.current_stage == AFLStage.BITFLIP_4_1:
            # 4/1位翻转：翻转连续4位
            instructions = self._bitflip_4_1(target_candidate, seed_data)
        elif self.current_stage == AFLStage.BITFLIP_8_8:
            # 8/8位翻转：翻转整个字节
            instructions = self._bitflip_8_8(target_candidate, seed_data)

        return instructions

    def _bitflip_1_1(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 1/1位翻转"""
        instructions = []

        # 限制变异数量，避免爆炸
        max_mutations = min(len(seed_data) * 8, 64)  # 最多64个变异

        for bit_idx in range(max_mutations):
            byte_idx = bit_idx // 8
            bit_in_byte = bit_idx % 8

            if byte_idx >= len(seed_data):
                break

            # 创建变异数据
            mutated_data = bytearray(seed_data)
            mutated_data[byte_idx] ^= (1 << bit_in_byte)

            # 创建FLIP_BITS指令（复用现有指令格式）
            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_FLIP_BITS,
                arg_index=1,  # 通常是缓冲区参数
                data=bytes(mutated_data)
            )

            instructions.append(instruction)

        print(f"[AFLMutator] 🔀 Generated {len(instructions)} 1/1 bitflip mutations")
        return instructions

    def _bitflip_2_1(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 2/1位翻转"""
        instructions = []
        max_mutations = min(len(seed_data) * 8 - 1, 32)

        for bit_idx in range(max_mutations):
            byte_idx = bit_idx // 8
            bit_in_byte = bit_idx % 8

            if byte_idx >= len(seed_data) or bit_in_byte >= 7:
                continue

            mutated_data = bytearray(seed_data)

            # 翻转连续2位
            mutated_data[byte_idx] ^= (3 << bit_in_byte)  # 3 = 0b11

            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_FLIP_BITS,
                arg_index=1,
                data=bytes(mutated_data)
            )

            instructions.append(instruction)

        print(f"[AFLMutator] 🔀 Generated {len(instructions)} 2/1 bitflip mutations")
        return instructions

    def _bitflip_4_1(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 4/1位翻转"""
        instructions = []
        max_mutations = min(len(seed_data) * 8 - 3, 16)

        for bit_idx in range(max_mutations):
            byte_idx = bit_idx // 8
            bit_in_byte = bit_idx % 8

            if byte_idx >= len(seed_data) or bit_in_byte >= 5:
                continue

            mutated_data = bytearray(seed_data)

            # 翻转连续4位
            mutated_data[byte_idx] ^= (15 << bit_in_byte)  # 15 = 0b1111

            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_FLIP_BITS,
                arg_index=1,
                data=bytes(mutated_data)
            )

            instructions.append(instruction)

        print(f"[AFLMutator] 🔀 Generated {len(instructions)} 4/1 bitflip mutations")
        return instructions

    def _bitflip_8_8(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 8/8位翻转（字节翻转）"""
        instructions = []

        for byte_idx in range(min(len(seed_data), 32)):
            mutated_data = bytearray(seed_data)

            # 翻转整个字节
            mutated_data[byte_idx] ^= 0xFF

            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_FLIP_BITS,
                arg_index=1,
                data=bytes(mutated_data)
            )

            instructions.append(instruction)

        print(f"[AFLMutator] 🔀 Generated {len(instructions)} 8/8 bitflip mutations")
        return instructions

    def _generate_arithmetic_instructions(self, target_candidate) -> List[FuzzInstruction]:
        """生成算术变异指令"""
        instructions = []
        seed_data = self.current_seed_data

        if self.current_stage == AFLStage.ARITH_8:
            instructions = self._arithmetic_8(target_candidate, seed_data)
        elif self.current_stage == AFLStage.ARITH_16:
            instructions = self._arithmetic_16(target_candidate, seed_data)
        elif self.current_stage == AFLStage.ARITH_32:
            instructions = self._arithmetic_32(target_candidate, seed_data)

        return instructions

    def _arithmetic_8(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 8位算术变异"""
        instructions = []

        for byte_idx in range(min(len(seed_data), 16)):
            original_byte = seed_data[byte_idx]

            # AFL算术范围：±1 到 ±35
            for delta in range(-35, 36):
                if delta == 0:
                    continue

                new_value = (original_byte + delta) & 0xFF
                if new_value == original_byte:
                    continue

                mutated_data = bytearray(seed_data)
                mutated_data[byte_idx] = new_value

                # 使用INTERESTING_VALUES指令
                instruction = FuzzInstruction(
                    syscall_index=target_candidate.index,
                    cmd=FUZZ_CMD_INTERESTING_VALUES,
                    arg_index=1,
                    data=struct.pack('B', new_value)
                )

                instructions.append(instruction)

        print(f"[AFLMutator] 🔢 Generated {len(instructions)} 8-bit arithmetic mutations")
        return instructions

    def _arithmetic_16(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 16位算术变异"""
        instructions = []

        for byte_idx in range(0, min(len(seed_data) - 1, 16), 2):
            # 小端和大端
            for endian in ['little', 'big']:
                original_value = int.from_bytes(
                    seed_data[byte_idx:byte_idx+2],
                    byteorder=endian
                )

                for delta in [-35, -1, 1, 35]:  # 简化范围
                    new_value = (original_value + delta) & 0xFFFF
                    if new_value == original_value:
                        continue

                    new_bytes = new_value.to_bytes(2, byteorder=endian)

                    instruction = FuzzInstruction(
                        syscall_index=target_candidate.index,
                        cmd=FUZZ_CMD_INTERESTING_VALUES,
                        arg_index=1,
                        data=new_bytes
                    )

                    instructions.append(instruction)

        print(f"[AFLMutator] 🔢 Generated {len(instructions)} 16-bit arithmetic mutations")
        return instructions

    def _arithmetic_32(self, target_candidate, seed_data: bytes) -> List[FuzzInstruction]:
        """AFL 32位算术变异"""
        instructions = []

        for byte_idx in range(0, min(len(seed_data) - 3, 8), 4):
            for endian in ['little', 'big']:
                original_value = int.from_bytes(
                    seed_data[byte_idx:byte_idx+4],
                    byteorder=endian
                )

                for delta in [-35, -1, 1, 35]:
                    new_value = (original_value + delta) & 0xFFFFFFFF
                    if new_value == original_value:
                        continue

                    new_bytes = new_value.to_bytes(4, byteorder=endian)

                    instruction = FuzzInstruction(
                        syscall_index=target_candidate.index,
                        cmd=FUZZ_CMD_INTERESTING_VALUES,
                        arg_index=1,
                        data=new_bytes
                    )

                    instructions.append(instruction)

        print(f"[AFLMutator] 🔢 Generated {len(instructions)} 32-bit arithmetic mutations")
        return instructions

    def _generate_interesting_instructions(self, target_candidate) -> List[FuzzInstruction]:
        """生成有趣值指令"""
        instructions = []

        if self.current_stage == AFLStage.INTEREST_8:
            instructions = self._interesting_8(target_candidate)
        elif self.current_stage == AFLStage.INTEREST_16:
            instructions = self._interesting_16(target_candidate)
        elif self.current_stage == AFLStage.INTEREST_32:
            instructions = self._interesting_32(target_candidate)

        return instructions

    def _interesting_8(self, target_candidate) -> List[FuzzInstruction]:
        """AFL 8位有趣值"""
        instructions = []

        for value in self.INTERESTING_8:
            instruction = FuzzInstruction(
                syscall_index=target_candidate.index,
                cmd=FUZZ_CMD_INTERESTING_VALUES,
                arg_index=1,
                data=struct.pack('b', value)
            )
            instructions.append(instruction)

        print(f"[AFLMutator] ⭐ Generated {len(instructions)} 8-bit interesting value mutations")
        return instructions

    def _interesting_16(self, target_candidate) -> List[FuzzInstruction]:
        """AFL 16位有趣值"""
        instructions = []

        for value in self.INTERESTING_16:
            for endian in ['little', 'big']:
                instruction = FuzzInstruction(
                    syscall_index=target_candidate.index,
                    cmd=FUZZ_CMD_INTERESTING_VALUES,
                    arg_index=1,
                    data=value.to_bytes(2, byteorder=endian, signed=True)
                )
                instructions.append(instruction)

        print(f"[AFLMutator] ⭐ Generated {len(instructions)} 16-bit interesting value mutations")
        return instructions

    def _interesting_32(self, target_candidate) -> List[FuzzInstruction]:
        """AFL 32位有趣值"""
        instructions = []

        for value in self.INTERESTING_32:
            for endian in ['little', 'big']:
                instruction = FuzzInstruction(
                    syscall_index=target_candidate.index,
                    cmd=FUZZ_CMD_INTERESTING_VALUES,
                    arg_index=1,
                    data=value.to_bytes(4, byteorder=endian, signed=True)
                )
                instructions.append(instruction)

        print(f"[AFLMutator] ⭐ Generated {len(instructions)} 32-bit interesting value mutations")
        return instructions

    def _advance_afl_stage(self):
        """推进AFL阶段"""
        self.stage_progress += 1

        # 检查是否完成当前阶段
        if self._is_stage_complete():
            self._next_afl_stage()

    def _is_stage_complete(self) -> bool:
        """判断当前阶段是否完成"""
        # 简化：每个阶段执行一定次数后切换
        stage_limits = {
            AFLStage.BITFLIP_1_1: 50,
            AFLStage.BITFLIP_2_1: 30,
            AFLStage.BITFLIP_4_1: 20,
            AFLStage.BITFLIP_8_8: 10,
            AFLStage.ARITH_8: 40,
            AFLStage.ARITH_16: 30,
            AFLStage.ARITH_32: 20,
            AFLStage.INTEREST_8: 10,
            AFLStage.INTEREST_16: 20,
            AFLStage.INTEREST_32: 20,
            AFLStage.HAVOC: 100,
        }

        limit = stage_limits.get(self.current_stage, 50)
        return self.stage_progress >= limit

    def _next_afl_stage(self):
        """切换到下一个AFL阶段"""
        stage_sequence = [
            AFLStage.BITFLIP_1_1, AFLStage.BITFLIP_2_1, AFLStage.BITFLIP_4_1,
            AFLStage.BITFLIP_8_8, AFLStage.BITFLIP_16_8, AFLStage.BITFLIP_32_8,
            AFLStage.ARITH_8, AFLStage.ARITH_16, AFLStage.ARITH_32,
            AFLStage.INTEREST_8, AFLStage.INTEREST_16, AFLStage.INTEREST_32,
            AFLStage.HAVOC
        ]

        try:
            current_idx = stage_sequence.index(self.current_stage)
            next_idx = (current_idx + 1) % len(stage_sequence)
            self.current_stage = stage_sequence[next_idx]
        except ValueError:
            self.current_stage = AFLStage.BITFLIP_1_1

        self.stage_progress = 0
        print(f"[AFLMutator] 🔄 Advanced to stage: {self.current_stage}")

    def record_stage_feedback(self, found_new_coverage: bool):
        """记录阶段反馈"""
        stage = self.current_stage
        self.stage_stats[stage]["executions"] += 1

        if found_new_coverage:
            self.stage_stats[stage]["finds"] += 1
            self.stage_finds += 1

    def get_afl_stats(self) -> Dict[str, Any]:
        """获取AFL统计信息"""
        return {
            "current_stage": self.current_stage,
            "stage_progress": self.stage_progress,
            "stage_finds": self.stage_finds,
            "stage_stats": self.stage_stats.copy()
        }

    def print_afl_stats(self):
        """打印AFL统计信息"""
        print(f"\n[AFLMutator] 📊 AFL Stage Statistics:")
        print(f"  Current stage: {self.current_stage}")
        print(f"  Stage progress: {self.stage_progress}")
        print(f"  Stage finds: {self.stage_finds}")

        for stage, stats in self.stage_stats.items():
            if stats["executions"] > 0:
                find_rate = stats["finds"] / stats["executions"] * 100
                print(f"  {stage}: {stats['executions']} execs, {stats['finds']} finds ({find_rate:.1f}%)")

    # 覆盖父类方法，使用AFL增强版本
    def build_instructions(self, iteration: int, fork_point: Optional[int] = None) -> List[FuzzInstruction]:
        """覆盖父类方法，使用AFL增强版本"""
        return self.build_instructions_afl_enhanced(iteration, fork_point)
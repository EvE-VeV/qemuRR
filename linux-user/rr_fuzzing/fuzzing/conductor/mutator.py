#!/usr/bin/env python3
"""
Mutator - Mutation Engine (Layer 2)

Provides basic and smart mutation capabilities:
- BaseMutator: Simple random mutation
- SmartMutator: Smart mutation based on trace analysis and recipe support
"""

import os
import json
import struct
import random
import sys
import time
import subprocess
import re
from pathlib import Path
from typing import List, Optional, Any, Dict

# Imports for trace_analyzer and other engine components

try:
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
    from .conductor_types import MutationRecipe
    from .shadow_registry import ShadowRegistry
except ImportError:
    # Standalone script fallback
    # This block is intentionally left empty as relative imports are now preferred.
    # If this script is run standalone, it should be run from the package root
    # or the package should be installed.
    pass


def perform_fd_tracking(syscalls):
    """Build forbidden-fd and network-fd maps from a list of SyscallRecord objects.

    Returns:
        (forbidden_map, network_fd_map): dicts mapping syscall index -> bool
        - forbidden_map: True if syscall uses a library/early-init FD (skip mutation)
        - network_fd_map: True if syscall uses a network socket FD (priority target)
    """
    forbidden_map = {}
    network_fd_map = {}
    active_forbidden_fds = set()
    active_network_fds = set()

    FD_USING_SYSCALLS = {
        'read', 'write', 'pread64', 'pwrite64', 'readv', 'writev',
        'recv', 'recvfrom', 'recvmsg', 'send', 'sendto', 'sendmsg',
        'ioctl', 'fcntl', 'lseek', 'fstat', 'ftruncate', 'fsync',
        'setsockopt', 'getsockopt', 'getsockname', 'getpeername',
        'shutdown', 'close',
    }
    FD_CREATING_SYSCALLS = {
        'socket', 'accept', 'accept4', 'open', 'openat', 'creat',
        'dup', 'dup2', 'dup3', 'pipe', 'pipe2',
    }
    SC_SOCKET = 1
    SC_ACCEPT = 5
    SC_ACCEPT4 = 18

    for sc in syscalls:
        is_forbidden = False
        is_network = False

        if sc.name == 'socketcall' and sc.args and sc.args[0] != SC_SOCKET:
            is_network = True

        sc_uses_fd = sc.uses_fd or (sc.name in FD_USING_SYSCALLS)
        if sc_uses_fd and sc.args:
            fd = sc.args[0]
            if fd in active_forbidden_fds:
                is_forbidden = True
            if fd in active_network_fds:
                is_network = True

        forbidden_map[sc.index] = is_forbidden
        network_fd_map[sc.index] = is_network

        sc_creates_fd = sc.creates_fd or (sc.name in FD_CREATING_SYSCALLS and sc.retval > 2)
        sc_created_fd = sc.created_fd if sc.creates_fd else (int(sc.retval) if sc_creates_fd else -1)

        if sc.name == 'socketcall' and sc.args and sc.retval > 2:
            sub = sc.args[0]
            if sub in (SC_SOCKET, SC_ACCEPT, SC_ACCEPT4):
                sc_creates_fd = True
                sc_created_fd = int(sc.retval)

        if sc_creates_fd and sc_created_fd > 2:
            filename = "unknown"
            if sc.name in ['open', 'openat']:
                idx = 1 if sc.name == 'openat' else 0
                if idx in sc.arg_data:
                    try:
                        filename = sc.arg_data[idx].split(b'\x00')[0].decode('utf-8', errors='ignore')
                    except Exception:
                        filename = str(sc.arg_data[idx])
            elif sc.name in ['socket', 'accept', 'accept4']:
                filename = f"network_{sc.name}"
                active_network_fds.add(sc_created_fd)
            elif sc.name == 'socketcall' and sc.args and sc.args[0] in (SC_SOCKET, SC_ACCEPT, SC_ACCEPT4):
                sub_name = {SC_SOCKET: 'socket', SC_ACCEPT: 'accept', SC_ACCEPT4: 'accept4'}[sc.args[0]]
                filename = f"network_socketcall_{sub_name}"
                active_network_fds.add(sc_created_fd)

            is_library = "/lib/" in filename or "/usr/lib/" in filename or "ld.so.cache" in filename
            is_early_unknown = (sc.index < 30 and filename == "unknown")

            if is_library or is_early_unknown:
                active_forbidden_fds.add(sc_created_fd)
            else:
                active_forbidden_fds.discard(sc_created_fd)

        if sc.name == 'close' and sc.args:
            fd = sc.args[0]
            active_forbidden_fds.discard(fd)
            active_network_fds.discard(fd)

    return forbidden_map, network_fd_map


class BaseMutator:
    """
    Base Mutation Engine (Simple random mutation)
    
    Provides basic random mutations without trace analysis.
    Used as backup or for standalone fuzzing.
    
    Architecture: DETAILED_ARCHITECTURE.md lines 87-106
    """
    
    def __init__(self, use_io_mutation: bool = True):
        """Initialize BaseMutator

        Args:
            use_io_mutation: Whether to enable IO return value mutation (default True)
        """
        self.iteration_count = 0
        self.use_io_mutation = use_io_mutation
        self.io_mutator = IOReturnValueMutator() if use_io_mutation else None
        self.last_mutation_type = 'unknown'
        self.dictionary = [] # Dictionary for token injection
        # FD tracking maps — populated lazily on first mutate() call
        self.syscall_forbidden_map = {}  # index -> bool (library/early-init FD)
        self.syscall_network_fd_map = {} # index -> bool (network socket FD)

        mode_str = "Random Mutation + IO Retval Mutation" if use_io_mutation else "Random Mutation Mode"
        alog(f"Initialized ({mode_str})", "MUTATOR", "INFO")
    
    def _init_fd_tracking(self, trace):
        """Lazily build FD tracking maps from trace on first call."""
        if trace and hasattr(trace, 'syscalls') and trace.syscalls and not self.syscall_forbidden_map:
            self.syscall_forbidden_map, self.syscall_network_fd_map = perform_fd_tracking(trace.syscalls)
            forbidden_count = sum(1 for v in self.syscall_forbidden_map.values() if v)
            network_count = sum(1 for v in self.syscall_network_fd_map.values() if v)
            alog(f"FD Tracking: {forbidden_count} library-IO protected, "
                 f"{network_count} network-socket syscalls identified", "MUTATOR", "INFO")

    def mutate(self, trace, fork_point: int = None, analyzer: Optional[Any] = None) -> List[FuzzInstruction]:
        """
        Generate random mutation

        Args:
            trace: Trace object (may be None for BaseMutator)
            fork_point: Syscall index of fork point (for compatibility with SmartMutator)

        Returns:
            List of FuzzInstructions
        """
        self.iteration_count += 1
        self._init_fd_tracking(trace)

        # Strategy: 70% probability for IO return value mutation if trace is available
        if self.use_io_mutation and self.io_mutator and trace and random.random() < 0.7:
            self.last_mutation_type = 'io_mutation'
            instrs = self._generate_io_mutations(trace, fork_point)
            
            # Limit number of instructions to avoid pipe overflow
            if len(instrs) > FUZZ_MAX_INSTRUCTIONS:
                alog(f"IO mutation exceeded limit, truncating to {FUZZ_MAX_INSTRUCTIONS}", "MUTATOR", "WARN")
                instrs = instrs[:FUZZ_MAX_INSTRUCTIONS]
            return instrs

        # Baseline random mutation
        self.last_mutation_type = 'random'
        # Generate 1-3 random mutations
        num_mutations = random.randint(1, 3)
        instructions = []
        
        for i in range(num_mutations):
            if i == 0 and fork_point is not None:
                syscall_index = fork_point
                alog(f"Mutation targeting fork_point={fork_point}", "MUTATOR")
            else:
                # 🔥 2026-01-22: Removed the conservative "+20" locality limit.
                # Now allow targeting any syscall up to the end of the trace (or default 1000).
                max_idx = (len(trace.syscalls) - 1) if (trace and hasattr(trace, 'syscalls')) else 1000
                if fork_point is not None:
                    syscall_index = random.randint(fork_point, max(fork_point, max_idx))
                else:
                    syscall_index = random.randint(0, max_idx)
                # Skip library/early-init FDs to avoid false-positive crashes
                if self.syscall_forbidden_map.get(syscall_index, False):
                    alog(f"Skip forbidden-FD syscall index={syscall_index}", "MUTATOR", "DEBUG")
                    continue
                alog(f"Mutation {i+1} targeting syscall_index={syscall_index} (max_idx={max_idx})", "MUTATOR")

            # Mutation command selection
            mutation_types = [
                FUZZ_CMD_FLIP_BITS,
                FUZZ_CMD_INTERESTING_VALUES,
                FUZZ_CMD_BOUNDARY_VALUE,
                FUZZ_CMD_REPLACE_BUFFER,
                FUZZ_CMD_MUTATE_FLAGS,
                FUZZ_CMD_MUTATE_AUX_BUFFER,  # Aux Data Mutation
                FUZZ_CMD_TRUNCATE,
                FUZZ_CMD_EXTEND,
                FUZZ_CMD_LIGHT_MUTATION
            ]
            cmd = random.choice(mutation_types)

            # Generate random data + set mutation_type
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
                # Aux Data mutation: Generate attack pattern data
                attack_patterns = [
                    b'%s%s%s%p',           # Format string attack
                    b'A' * 64,             # Buffer overflow
                    b'../../../etc/passwd', # Path traversal
                    b'; cat /etc/passwd',  # Command injection
                    b'\x00' * 8,           # NULL injection
                ]
                data = random.choice(attack_patterns)
                mut_type = 'aux_buffer'
            elif cmd == FUZZ_CMD_TRUNCATE:
                # Truncate attack: Reduce data size
                truncate_size = random.choice([0, 1, 2, 4, 8])
                data = struct.pack('I', truncate_size)
                mut_type = 'truncate'
            elif cmd == FUZZ_CMD_EXTEND:
                # Extend attack: Increase data size to trigger overflow
                extend_size = random.choice([64, 128, 256, 512, 1024])
                data = struct.pack('I', extend_size)
                mut_type = 'extend'
            elif cmd == FUZZ_CMD_LIGHT_MUTATION:
                # Light mutation: Flip only 1-2 bits
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
                mutation_type=mut_type 
            )
            instructions.append(instruction)

        # Limit verification
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            alog(f"Truncating instructions to {FUZZ_MAX_INSTRUCTIONS}", "MUTATOR", "WARN")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions  # This is the content for QEMU, wrapped as FuzzInstruction

    def _generate_io_mutations(self, trace, fork_point: int = None, analyzer: Optional[Any] = None) -> List[FuzzInstruction]:
        """Generate IO return value mutation instructions

        Args:
            trace: Trace object
            fork_point: Fork point syscall index (optional)
            analyzer: Existing TraceAnalyzer instance (optional)

        Returns:
            List of FuzzInstructions
        """
        alog(f"Attempting IO mutation, trace={trace}, fork_point={fork_point}", "MUTATOR")

        # Identify IO syscalls - respect passed analyzer parameter
        effective_analyzer = analyzer if analyzer is not None else getattr(self, 'analyzer', None)
        io_syscalls = self.io_mutator.identify_io_syscalls(trace, analyzer=effective_analyzer)
        alog(f"Found {len(io_syscalls)} IO syscalls", "MUTATOR")

        if not io_syscalls:
            # No IO syscalls, fall back to random mutation
            alog("No IO syscalls found, falling back to random mutation", "MUTATOR", "INFO")
            return self._generate_random_mutations(trace, fork_point)

        # Prioritize IO syscall at fork_point (if specified)
        target_io = None
        if fork_point is not None:
            for io in io_syscalls:
                if io['index'] == fork_point:
                    target_io = io
                    break

        # If no IO syscall found at fork_point, choose one randomly
        if target_io is None:
            target_io = random.choice(io_syscalls)

        # Generate mutation for this IO syscall
        mutations = self.io_mutator.generate_mutations_for_io(
            target_io,
            strategy='buffer_overflow' if target_io['is_input'] else 'boundary'
        )

        # Priority sorting
        mutations = self.io_mutator.prioritize_mutations(mutations)

        # Increase mutation density to test a wider range of values
        num_mutations = random.randint(3, 6)
        selected_mutations = mutations[:num_mutations]

        # Convert to FuzzInstruction
        instructions = []
        for m in selected_mutations:
            # 1. Return value mutation
            data = struct.pack('Q', m.new_return_value)  # New return value

            instruction = FuzzInstruction(
                syscall_index=m.syscall_index,
                cmd=FUZZ_CMD_MUTATE_ARG,  # Temporary use, can define specialized IO_RETURN command later
                arg_index=0xFF,  # Special marker: 0xFF indicates changing return value
                data=data,
                mutation_type='io_return_value'
            )
            instructions.append(instruction)

            alog(f"IO Mutation (retval): {m.description}", "MUTATOR")

            # 2. If buffer_content exists and this is a network-FD syscall, inject buffer
            # Skip buffer injection for file-FD syscalls to avoid false-positive heap corruption
            is_network_fd = self.syscall_network_fd_map.get(m.syscall_index, False)
            if m.buffer_content and is_network_fd:
                # Get buffer argument index (read's second argument is buffer pointer)
                buf_arg_index = 1
                
                # Chance to use attack patterns instead of IOMutator content
                content_to_use = m.buffer_content
                alog(f"WARN: Inside buffer_content. Dict len: {len(self.dictionary)}", "MUTATOR", "WARN")
                with open("/tmp/debug_token.txt", "a") as df:
                    df.write(f"INSIDE BUFFER: Dict len={len(self.dictionary)}\n")
                
                # Chance to use attack patterns instead of IOMutator content
                if random.random() < 0.01: # Reduced from 0.3 to force dictionary
                     patterns = [
                        b'%s%s%s%s', b'A' * 64, b'../../../etc/passwd', 
                        b'; cat /etc/passwd', b'\x00' * 8, 
                        b'CRASH_ME', b'CRASH_ME\n', 
                        b'CRASH_ME\x00', b'CRASH_ME\n\x00',
                        b'A' * 1024, b'A' * 4096,  # Stack overflow
                        b'USER ' + b'A' * 2048 + b'\r\n',
                        b'MKD ' + b'A' * 2048 + b'\r\n'
                     ]
                     content_to_use = random.choice(patterns)
                
                # [NEW] Dictionary Injection - FORCED
                elif self.dictionary: # Removed random check and random.random() < 0.5
                     try:
                         token = random.choice(self.dictionary)
                         alog(f"WARN: Selected dictionary token: {token}", "MUTATOR", "WARN")
                         
                         if random.random() < 0.5:
                             content_to_use = token
                         else:
                             content_to_use = b"A" * 8 + token + b"B" * 8
                         alog(f"Dictionary Mutation: Injected '{token}'", "MUTATOR", "WARN")
                     except Exception as e:
                         alog(f"ERROR: Dictionary mutation failed: {e}", "MUTATOR", "ERROR")
                         import traceback
                         traceback.print_exc()
                         content_to_use = b"A" * 64 # Fallback

                buffer_instruction = FuzzInstruction(
                    syscall_index=m.syscall_index,
                    cmd=FUZZ_CMD_REPLACE_BUFFER,
                    arg_index=buf_arg_index,
                    data=content_to_use[:min(len(content_to_use), 256)]
                )
                instructions.append(buffer_instruction)
                alog(f"IO Mutation (buffer): Fill {len(content_to_use)} bytes", "MUTATOR")



        # Verify instruction count does not exceed limit
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            alog(f"IO mutation generated {len(instructions)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}", "MUTATOR", "WARN")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions

    def _generate_random_mutations(self, trace, fork_point: int = None) -> List[FuzzInstruction]:
        """Generate traditional random mutations (helper method)"""
        # This is the original implementation of the mutate method, extracted as a standalone method
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
                if self.syscall_forbidden_map.get(syscall_index, False):
                    continue

            # Aux Data mutation commands (consistent with mutate method)
            mutation_types = [
                FUZZ_CMD_FLIP_BITS,
                FUZZ_CMD_INTERESTING_VALUES,
                FUZZ_CMD_BOUNDARY_VALUE,
                FUZZ_CMD_REPLACE_BUFFER,
                FUZZ_CMD_MUTATE_FLAGS,
                FUZZ_CMD_MUTATE_AUX_BUFFER,
                FUZZ_CMD_TRUNCATE,
                FUZZ_CMD_EXTEND,
                FUZZ_CMD_LIGHT_MUTATION
            ]
            cmd = random.choice(mutation_types)

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
                # Use attack patterns for buffer replacement too, or random
                if random.random() < 0.5:
                     # Use attack patterns 
                     patterns = [
                        b'%s%s%s%s', b'A' * 64, b'../../../etc/passwd', 
                        b'; cat /etc/passwd', b'\x00' * 8, 
                        b'CRASH_ME', b'CRASH_ME\n',
                        b'A' * 512, b'A' * 1024, b'A' * 4096,  # Stack overflow patterns
                        b'USER ' + b'A' * 2048 + b'\r\n',      # Protocol specific
                        b'MKD ' + b'A' * 2048 + b'\r\n'
                     ]
                     data = random.choice(patterns)
                else:
                     size = random.choice([4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096])
                     data = bytes([random.randint(0, 255) for _ in range(size)])
                mut_type = 'replace_buffer'
            elif cmd == FUZZ_CMD_MUTATE_AUX_BUFFER:
                # Aux Data mutation: Generate attack pattern data
                attack_patterns = [
                    b'%s%s%s%p',           # Format string attack
                    b'A' * 64,             # Buffer overflow
                    b'../../../etc/passwd', # Path traversal
                    b'; cat /etc/passwd',  # Command injection
                    b'\x00' * 8,           # NULL injection
                    b'CRASH_ME',           # Explicit target trigger
                    b'CRASH_ME\n',         # Explicit target trigger (newline)
                    b'CRASH_ME\x00',       # Explicit target trigger (null-terminated)
                    b'CRASH_ME\n\x00',     # Explicit target trigger (newline + null)
                    b'A' * 1024,           # Large buffer
                    b'A' * 4096,           # Very large buffer
                ]
                data = random.choice(attack_patterns)
                mut_type = 'aux_buffer'
            elif cmd == FUZZ_CMD_TRUNCATE:
                truncate_size = random.choice([0, 1, 2, 4, 8])
                data = struct.pack('I', truncate_size)
                mut_type = 'truncate'
            elif cmd == FUZZ_CMD_EXTEND:
                extend_size = random.choice([64, 128, 256, 512, 1024, 2048, 4096, 8192])
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
                mutation_type=mut_type 
            )
            instructions.append(instruction)

        # Verify instruction count does not exceed limit
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            alog(f"Random mutation generated {len(instructions)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}", "MUTATOR", "WARN")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions


class SmartMutator:
    """
    Smart Mutator
    
    Analyzes trace files, filters mutable syscalls, and uses multiple strategies
    to generate smart mutation instructions.
    """
    
    # Class-level cache to avoid redundant parsing of same trace
    _trace_cache = {}  # {trace_file: TraceAnalyzer}
    
    def __init__(self, trace_file, recipe_file=None, target_binary=None, path_finder=None, analyzer=None, word_size=0, endian='auto', dictionary_file=None, arch='auto', auth_boundary=0):
        """
        Initialize SmartMutator

        Args:
            trace_file: Path to trace file
            recipe_file: Path to recipe file (optional, Phase 2)
            target_binary: Path to target binary (for PathFinder CFG analysis)
            path_finder: Existing PathFinder instance (optional, avoids re-initialization)
            analyzer: Existing TraceAnalyzer instance (optional, avoids redundant analysis)
            word_size: Word size (32 or 64, 0 for auto)
            endian: Endianness ('auto', 'little', 'big')
            dictionary_file: Path to external dictionary file (optional)
        """
        self.trace_file = trace_file
        self.word_size = word_size
        self.endian = endian
        self.arch = arch
        # Auth boundary: syscall index after which post-auth business logic begins.
        # Mutations on network-facing syscalls (socket fds) after this index are
        # the primary attack surface — equivalent to an authenticated attacker
        # sending malformed packets. Default=0 means no boundary (legacy behaviour).
        self.auth_boundary = auth_boundary
        
        # Use passed analyzer or cached TraceAnalyzer if available
        if analyzer:
            self.analyzer = analyzer
            if trace_file not in SmartMutator._trace_cache:
                SmartMutator._trace_cache[trace_file] = analyzer
        elif trace_file in SmartMutator._trace_cache:
            alog(f"Using cached analysis results: {trace_file}", "MUTATOR", "DEBUG")
            self.analyzer = SmartMutator._trace_cache[trace_file]
        else:
            # Analyze using repaired TraceAnalyzer
            alog(f"Analyzing trace file: {trace_file}", "MUTATOR", "INFO")
            
            # ✅ BB Trace support
            try:
                from .bb_trace_parser import BBTraceParser, BBEntry
            except ImportError:
                alog("Could not import bb_trace_parser. BB Trace support disabled.", "MUTATOR", "WARN")
            
            # Import TraceAnalyzer
            from .trace_analyzer import TraceAnalyzer
            
            # TraceAnalyzer calls analyze() automatically in __init__
            self.analyzer = TraceAnalyzer(trace_file, word_size=word_size, endian=endian, arch=arch)
            
            # Cache for future use
            SmartMutator._trace_cache[trace_file] = self.analyzer
            
            # 🔥 Performance: Cap trace cache to prevent memory pressure
            if len(SmartMutator._trace_cache) > 10:
                del_key = next(iter(SmartMutator._trace_cache))
                del SmartMutator._trace_cache[del_key]
        
        # Shadow Registry for resource tracking (Phase B)
        from .shadow_registry import ShadowRegistry
        self.shadow_registry = ShadowRegistry()
        
        # Get all pure replay syscalls (those with aux_data)
        pure_syscalls = self.analyzer.get_pure_syscalls()
        
        # Save all syscalls for later use
        self.syscalls = self.analyzer.syscalls
        
        # Convert to Candidate objects (with full metadata)
        self.pure_candidates = [sc for sc in pure_syscalls]
        
        # Get hybrid replay syscalls (without aux_data)
        hybrid_syscalls = self.analyzer.get_hybrid_syscalls()
        self.hybrid_candidates = [sc for sc in hybrid_syscalls]
        
        # FD tracking and environment filtering
        self._perform_fd_tracking()
        
        # These can be removed later
        # These can be removed later
        alog(f"Found {len(self.pure_candidates)} pure replay syscalls:", "MUTATOR", "DEBUG")
        for cand in self.pure_candidates[:10]:  # Only print first 10
            alog(f"  index={cand.index}, name={cand.name}, nr={cand.syscall_nr}", "MUTATOR", "DEBUG")
        if len(self.pure_candidates) > 10:
            alog(f"  ... and {len(self.pure_candidates) - 10} more", "MUTATOR", "DEBUG")
        
        # Lazy filtering, wait for PathFinder ready
        self.mutable_candidates = []
        
        # PathFinder & Recipe drive mode
        self.recipes = []
        self.recipe_mode = False
        self.path_finder = None
        self.target_binary = target_binary

        # PathFinder integration (automatic recipe generation)
        if path_finder:
            self.path_finder = path_finder
            alog(f"Using external PathFinder instance", "MUTATOR", "INFO")
        elif target_binary:
            self._init_pathfinder(trace_file, target_binary)
        else:
            self.path_finder = None

        # Manual recipe file loading
        if recipe_file and os.path.exists(recipe_file):
            self._load_recipes(recipe_file)
            self.recipe_mode = True
            alog(f"Recipe-driven mode enabled (Manual: {len(self.recipes)} recipes)", "MUTATOR", "INFO")

        # Attempt to auto-generate recipes from PathFinder
        auto_recipes = self._generate_automatic_recipes()
        if auto_recipes:
            self.recipes.extend(auto_recipes)
            alog(f"Automatically generated {len(auto_recipes)} recipes (Total: {len(self.recipes)})", "MUTATOR", "INFO")

        # 🔥 Cap recipes to prevent memory growth
        if len(self.recipes) > 200:
            alog(f"⚠️ Too many recipes ({len(self.recipes)}), capping at 200", "MUTATOR", "WARN")
            self.recipes = self.recipes[:200]

        if len(self.recipes) > 0:
            self.recipe_mode = True
            alog(f"Recipe-driven mode enabled (Total: {len(self.recipes)} recipes)", "MUTATOR", "INFO")
        else:
            alog(f"Random mutation mode (No recipes provided or generated)", "MUTATOR", "WARN")
        
        # Now PathFinder initialized, perform candidate filtering
        self.mutable_candidates = self._filter_mutable_candidates()
        
        # Stagnation Detection parameters
        self.last_new_coverage_iter = 0
        self.stagnation_threshold = 1000 
        self.is_stagnant = False 
        self.total_iterations = 0 
        self.last_mutation_type = 'unknown'
        self.use_io_mutation = True # SmartMutator always uses IO mutation
        self.io_mutator = IOReturnValueMutator()
        self.io_mutation_prob = 0.2 # Lower probability for IO mutation in SmartMutator
        
        # Dictionary Support
        self.dictionary = [
            # Command Injection
            b";", b"|", b"&", b"$(id)", b"`id`", b"\n", b"admin", b"root", b"127.0.0.1",
            # Path Traversal
            b"../", b"../../../../etc/passwd", b"..\\", 
            # Format String
            b"%s%s%s%s%s", b"%n%n%n", b"%p%p%p",
            # Shell/Logic
            b"True", b"False", b"yes", b"no", b"allow", b"deny",
            # HTTP/Web
            b"application/x-www-form-urlencoded", b"multipart/form-data", b"text/html"
        ]
        if target_binary:
            self._extract_dictionary_tokens(target_binary)
            
        # Load external dictionary if provided
        if dictionary_file:
            self._load_dictionary(dictionary_file)
            
        alog(f"Stagnation detection enabled (threshold={self.stagnation_threshold} iterations)", "MUTATOR", "INFO")

    def clear(self):
        """Explicitly release resources"""
        self.recipes = []
        self.mutable_candidates = []
        self.syscalls = []
        self.pure_candidates = []
        self.hybrid_candidates = []
        self.dictionary = []
        self.analyzer = None
        self.path_finder = None
        self.shadow_registry = None
        import gc
        gc.collect()

    def _load_dictionary(self, dict_file):
        """Load tokens from external dictionary file"""
        if not os.path.exists(dict_file):
            alog(f"Dictionary file not found: {dict_file}", "MUTATOR", "WARN")
            return
            
        try:
            count = 0
            with open(dict_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Handle quoted strings (e.g. "GET")
                    if line.startswith('"') and line.endswith('"'):
                        token_str = line[1:-1]
                        # Process generic escape sequences
                        token_bytes = token_str.encode('utf-8').decode('unicode_escape').encode('latin1')
                    else:
                        token_bytes = line.encode('utf-8')
                        
                    self.dictionary.append(token_bytes)
                    count += 1
            
            alog(f"Loaded {count} tokens from dictionary: {dict_file}", "MUTATOR", "INFO")
        except Exception as e:
            alog(f"Failed to load dictionary {dict_file}: {e}", "MUTATOR", "ERROR")
    
    def _perform_fd_tracking(self):
        """Build forbidden-fd and network-fd maps, then register syscalls in ShadowRegistry."""
        self.syscall_forbidden_map, self.syscall_network_fd_map = perform_fd_tracking(self.syscalls)
        for sc in self.syscalls:
            self.shadow_registry.register_syscall(sc)
        forbidden_count = sum(1 for v in self.syscall_forbidden_map.values() if v)
        network_count = sum(1 for v in self.syscall_network_fd_map.values() if v)
        alog(f"FD Tracking: {forbidden_count} library-IO protected, "
             f"{network_count} network-socket syscalls identified "
             f"(auth_boundary={self.auth_boundary})", "MUTATOR", "INFO")
    
    def _should_skip_mutation(self, syscall_info, index):
        """
        Determine if mutation for this syscall should be skipped
        
        Args:
            syscall_info: Syscall info object
            index: Index position in trace
        
        Returns:
            bool: True to skip, False to allow mutation
        """
        # Core protection
        # 1. General startup phase protection: First 40 syscalls usually ld.so and libc init
        # Remove hardcoded index < 40 check, use PathFinder smart filtering instead
        # if index < 40:
        #    alog(f"Startup Protection: Skip early init syscall (index={index})", "MUTATOR", "DEBUG")
        #    return True
            
        syscall_name = getattr(syscall_info, 'name', '').lower()
        
        # 2. Identified Forbidden FD protection
        if self.syscall_forbidden_map.get(index, False):
            alog(f"Skip Forbidden IO: {syscall_name} (index={index})", "MUTATOR", "DEBUG")
            return True
        
        # Important IO syscalls never skip (already FD/Startup filtered)
        if syscall_name in IMPORTANT_SYSCALLS:
            return False  # Never skip
        
        # Skip key syscalls during initialization phase (using dynamic threshold)
        # Note: dynamic_threshold will be set by Conductor during first fuzzing
        threshold = getattr(self, 'dynamic_threshold', INIT_PHASE_THRESHOLD)
        if index < threshold:
            if any(init_sc in syscall_name for init_sc in INIT_SYSCALLS):
                alog(f"Skip init syscall: {syscall_name} (index={index}, threshold={threshold})", "MUTATOR", "DEBUG")
                return True
        
        # 1. PathFinder enhanced filtering:
        # If PathFinder available, check if syscall is reachable by target code segment
        if self.path_finder and hasattr(self.path_finder, 'bb_to_syscall'):
            # Check if any target BB maps to this syscall
            is_target_reachable = False
            for bb_addr, sc_idx in self.path_finder.bb_to_syscall.items():
                if sc_idx == index:
                    is_target_reachable = True
                    break
            
            if not is_target_reachable:
                # If syscall is in trace but never called/covered by BB in target range,
                # it's likely called by early loader or libc init code.
                # alog(f"PathFinder Filter: Skip non-target syscall (index={index}, {syscall_name})", "MUTATOR", "DEBUG")
                pass
                return True
        
        return False
    
    def _filter_mutable_candidates(self):
        """
        Filter mutable candidates with hierarchical prioritization.

        Principles:
        1. Exclude high-risk syscalls (FORBIDDEN_MUTATION_SYSCALLS)
        2. Retain safe syscalls beyond just IO
        3. Priority levels: Important > Primary IO > Secondary IO > Others

        Returns:
            list: List of safe mutable syscall candidates
        """
        # Tier 0: Network-fd syscalls AFTER auth_boundary — primary attack surface.
        # These represent attacker-controllable network input in post-auth sessions.
        network_post_auth = []
        important = []    # Important syscalls (must mutate)
        primary_io = []   # Primary IO syscalls (file fd)
        secondary_io = [] # Secondary IO syscalls
        others = []       # Other safe syscalls

        all_candidates = list(self.pure_candidates) + list(self.hybrid_candidates)

        alog(f"Filtering {len(all_candidates)} candidates (Enhanced mode, auth_boundary={self.auth_boundary})...", "MUTATOR", "INFO")

        for candidate in all_candidates:
            syscall_name = candidate.name

            # 1. Skip forbidden syscalls
            if syscall_name in FORBIDDEN_MUTATION_SYSCALLS:
                continue

            # 2. Tier 0: network socket fd + post-auth → highest priority (checked BEFORE
            # _should_skip_mutation to prevent PathFinder from filtering these out).
            # Use > (not >=) because auth_boundary is the accept() index itself;
            # only syscalls AFTER accept() are attacker-controllable post-auth input.
            is_network = self.syscall_network_fd_map.get(candidate.index, False)
            is_post_auth = self.auth_boundary > 0 and candidate.index > self.auth_boundary
            if is_network and is_post_auth:
                network_post_auth.append(candidate)
                continue

            # 2b. Hard exclusion: if auth_boundary is set, non-network syscalls that are
            # at or before auth_boundary are pre-auth (ld.so loading, libc init, TCP setup).
            # Mutating these causes ELF-loader false positives. Exclude unconditionally.
            if self.auth_boundary > 0 and candidate.index <= self.auth_boundary:
                continue

            # 3. Skip initialization-phase syscalls (PathFinder filter etc.)
            if self._should_skip_mutation(candidate, candidate.index):
                continue

            # 4. Remaining priority tiers
            if syscall_name in IMPORTANT_SYSCALLS:
                important.append(candidate)
            elif syscall_name in PRIMARY_IO_SYSCALLS:
                primary_io.append(candidate)
            elif syscall_name in SECONDARY_IO_SYSCALLS:
                secondary_io.append(candidate)
            else:
                others.append(candidate)

        alog(f"Candidate tiers — network_post_auth={len(network_post_auth)}, "
             f"important={len(important)}, primary_io={len(primary_io)}, "
             f"secondary_io={len(secondary_io)}, others={len(others)}", "MUTATOR", "INFO")

        # Final consolidation: network_post_auth gets top billing
        mutable = network_post_auth + important + primary_io + secondary_io + others

        # 🔥 Cap candidates to prevent massive memory footprint on large traces
        if len(mutable) > 1000:
            alog(f"⚠️ Too many mutable candidates ({len(mutable)}), capping at 1000", "MUTATOR", "WARN")
            mutable = mutable[:1000]

        alog(f"Mutable syscall candidates: {len(mutable)}", "MUTATOR", "INFO")
        if not mutable:
            alog(f"WARNING: No candidates found for mutation!", "MUTATOR", "WARN")

        return mutable

    def _init_pathfinder(self, trace_file, target_binary):
        """
        Initialize PathFinder for CFG analysis
        """
        try:
            # Import PathFinder
            # Remove sys.path manipulation, rely on package structure
            from .dual_level_path_finder import DualLevelPathFinder as PathFinder
            # Config is part of DB or params, maybe unnecessary or can use dummy
            # DualLevel uses different config, let's omit Config class import as it's not strictly needed if we pass dict or it handles it.
            # actually DualLevelPathFinder constructor signature might be different. 
            # Original: PathFinder(binary, config)
            # DualLevel: DualLevelPathFinder(binary, config_dict/obj)


            # Create config (conservative settings)
            config = {
                "verbose": False,
                "timeout": 30,  # 30s timeout
                "max_cfg_nodes": 5000,  # Limit nodes
                "graceful_disable": True,  # Disable on error instead of exception
                "enable_auto_fast_mode": True  # Auto simplify mode
            }

            # Initialize PathFinder
            self.path_finder = PathFinder(target_binary, config)
            alog(f"PathFinder initialized", "MUTATOR", "INFO")

            # Build dynamic CFG from trace
            if self.path_finder.build_from_trace(trace_file):
                alog(f"PathFinder dynamic CFG built", "MUTATOR", "INFO")
            else:
                alog(f"PathFinder dynamic CFG build failed", "MUTATOR", "WARN")

        except Exception as e:
            alog(f"PathFinder initialization failed: {e}", "MUTATOR", "ERROR")
            self.path_finder = None

    def _generate_automatic_recipes(self):
        """
        Auto-generate recipes from PathFinder
        """
        if not self.path_finder or not self.path_finder.is_available():
            return []

        try:
            # Analyze uncovered branches (simplified version, based on dynamic CFG)
            uncovered_branches = self._find_uncovered_branches()
            if not uncovered_branches:
                alog(f"PathFinder found no uncovered branches", "MUTATOR", "INFO")
                return []

            alog(f"PathFinder found {len(uncovered_branches)} uncovered branches", "MUTATOR", "INFO")

            # Generate recipes (now list of MutationRecipe objects)
            recipes = self.path_finder.generate_recipes(uncovered_branches, max_recipes=10)

            # Convert to compatible dictionary format (until we fully migrate RecipePool)
            auto_recipes = []
            for i, recipe in enumerate(recipes):
                if isinstance(recipe, MutationRecipe):
                    r_dict = recipe.to_dict()
                else:
                    r_dict = recipe

                # Ensure id field
                if 'id' not in r_dict or not r_dict['id']:
                    r_dict['id'] = f"pathfinder_auto_{i}_{int(time.time())}"
                
                auto_recipes.append(r_dict)

            return auto_recipes

        except Exception as e:
            alog(f"PathFinder recipe generation failed: {e}", "MUTATOR", "ERROR")
            return []

    def _find_uncovered_branches(self):
        """
        Find uncovered branches based on dynamic CFG (simplified implementation)
        """
        if not self.path_finder or not hasattr(self.path_finder, 'dynamic_edges'):
            # For DualLevelPathFinder, we generate branches based on coverage at runtime
            return []

        uncovered = []

        # Simplified logic: Iterate through all dynamic nodes, looking for nodes with single outgoing edge
        # These nodes might have unexplored branches
        for node_id, edges in self.path_finder.dynamic_edges.items():
            if len(edges) == 1:  # Only one outgoing edge, likely another branch unexplored
                edge = list(edges)[0]
                
                # Construct hypothetical uncovered branch
                uncovered_branch = {
                    'from': self.path_finder.dynamic_nodes.get(node_id, node_id),
                    'to': self.path_finder.dynamic_nodes.get(edge, edge),
                    'id': f"uncovered_{node_id}",
                    'type': 'conditional'
                }
                uncovered.append(uncovered_branch)
        
        return uncovered

    def _extract_dictionary_tokens(self, target_binary):
        """Extract dictionary tokens from target binary using strings"""
        if not target_binary or not os.path.exists(target_binary):
            alog("Target binary not provided or not found, skipping dictionary extraction", "MUTATOR", "WARN")
            return

        try:
            alog(f"Extracting dictionary tokens from {target_binary}...", "MUTATOR", "INFO")
            result = subprocess.run(['strings', target_binary], capture_output=True, text=True, check=True)
            strings = result.stdout.splitlines()

            count = 0
            for s in strings:
                s = s.strip()
                # Optimized range for keywords and identifiers
                if 4 <= len(s) <= 32:
                    try:
                        token = s.encode('utf-8')
                        if token not in self.dictionary:
                            self.dictionary.append(token)
                            count += 1
                    except:
                        pass
            
            # Common Magic Bytes and Protocol Keywords
            common_magics = [
                # HTTP / Web
                b"HTTP/1.1", b"GET", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS",
                b"Host:", b"User-Agent:", b"Content-Length:", b"Content-Type:", b"Connection:",
                b"Accept-Encoding:", b"Authorization: Basic ", b"Cookie: ",
                
                # Protocol Specifics (FTP, SMTP, etc)
                b"USER ", b"PASS ", b"PORT ", b"RETR ", b"STOR ", b"HELO ", b"MAIL FROM:", b"RCPT TO:",
                
                # Device / Admin
                b"admin", b"password", b"root", b"123456", b"guest", b"1234",
                b"soap:Envelope", b"urn:schemas", 
                
                # UPnP / SSDP
                b"M-SEARCH", b"NOTIFY", b"uuid:", b"serviceType", b"deviceType",
                b"ST: ", b"MX: ", b"MAN: \"ssdp:discover\"",
                
                # Security / Shell
                b"/bin/sh", b"; cat /etc/passwd", b"id", b"whoami", b"&& sleep 10",
                b"`id`", b"$(id)", b"| id",
                
                # Format Strings
                b"%s%s%s%s", b"%x%x%x%x", b"%p%p%p%p", b"%n%n%n%n"
            ]
            
            for m in common_magics:
                if m not in self.dictionary:
                    self.dictionary.append(m)
                    count += 1

            alog(f"Extracted dictionary: {count} new tokens. Total size: {len(self.dictionary)}", "MUTATOR", "INFO")
            
            # Cap dictionary size but keep it representative
            if len(self.dictionary) > 1000:
                 self.dictionary = random.sample(self.dictionary, 1000)
                 alog("Dictionary capped at 1000 items", "MUTATOR", "INFO")

        except Exception as e:
             alog(f"Failed to extract dictionary: {e}", "MUTATOR", "ERROR")



    def _load_recipes(self, recipe_file):
        """
        Load recipe from JSON file
        
        Args:
            recipe_file: Path to recipe file (recipes.json)
        """
        try:
            with open(recipe_file, 'r') as f:
                data = json.load(f)
            
            self.recipes = data.get('recipes', [])
            alog(f"Loaded {len(self.recipes)} recipes from {recipe_file}", "MUTATOR", "INFO")
            
            # Print first few recipes (debug)
            for i, recipe in enumerate(self.recipes[:5]):
                alog(f"  Recipe {i}: {recipe['source_branch']} -> {recipe['target_branch']}, "
                      f"syscall_idx={recipe['syscall_index']}, type={recipe['mutation_type']}", "MUTATOR", "DEBUG")
            
        except Exception as e:
            alog(f"Failed to load recipes: {e}", "MUTATOR", "ERROR")
            self.recipes = []
    
    def _recipe_to_instruction(self, recipe):
        """
        Convert recipe to FuzzInstruction
        
        Args:
            recipe: Recipe dictionary (from recipes.json)
        
        Returns:
            FuzzInstruction or None
        """
        try:
            syscall_index = recipe['syscall_index']
            mutation_type = recipe['mutation_type']
            offset = recipe.get('offset', 0)
            size = recipe.get('size', 4)
            data_template = recipe.get('data_template', 'RANDOM')
            
            # 🔥 Phase 5 Check: Forbidden Syscall Enforcement
            from .constants import FORBIDDEN_MUTATION_SYSCALLS
            all_syscalls = getattr(self.analyzer, 'syscalls', [])
            target_sc_name = "unknown"
            if 0 <= syscall_index < len(all_syscalls):
                target_sc_name = all_syscalls[syscall_index].name
            
            if target_sc_name in FORBIDDEN_MUTATION_SYSCALLS:
                alog(f"Recipe-Safety: Skipping mutation for forbidden syscall {target_sc_name} at index {syscall_index}", "MUTATOR", "WARN")
                return None
            
            # Generate actual data based on data_template
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
                # Hex value
                val = int(data_template, 16)
                mutation_data = struct.pack('Q', val)[:size]
            else:
                # Default random
                mutation_data = bytes([random.randint(0, 255) for _ in range(size)])
            
            # Select command based on mutation_type
            if mutation_type == 'buffer_overwrite':
                # Exact buffer overwrite at specified offset
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
                # Default to buffer replacement
                return FuzzInstruction(syscall_index, FUZZ_CMD_REPLACE_BUFFER, 1, mutation_data, 0, size)
                
        except Exception as e:
            print(f"[Mutator] Failed to convert recipe to instruction: {e}")
            return None
    
    def _build_from_recipes(self, iteration):
        """
        Generate Fuzz instructions from recipe

        Args:
            iteration: Current iteration count

        Returns:
            list: List of FuzzInstructions
        """
        instrs = []
        
        # Select recipe (cyclic use)
        recipe_idx = iteration % len(self.recipes)
        recipe = self.recipes[recipe_idx]
        
        # Record recipe used (for feedback)
        self.last_recipe_used = recipe
        
        print(f"[Mutator] Using recipe {recipe_idx}/{len(self.recipes)}: "
              f"{recipe['source_branch']} -> {recipe['target_branch']}")
        
        # Convert to instruction
        instr = self._recipe_to_instruction(recipe)
        if instr:
            instrs.append(instr)
            print(f"[Mutator]   Generated instruction: syscall_idx={recipe['syscall_index']}, "
                  f"cmd={recipe['mutation_type']}")
        
        return instrs
    
    def update_stagnation_status(self, iteration: int, has_new_coverage: bool):
        """
        Update stagnation detection status

        Args:
            iteration: Current iteration count
            has_new_coverage: Whether new coverage was found in this iteration
        """
        self.total_iterations = iteration
        
        if has_new_coverage:
            # New coverage found, reset stagnation count
            self.last_new_coverage_iter = iteration
            was_stagnant = self.is_stagnant
            self.is_stagnant = False
            
            if was_stagnant:
                print(f"[Mutator] Recovered from stagnation at iteration {iteration}!")
        else:
            # Check for stagnation
            stagnation_duration = iteration - self.last_new_coverage_iter
            
            if stagnation_duration >= self.stagnation_threshold:
                if not self.is_stagnant:
                    self.is_stagnant = True
                    print(f"[Mutator] Stagnation detected at iteration {iteration}!")
                    print(f"[Mutator] Switching to aggressive mutation mode...")
    
    def _select_strategy(self):
        """
        Choose mutation strategy with balanced probability
        
        New design principles:
        1. Balance discovery capability for various vulnerability types
        2. Avoid excessive bias towards a single vulnerability type
        3. Support diversified mutation patterns
        
        Returns:
            int: Strategy type (0-10)
        """
        if self.is_stagnant:
            # Stagnation mode: Aggressive strategy distribution
            strategy_weights = [
                8,   # 0: FLIP_BITS
                15,  # 1: INTERESTING_VALUES
                12,  # 2: TRUNCATE
                20,  # 3: EXTEND
                5,   # 4: LIGHT_MUTATION
                10,  # 5: MUTATE_AUX_BUFFER
                8,   # 6: REPLACE_BUFFER (small)
                12,  # 7: REPLACE_BUFFER (large)
                12,  # 8: BOUNDARY_VALUE
                10,  # 9: MUTATE_FLAGS
                8,   # 10: OVERWRITE_AT_OFFSET
            ]
        else:
            # Regular mode: Balanced strategy distribution
            strategy_weights = [
                12,  # 0: FLIP_BITS
                12,  # 1: INTERESTING_VALUES
                10,  # 2: TRUNCATE
                14,  # 3: EXTEND
                8,   # 4: LIGHT_MUTATION
                9,   # 5: MUTATE_AUX_BUFFER
                9,   # 6: REPLACE_BUFFER (small)
                10,  # 7: REPLACE_BUFFER (large)
                10,  # 8: BOUNDARY_VALUE
                9,   # 9: MUTATE_FLAGS
                7,   # 10: OVERWRITE_AT_OFFSET
            ]

        return random.choices(range(11), weights=strategy_weights)[0]
    
    def _generate_http_request(self, url_path: bytes, method: bytes = b'GET',
                               auth_header: bytes = b'', extra_headers: bytes = b'',
                               host: bytes = b'127.0.0.1', body: bytes = b'') -> bytes:
        """Generate a syntactically valid HTTP/1.1 request with the given path."""
        request = method + b' ' + url_path + b' HTTP/1.1\r\n'
        request += b'Host: ' + host + b'\r\n'
        if auth_header:
            request += auth_header
        if extra_headers:
            request += extra_headers
        if body:
            request += b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
        request += b'\r\n'
        if body:
            request += body
        return request

    def _load_original_buffer(self, syscall_index: int) -> bytes:
        """Try to load original aux_data buffer from trace file (raw binary scan)."""
        try:
            trace_file = getattr(self.analyzer, 'trace_file', None)
            if not trace_file:
                return b''
            with open(trace_file, 'rb') as f:
                data = f.read()
            # Find HTTP request patterns in trace binary
            for pattern in (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD '):
                idx = data.find(pattern)
                if idx >= 0:
                    # Extract up to 512 bytes, stop at double CRLF
                    chunk = data[idx:idx+512]
                    end = chunk.find(b'\r\n\r\n')
                    if end >= 0:
                        return chunk[:end+4]
            return b''
        except Exception:
            return b''

    def _generate_network_read_mutation(self, target_candidate, iteration: int) -> 'FuzzInstruction':
        """
        Generate HTTP-structure-aware mutation for network read syscalls.

        KEY CONSTRAINT for RR-Fuzz: Keep the URL path UNCHANGED to avoid replay divergence
        (different URL → different syscall sequence → divergence → early exit → no coverage).
        Instead inject attack payloads in:
        - URL query parameters (same path, different params)
        - Header values (Authorization, User-Agent, Referer, etc.)
        - Safe in-path injections that don't change file access patterns

        Returns a FUZZ_CMD_MUTATE_AUX_BUFFER instruction with a complete HTTP request.
        """
        index = target_candidate.index

        # Load and cache original HTTP request from trace
        if not hasattr(self, '_cached_orig_request'):
            orig = self._load_original_buffer(index)
            self._cached_orig_request = orig
            # Parse original URL path from request line
            orig_url = b'/'
            orig_method = b'GET'
            auth_line = b''
            host_line = b''
            if orig:
                lines = orig.split(b'\r\n')
                if lines:
                    parts = lines[0].split(b' ')
                    if len(parts) >= 2:
                        orig_method = parts[0]
                        orig_url = parts[1]
                for line in lines[1:]:
                    if line.lower().startswith(b'authorization:'):
                        auth_line = line + b'\r\n'
                    elif line.lower().startswith(b'host:'):
                        host_line = line + b'\r\n'
            self._cached_orig_url = orig_url
            self._cached_orig_method = orig_method
            self._cached_auth_header = auth_line
            self._cached_host_header = host_line

        orig_url = self._cached_orig_url        # e.g. b'/'
        orig_method = self._cached_orig_method  # e.g. b'GET'
        auth_header = self._cached_auth_header  # e.g. b'Authorization: Basic ...\r\n'
        host_header = self._cached_host_header  # e.g. b'Host: 127.0.0.1:8093\r\n'

        # Attack payloads that go INTO safe injection points (not changing URL path)
        # These inject into query params, header values, etc.
        attack_payloads = [
            b'%s%s%s%n',
            b'%p%p%p%p',
            b'A' * 64,
            b'A' * 256,
            b'A' * 512,
            b"' OR '1'='1",
            b'; cat /etc/passwd',
            b'`cat /etc/passwd`',
            b'../../../etc/passwd',
            b'\x00' * 16,
            bytes(range(32, 128)) * 2,   # printable ASCII range
        ]

        payload = random.choice(attack_payloads)

        # Choose injection strategy (avoid changing the URL to prevent divergence)
        strategy = random.randint(0, 5)
        extra_headers = b''

        if strategy == 0:
            # Query parameter injection (keep same path)
            url = orig_url + b'?name=' + payload[:64]
        elif strategy == 1:
            # User-Agent injection
            url = orig_url
            extra_headers = b'User-Agent: ' + payload[:128] + b'\r\n'
        elif strategy == 2:
            # Referer injection
            url = orig_url
            extra_headers = b'Referer: http://localhost/' + payload[:64] + b'\r\n'
        elif strategy == 3:
            # Cookie injection
            url = orig_url
            extra_headers = b'Cookie: session=' + payload[:64] + b'\r\n'
        elif strategy == 4:
            # X-Forwarded-For injection
            url = orig_url
            extra_headers = b'X-Forwarded-For: ' + payload[:32] + b'\r\n'
        else:
            # Keep original URL with no extra headers (baseline replay check)
            url = orig_url

        data = self._generate_http_request(
            url, method=orig_method,
            auth_header=auth_header,
            extra_headers=extra_headers
        )
        # Bug A fix: EXTEND aux buffer first so MUTATE_AUX_BUFFER is not truncated.
        # extend_by=1024 → new aux->size = min(orig_size+1024, 1024) = 1024 (C-side caps at 1024).
        # MUTATE_AUX_BUFFER then copies min(len(data), 1024) bytes into the enlarged buffer.
        extend_instr = FuzzInstruction(index, FUZZ_CMD_EXTEND, 1,
                                       struct.pack('I', 1024),
                                       mutation_type='http_extend')
        mutate_instr = FuzzInstruction(index, FUZZ_CMD_MUTATE_AUX_BUFFER, 1, data,
                                       mutation_type='http_request')
        return [extend_instr, mutate_instr]

    def _generate_file_fd_retval_mutation(self, target_candidate) -> 'FuzzInstruction':
        """
        File-fd read syscalls: simulate errno or early EOF only.

        Rationale: attackers cannot control the contents of config files, NVRAM,
        TLS certificates, or any file-backed FD on a real embedded device.
        Buffer-replacement mutations on these syscalls create impossible program
        states that generate false-positive crashes (verified: E1200 "combined-state"
        crashes require simultaneous socket + file-fd mutation — unreachable in practice).

        Only retval-level faults are within the attacker threat model for file fds.
        """
        index = target_candidate.index
        # Plausible errno values for read() failures on a real filesystem
        error_retvals = [
            -2,   # ENOENT — file disappeared
            -5,   # EIO   — I/O error (flash/NFS fault)
            -13,  # EACCES — permission denied
            -11,  # EAGAIN — would block (non-blocking fd)
            0,    # EOF   — empty file or end-of-file
            1,    # short read (1 byte returned)
            4,    # short read (4 bytes returned)
        ]
        val = random.choice(error_retvals)
        data = struct.pack('q', val)
        return FuzzInstruction(index, FUZZ_CMD_MUTATE_ARG, 0xFF, data,
                               mutation_type='file_fd_retval')

    def _generate_advanced_instruction(self, target_candidate, strategy_type, iteration):
        """
        Generate advanced mutation instruction (fully utilize 11 C-side mutation commands)
        """
        index = target_candidate.index
        instr = None

        sc_name_lower = target_candidate.name.lower()
        is_read_like = sc_name_lower in ('read', 'recv', 'recvfrom', 'recvmsg', 'pread64', 'readv')
        # Stat/open/lseek on file fds also carry no attacker-controlled data
        is_file_meta = sc_name_lower in ('fstat', 'fstat64', 'stat', 'stat64', 'lstat', 'lstat64',
                                          'open', 'openat', 'creat', 'lseek', 'llseek', '_llseek')
        is_network_fd = self.syscall_network_fd_map.get(target_candidate.index, False)

        # File-fd I/O: only simulate retval errors — never inject buffer content.
        # Attacker threat model: the attacker controls only data arriving over a network
        # socket (recv/read on socket fds). Config files, NVRAM, TLS certs, and any
        # file-backed fd on the device are NOT attacker-controlled.
        # Buffer mutations on these syscalls create impossible program states and generate
        # combined-state false positives (verified: E1200 36 crashes → 0 network-exploitable).
        if (is_read_like or is_file_meta) and not is_network_fd:
            return [self._generate_file_fd_retval_mutation(target_candidate)]

        # For network reads, use HTTP-structure-aware mutations 60% of the time
        is_network_read = is_read_like and is_network_fd
        if is_network_read and random.random() < 0.6:
            # Returns [extend_instr, mutate_instr] (Bug A fix)
            return self._generate_network_read_mutation(target_candidate, iteration)
        
        # Select mutation command based on strategy type
        if strategy_type == 0:
            # FLIP_BITS
            num_flips = random.randint(1, 8)
            data = struct.pack('I', num_flips)
            instr = FuzzInstruction(index, FUZZ_CMD_FLIP_BITS, 1, data, mutation_type='bitflip')
        
        elif strategy_type == 1:
            # INTERESTING_VALUES
            syscall_name = target_candidate.name.lower()
            if 'read' in syscall_name or 'recv' in syscall_name:
                pattern_type = random.randint(0, 7)
                data = struct.pack('B', pattern_type)
                instr = FuzzInstruction(index, FUZZ_CMD_INTERESTING_VALUES, 1, data, mutation_type='vuln_pattern')
            else:
                boundary_values = [0, 1, -1, 0xFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF]
                value = random.choice(boundary_values)
                data = struct.pack('Q', value & 0xFFFFFFFFFFFFFFFF)
                instr = FuzzInstruction(index, FUZZ_CMD_INTERESTING_VALUES, 1, data, mutation_type='interesting_value')
        
        elif strategy_type == 2:
            # TRUNCATE
            truncate_to = random.randint(0, 8)
            data = struct.pack('I', truncate_to)
            instr = FuzzInstruction(index, FUZZ_CMD_TRUNCATE, 1, data, mutation_type='truncate')
        
        elif strategy_type == 3:
            # EXTEND
            extend_by = random.choice([1, 4, 16, 64, 256, 1024])
            data = struct.pack('I', extend_by)
            instr = FuzzInstruction(index, FUZZ_CMD_EXTEND, 1, data, mutation_type='extend')
        
        elif strategy_type == 4:
            # LIGHT_MUTATION
            num_flips = random.randint(1, 2)
            data = struct.pack('I', num_flips)
            instr = FuzzInstruction(index, FUZZ_CMD_LIGHT_MUTATION, 1, data, mutation_type='light_mutation')
        
        elif strategy_type == 5:
            # MUTATE_AUX_BUFFER
            # 🔥 2026-01-22: Dictionary Injection support for Aux Buffers
            if self.dictionary and random.random() < 0.4:
                data = random.choice(self.dictionary)
                # cmd remains same, C-side will replace content with this data
                instr = FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, data, mutation_type='dictionary_aux')
            else:
                num_changes = random.randint(1, 4)
                data = struct.pack('I', num_changes)
                instr = FuzzInstruction(index, FUZZ_CMD_MUTATE_AUX_BUFFER, 1, data, mutation_type='aux_buffer')
        
        elif strategy_type == 6:
            # REPLACE_BUFFER (small)
            # 🔥 2026-01-22: Use dictionary tokens if available
            if self.dictionary and random.random() < 0.6:
                data = random.choice(self.dictionary)
                instr = FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, data, mutation_type='dictionary_token')
            else:
                size = random.choice([4, 8, 16, 32])
                data = bytes([random.randint(0, 255) for _ in range(size)])
                instr = FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, data, mutation_type='replace_buffer')
        
        elif strategy_type == 7:
            # REPLACE_BUFFER (large)
            # 🔥 2026-01-22: Inject multiple tokens or large patterns
            if self.dictionary and random.random() < 0.3:
                tokens = random.sample(self.dictionary, min(3, len(self.dictionary)))
                data = b"".join(tokens)
                instr = FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, data, mutation_type='dictionary_multi')
            else:
                size = random.choice([128, 512, 1024])
                pattern = random.choice([b'A', b'\x00', b'\xFF'])
                data = pattern * size
                instr = FuzzInstruction(index, FUZZ_CMD_REPLACE_BUFFER, 1, data, mutation_type='replace_buffer_large')
            
        elif strategy_type == 8:
            # BOUNDARY_VALUE
            value = random.choice([0, -1, 0x7FFFFFFF, 0xFFFFFFFF, 1024, 4096])
            data = struct.pack('q', value)
            instr = FuzzInstruction(index, FUZZ_CMD_BOUNDARY_VALUE, 1, data, mutation_type='boundary_value')

        elif strategy_type == 9:
            # MUTATE_FLAGS
            data = struct.pack('B', random.choice([1, 4]))
            instr = FuzzInstruction(index, FUZZ_CMD_MUTATE_FLAGS, 0, data, mutation_type='flags')

        elif strategy_type == 10:
            # OVERWRITE_AT_OFFSET
            offset = random.randint(0, 16)
            val = random.randint(0, 255)
            data = struct.pack('BB', offset, val)
            instr = FuzzInstruction(index, FUZZ_CMD_OVERWRITE_AT_OFFSET, 1, data, mutation_type='overwrite_offset')
            
        # 🔥 Phase B: Resource-Aware Rails Correction
        if instr and target_candidate.uses_fd:
            if instr.cmd in [FUZZ_CMD_BOUNDARY_VALUE, FUZZ_CMD_INTERESTING_VALUES] and instr.arg_index == 0:
                valid_fd = self.shadow_registry.get_random_valid_fd()
                instr.data = struct.pack('Q', valid_fd & 0xFFFFFFFFFFFFFFFF)

        return [instr] if instr else []
    
    def _generate_io_mutations(self, trace, fork_point: int = None, analyzer: Optional[Any] = None) -> List[FuzzInstruction]:
        """Generate IO return value mutation instructions for SmartMutator

        Args:
            trace: Trace object
            fork_point: Fork point syscall index (optional)
            analyzer: Existing TraceAnalyzer instance (optional)

        Returns:
            List of FuzzInstructions
        """
        alog(f"SmartMutator attempting IO mutation, trace={trace}, fork_point={fork_point}", "MUTATOR")

        # Identify IO syscalls using the SmartMutator's analyzer
        io_syscalls = self.io_mutator.identify_io_syscalls(trace, analyzer=self.analyzer)
        alog(f"SmartMutator found {len(io_syscalls)} IO syscalls", "MUTATOR")

        if not io_syscalls:
            alog("SmartMutator: No IO syscalls found, falling back to smart random mutation", "MUTATOR", "INFO")
            return self.build_fuzz_instructions(getattr(trace.metadata, 'exec_count', 0), fork_point=fork_point)

        # Prioritize IO syscall at fork_point (if specified)
        target_io = None
        if fork_point is not None:
            for io in io_syscalls:
                if io['index'] == fork_point:
                    target_io = io
                    break

        # If no IO syscall found at fork_point, choose one randomly
        if target_io is None:
            target_io = random.choice(io_syscalls)

        # Generate mutation for this IO syscall
        mutations = self.io_mutator.generate_mutations_for_io(
            target_io,
            strategy='buffer_overflow' if target_io['is_input'] else 'boundary'
        )

        # Priority sorting
        mutations = self.io_mutator.prioritize_mutations(mutations)

        # Increase mutation density to test a wider range of values
        num_mutations = random.randint(3, 6)
        selected_mutations = mutations[:num_mutations]

        # Convert to FuzzInstruction
        instructions = []
        for m in selected_mutations:
            # 1. Return value mutation
            data = struct.pack('Q', m.new_return_value)  # New return value

            instruction = FuzzInstruction(
                syscall_index=m.syscall_index,
                cmd=FUZZ_CMD_MUTATE_ARG,  # Temporary use, can define specialized IO_RETURN command later
                arg_index=0xFF,  # Special marker: 0xFF indicates changing return value
                data=data,
                mutation_type='io_return_value'
            )
            instructions.append(instruction)

            alog(f"SmartMutator IO Mutation (retval): {m.description}", "MUTATOR")

            # 2. If buffer_content exists, also generate REPLACE_BUFFER instruction.
            # Skip buffer injection for file-fd syscalls — the attacker cannot control
            # file contents on a real device (config, NVRAM, certs). Injecting file
            # buffer content creates combined-state false positives (verified on E1200).
            _is_file_fd_io = not self.syscall_network_fd_map.get(m.syscall_index, False)
            if m.buffer_content and not _is_file_fd_io:
                # Get buffer argument index (read's second argument is buffer pointer)
                buf_arg_index = 1
                
                # Chance to use attack patterns instead of IOMutator content
                content_to_use = m.buffer_content
                # [NEW] Dictionary Injection
                if random.random() < 0.3:
                     patterns = [
                        b'%s%s%s%s', b'A' * 64, b'../../../etc/passwd', 
                        b'; cat /etc/passwd', b'\x00' * 8, 
                        b'CRASH_ME', b'CRASH_ME\n', 
                        b'CRASH_ME\x00', b'CRASH_ME\n\x00'
                     ]
                     content_to_use = random.choice(patterns)
                elif self.dictionary and random.random() < 0.5:
                     try:
                         token = random.choice(self.dictionary)
                         if random.random() < 0.5:
                             content_to_use = token
                         else:
                             content_to_use = b"A" * 8 + token + b"B" * 8
                         alog(f"Dictionary Mutation: Injected '{token}'", "MUTATOR")
                     except Exception:
                         pass

                buffer_instruction = FuzzInstruction(
                    syscall_index=m.syscall_index,
                    cmd=FUZZ_CMD_REPLACE_BUFFER,
                    arg_index=buf_arg_index,
                    data=content_to_use[:min(len(content_to_use), 256)]
                )
                instructions.append(buffer_instruction)
                alog(f"SmartMutator IO Mutation (buffer): Fill {len(content_to_use)} bytes", "MUTATOR")

        # Verify instruction count does not exceed limit
        if len(instructions) > FUZZ_MAX_INSTRUCTIONS:
            alog(f"SmartMutator IO mutation generated {len(instructions)} instructions, truncating to {FUZZ_MAX_INSTRUCTIONS}", "MUTATOR", "WARN")
            instructions = instructions[:FUZZ_MAX_INSTRUCTIONS]

        return instructions

    def mutate(self, trace, fork_point: int = None, analyzer: Optional[Any] = None) -> List['FuzzInstruction']:
        """
        Smart mutation strategy: Systematic + Recipe-driven
        Uses shared analyzer if available.
        """
        # Phase B: Sync ShadowRegistry to fork_point to have accurate resource state
        if fork_point is not None:
            self.shadow_registry.sync_to_index(self.syscalls, fork_point)
            
        # Prioritize IO return value mutation if enabled (Layer 1.5)
        if self.use_io_mutation and random.random() < self.io_mutation_prob:
            return self._generate_io_mutations(trace, fork_point, analyzer=self.analyzer)
            
        iteration = getattr(trace.metadata, 'exec_count', 0) if hasattr(trace, 'metadata') else 0
        return self.build_fuzz_instructions(iteration, fork_point=fork_point)
    
    def build_fuzz_instructions(self, iteration: int, fork_point: int = None):
        """
        Construct Fuzz instructions
        
        Adaptive strategy based on stagnation and iteration count.
        Uses enhanced set of 11 mutation commands including:
        FLIP_BITS, INTERESTING_VALUES, TRUNCATE, EXTEND, LIGHT_MUTATION,
        MUTATE_AUX_BUFFER, REPLACE_BUFFER, BOUNDARY_VALUE, MUTATE_FLAGS,
        OVERWRITE_AT_OFFSET.
        
        Args:
            iteration: Current iteration count
            fork_point: Syscall index of fork point (optional)
        
        Returns:
            list: List of FuzzInstructions
        """
        instrs = []

        # Recipe-driven mode selection
        if self.recipe_mode and self.recipes:
            # import random  <-- REMOVED

            
            # Adjust recipe probability based on iteration count to balance directed vs systematic fuzzing

            # Adjust recipe probability based on iteration count
            if iteration < 1000:
                recipe_probability = 0.7  # 70% use recipe in early phase
            elif iteration < 5000:
                recipe_probability = 0.5  # 50% use recipe in mid phase
            else:
                recipe_probability = 0.3  # 30% use recipe in late phase
            
            # Further reduce recipe usage when stagnant (increase exploration)
            if self.is_stagnant:
                recipe_probability *= 0.6  # Reduce recipe usage when stagnant

            if random.random() < recipe_probability:
                self.last_mutation_type = 'recipe'
                return self._build_from_recipes(iteration)
            else:
                # Fall through to systematic exploration
                print(f"[Mutator] Skipping recipe, using systematic exploration (iteration={iteration}, prob={recipe_probability:.1%})")

        # ━━━━ If no recipe or recipe probability miss, use systematic exploration ━━━━

        # ━━━━ Enhanced: Random Mutation Mode ━━━━
        self.last_mutation_type = 'smart_random'

        if not self.mutable_candidates:
            print("[Mutator] WARNING: No mutable candidates found!")
            return []

        # ━━━━ Havoc Mode: Stacking Multiple Mutations ━━━━
        # 10% probability usually, 50% if stagnant
        havoc_prob = 0.5 if self.is_stagnant else 0.1
        if random.random() < havoc_prob:
            num_stacked = random.randint(2, 8)
            print(f"[Mutator] ⚡ Havoc Mode Triggered! Stacking {num_stacked} mutations")
            
            # Select targets (can be one or multiple)
            valid_candidates = [c for c in self.mutable_candidates if fork_point is None or c.index >= fork_point]
            if not valid_candidates: valid_candidates = self.mutable_candidates
            
            stacked_instrs = []
            for _ in range(num_stacked):
                target = random.choice(valid_candidates)
                strategy = self._select_strategy()
                stacked_instrs.extend(self._generate_advanced_instruction(target, strategy, iteration))
            
            self.last_mutation_type = 'havoc'
            return stacked_instrs[:FUZZ_MAX_INSTRUCTIONS]
        
        num_candidates = len(self.mutable_candidates)
        
        # Determine mutation intensity based on stagnation status
        if self.is_stagnant:
            # Aggressive mode: High mutation count
            if num_candidates < 5:
                num_mutations = min(4, max(3, num_candidates))
            elif num_candidates < 10:
                num_mutations = min(7, max(5, num_candidates))
            else:
                num_mutations = min(15, max(8, num_candidates // 2))
            
            stagnation_duration = iteration - self.last_new_coverage_iter
            print(f"[Mutator] Stagnant mode: Mutating {num_mutations} syscalls (duration={stagnation_duration})")
        else:
            # Regular mode: Moderate mutation count
            if num_candidates < 5:
                num_mutations = min(3, max(2, num_candidates))
            elif num_candidates < 10:
                num_mutations = min(5, max(3, num_candidates))
            else:
                num_mutations = min(8, max(5, num_candidates // 3))
        
        # P2: Filter candidates >= fork_point
        valid_candidates = self.mutable_candidates
        if fork_point is not None:
            valid_candidates = [c for c in self.mutable_candidates if c.index >= fork_point]
            print(f"[Mutator] Fork point={fork_point}, candidates >= fork_point: {len(valid_candidates)}")
            
            if len(valid_candidates) == 0:
                # 🔍 RELAXATION: If no candidates >= fork_point, check if fork_point itself is a valid IO
                # (it might have been filtered out due to FD tracking or other environment factors)
                all_syscalls = getattr(self.analyzer, 'syscalls', [])
                target_sc = next((sc for sc in all_syscalls if sc.index == fork_point), None)
                
                if target_sc and target_sc.name in IMPORTANT_SYSCALLS:
                    print(f"[Mutator] OK: Fork point {fork_point} ({target_sc.name}) is an IO syscall - Force including it")
                    valid_candidates = [target_sc]
                else:
                    print(f"[Mutator] WARNING: No candidates >= fork_point and {fork_point} is not a valid IO target")
                    valid_candidates = self.mutable_candidates
        
        num_candidates = len(valid_candidates)
        
        print(f"[Mutator] Iteration {iteration}: Mutating {num_mutations} from {num_candidates} IO candidates")
        
        # P3: Classify candidates (all candidates are already IO syscalls)
        primary_io = [c for c in valid_candidates if c.name in PRIMARY_IO_SYSCALLS]
        secondary_io = [c for c in valid_candidates if c.name in SECONDARY_IO_SYSCALLS]
        
        print(f"[Mutator]   Primary IO: {len(primary_io)}, Secondary IO: {len(secondary_io)}")
        
        # P4: If fork_point specified, guarantee at least one mutation target is it
        fork_point_candidate = None
        if fork_point is not None:
            for c in valid_candidates:
                if c.index == fork_point:
                    fork_point_candidate = c
                    break
            
            if fork_point_candidate:
                strategy_type = self._select_strategy()
                instrs.extend(self._generate_advanced_instruction(fork_point_candidate, strategy_type, iteration))
                print(f"[Mutator] P4: Guaranteed mutation at fork_point={fork_point} ({fork_point_candidate.name})")
                num_mutations -= 1
            elif fork_point is not None:
                print(f"[Mutator] WARNING: fork_point={fork_point} not in valid candidates")

        # P5: Select remaining mutation targets
        if num_mutations > 0 and len(valid_candidates) > 0:
            targets = self._select_diverse_targets(valid_candidates, num_mutations, iteration)
            for target_sc in targets:
                # Avoid redundant mutation of fork_point
                if fork_point_candidate and target_sc.index == fork_point_candidate.index:
                    continue
                
                strategy_type = self._select_strategy()
                instrs.extend(self._generate_advanced_instruction(target_sc, strategy_type, iteration))
        


        # Record result and verify limit
        self.last_mutation_type = 'smart' if len(instrs) > 0 else 'none'
        
        if len(instrs) > FUZZ_MAX_INSTRUCTIONS:
            print(f"[SmartMutator] Truncating instructions to {FUZZ_MAX_INSTRUCTIONS}")
            instrs = instrs[:FUZZ_MAX_INSTRUCTIONS]
        
        print(f"[Mutator] Generated {len(instrs)} mutation instructions")
        return instrs

    def _select_diverse_targets(self, candidates: list, num_targets: int, iteration: int) -> list:
        """
        Strategy:
        1. Rotation: Cycle through candidates based on iteration ID.
        2. Dispersion: Ensure selected syscalls are spread across the trace.
        3. Jitter: Add occasional random selection for unpredictability.
        4. History avoidance: Prevent consecutive iterations from targeting identical sets.

        Args:
            candidates: List of optional candidates (sorted by index)
            num_targets: Number of targets to select
            iteration: Current iteration ID
        Returns:
            List of selected candidates
        """
        if not candidates:
            return []

        if len(candidates) <= num_targets:
            return candidates.copy()

        selected = []
        count = len(candidates)

        # Strategy 1: Iteration-based rotation start point
        start_idx = iteration % count

        # Strategy 2: Distributed selection - Try to select candidates far apart
        if num_targets == 1:
            # Single selection: based on iteration rotation
            selected.append(candidates[start_idx])
        else:
            # Multiple selections: use stepping algorithm to ensure distribution
            step = max(1, count // num_targets)
            for i in range(num_targets):
                idx = (start_idx + i * step) % count
                selected.append(candidates[idx])

        # Strategy 3: Random perturbation (25% probability)
        if random.random() < 0.25:
            # Replace one selected candidate with a random candidate
            if selected:
                replace_idx = random.randrange(len(selected))
                selected[replace_idx] = random.choice(candidates)

        # Deduplication (in case rotation produces duplicates)
        final_selected = []
        seen_indices = set()
        for cand in selected:
            if cand.index not in seen_indices:
                final_selected.append(cand)
                seen_indices.add(cand.index)

        # If count insufficient after deduplication, supplement selection
        if len(final_selected) < num_targets:
            for candidate in candidates:
                if candidate.index not in seen_indices:
                    final_selected.append(candidate)
                    seen_indices.add(candidate.index)
                if len(final_selected) >= num_targets:
                    break

        return final_selected[:num_targets]


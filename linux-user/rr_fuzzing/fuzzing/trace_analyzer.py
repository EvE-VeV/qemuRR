#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RR-Fuzz Trace Analyzer

Functionality:
1. Parse binary trace files
2. Identify syscall types (Pure/Hybrid)
3. Extract syscall sequences and argument information
4. Provide metadata for Conductor

Author: RR-Fuzz Team
Date: 2025-10-26
"""

import struct
import os
import sys
from enum import IntEnum
from typing import List, Dict, Tuple, Optional
from pathlib import Path
import traceback

# 🔥 FIX: bb_trace_parser is in the conductor directory, not the analysis directory
conductor_dir = os.path.join(os.path.dirname(__file__), 'conductor')
if conductor_dir not in sys.path:
    sys.path.insert(0, conductor_dir)

try:
    from bb_trace_parser import BBTraceParser, BBEntry
    BB_TRACE_AVAILABLE = True
except ImportError as e:
    BB_TRACE_AVAILABLE = False

try:
    from conductor.async_logger import alog
except ImportError:
    # Fallback to print if alog is not available
    def alog(msg, *args, **kwargs):
        print(f"[{args[0] if args else 'LOG'}] {msg}")


class AuxDataType(IntEnum):
    """aux_data type enum (consistent with rr_aux_data.h)"""
    AUX_TYPE_BUFFER = 1
    AUX_TYPE_STRING = 2
    AUX_TYPE_RANDOM = 3
    AUX_TYPE_STRUCT = 4


class SyscallRecord:
    """Syscall Record"""
    def __init__(self, index: int, syscall_nr: int, retval: int, 
                 has_aux_data: bool, aux_data_size: int = 0,
                 args: List[int] = None, creates_fd: bool = False,
                 uses_fd: bool = False, created_fd: int = -1,
                 arg_data: Dict[int, bytes] = None):
        self.index = index
        self.syscall_nr = syscall_nr
        self.retval = retval
        self.has_aux_data = has_aux_data
        self.aux_data_size = aux_data_size
        self.args = args if args else [0] * 8
        self.creates_fd = creates_fd
        self.uses_fd = uses_fd
        self.created_fd = created_fd
        self.arg_data = arg_data if arg_data else {}
        self.name = self._nr_to_name(syscall_nr)
        self.category = self._categorize()
    
    @staticmethod
    def _nr_to_name(nr: int) -> str:
        """Convert syscall number to name (multi-architecture)"""
        # x86_64 syscall mappings
        x86_64_map = {
            0: 'read',
            1: 'write',
            2: 'open',
            3: 'close',
            4: 'stat',
            5: 'fstat',
            6: 'lstat',
            7: 'poll',
            8: 'lseek',
            9: 'mmap',
            10: 'mprotect',
            11: 'munmap',
            12: 'brk',
            13: 'rt_sigaction',
            14: 'rt_sigprocmask',
            15: 'rt_sigreturn',
            16: 'ioctl',
            17: 'pread64',
            18: 'pwrite64',
            19: 'readv',
            20: 'writev',
            21: 'access',
            22: 'pipe',
            23: 'select',
            24: 'sched_yield',
            25: 'mremap',
            32: 'dup',
            33: 'dup2',
            35: 'nanosleep',
            37: 'alarm',
            39: 'getpid',
            41: 'socket',
            42: 'connect',
            43: 'accept',
            44: 'sendto',
            45: 'recvfrom',
            46: 'sendmsg',
            47: 'recvmsg',
            56: 'clone',
            57: 'fork',
            59: 'execve',
            60: 'exit',
            61: 'wait4',
            63: 'uname',
            72: 'fcntl',
            73: 'flock',
            74: 'fsync',
            77: 'ftruncate',
            79: 'getcwd',
            80: 'chdir',
            89: 'readlink',
            96: 'gettimeofday',
            102: 'getuid',
            104: 'getgid',
            110: 'getppid',
            158: 'arch_prctl',
            186: 'gettid',
            202: 'futex',
            217: 'getdents64',
            218: 'set_tid_address',
            228: 'clock_gettime',
            231: 'exit_group',
            257: 'openat',
            262: 'newfstatat',
            273: 'set_robust_list',
            318: 'getrandom',
        }
        
        # ✅ MIPS syscall mappings (offset by 4000)
        # Reference: https://github.com/torvalds/linux/blob/master/arch/mips/include/uapi/asm/unistd.h
        mips_map = {
            4000: 'syscall',     # sys_syscall
            4001: 'exit',
            4002: 'fork',
            4003: 'read',
            4004: 'write',
            4005: 'open',
            4006: 'close',
            4007: 'waitpid',
            4008: 'creat',
            4009: 'link',
            4010: 'unlink',
            4011: 'execve',
            4012: 'chdir',
            4013: 'time',
            4014: 'mknod',
            4015: 'chmod',
            4016: 'lchown',
            4019: 'lseek',
            4020: 'getpid',
            4021: 'mount',
            4022: 'umount',
            4023: 'setuid',
            4024: 'getuid',
            4033: 'access',
            4041: 'dup',
            4042: 'pipe',
            4045: 'brk',
            4047: 'getgid',
            4049: 'geteuid',
            4050: 'getegid',
            4054: 'ioctl',
            4055: 'fcntl',
            4063: 'dup2',
            4064: 'getppid',
            4076: 'brk',      # dup of 4045, different ABI
            4090: 'mmap',
            4091: 'munmap',
            4106: 'stat',
            4107: 'lstat',
            4108: 'fstat',
            4120: 'clone',
            4122: 'uname',
            4125: 'mprotect',
            4140: 'llseek',
            4141: 'getdents',
            4179: 'rt_sigaction',
            4180: 'pread64',
            4181: 'pwrite64',
            # ✅ Network syscalls (Critical for jjhttpd/upnp)
            4183: 'socket',
            4184: 'connect',
            4185: 'accept',
            4186: 'sendto',
            4187: 'recvfrom',
            4188: 'sendmsg',
            4189: 'recvmsg',
            4190: 'shutdown',
            4191: 'bind',
            4192: 'listen',
            4193: 'getsockname',
            4194: 'getpeername',
            4195: 'socketpair',
            4196: 'send',
            4197: 'recv',
            4198: 'getsockopt',
            4199: 'setsockopt',
            # More syscalls
            4213: 'set_tid_address',
            4214: 'getdents64',
            4215: 'fcntl64',
            4238: 'set_robust_list',
            4246: 'exit_group',
            4248: 'tkill',
            4266: 'tgkill',
            4294: 'getrandom',
            4300: 'mmap2',
            4305: 'openat',
            4326: 'newfstatat',
        }
        
        # Try MIPS first (4000+ range)
        if nr >= 4000:
            name = mips_map.get(nr)
            if name:
                return name
        
        # Try x86_64
        name = x86_64_map.get(nr)
        if name:
            return name
        
        # Fallback to generic name
        return f'syscall_{nr}'
    
    def _categorize(self) -> str:
        """Classify syscall - returns functional category, not pure/hybrid classification"""
        # ✅ FIX: Pure syscalls should also be classified by function, do not return 'pure_replay'
        # 'pure_replay' and 'hybrid_replay' are statistical fields, not categories
        
        # Categorize by syscall name
        if self.name in ['read', 'pread64', 'readv', 'preadv',
                         'recv', 'recvfrom', 'recvmsg',
                         'getrandom']:
            return 'input_io'
        elif self.name in ['write', 'pwrite64', 'writev', 'pwritev',
                           'send', 'sendto', 'sendmsg']:
            return 'output_io'
        elif self.name in ['open', 'openat', 'creat',
                           'stat', 'fstat', 'lstat', 'newfstatat',
                           'access', 'faccessat', 'close']:
            return 'file_ops'
        elif self.name in ['mmap', 'mmap2', 'munmap', 'mprotect', 'brk']:
            return 'memory_mgmt'
        elif self.name in ['socket', 'connect', 'bind', 'listen', 'accept']:
            return 'network'
        elif self.name in ['gettimeofday', 'clock_gettime', 'time']:
            return 'time'
        elif self.name in ['fork', 'clone', 'vfork', 'execve', 'exit', 'exit_group']:
            return 'process'
        else:
            # ✅ FIX: Unknown syscalls return 'unknown', not 'hybrid_replay'
            return 'unknown'
    
    @staticmethod
    def get_name(nr: int) -> str:
        return SyscallRecord._nr_to_name(nr)
    
    def __repr__(self):
        return (f"SyscallRecord(index={self.index}, name={self.name}, "
                f"nr={self.syscall_nr}, retval={self.retval}, "
                f"aux_data={self.has_aux_data}, category={self.category})")


class TraceAnalyzer:
    """Binary Trace Analyzer"""
    
    # Supported trace format magic numbers
    VALID_TRACE_MAGICS = {
        0x52525452: "RTRR",  # Old format or format in documentation
        0x52525254: "TRRR",  # Actual format generated by QEMU (current)
    }
    TRACE_VERSION = 1
    
    def __init__(self, trace_file: str, endian: str = 'auto', word_size: int = 0):
        """
        Initialize TraceAnalyzer
        
        Args:
            trace_file: Path to trace file
            endian: Byte order - 'little', 'big', or 'auto' (default: auto-detect)
            word_size: Architecture word size - 32, 64, or 0 for auto-detect (default)
        """
        self.trace_file = trace_file
        self.syscalls: List[SyscallRecord] = []
        self.pure_syscalls: List[SyscallRecord] = []
        self.hybrid_syscalls: List[SyscallRecord] = []
        self.stats = {
            'total': 0,
            'pure_replay': 0,
            'hybrid_replay': 0,
            'input_io': 0,
            'output_io': 0,
            'file_ops': 0,
            'memory_mgmt': 0,
            'network': 0,
            'time': 0,
            'process': 0,
            'unknown': 0
        }
        
        # ✅ CRITICAL FIX: Multi-architecture support (endianness + word size)
        self.endian_format = endian
        self.detected_endian = None
        self.struct_prefix = '<'
        
        # ✅ NEW: Architecture word size support
        self.word_size_format = word_size  # 32, 64, or 0 (auto)
        self.detected_word_size = None  # Will be set during analysis
        self.arg_format = 'Q'  # Default to 64-bit, will be updated
        self.args_size = 64  # 8 args * 8 bytes
        self.retval_size = 8
        
        # BB trace related
        self.bb_trace_parser: Optional[BBTraceParser] = None
        self.bb_trace_available = False
        self.merged_execution_sequence = []
        
        self._analyzed = False
        
        # Parse trace file automatically
        self.analyze()
    
    def analyze(self) -> bool:
        """Analyze trace file"""
        # ✅ FIX: Skip if already analyzed (for cached analyzers)
        if self._analyzed:
            return True
        
        # Handle None or empty trace_file
        if self.trace_file is None:
            alog(f"[TraceAnalyzer] ⚠️  No trace file provided, skipping analysis", "TRACE", "WARNING")
            return False
        
        if not os.path.exists(self.trace_file):
            alog(f"[TraceAnalyzer] ❌ Trace file not found: {self.trace_file}", "TRACE", "ERROR")
            return False

        # ✅ Performance Optimization: Try to load from cache first
        import pickle
        import time
        cache_file = str(self.trace_file) + ".analyzer.pkl"
        
        try:
            if os.path.exists(cache_file):
                # Check timestamps (re-analyze if trace is newer)
                trace_mtime = os.path.getmtime(self.trace_file)
                cache_mtime = os.path.getmtime(cache_file)
                
                if cache_mtime >= trace_mtime:
                    alog(f"[TraceAnalyzer] 📦 Loading cached analysis from {cache_file}...", "TRACE", "INFO")
                    with open(cache_file, 'rb') as f:
                        cached_data = pickle.load(f)
                        self.syscalls = cached_data['syscalls']
                        self.stats = cached_data['stats']
                        self.pure_syscalls = cached_data['pure_syscalls']
                        self.hybrid_syscalls = cached_data['hybrid_syscalls']
                        self.bb_trace_available = cached_data['bb_trace_available']
                        # BB parser logic is complex to pickle full state, so we might need to handle it carefully
                        # But for now, let's assume if bb_trace was available, we also cached execution sequence
                        self.merged_execution_sequence = cached_data.get('merged_execution_sequence', [])
                        
                        # Re-attach bb parser if possible or just use cached data
                        # Ideally we fully reconstruct, but for lighter use we might just need stats
                        if self.bb_trace_available and 'bb_entries' in cached_data:
                             # Reconstruct lightweight parser if needed, or just rely on merged sequence
                             pass
                             
                        self._analyzed = True
                        return True
        except Exception as e:
            alog(f"[TraceAnalyzer] ⚠️ Cache load failed, re-analyzing: {e}", "TRACE", "WARN")

        # Full Analysis
        try:
            with open(self.trace_file, 'rb') as f:
                # Read header
                if not self._read_header(f):
                    return False
                
                # Read all syscall records
                self._read_syscall_records(f)
                
                # Classification and statistics
                self._classify_and_stats()
                
                # Attempt to load BB trace
                self._load_bb_trace()
                
                alog(f"✅ Analysis completed: Total syscalls={self.stats['total']}, "
                     f"Pure={self.stats['pure_replay']}, Hybrid={self.stats['hybrid_replay']}", "TRACE", "DEBUG")
                if self.bb_trace_available:
                     alog(f"  BB Trace: ✅ Available ({self.bb_trace_parser.stats['total_bbs']} BBs)", "TRACE", "DEBUG")
                
                # ✅ FIX: Mark as analyzed
                self._analyzed = True
                
                # ✅ Save to cache
                try:
                    cache_data = {
                        'syscalls': self.syscalls,
                        'stats': self.stats,
                        'pure_syscalls': self.pure_syscalls,
                        'hybrid_syscalls': self.hybrid_syscalls,
                        'bb_trace_available': self.bb_trace_available,
                        'merged_execution_sequence': self.merged_execution_sequence,
                        # We don't pickle the entire bb_trace_parser as it might be huge or non-picklable
                    }
                    if self.bb_trace_available and self.bb_trace_parser:
                         # cache key attributes if needed later
                         pass
                    
                    with open(cache_file, 'wb') as f:
                        pickle.dump(cache_data, f)
                    alog(f"[TraceAnalyzer] 📦 Saved analysis cache to {cache_file}", "TRACE", "INFO")
                except Exception as e:
                    alog(f"[TraceAnalyzer] ⚠️ Failed to save cache: {e}", "TRACE", "WARN")

                return True
                
        except Exception as e:
            alog(f"[TraceAnalyzer] ❌ Failed to analyze trace: {e}", "TRACE", "ERROR")
            traceback.print_exc()
            return False
    
    def _read_header(self, f) -> bool:
        """Read trace header and detect endianness"""
        # Magic number (4 bytes) - architecture-neutral
        magic = struct.unpack('I', f.read(4))[0]
        if magic not in self.VALID_TRACE_MAGICS:
            valid_magics_str = ", ".join([f"0x{m:08X} ({n})" for m, n in self.VALID_TRACE_MAGICS.items()])
            alog(f"[TraceAnalyzer] ❌ Invalid trace magic: 0x{magic:08X}", "TRACE", "ERROR")
            alog(f"[TraceAnalyzer]    Expected one of: {valid_magics_str}", "TRACE", "ERROR")
            return False
        
        format_name = self.VALID_TRACE_MAGICS[magic]
        
        # First, read version and count from both endianness to detect
        saved_pos = f.tell()
        
        # Try little-endian
        version_le = struct.unpack('<I', f.read(4))[0]
        count_le = struct.unpack('<I', f.read(4))[0]
        
        # Try big-endian
        f.seek(saved_pos)
        version_be = struct.unpack('>I', f.read(4))[0]
        count_be = struct.unpack('>I', f.read(4))[0]
        
        # Determine endianness first
        if self.endian_format == 'auto':
            # Read first record header to check syscall_nr validity
            first_syscall_pos = f.tell()
            header_bytes = f.read(8)
            f.seek(first_syscall_pos)
            
            if len(header_bytes) >= 8:
                _, syscall_nr_le = struct.unpack('<Ii', header_bytes)
                _, syscall_nr_be = struct.unpack('>Ii', header_bytes)
                
                # MIPS: 4000-4400, x86/ARM: 0-500
                nr_le_valid = (0 <= syscall_nr_le <= 500) or (4000 <= syscall_nr_le <= 4400)
                nr_be_valid = (0 <= syscall_nr_be <= 500) or (4000 <= syscall_nr_be <= 4400)
                
                if nr_be_valid and not nr_le_valid:
                    self.detected_endian = 'big'
                    self.struct_prefix = '>'
                    version, count = version_be, count_be
                else:
                    self.detected_endian = 'little'
                    self.struct_prefix = '<'
                    version, count = version_le, count_le
            else:
                # Fallback to version/count heuristic
                le_score = (version_le == 1) + (0 < count_le < 1000000)
                be_score = (version_be == 1) + (0 < count_be < 1000000)
                if be_score > le_score:
                    self.detected_endian = 'big'
                    self.struct_prefix = '>'
                    version, count = version_be, count_be
                else:
                    self.detected_endian = 'little'
                    self.struct_prefix = '<'
                    version, count = version_le, count_le
        else:
            # User-specified
            if self.endian_format == 'big':
                self.struct_prefix = '>'
                self.detected_endian = 'big'
                version, count = version_be, count_be
            else:
                self.struct_prefix = '<'
                self.detected_endian = 'little'
                version, count = version_le, count_le
        
        # Now detect word size using count
        if self.word_size_format == 0:
            file_size = os.path.getsize(self.trace_file)
            avg_record_size = (file_size - 12) / max(count, 1)
            
            if avg_record_size < 200:
                self.detected_word_size = 32
            else:
                self.detected_word_size = 64
            
            alog(f"[TraceAnalyzer] Heuristic: avg_record_size={avg_record_size:.1f} → {self.detected_word_size}-bit", "TRACE", "DEBUG")
        else:
            self.detected_word_size = self.word_size_format
        
        # Update format strings based on word size
        if self.detected_word_size == 32:
            self.arg_format = 'I'  # 32-bit unsigned
            self.args_size = 32  # 8 args * 4 bytes
            self.retval_size = 4
            alog(f"[TraceAnalyzer] Using 32-bit format (MIPS/ARM32)", "TRACE", "INFO")
        else:
            self.arg_format = 'Q'  # 64-bit unsigned
            self.args_size = 64  # 8 args * 8 bytes
            self.retval_size = 8
            alog(f"[TraceAnalyzer] Using 64-bit format (x86_64/ARM64)", "TRACE", "INFO")
        
        if version != self.TRACE_VERSION:
            print(f"[TraceAnalyzer] ⚠️  Trace version mismatch: {version} (expected {self.TRACE_VERSION})")
        
        self.stats['total'] = count
        alog(f"[TraceAnalyzer] Trace: format={format_name}, version={version}, count={count}, endian={self.detected_endian}, word_size={self.detected_word_size}", "TRACE", "INFO")
        
        return True
    
    def _read_syscall_records(self, f):
        """Read all syscall records - manually aligned with C writer logic"""
        index = 0
        
        # Determine sizes based on detected environment
        # Target: abi_long size (detected_word_size)
        target_long_size = self.detected_word_size // 8
        # Host: size_t size (always 8 for QEMU on 64-bit host)
        host_long_size = 8 
        
        while True:
            # [A] Record header (8 bytes): index + syscall_nr
            header_data = f.read(8)
            if len(header_data) < 8:
                break  # EOF
            
            rec_index, syscall_nr = struct.unpack(f'{self.struct_prefix}Ii', header_data)
            
            # [B] Args (8 * 8 = 64 bytes) - ALWAYS 64-bit for universality
            args_size = 64
            args_data = f.read(args_size)
            if len(args_data) < args_size: break
            args = list(struct.unpack(f'{self.struct_prefix}8Q', args_data))
            
            # [C] Retval (8 bytes) - ALWAYS 64-bit for universality
            retval_data = f.read(8)
            if len(retval_data) < 8: break
            retval = struct.unpack(f'{self.struct_prefix}q', retval_data)[0]
            
            # [D] Arg sizes (8 * 8 = 64 bytes) - ALWAYS 64-bit for universality
            arg_sizes_data = f.read(64)
            if len(arg_sizes_data) < 64: break
            arg_sizes_list = list(struct.unpack(f'{self.struct_prefix}8Q', arg_sizes_data))
            
            # [E] Flags and created_fd (EXACTLY 6 bytes, no padding in fwrite)
            # Layout: bool(1), bool(1), int32_t(4) = 6 bytes
            flags_data = f.read(6)
            if len(flags_data) < 6: break
            
            creates_fd = struct.unpack(f'{self.struct_prefix}?', flags_data[0:1])[0]
            uses_fd = struct.unpack(f'{self.struct_prefix}?', flags_data[1:2])[0]
            created_fd = struct.unpack(f'{self.struct_prefix}i', flags_data[2:6])[0]
            
            # ===== Step 2: Read variable arg_data section =====
            arg_data_map = {}
            while True:
                arg_idx_bytes = f.read(4)
                if len(arg_idx_bytes) < 4: break
                
                arg_idx = struct.unpack(f'{self.struct_prefix}i', arg_idx_bytes)[0]
                if arg_idx == -1:  # End marker
                    break
                
                # Read size (size_t = 8 bytes) and data
                size_bytes = f.read(8)
                if len(size_bytes) < 8: break
                
                size = struct.unpack(f'{self.struct_prefix}Q', size_bytes)[0]
                if size > 10000000:  # Sanity check
                    if index < 100:
                        alog(f"[TraceAnalyzer] ⚠️ Suspicious arg_size={size} at rec {index}, offset {f.tell()-8}", "TRACE", "WARN")
                    break
                
                data = f.read(size)
                if len(data) < size: break
                arg_data_map[arg_idx] = data
            
            # ===== Step 3: Read aux_data section =====
            has_aux_data = False
            aux_data_size = 0
            
            marker_bytes = f.read(4)
            if len(marker_bytes) >= 4:
                # The marker in file is written as uint32_t 0x41555844
                # On little-endian machine it's 44 58 55 41
                if marker_bytes in [b'AUXD', b'DXUA']:
                    has_aux_data = True
                    aux_cnt_bytes = f.read(4)
                    if len(aux_cnt_bytes) >= 4:
                        aux_count = struct.unpack(f'{self.struct_prefix}I', aux_cnt_bytes)[0]
                        
                        for j in range(aux_count):
                            aux_header = f.read(6) # kind(1), arg_mask(1), size(4)
                            if len(aux_header) < 6: break
                            
                            kind = struct.unpack(f'{self.struct_prefix}B', aux_header[0:1])[0]
                            arg_mask = struct.unpack(f'{self.struct_prefix}B', aux_header[1:2])[0]
                            size = struct.unpack(f'{self.struct_prefix}I', aux_header[2:6])[0]
                            
                            data = f.read(size)
                            if len(data) < size: break
                            aux_data_size += size
                elif marker_bytes == b'\x00\x00\x00\x00':
                    pass
                else:
                    # Desync recovery: if we found marker_bytes that looks like index, 
                    # we should backtrack. But in current format, they strictly follow.
                    f.seek(-4, os.SEEK_CUR) 

            # Create Record
            record = SyscallRecord(
                index=rec_index,
                syscall_nr=syscall_nr,
                retval=retval,
                has_aux_data=has_aux_data,
                aux_data_size=aux_data_size,
                args=args,
                creates_fd=creates_fd,
                uses_fd=uses_fd,
                created_fd=created_fd,
                arg_data=arg_data_map
            )
            
            self.syscalls.append(record)
            index += 1
        
        alog(f"[TraceAnalyzer] ✅ Read {len(self.syscalls)} syscall records", "TRACE", "INFO")
    
    def _classify_and_stats(self):
        """Classification and Statistics"""
        # ✅ FIX: Clear lists before classifying (in case called multiple times)
        self.pure_syscalls = []
        self.hybrid_syscalls = []
        # Reset stats counters (pure_replay and hybrid_replay are separate from categories)
        self.stats['pure_replay'] = 0
        self.stats['hybrid_replay'] = 0
        for cat in ['input_io', 'output_io', 'file_ops', 'memory_mgmt', 'network', 'time', 'process', 'unknown']:
            self.stats[cat] = 0
        
        for record in self.syscalls:
            # Classify Pure/Hybrid (one dimension)
            if record.has_aux_data:
                self.pure_syscalls.append(record)
                self.stats['pure_replay'] += 1
            else:
                self.hybrid_syscalls.append(record)
                self.stats['hybrid_replay'] += 1
            
            # ✅ FIX: Statistics by functional category (another dimension, orthogonal to pure/hybrid)
            # Category now only contains functional categories (input_io, file_ops, etc.), not pure_replay/hybrid_replay
            if record.category in self.stats:
                self.stats[record.category] += 1
    
    def _load_bb_trace(self):
        """Load and parse BB trace file"""
        if not BB_TRACE_AVAILABLE:
            return
        
        # Construct BB trace file path (trace_file + ".bbl")
        bb_trace_file = str(self.trace_file) + ".bbl"
        
        if not os.path.exists(bb_trace_file):
            print(f"[TraceAnalyzer] BB trace file not found: {bb_trace_file}")
            return
        
        try:
            self.bb_trace_parser = BBTraceParser(bb_trace_file)
            if self.bb_trace_parser.parse():
                self.bb_trace_available = True
                # Merge execution sequence
                self._merge_execution_sequence()
        except Exception as e:
            print(f"[TraceAnalyzer] Failed to load BB trace: {e}")
    
    def _merge_execution_sequence(self):
        """Merge syscall trace and BB trace, generating a complete execution sequence"""
        if not self.bb_trace_available or not self.bb_trace_parser:
            return
        
        # Simplified version: organize BBs by syscall index
        self.merged_execution_sequence = []
        current_syscall_idx = 0
        
        for entry in self.bb_trace_parser.entries:
            # When syscall index changes, insert syscall marker
            if entry.syscall_idx > current_syscall_idx:
                # Find corresponding syscall record
                for syscall in self.syscalls:
                    if syscall.index == entry.syscall_idx:
                        self.merged_execution_sequence.append(('syscall', syscall))
                        break
                current_syscall_idx = entry.syscall_idx
            
            # Add BB
            self.merged_execution_sequence.append(('bb', entry.pc))
    
    def classify_syscalls(self, syscalls):
        """Classify Syscalls"""
        pure = [s for s in syscalls if s['has_aux_data']]
        hybrid = [s for s in syscalls if not s['has_aux_data']]
        return pure, hybrid

    def get_pure_candidates(self):
        if not self.syscalls:
            self.analyze()
        return self.pure_syscalls

    def get_hybrid_candidates(self):
        if not self.syscalls:
            self.analyze()
        return self.hybrid_syscalls

    def get_pure_syscalls(self) -> List[SyscallRecord]:
        """Get Pure Replay Syscalls"""
        return self.pure_syscalls
    
    def get_hybrid_syscalls(self) -> List[SyscallRecord]:
        """Get Hybrid Replay Syscalls"""
        return self.hybrid_syscalls
    
    def get_syscalls_by_category(self, category: str) -> List[SyscallRecord]:
        """Get Syscalls by Category"""
        return [sc for sc in self.syscalls if sc.category == category]
    
    def print_summary(self):
        """Print Analysis Summary"""
        print("\n" + "━" * 60)
        print("📊 Trace Analysis Summary")
        print("━" * 60)
        
        print(f"\n📈 Overall Statistics:")
        print(f"  Total syscalls:  {self.stats['total']}")
        print(f"  Pure Replay:     {self.stats['pure_replay']} "
              f"({self.stats['pure_replay'] * 100 // max(self.stats['total'], 1)}%)")
        print(f"  Hybrid Replay:   {self.stats['hybrid_replay']} "
              f"({self.stats['hybrid_replay'] * 100 // max(self.stats['total'], 1)}%)")
        
        print(f"\n🔍 Category Breakdown:")
        categories = ['input_io', 'output_io', 'file_ops', 'memory_mgmt', 
                      'network', 'time', 'process']
        for cat in categories:
            count = self.stats.get(cat, 0)
            if count > 0:
                pct = count * 100 // max(self.stats['total'], 1)
                print(f"  {cat:15s}: {count:4d} ({pct:2d}%)")
        
        print(f"\n📝 Top 10 Syscalls:")
        syscall_counts = {}
        for sc in self.syscalls:
            syscall_counts[sc.name] = syscall_counts.get(sc.name, 0) + 1
        
        sorted_syscalls = sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)
        for name, count in sorted_syscalls[:10]:
            pct = count * 100 // max(self.stats['total'], 1)
            print(f"  {name:20s}: {count:4d} ({pct:2d}%)")
        
        print("━" * 60 + "\n")
    
    def export_to_json(self, output_file: str):
        """Export analysis results to JSON"""
        import json
        
        data = {
            'trace_file': self.trace_file,
            'stats': self.stats,
            'syscalls': [
                {
                    'index': sc.index,
                    'name': sc.name,
                    'nr': sc.syscall_nr,
                    'retval': sc.retval,
                    'has_aux_data': sc.has_aux_data,
                    'category': sc.category
                }
                for sc in self.syscalls
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[TraceAnalyzer] ✅ Exported to {output_file}")
    
    # ========== BB Trace Related Methods ==========
    
    def has_bb_trace(self) -> bool:
        """Check if BB trace data is available"""
        return self.bb_trace_available and self.bb_trace_parser is not None
    
    def get_bb_sequence(self) -> List[int]:
        """Get full BB execution sequence (list of PC addresses)"""
        if not self.has_bb_trace():
            return []
        return self.bb_trace_parser.get_bb_sequence()
    
    def get_bb_between_syscalls(self, start_syscall_idx: int, end_syscall_idx: int) -> List[int]:
        """Get BB sequence between two syscalls"""
        if not self.has_bb_trace():
            return []
        return self.bb_trace_parser.get_bb_between_syscalls(start_syscall_idx, end_syscall_idx)
    
    def get_merged_execution_sequence(self) -> List[Tuple[str, any]]:
        """
        Get merged execution sequence
        
        Returns: [('bb', pc), ('syscall', SyscallRecord), ...]
        """
        return self.merged_execution_sequence
    
    def get_bb_coverage_summary(self) -> Dict[str, any]:
        """Get BB coverage summary"""
        if not self.has_bb_trace():
            return {'error': 'BB trace not available'}
        return self.bb_trace_parser.get_coverage_summary()
    
    def export_bb_trace_to_json(self, output_file: str):
        """Export BB trace to JSON format (for offline analysis)"""
        if not self.has_bb_trace():
            print("[TraceAnalyzer] ❌ No BB trace available")
            return
        
        import json
        
        data = {
            'trace_file': self.trace_file,
            'bb_trace_file': str(self.trace_file) + ".bbl",
            'stats': self.bb_trace_parser.stats,
            'bb_sequence': [
                {
                    'pc': hex(entry.pc),
                    'syscall_idx': entry.syscall_idx,
                    'flags': entry.flags
                }
                for entry in self.bb_trace_parser.entries
            ],
            'syscall_bb_map': {
                str(k): [hex(pc) for pc in v]
                for k, v in self.bb_trace_parser.get_syscall_bb_map().items()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[TraceAnalyzer] ✅ BB trace exported to {output_file}")


def main():
    """Test Entry Point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="RR-Fuzz Trace Analyzer")
    parser.add_argument("trace_file", help="Path to trace file")
    parser.add_argument("-w", "--word-size", type=int, default=0, help="Word size (32 or 64, default: auto)")
    parser.add_argument("-e", "--endian", default="auto", help="Endianness (little, big, or auto)")
    parser.add_argument("-j", "--json", help="Export as JSON file")
    
    args = parser.parse_args()
    
    # Update word size based on command line
    analyzer = TraceAnalyzer(args.trace_file, endian=args.endian, word_size=args.word_size)
    
    if analyzer.analyze():
        analyzer.print_summary()
        
        # Optional: Export JSON
        if args.json:
            analyzer.export_to_json(args.json)


if __name__ == '__main__':
    main()


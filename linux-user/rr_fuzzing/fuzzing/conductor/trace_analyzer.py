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

conductor_dir = os.path.dirname(__file__)
if conductor_dir not in sys.path:
    sys.path.insert(0, conductor_dir)

try:
    from .bb_trace_parser import BBTraceParser, BBEntry
    BB_TRACE_AVAILABLE = True
except ImportError as e:
    BB_TRACE_AVAILABLE = False

try:
    from .async_logger import alog
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
    def __init__(self, nr: int, index: int, args: List[int], retval: int, 
                 arg_sizes: List[int] = None, arg_data: Dict[int, bytes] = None, 
                 creates_fd: bool = False, uses_fd: bool = False, created_fd: int = -1, 
                 aux_entries: List[Tuple[int, int, bytes]] = None, arch: str = 'auto',
                 word_size: int = 64):
        self.nr = nr
        self.index = index
        self.args = args
        self.retval = retval
        self.arg_sizes = arg_sizes if arg_sizes else [0] * 8
        self.arg_data = arg_data if arg_data else {}
        self.creates_fd = creates_fd
        self.uses_fd = uses_fd
        self.created_fd = created_fd
        self.aux_entries = aux_entries if aux_entries else []
        self.has_aux_data = len(self.aux_entries) > 0
        self.arch = arch
        self.word_size = word_size
        self.name = self._nr_to_name(nr, arch, word_size)
        self.category = self._categorize()

    @property
    def syscall_nr(self):
        """Backward compatibility for renamed attribute"""
        return self.nr
    
    @staticmethod
    def _nr_to_name(nr: int, arch: str = 'auto', word_size: int = 64) -> str:
        """Map syscall number to name based on architecture"""
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
            4027: 'alarm',
            4114: 'wait4',
            4140: 'llseek',
            4141: 'getdents',
            4142: 'select',
            4143: 'select',       # MIPS O32 uses both 142 and 143 across kernel versions
            # ✅ MIPS O32 individual socket syscalls (__NR_Linux + 168..184)
            # Verified from qemu strace of actual Linksys E1200 firmware
            4168: 'accept',
            4169: 'bind',
            4170: 'connect',
            4171: 'getpeername',
            4172: 'getsockname',
            4173: 'getsockopt',
            4174: 'listen',
            4175: 'recv',
            4176: 'recvfrom',
            4177: 'recvmsg',
            4178: 'send',
            4179: 'sendmsg',
            4180: 'sendto',
            4181: 'setsockopt',
            4182: 'socketcall',
            4183: 'socket',
            4184: 'socketpair',
            4194: 'rt_sigaction',
            4195: 'rt_sigprocmask',
            4200: 'pread64',
            4201: 'pwrite64',
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
        
        # ✅ i386 syscall mappings (for MikroTik/Generic x86-32)
        i386_map = {
             0: 'restart_syscall', 1: 'exit', 2: 'fork', 3: 'read', 4: 'write', 5: 'open', 6: 'close',
             7: 'waitpid', 8: 'creat', 9: 'link', 10: 'unlink', 11: 'execve', 12: 'chdir', 13: 'time',
             19: 'lseek', 20: 'getpid', 33: 'access', 41: 'dup', 42: 'pipe', 45: 'brk',
             54: 'ioctl', 55: 'fcntl', 63: 'dup2', 64: 'getppid', 90: 'mmap', 91: 'munmap',
             102: 'socketcall', 106: 'stat', 107: 'lstat', 108: 'fstat', 119: 'sigreturn',
             120: 'clone', 122: 'uname', 125: 'mprotect', 140: '_llseek', 141: 'getdents',
             142: 'select', 168: 'poll', 174: 'rt_sigaction', 175: 'rt_sigprocmask',
             180: 'pread64', 181: 'pwrite64', 183: 'getcwd', 190: 'vfork', 192: 'mmap2',
             195: 'stat64', 196: 'lstat64', 197: 'fstat64', 221: 'fcntl64', 240: 'futex',
             252: 'exit_group', 265: 'clock_gettime', 268: 'tgkill', 295: 'openat',
             300: 'faccessat', 355: 'getrandom', 359: 'socket', 360: 'connect',
             362: 'sendto', 364: 'recvfrom', 369: 'accept4',
        }

        # ✅ ARM64 (AArch64) syscall mappings
        # Reference: https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h
        arm64_map = {
            17: 'getcwd', 20: 'epoll_create1', 21: 'epoll_ctl', 22: 'epoll_pwait',
            23: 'dup', 24: 'dup3', 25: 'fcntl', 29: 'ioctl', 32: 'flock',
            33: 'mknodat', 34: 'mkdirat', 35: 'unlinkat', 36: 'symlinkat',
            37: 'linkat', 38: 'renameat', 43: 'statfs', 44: 'fstatfs',
            45: 'truncate', 46: 'ftruncate', 48: 'faccessat', 49: 'chdir',
            50: 'fchdir', 51: 'chroot', 52: 'fchmod', 53: 'fchmodat',
            54: 'fchownat', 55: 'fchown', 56: 'openat', 57: 'close',
            59: 'pipe2', 61: 'getdents64', 62: 'lseek', 63: 'read', 64: 'write',
            65: 'readv', 66: 'writev', 67: 'pread64', 68: 'pwrite64',
            69: 'preadv', 70: 'pwritev', 78: 'readlinkat', 79: 'newfstatat', 80: 'fstat',
            81: 'sync', 82: 'fsync', 93: 'exit', 94: 'exit_group', 96: 'set_tid_address',
            98: 'futex', 99: 'set_robust_list', 101: 'nanosleep', 103: 'setitimer',
            113: 'clock_gettime', 115: 'clock_nanosleep', 134: 'rt_sigaction',
            135: 'rt_sigprocmask', 139: 'rt_sigreturn', 160: 'uname', 167: 'prctl',
            169: 'gettimeofday', 172: 'getpid', 173: 'getppid', 174: 'getuid', 178: 'gettid',
            179: 'sysinfo', 198: 'socket', 200: 'bind', 201: 'listen', 202: 'accept',
            203: 'connect', 204: 'getsockname', 205: 'getpeername',
            206: 'sendto', 207: 'recvfrom', 208: 'setsockopt', 209: 'getsockopt',
            210: 'shutdown', 211: 'sendmsg', 212: 'recvmsg', 213: 'readahead',
            214: 'brk', 215: 'munmap', 216: 'mremap', 220: 'clone', 221: 'execve',
            222: 'mmap', 226: 'mprotect', 242: 'accept4', 260: 'wait4',
            276: 'renameat2', 278: 'getrandom', 281: 'setxattr', 282: 'lsetxattr',
            283: 'fsetxattr', 284: 'getxattr', 285: 'lgetxattr', 286: 'fgetxattr',
            291: 'statx',
        }


        # ✅ ARM32 syscall mappings
        # Reference: https://github.com/torvalds/linux/blob/master/arch/arm/tools/syscall.tbl
        arm32_map = {
            3: 'read',
            4: 'write',
            5: 'open',
            6: 'close',
            10: 'unlink',
            11: 'execve',
            12: 'chdir',
            19: 'lseek',
            20: 'getpid',
            33: 'access',
            41: 'dup',
            42: 'pipe',
            45: 'brk',
            54: 'ioctl',
            55: 'fcntl',
            63: 'dup2',
            64: 'getppid',
            90: 'mmap',
            91: 'munmap',
            106: 'stat',
            107: 'lstat',
            108: 'fstat',
            120: 'clone',
            122: 'uname',
            125: 'mprotect',
            140: 'llseek',
            141: 'getdents',
            179: 'rt_sigaction',
            180: 'pread64',
            181: 'pwrite64',
            # Network
            281: 'socket',
            282: 'bind',
            283: 'connect',
            284: 'listen',
            285: 'accept',
            286: 'getsockname',
            287: 'getpeername',
            288: 'socketpair',
            289: 'send',
            290: 'recv',
            291: 'sendto',
            292: 'recvfrom',
            293: 'sendmsg',
            294: 'recvmsg',
            295: 'shutdown',
            296: 'setsockopt',
            297: 'getsockopt',
            # Other
            322: 'openat',
            327: 'newfstatat',
            345: 'getrandom',
        }
        
        # Architecture-aware mapping
        if arch == 'arm64' or arch == 'aarch64':
            return arm64_map.get(nr, f'syscall_{nr}')
        if arch == 'mips':
            return mips_map.get(nr, f'syscall_{nr}')
        if arch == 'i386':
            return i386_map.get(nr, f'syscall_{nr}')
        if arch == 'arm':
            return arm32_map.get(nr, f'syscall_{nr}')
        if arch == 'x86_64':
             return x86_64_map.get(nr, f'syscall_{nr}')

        # Heuristic (arch='auto')
        # If we know it's a 32-bit trace, prioritize 32-bit maps
        is_32bit = word_size == 32
        
        if nr >= 4000:
            return mips_map.get(nr, f'syscall_{nr}')
        
        if is_32bit:
            # For 32-bit, try MIPS (without offset), i386, and ARM32
            # MIPS O32 often has numbers like 3, 4, 5... (read, write, open) 
            # if the 4000 offset is stripped or implicit.
            if nr < 300:
                # Try i386 first as it's most common for small numbers
                name = i386_map.get(nr)
                if name: return name
            
            # Try ARM32 or MIPS fallback
            name = arm32_map.get(nr)
            if name: return name
            
            # Some MIPS versions also use small numbers
            name = mips_map.get(nr + 4000)
            if name: return name

        if nr > 250:
            # Likely ARM32 or specific x86_64 calls
            name = arm32_map.get(nr)
            if name: return name
            return x86_64_map.get(nr, f'syscall_{nr}')

        # 0-250: High ambiguity between x86_64 and arm64
        # Without exact arch, we guess x86_64 as default
        name = x86_64_map.get(nr)
        return name if name else f'syscall_{nr}'

    
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
                f"nr={self.nr}, retval={self.retval}, "
                f"aux_data={self.has_aux_data}, category={self.category})")


class TraceAnalyzer:
    """Binary Trace Analyzer"""
    
    # Supported trace format magic numbers
    VALID_TRACE_MAGICS = {
        0x52525452: "RTRR",  # Old format or format in documentation
        0x52525254: "TRRR",  # Actual format generated by QEMU (current)
    }
    TRACE_VERSION = 1
    
    def __init__(self, trace_file: str, endian: str = 'auto', word_size: int = 0, arch: str = 'auto'):
        """
        Initialize TraceAnalyzer
        
        Args:
            trace_file: Path to trace file
            endian: Byte order - 'little', 'big', or 'auto' (default: auto-detect)
            word_size: Architecture word size - 32, 64, or 0 for auto-detect (default)
            arch: Architecture name ('arm', 'arm64', 'mips', 'i386', 'x86_64', 'auto')
        """
        self.trace_file = trace_file
        self.arch = arch
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
                
                alog(f"✅ Analysis completed: Total syscalls={len(self.syscalls)} (Header said {self.stats['total']}), "
                     f"Pure={self.stats['pure_replay']}, Hybrid={self.stats['hybrid_replay']}", "TRACE", "DEBUG")
                
                # Update total to match actual records read
                self.stats['total'] = len(self.syscalls)
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
        
        # Detected architecture (default to auto)
        self.detected_arch = 'auto'

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
        
        # Now detect word size using count or arch
        if self.word_size_format == 0:
            # Check if arch gives us a hint
            if self.arch in ['arm', 'mips', 'i386']:
                self.detected_word_size = 32
                alog(f"[TraceAnalyzer] Word size fixed to 32-bit (Arch={self.arch})", "TRACE", "INFO")
            elif self.arch in ['arm64', 'x86_64', 'aarch64']:
                self.detected_word_size = 64
                alog(f"[TraceAnalyzer] Word size fixed to 64-bit (Arch={self.arch})", "TRACE", "INFO")
            else:
                # Heuristic fallback
                file_size = os.path.getsize(self.trace_file)
                # Note: count might be small but file large due to BB traces
                # Syscall records are either 32-bit (40 bytes) or 64-bit (64 bytes)
                # If we have BB trace, file_size is misleading.
                
                # Try to use a safer heuristic: check the first record
                self.detected_word_size = 32 # Default
                
                try:
                    with open(self.trace_file, 'rb') as f_check:
                        f_check.seek(20) # after header
                        # If it is 64-bit, the 2nd word (ret) might have many zeros or be large
                        # But more reliably, we can check if the count * 64 < file_size
                        if count * 64 <= file_size:
                             # Could be 64-bit. Let's look at the first record 
                             # 64-bit record has nr at [0:4], ret at [8:16]
                             # 32-bit record has nr at [0:4], ret at [4:8]
                             # If we read it as 32-bit and find valid syscall number
                             pass
                             
                        # Simplified: use file size if no BB trace, or just stick to 32-bit for now
                        avg_record_size = (file_size - 20) / max(count, 1)
                        if 60 < avg_record_size < 100:
                             self.detected_word_size = 64
                        else:
                             self.detected_word_size = 32
                except:
                    pass
                
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
        
        alog(f"[TraceAnalyzer] Trace: format={format_name}, version={version}, count={count}, endian={self.detected_endian}, word_size={self.detected_word_size}", "TRACE", "INFO")
        
        # [B] Architecture Detection if word_size is 64
        if self.detected_word_size == 64:
             # Sample first few syscalls to distinguish x86_64 vs AArch64
             saved_p = f.tell()
             try:
                 # Read first record's syscall number (offset 4 from record start, but record start is tricky)
                 # Actually, let's just use the first record we find later.
                 pass
             except: f.seek(saved_p)
             
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
            
            # Create SyscallRecord
            sc = SyscallRecord(
                nr=syscall_nr,
                index=index,
                args=args,
                retval=retval,
                arg_sizes=arg_sizes_list,
                arg_data={}, # Will be populated
                creates_fd=creates_fd,
                uses_fd=uses_fd,
                created_fd=created_fd,
                arch=self.arch,
                word_size=self.detected_word_size
            )
            
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
            
            # Update record with data
            sc.arg_data = arg_data_map
            
            # ===== Step 3: Read aux_data section =====
            has_aux_data = False
            aux_entries = []
            
            marker_bytes = f.read(4)
            if len(marker_bytes) == 4:
                # The marker in file is written as uint32_t 0x41555844 ("AUXD")
                # On little-endian machine it's 44 58 55 41
                if marker_bytes in [b'AUXD', b'DXUA']:
                    has_aux_data = True
                    aux_cnt_bytes = f.read(4)
                    if len(aux_cnt_bytes) >= 4:
                        aux_count = struct.unpack(f'{self.struct_prefix}I', aux_cnt_bytes)[0]
                        
                        for j in range(aux_count):
                            # Entry header: kind(1), arg_mask(1), size(4)
                            aux_header = f.read(6)
                            if len(aux_header) < 6: break
                            
                            kind = struct.unpack(f'{self.struct_prefix}B', aux_header[0:1])[0]
                            arg_mask = struct.unpack(f'{self.struct_prefix}B', aux_header[1:2])[0]
                            size = struct.unpack(f'{self.struct_prefix}I', aux_header[2:6])[0]
                            
                            data = f.read(size)
                            if len(data) < size: break
                            aux_entries.append((kind, arg_mask, data))
                elif marker_bytes == b'\x00\x00\x00\x00':
                    # No aux data marker
                    has_aux_data = False
                else:
                    # Desync? Or just end of file?
                    # If marker is not AUXD or 0, we might be misaligned.
                    f.seek(-4, os.SEEK_CUR)

            # Architecture detection if not specified
            if self.detected_arch == 'auto':
                 if self.arch != 'auto':
                      self.detected_arch = self.arch
                 elif self.detected_word_size == 64:
                      # AArch64: 56 (openat), 63 (read), 64 (write), 79 (newfstatat), 172 (getpid), 214 (brk)
                      if syscall_nr in [56, 63, 64, 79, 172, 214]: 
                           self.detected_arch = 'arm64'
                           alog(f"[TraceAnalyzer] 🏛️ Detected architecture: AArch64 (at rec {rec_index})", "TRACE", "INFO")
                           # Backtrack and update names for previous records
                           for sc in self.syscalls:
                               sc.arch = 'arm64'
                               sc.name = SyscallRecord._nr_to_name(sc.nr, 'arm64')
                               sc.category = sc._categorize()
                      elif syscall_nr in [0, 1, 2, 3]: # x86_64
                           self.detected_arch = 'x86_64'
                           alog(f"[TraceAnalyzer] 🏛️ Detected architecture: x86_64 (at rec {rec_index})", "TRACE", "INFO")
                           for sc in self.syscalls:
                               sc.arch = 'x86_64'
                               sc.name = SyscallRecord._nr_to_name(sc.nr, 'x86_64', sc.word_size) # Pass word_size
                               sc.category = sc._categorize()
                 elif self.detected_word_size == 32:
                      # MIPS O32 syscall numbers are >= 4000 — detect early
                      if syscall_nr >= 4000:
                           self.detected_arch = 'mips'
                           alog(f"[TraceAnalyzer] 🏛️ Detected architecture: MIPS O32 (at rec {rec_index}, nr={syscall_nr})", "TRACE", "INFO")
                           for sc in self.syscalls:
                               sc.arch = 'mips'
                               sc.name = SyscallRecord._nr_to_name(sc.nr, 'mips', 32)
                               sc.category = sc._categorize()
                      else:
                           # Default to arm for non-MIPS 32-bit (ARM is most common)
                           self.detected_arch = 'arm'

            # Create Record
            record = SyscallRecord(
                nr=syscall_nr,
                index=rec_index,
                args=args,
                retval=retval,
                arg_sizes=arg_sizes_list,
                arg_data=arg_data_map,
                creates_fd=creates_fd,
                uses_fd=uses_fd,
                created_fd=created_fd,
                aux_entries=aux_entries,
                arch=self.detected_arch,
                word_size=self.detected_word_size
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
                    'nr': sc.nr,
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
    
    def get_auth_boundary(self) -> int:
        """
        Auto-detect auth_boundary: the syscall index of the first accept() call.

        This marks the boundary between pre-auth setup (ld.so, libc init, TCP bind/listen)
        and post-auth business logic.  Mutations BEFORE this index cannot be triggered by
        a remote attacker, so they are excluded from the mutable candidate pool.

        For MIPS O32 targets that route socket ops through the socketcall(2) multiplexer
        (SYS_ACCEPT=5), that call is used instead of a bare accept().

        Returns:
            Index of the first accept/socketcall(SYS_ACCEPT) in the trace, or 0 if not found.
        """
        ACCEPT_NAMES = {'accept', 'accept4'}
        SOCKETCALL_SYS_ACCEPT  = 5   # SYS_ACCEPT  in Linux socketcall(2) numbering
        SOCKETCALL_SYS_ACCEPT4 = 18  # SYS_ACCEPT4

        for sc in self.syscalls:
            if sc.name in ACCEPT_NAMES:
                alog(f"auth_boundary auto-detected: {sc.name}() at index={sc.index}", "TRACE", "INFO")
                return sc.index
            # MIPS O32 socketcall multiplexer: args[0] is the sub-call number
            if sc.name == 'socketcall' and sc.args:
                sub = sc.args[0]
                if sub in (SOCKETCALL_SYS_ACCEPT, SOCKETCALL_SYS_ACCEPT4):
                    alog(f"auth_boundary auto-detected: socketcall(SYS_ACCEPT) at index={sc.index}", "TRACE", "INFO")
                    return sc.index
        alog("auth_boundary not detected (no accept() in trace)", "TRACE", "WARN")
        return 0

    def clear(self):
        """Release memory-intensive trace data"""
        self.syscalls = []
        self.pure_syscalls = []
        self.hybrid_syscalls = []
        self.merged_execution_sequence = []
        if self.bb_trace_parser:
             # BBTraceParser might have internal lists too
             if hasattr(self.bb_trace_parser, 'bb_entries'):
                  self.bb_trace_parser.bb_entries = []
        import gc
        gc.collect()
        self._analyzed = False
        alog(f"[TraceAnalyzer] 🧹 Released memory for {self.trace_file}", "TRACE", "DEBUG")


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


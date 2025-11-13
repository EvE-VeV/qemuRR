#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
系统调用Handler自动生成器

功能：
1. 从syscall_64.tbl解析所有系统调用
2. 自动生成rr_syscall_dispatch.c的handler表
3. 自动分类系统调用类型
4. 生成完整的C代码

作者: RR-Fuzz Team
日期: 2025-11-05
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class SyscallType(Enum):
    """系统调用类型"""
    FILE_IO = "SYSCALL_TYPE_FILE_IO"
    NETWORK = "SYSCALL_TYPE_NETWORK"
    PROCESS = "SYSCALL_TYPE_PROCESS"
    MEMORY = "SYSCALL_TYPE_MEMORY"
    TIME = "SYSCALL_TYPE_TIME"
    SIGNAL = "SYSCALL_TYPE_SIGNAL"
    SYSTEM_INFO = "SYSCALL_TYPE_SYSTEM_INFO"
    IPC = "SYSCALL_TYPE_IPC"
    UNKNOWN = "SYSCALL_TYPE_UNKNOWN"


class SyscallImportance(Enum):
    """系统调用重要性"""
    CRITICAL = "SYSCALL_IMPORTANCE_CRITICAL"
    IMPORTANT = "SYSCALL_IMPORTANCE_IMPORTANT"
    OPTIONAL = "SYSCALL_IMPORTANCE_OPTIONAL"
    ENVIRONMENT = "SYSCALL_IMPORTANCE_ENVIRONMENT"


@dataclass
class SyscallInfo:
    """系统调用信息"""
    number: int
    abi: str  # common, 64, x32
    name: str
    entry_point: str
    
    # 自动推断的属性
    syscall_type: SyscallType = SyscallType.UNKNOWN
    importance: SyscallImportance = SyscallImportance.ENVIRONMENT
    needs_fd_mapping: bool = False
    needs_addr_mapping: bool = False
    is_fd_syscall: bool = False
    
    # Handler函数名
    apply_args_func: str = "apply_generic_args"
    apply_fd_mapping_func: Optional[str] = None
    post_hook_func: str = "generic_post_hook"


class SyscallClassifier:
    """系统调用分类器"""
    
    # 文件I/O相关系统调用
    FILE_IO_SYSCALLS = {
        # 基本文件操作
        'open', 'openat', 'openat2', 'creat', 'close',
        'read', 'write', 'readv', 'writev', 'pread64', 'pwrite64',
        'preadv', 'pwritev', 'preadv2', 'pwritev2',
        
        # 文件属性和状态
        'stat', 'fstat', 'lstat', 'newfstatat', 'statx',
        'access', 'faccessat', 'faccessat2', 'chmod', 'fchmod',
        'fchmodat', 'chown', 'fchown', 'lchown', 'fchownat',
        
        # 目录操作
        'getdents', 'getdents64', 'mkdir', 'mkdirat', 'rmdir',
        'chdir', 'fchdir', 'getcwd',
        
        # 文件控制
        'fcntl', 'ioctl', 'lseek', 'dup', 'dup2', 'dup3',
        'pipe', 'pipe2', 'select', 'pselect6', 'poll', 'ppoll',
        'epoll_create', 'epoll_create1', 'epoll_ctl', 'epoll_wait', 'epoll_pwait',
        
        # 文件系统操作
        'mount', 'umount2', 'statfs', 'fstatfs', 'truncate', 'ftruncate',
        'fallocate', 'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2',
        'link', 'linkat', 'symlink', 'symlinkat', 'readlink', 'readlinkat',
        
        # 同步操作
        'sync', 'syncfs', 'fsync', 'fdatasync',
        
        # 扩展属性
        'getxattr', 'lgetxattr', 'fgetxattr', 'setxattr', 'lsetxattr', 'fsetxattr',
        'listxattr', 'llistxattr', 'flistxattr', 'removexattr', 'lremovexattr', 'fremovexattr',
    }
    
    # 网络相关系统调用
    NETWORK_SYSCALLS = {
        'socket', 'socketpair', 'bind', 'listen', 'accept', 'accept4',
        'connect', 'getsockname', 'getpeername',
        'send', 'sendto', 'sendmsg', 'sendmmsg',
        'recv', 'recvfrom', 'recvmsg', 'recvmmsg',
        'setsockopt', 'getsockopt', 'shutdown',
    }
    
    # 进程管理相关系统调用
    PROCESS_SYSCALLS = {
        'fork', 'vfork', 'clone', 'clone3', 'execve', 'execveat',
        'exit', 'exit_group', 'wait4', 'waitid', 'waitpid',
        'getpid', 'gettid', 'getppid', 'getpgid', 'setpgid',
        'getpgrp', 'setsid', 'getsid',
        'getuid', 'setuid', 'getgid', 'setgid',
        'geteuid', 'setreuid', 'getegid', 'setregid',
        'getresuid', 'setresuid', 'getresgid', 'setresgid',
        'getgroups', 'setgroups',
        'prctl', 'arch_prctl',
        'setns', 'unshare',
        'capget', 'capset',
        'ptrace',
    }
    
    # 内存管理相关系统调用
    MEMORY_SYSCALLS = {
        'mmap', 'munmap', 'mremap', 'mprotect', 'madvise', 'mlock', 'munlock',
        'mlockall', 'munlockall', 'mincore', 'msync',
        'brk', 'sbrk',
        'mmap2',
        'remap_file_pages',
        'mbind', 'get_mempolicy', 'set_mempolicy', 'migrate_pages', 'move_pages',
    }
    
    # 时间相关系统调用
    TIME_SYSCALLS = {
        'time', 'gettimeofday', 'settimeofday',
        'clock_gettime', 'clock_settime', 'clock_getres',
        'clock_nanosleep', 'nanosleep',
        'getitimer', 'setitimer',
        'alarm', 'timer_create', 'timer_settime', 'timer_gettime',
        'timer_getoverrun', 'timer_delete',
        'timerfd_create', 'timerfd_settime', 'timerfd_gettime',
    }
    
    # 信号相关系统调用
    SIGNAL_SYSCALLS = {
        'rt_sigaction', 'rt_sigprocmask', 'rt_sigpending', 'rt_sigtimedwait',
        'rt_sigqueueinfo', 'rt_sigsuspend', 'rt_sigreturn',
        'sigaltstack', 'kill', 'tkill', 'tgkill',
        'signalfd', 'signalfd4',
    }
    
    # IPC相关系统调用
    IPC_SYSCALLS = {
        'msgget', 'msgsnd', 'msgrcv', 'msgctl',
        'semget', 'semop', 'semctl', 'semtimedop',
        'shmget', 'shmat', 'shmdt', 'shmctl',
        'mq_open', 'mq_unlink', 'mq_timedsend', 'mq_timedreceive',
        'mq_notify', 'mq_getsetattr',
        'eventfd', 'eventfd2',
    }
    
    # 系统信息相关系统调用
    SYSTEM_INFO_SYSCALLS = {
        'uname', 'sysinfo', 'syslog', 'klogctl',
        'getrusage', 'getrlimit', 'setrlimit', 'prlimit64',
        'getrandom', 'getcpu',
        'sysfs', 'ustat',
        'personality',
        'set_tid_address', 'set_robust_list', 'get_robust_list',
        'sched_setparam', 'sched_getparam', 'sched_setscheduler',
        'sched_getscheduler', 'sched_get_priority_max', 'sched_get_priority_min',
        'sched_rr_get_interval', 'sched_yield', 'sched_setaffinity', 'sched_getaffinity',
        'umask', 'chroot', 'pivot_root',
        'reboot', 'acct', 'init_module', 'delete_module',
        'quotactl', 'lookup_dcookie',
        'perf_event_open', 'fanotify_init', 'fanotify_mark',
        'name_to_handle_at', 'open_by_handle_at',
        'setdomainname', 'sethostname',
        'ioperm', 'iopl', 'modify_ldt',
        'io_setup', 'io_destroy', 'io_getevents', 'io_submit', 'io_cancel',
        'rseq', 'pidfd_open', 'pidfd_send_signal', 'pidfd_getfd',
    }
    
    # 高优先级（CRITICAL）系统调用
    CRITICAL_SYSCALLS = {
        'read', 'write', 'open', 'openat', 'close',
        'mmap', 'munmap',
        'send', 'sendto', 'recv', 'recvfrom',
        'exit_group', 'writev', 'sendmsg', 'recvmsg',
    }
    
    # 重要（IMPORTANT）系统调用
    IMPORTANT_SYSCALLS = {
        'stat', 'fstat', 'lstat', 'newfstatat',
        'mprotect', 'brk', 'ioctl',
        'socket', 'bind', 'listen', 'accept', 'connect',
        'fork', 'clone', 'execve',
        'pread64', 'pwrite64', 'readv',
        'fcntl', 'dup', 'dup2', 'pipe',
    }
    
    # 需要FD映射的系统调用
    FD_MAPPING_SYSCALLS = {
        'read', 'write', 'readv', 'writev', 'pread64', 'pwrite64',
        'close', 'fstat', 'ioctl', 'fcntl', 'dup', 'dup2', 'dup3',
        'getdents', 'getdents64', 'lseek',
        'fsync', 'fdatasync', 'fchmod', 'fchown', 'ftruncate',
        'fstatfs', 'fchdir', 'flock',
        # 网络相关
        'send', 'sendto', 'sendmsg', 'recv', 'recvfrom', 'recvmsg',
        'bind', 'listen', 'accept', 'accept4', 'connect',
        'getsockname', 'getpeername', 'setsockopt', 'getsockopt', 'shutdown',
        # at系列（第一个参数可能是dirfd）
        'openat', 'mkdirat', 'unlinkat', 'renameat', 'linkat', 'symlinkat',
        'readlinkat', 'fchmodat', 'fchownat', 'faccessat', 'newfstatat',
    }
    
    # 需要地址映射的系统调用
    ADDR_MAPPING_SYSCALLS = {
        'mmap', 'munmap', 'mremap', 'mprotect', 'madvise',
        'msync', 'mincore', 'mlock', 'munlock',
    }
    
    # 产生FD的系统调用（需要在post_hook中建立映射）
    FD_CREATING_SYSCALLS = {
        'open', 'openat', 'openat2', 'creat',
        'socket', 'socketpair', 'accept', 'accept4',
        'dup', 'dup2', 'dup3',
        'pipe', 'pipe2',
        'epoll_create', 'epoll_create1',
        'eventfd', 'eventfd2',
        'signalfd', 'signalfd4',
        'timerfd_create',
        'memfd_create',
        'userfaultfd',
    }
    
    @classmethod
    def classify(cls, syscall_name: str) -> Tuple[SyscallType, SyscallImportance]:
        """分类系统调用"""
        # 确定类型
        if syscall_name in cls.FILE_IO_SYSCALLS:
            syscall_type = SyscallType.FILE_IO
        elif syscall_name in cls.NETWORK_SYSCALLS:
            syscall_type = SyscallType.NETWORK
        elif syscall_name in cls.PROCESS_SYSCALLS:
            syscall_type = SyscallType.PROCESS
        elif syscall_name in cls.MEMORY_SYSCALLS:
            syscall_type = SyscallType.MEMORY
        elif syscall_name in cls.TIME_SYSCALLS:
            syscall_type = SyscallType.TIME
        elif syscall_name in cls.SIGNAL_SYSCALLS:
            syscall_type = SyscallType.SIGNAL
        elif syscall_name in cls.IPC_SYSCALLS:
            syscall_type = SyscallType.IPC
        elif syscall_name in cls.SYSTEM_INFO_SYSCALLS:
            syscall_type = SyscallType.SYSTEM_INFO
        else:
            syscall_type = SyscallType.UNKNOWN
        
        # 确定重要性
        if syscall_name in cls.CRITICAL_SYSCALLS:
            importance = SyscallImportance.CRITICAL
        elif syscall_name in cls.IMPORTANT_SYSCALLS:
            importance = SyscallImportance.IMPORTANT
        elif syscall_name in cls.FD_MAPPING_SYSCALLS or syscall_name in cls.FD_CREATING_SYSCALLS:
            importance = SyscallImportance.IMPORTANT
        elif syscall_type in [SyscallType.FILE_IO, SyscallType.NETWORK, SyscallType.MEMORY]:
            importance = SyscallImportance.OPTIONAL
        else:
            importance = SyscallImportance.ENVIRONMENT
        
        return syscall_type, importance
    
    @classmethod
    def get_handler_functions(cls, syscall_name: str, 
                             syscall_type: SyscallType) -> Tuple[str, Optional[str], str]:
        """获取handler函数名"""
        # apply_args函数
        if syscall_type == SyscallType.FILE_IO:
            apply_args = "apply_file_io_args"
        elif syscall_type == SyscallType.NETWORK:
            apply_args = "apply_network_args"
        elif syscall_type == SyscallType.MEMORY:
            apply_args = "apply_memory_args"
        else:
            apply_args = "apply_generic_args"
        
        # apply_fd_mapping函数
        if syscall_name in cls.FD_MAPPING_SYSCALLS:
            if syscall_type == SyscallType.FILE_IO:
                apply_fd_mapping = "apply_file_io_fd_mapping"
            elif syscall_type == SyscallType.MEMORY:
                apply_fd_mapping = "apply_memory_fd_mapping"
            elif syscall_type == SyscallType.NETWORK:
                apply_fd_mapping = "apply_file_io_fd_mapping"  # 复用
            else:
                apply_fd_mapping = None
        else:
            apply_fd_mapping = None
        
        # post_hook函数
        if syscall_type == SyscallType.FILE_IO or syscall_name in cls.FD_CREATING_SYSCALLS:
            post_hook = "file_io_post_hook"
        elif syscall_type == SyscallType.NETWORK:
            post_hook = "network_post_hook"
        elif syscall_type == SyscallType.MEMORY:
            post_hook = "memory_post_hook"
        else:
            post_hook = "generic_post_hook"
        
        return apply_args, apply_fd_mapping, post_hook


class SyscallTableParser:
    """解析syscall_64.tbl文件"""
    
    def __init__(self, tbl_file: str):
        self.tbl_file = tbl_file
        self.syscalls: List[SyscallInfo] = []
    
    def parse(self) -> List[SyscallInfo]:
        """解析syscall表"""
        with open(self.tbl_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                # 跳过注释和空行
                if not line or line.startswith('#'):
                    continue
                
                # 解析行: <number> <abi> <name> <entry_point>
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                try:
                    number = int(parts[0])
                    abi = parts[1]
                    name = parts[2]
                    entry_point = parts[3]
                    
                    # 分类
                    syscall_type, importance = SyscallClassifier.classify(name)
                    
                    # 获取handler函数
                    apply_args, apply_fd_mapping, post_hook = \
                        SyscallClassifier.get_handler_functions(name, syscall_type)
                    
                    # 判断标志
                    needs_fd_mapping = name in SyscallClassifier.FD_MAPPING_SYSCALLS
                    needs_addr_mapping = name in SyscallClassifier.ADDR_MAPPING_SYSCALLS
                    is_fd_syscall = name in SyscallClassifier.FD_CREATING_SYSCALLS
                    
                    # 创建SyscallInfo
                    info = SyscallInfo(
                        number=number,
                        abi=abi,
                        name=name,
                        entry_point=entry_point,
                        syscall_type=syscall_type,
                        importance=importance,
                        needs_fd_mapping=needs_fd_mapping,
                        needs_addr_mapping=needs_addr_mapping,
                        is_fd_syscall=is_fd_syscall,
                        apply_args_func=apply_args,
                        apply_fd_mapping_func=apply_fd_mapping,
                        post_hook_func=post_hook
                    )
                    
                    self.syscalls.append(info)
                    
                except (ValueError, IndexError) as e:
                    print(f"⚠️  Failed to parse line: {line} ({e})")
                    continue
        
        print(f"✅ Parsed {len(self.syscalls)} syscalls from {self.tbl_file}")
        return self.syscalls


class SyscallHandlerGenerator:
    """生成C代码的handler表"""
    
    def __init__(self, syscalls: List[SyscallInfo]):
        self.syscalls = syscalls
    
    def generate_handler_table(self) -> str:
        """生成handler表的C代码"""
        lines = []
        
        lines.append("/* ==================== 自动生成的系统调用处理表 ==================== */")
        lines.append("/* 此文件由syscall_generator.py自动生成，请勿手动修改 */")
        lines.append("")
        lines.append("static rr_syscall_handler_t syscall_handlers[] = {")
        
        # 按类型分组
        by_type = {}
        for sc in self.syscalls:
            type_name = sc.syscall_type.name
            if type_name not in by_type:
                by_type[type_name] = []
            by_type[type_name].append(sc)
        
        # 生成各类型的handler
        for type_name in ['FILE_IO', 'NETWORK', 'PROCESS', 'MEMORY', 'TIME', 
                          'SIGNAL', 'IPC', 'SYSTEM_INFO', 'UNKNOWN']:
            if type_name not in by_type:
                continue
            
            lines.append(f"    /* {type_name.replace('_', ' ')}类 */")
            
            for sc in by_type[type_name]:
                fd_mapping = sc.apply_fd_mapping_func or "NULL"
                
                line = f'    {{"{sc.name}", {sc.number}, {sc.syscall_type.value}, ' \
                       f'{sc.importance.value},\n' \
                       f'     {sc.apply_args_func}, {fd_mapping}, {sc.post_hook_func}, ' \
                       f'{str(sc.needs_fd_mapping).lower()}, ' \
                       f'{str(sc.needs_addr_mapping).lower()}, ' \
                       f'{str(sc.is_fd_syscall).lower()}}},'
                
                lines.append(line)
            
            lines.append("")
        
        lines.append("    /* 结束标记 */")
        lines.append("    {NULL, -1, SYSCALL_TYPE_UNKNOWN, SYSCALL_IMPORTANCE_ENVIRONMENT, "
                    "NULL, NULL, NULL, false, false, false}")
        lines.append("};")
        lines.append("")
        
        return "\n".join(lines)
    
    def generate_stats(self) -> str:
        """生成统计信息"""
        lines = []
        lines.append("=" * 60)
        lines.append("系统调用Handler生成统计")
        lines.append("=" * 60)
        lines.append(f"\n总计: {len(self.syscalls)} 个系统调用\n")
        
        # 按类型统计
        by_type = {}
        for sc in self.syscalls:
            type_name = sc.syscall_type.name
            by_type[type_name] = by_type.get(type_name, 0) + 1
        
        lines.append("按类型分布:")
        for type_name, count in sorted(by_type.items(), key=lambda x: -x[1]):
            lines.append(f"  {type_name:20s}: {count:4d}")
        
        # 按重要性统计
        by_importance = {}
        for sc in self.syscalls:
            imp_name = sc.importance.name
            by_importance[imp_name] = by_importance.get(imp_name, 0) + 1
        
        lines.append("\n按重要性分布:")
        for imp_name, count in sorted(by_importance.items()):
            lines.append(f"  {imp_name:20s}: {count:4d}")
        
        # 特性统计
        needs_fd = sum(1 for sc in self.syscalls if sc.needs_fd_mapping)
        needs_addr = sum(1 for sc in self.syscalls if sc.needs_addr_mapping)
        creates_fd = sum(1 for sc in self.syscalls if sc.is_fd_syscall)
        
        lines.append("\n特性统计:")
        lines.append(f"  需要FD映射:       {needs_fd:4d}")
        lines.append(f"  需要地址映射:     {needs_addr:4d}")
        lines.append(f"  创建FD:           {creates_fd:4d}")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='系统调用Handler自动生成器')
    parser.add_argument('--tbl', default='../../../x86_64/syscall_64.tbl',
                       help='syscall_64.tbl文件路径')
    parser.add_argument('--output', default='rr_syscall_dispatch_generated.c',
                       help='输出文件路径')
    parser.add_argument('--stats', action='store_true',
                       help='只显示统计信息')
    
    args = parser.parse_args()
    
    # 解析系统调用表
    tbl_file = Path(__file__).parent / args.tbl
    if not tbl_file.exists():
        print(f"❌ 找不到文件: {tbl_file}")
        return 1
    
    print(f"📖 解析系统调用表: {tbl_file}")
    parser_obj = SyscallTableParser(str(tbl_file))
    syscalls = parser_obj.parse()
    
    # 生成代码
    generator = SyscallHandlerGenerator(syscalls)
    
    # 显示统计信息
    print("\n" + generator.generate_stats())
    
    if not args.stats:
        # 生成C代码
        code = generator.generate_handler_table()
        
        output_file = Path(__file__).parent / args.output
        with open(output_file, 'w') as f:
            f.write(code)
        
        print(f"\n✅ 已生成: {output_file}")
        print(f"   共 {len(syscalls)} 个系统调用handler")
    
    return 0


if __name__ == '__main__':
    exit(main())






























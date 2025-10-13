#!/usr/bin/env python3
"""
详细的Fork调试 - 捕获QEMU的完整输出
"""

import os
import sys
import subprocess
import time
import struct
import select
import threading

def read_stream(stream, name, buffer):
    """持续读取流并保存"""
    for line in iter(stream.readline, ''):
        buffer.append(f"[{name}] {line}")
        print(f"[{name}] {line}", end='', flush=True)

def test_fork_with_logs():
    """测试fork并捕获所有日志"""
    print("=" * 60)
    print("详细Fork测试 - 捕获所有QEMU输出")
    print("=" * 60)
    
    qemu_path = '/home/webfuzz/Documents/qemu/build/build-x86-arm-user/bin/qemu-x86_64'
    
    # 创建管道
    cmd_read, cmd_write = os.pipe()
    status_read, status_write = os.pipe()
    
    # 环境变量 - 启用最详细的日志
    env = os.environ.copy()
    env.update({
        'RR_DEBUG_LEVEL': '4',
        'RR_FUZZING_ENABLED': '1',
        'RR_MODE': 'fuzzing',
        'RR_STRACE_MODE': '1',
        'RR_STRACE_LOG_LEVEL': 'DEBUG',
        'RR_TRACE_FILE': '/home/webfuzz/Downloads/strace-ls-record.txt',
        'RR_FORK_SYSCALL': 'openat',
        'RR_CMD_PIPE': str(cmd_read),
        'RR_STATUS_PIPE': str(status_write),
        'RR_LOG_LEVEL': '4',
    })
    
    print(f"启动QEMU: {qemu_path}")
    proc = subprocess.Popen(
        [qemu_path, '/usr/bin/ls'],
        env=env,
        pass_fds=[cmd_read, status_write],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    # 启动线程读取输出
    stdout_lines = []
    stderr_lines = []
    
    stdout_thread = threading.Thread(target=read_stream, args=(proc.stdout, 'STDOUT', stdout_lines))
    stderr_thread = threading.Thread(target=read_stream, args=(proc.stderr, 'STDERR', stderr_lines))
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()
    
    time.sleep(0.5)
    
    def read_status(timeout=5):
        ready, _, _ = select.select([status_read], [], [], timeout)
        if not ready:
            return None, "TIMEOUT"
        try:
            data = os.read(status_read, 4)
            if not data:
                return None, "CLOSED"
            status = struct.unpack('i', data)[0]
            names = {1: "Ready", 2: "At Fork Point", 3: "Normal Exit", 4: "Crash", 5: "Signal", -1: "Error"}
            return status, names.get(status, f"Unknown({status})")
        except Exception as e:
            return None, f"ERROR: {e}"
    
    # 1. 等待Ready
    print("\n" + "=" * 60)
    print("步骤1: 等待Ready状态")
    print("=" * 60)
    status, name = read_status(3)
    print(f"状态: {status} ({name})")
    
    if status != 1:
        print("初始化失败！")
        proc.kill()
        return
    
    # 2. 第一个F
    print("\n" + "=" * 60)
    print("步骤2: 发送第1个'F'命令")
    print("=" * 60)
    os.write(cmd_write, b'F')
    print("已发送'F'")
    
    status, name = read_status(5)
    print(f"状态: {status} ({name})")
    
    # 3. 第二个F - 真正的fork
    print("\n" + "=" * 60)
    print("步骤3: 发送第2个'F'命令 (触发实际fork)")
    print("=" * 60)
    os.write(cmd_write, b'F')
    print("已发送'F'")
    print("等待子进程执行...")
    
    # 等待更长时间，观察日志
    for i in range(15):
        print(f"  等待中... {i+1}/15秒")
        time.sleep(1)
        
        # 检查是否有状态
        ready, _, _ = select.select([status_read], [], [], 0.1)
        if ready:
            try:
                data = os.read(status_read, 4)
                if data:
                    status = struct.unpack('i', data)[0]
                    names = {1: "Ready", 2: "At Fork Point", 3: "Normal Exit", 4: "Crash", 5: "Signal", -1: "Error"}
                    print(f"\n  ✓ 收到状态: {status} ({names.get(status, 'Unknown')})")
                    break
            except:
                pass
    else:
        print("\n  ✗ 15秒后仍无响应")
    
    # 清理
    print("\n" + "=" * 60)
    print("清理...")
    print("=" * 60)
    try:
        os.write(cmd_write, b'Q')
        proc.wait(timeout=2)
    except:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            proc.kill()
    
    # 等待线程
    time.sleep(0.5)
    
    # 分析stderr
    print("\n" + "=" * 60)
    print("STDERR日志分析")
    print("=" * 60)
    
    print("\n🔍 查找子进程相关日志:")
    child_lines = [l for l in stderr_lines if 'child' in l.lower() or 'Child' in l or 'fork' in l.lower()]
    for line in child_lines[-30:]:
        print(line.strip())
    
    print("\n🔍 查找trace耗尽日志:")
    exhausted_lines = [l for l in stderr_lines if 'exhausted' in l.lower() or 'Exhausted' in l]
    for line in exhausted_lines:
        print(line.strip())
    
    print("\n🔍 查找退出相关日志:")
    exit_lines = [l for l in stderr_lines if 'exit' in l.lower() or 'Exit' in l]
    for line in exit_lines[-20:]:
        print(line.strip())
    
    print("\n🔍 最后30行STDERR:")
    for line in stderr_lines[-30:]:
        print(line.strip())
    
    # 关闭
    os.close(cmd_read)
    os.close(cmd_write)
    os.close(status_read)
    os.close(status_write)

if __name__ == '__main__':
    test_fork_with_logs()


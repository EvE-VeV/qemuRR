#!/usr/bin/env python3
"""
测试多次Fork命令 - 找出为什么第二次卡住
"""

import os
import sys
import subprocess
import time
import struct
import select

def test_multiple_forks():
    """测试连续多次发送F命令"""
    print("=" * 60)
    print("测试: 连续发送多个F命令")
    print("=" * 60)
    
    # 查找QEMU
    qemu_path = '/home/webfuzz/Documents/qemu/build/build-x86-arm-user/bin/qemu-x86_64'
    if not os.path.exists(qemu_path):
        qemu_path = '/usr/bin/qemu-x86_64'
    
    if not os.path.exists(qemu_path):
        print("✗ 找不到qemu-x86_64")
        return
    
    print(f"✓ QEMU路径: {qemu_path}")
    
    # 创建管道
    cmd_read, cmd_write = os.pipe()
    status_read, status_write = os.pipe()
    
    # 环境变量
    env = os.environ.copy()
    env.update({
        'RR_DEBUG_LEVEL': '4',
        'RR_FUZZING_ENABLED': '1',
        'RR_MODE': 'fuzzing',
        'RR_STRACE_MODE': '1',
        'RR_TRACE_FILE': '/home/webfuzz/Downloads/strace-ls-record.txt',
        'RR_FORK_SYSCALL': 'openat',
        'RR_CMD_PIPE': str(cmd_read),
        'RR_STATUS_PIPE': str(status_write),
        'RR_LOG_LEVEL': '4',
    })
    
    print(f"✓ 启动QEMU...")
    proc = subprocess.Popen(
        [qemu_path, '/usr/bin/ls'],
        env=env,
        pass_fds=[cmd_read, status_write],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    print(f"✓ QEMU PID={proc.pid}")
    time.sleep(0.5)
    
    # 状态名称映射
    status_names = {
        1: "Ready",
        2: "At Fork Point",
        3: "Normal Exit",
        4: "Crash",
        5: "Signal",
        -1: "Error"
    }
    
    def read_status(timeout=5):
        """读取状态消息"""
        ready, _, _ = select.select([status_read], [], [], timeout)
        if not ready:
            return None, "TIMEOUT"
        
        try:
            data = os.read(status_read, 4)
            if not data:
                return None, "CLOSED"
            status = struct.unpack('i', data)[0]
            return status, status_names.get(status, f"Unknown({status})")
        except Exception as e:
            return None, f"ERROR: {e}"
    
    # 初始状态
    print(f"\n1️⃣ 等待初始Ready状态...")
    status, name = read_status(timeout=3)
    if status:
        print(f"   ✓ 收到: {status} ({name})")
    else:
        print(f"   ✗ {name}")
        proc.kill()
        return
    
    # 第一次F命令
    print(f"\n2️⃣ 发送第1个'F'命令...")
    os.write(cmd_write, b'F')
    print(f"   ✓ 已发送")
    
    status, name = read_status(timeout=5)
    if status:
        print(f"   ✓ 收到响应: {status} ({name})")
    else:
        print(f"   ✗ 没有响应: {name}")
    
    # 第二次F命令
    print(f"\n3️⃣ 发送第2个'F'命令...")
    os.write(cmd_write, b'F')
    print(f"   ✓ 已发送")
    
    print(f"   等待响应 (超时=10秒)...")
    status, name = read_status(timeout=10)
    if status:
        print(f"   ✓ 收到响应: {status} ({name})")
    else:
        print(f"   ✗ 没有响应: {name}")
        print(f"   ⚠️  这就是问题所在！")
        
        # 检查QEMU进程状态
        poll = proc.poll()
        if poll is None:
            print(f"   📌 QEMU进程仍在运行 (PID={proc.pid})")
            print(f"   📌 可能卡在fork server循环中等待子进程")
        else:
            print(f"   📌 QEMU进程已退出 (返回码={poll})")
    
    # 第三次尝试
    if status:
        print(f"\n4️⃣ 发送第3个'F'命令...")
        os.write(cmd_write, b'F')
        status, name = read_status(timeout=10)
        if status:
            print(f"   ✓ 收到响应: {status} ({name})")
        else:
            print(f"   ✗ 没有响应: {name}")
    
    # 清理
    print(f"\n5️⃣ 清理...")
    try:
        os.write(cmd_write, b'Q')
        proc.wait(timeout=2)
    except:
        print(f"   发送SIGTERM...")
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            print(f"   发送SIGKILL...")
            proc.kill()
    
    stdout, stderr = proc.communicate()
    
    # 分析stderr
    print(f"\n" + "=" * 60)
    print("QEMU STDERR 分析")
    print("=" * 60)
    
    # 查找关键信息
    lines = stderr.split('\n')
    
    print(f"\n🔍 查找fork相关日志:")
    fork_lines = [l for l in lines if 'fork' in l.lower() or 'Fork' in l or 'child' in l.lower()]
    for line in fork_lines[:20]:
        print(f"   {line}")
    
    print(f"\n🔍 查找系统调用执行日志:")
    syscall_lines = [l for l in lines if 'syscall' in l.lower() or 'openat' in l]
    for line in syscall_lines[:20]:
        print(f"   {line}")
    
    print(f"\n🔍 查找错误/警告:")
    error_lines = [l for l in lines if 'ERROR' in l or 'WARN' in l or 'Failed' in l]
    for line in error_lines[:20]:
        print(f"   {line}")
    
    print(f"\n📄 完整STDERR (最后100行):")
    print('\n'.join(lines[-100:]))
    
    # 关闭管道
    os.close(cmd_read)
    os.close(cmd_write)
    os.close(status_read)
    os.close(status_write)
    
    print(f"\n✓ 测试完成")


if __name__ == '__main__':
    test_multiple_forks()


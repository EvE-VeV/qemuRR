#!/usr/bin/env python3
"""
IPC调试测试脚本 - 验证Python和QEMU之间的通信
"""

import os
import sys
import subprocess
import time
import select

def test_basic_pipes():
    """测试1: 基本的管道通信"""
    print("=" * 60)
    print("测试1: 验证管道通信基础功能")
    print("=" * 60)
    
    # 创建管道
    cmd_read, cmd_write = os.pipe()
    status_read, status_write = os.pipe()
    
    print(f"✓ 创建了管道:")
    print(f"  - 命令管道: {cmd_read} (读) -> {cmd_write} (写)")
    print(f"  - 状态管道: {status_read} (读) <- {status_write} (写)")
    
    # 测试写入和读取
    os.write(cmd_write, b'F')
    data = os.read(cmd_read, 1)
    print(f"✓ 管道读写测试: 写入'F', 读取'{data.decode()}'")
    
    # 清理
    os.close(cmd_read)
    os.close(cmd_write)
    os.close(status_read)
    os.close(status_write)
    print()


def test_qemu_startup():
    """测试2: QEMU进程启动和环境变量传递"""
    print("=" * 60)
    print("测试2: 验证QEMU进程启动")
    print("=" * 60)
    
    # 查找QEMU可执行文件
    qemu_paths = [
        '/home/webfuzz/Documents/qemu/build/build-x86-arm-user/bin/qemu-x86_64',
        '/usr/bin/qemu-x86_64',
    ]
    
    qemu_path = None
    for path in qemu_paths:
        if os.path.exists(path):
            qemu_path = path
            break
    
    if not qemu_path:
        print("✗ 找不到qemu-x86_64可执行文件")
        return False
    
    print(f"✓ 找到QEMU: {qemu_path}")
    
    # 创建管道
    cmd_read, cmd_write = os.pipe()
    status_read, status_write = os.pipe()
    
    # 设置环境变量
    env = os.environ.copy()
    env.update({
        'RR_DEBUG_LEVEL': '4',  # 最高调试级别
        'RR_FUZZING_ENABLED': '1',
        'RR_MODE': 'fuzzing',
        'RR_STRACE_MODE': '1',
        'RR_TRACE_FILE': '/home/webfuzz/Downloads/strace-ls-record.txt',
        'RR_FORK_SYSCALL': 'openat',
        'RR_CMD_PIPE': str(cmd_read),
        'RR_STATUS_PIPE': str(status_write),
        'RR_LOG_LEVEL': '4',
    })
    
    print(f"✓ 设置环境变量:")
    for key in ['RR_MODE', 'RR_TRACE_FILE', 'RR_FORK_SYSCALL', 'RR_CMD_PIPE', 'RR_STATUS_PIPE']:
        print(f"  - {key} = {env[key]}")
    
    # 启动QEMU
    print(f"\n启动QEMU进程...")
    proc = subprocess.Popen(
        [qemu_path, '/usr/bin/ls'],
        env=env,
        pass_fds=[cmd_read, status_write],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    print(f"✓ QEMU进程已启动 (PID={proc.pid})")
    
    # 等待一下让QEMU初始化
    time.sleep(1)
    
    # 检查进程是否还活着
    poll_result = proc.poll()
    if poll_result is not None:
        print(f"✗ QEMU进程已退出 (返回码={poll_result})")
        stdout, stderr = proc.communicate()
        print("\n--- STDOUT ---")
        print(stdout[:500])
        print("\n--- STDERR ---")
        print(stderr[:1000])
        return False
    
    print(f"✓ QEMU进程运行中")
    
    # 检查是否有状态消息
    print(f"\n检查是否收到状态消息...")
    # 设置非阻塞模式
    import fcntl
    fl = fcntl.fcntl(status_read, fcntl.F_GETFL)
    fcntl.fcntl(status_read, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    
    try:
        status_data = os.read(status_read, 4)
        if status_data:
            import struct
            status = struct.unpack('i', status_data)[0]
            status_names = {1: "Ready", 2: "At Fork Point", 3: "Normal Exit", 
                          4: "Crash", 5: "Signal", -1: "Error"}
            print(f"✓ 收到状态消息: {status} ({status_names.get(status, 'Unknown')})")
        else:
            print("  (没有立即可读的状态)")
    except BlockingIOError:
        print("  (没有立即可读的状态)")
    
    # 尝试发送F命令
    print(f"\n发送'F'命令...")
    os.write(cmd_write, b'F')
    print(f"✓ 已发送'F'")
    
    # 等待响应 (最多5秒)
    print(f"等待响应...")
    import select
    ready, _, _ = select.select([status_read], [], [], 5.0)
    
    if ready:
        try:
            status_data = os.read(status_read, 4)
            if status_data:
                import struct
                status = struct.unpack('i', status_data)[0]
                status_names = {1: "Ready", 2: "At Fork Point", 3: "Normal Exit", 
                              4: "Crash", 5: "Signal", -1: "Error"}
                print(f"✓ 收到响应: {status} ({status_names.get(status, 'Unknown')})")
            else:
                print("✗ 管道关闭")
        except Exception as e:
            print(f"✗ 读取错误: {e}")
    else:
        print("✗ 5秒内没有收到响应 - QEMU可能卡住了")
    
    # 清理
    print(f"\n清理资源...")
    try:
        os.write(cmd_write, b'Q')
        proc.wait(timeout=2)
    except:
        proc.kill()
    
    stdout, stderr = proc.communicate()
    
    print("\n--- QEMU STDERR (前2000字符) ---")
    print(stderr[:2000])
    
    # 关闭管道
    os.close(cmd_read)
    os.close(cmd_write)
    os.close(status_read)
    os.close(status_write)
    
    print("\n✓ 测试完成")
    return True


def main():
    print("\n" + "=" * 60)
    print("RR-Fuzz IPC 调试测试")
    print("=" * 60 + "\n")
    
    # 测试1: 基本管道
    test_basic_pipes()
    
    # 测试2: QEMU启动和通信
    test_qemu_startup()
    
    print("\n" + "=" * 60)
    print("所有测试完成")
    print("=" * 60)


if __name__ == '__main__':
    main()


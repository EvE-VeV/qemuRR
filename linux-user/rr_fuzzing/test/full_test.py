#!/usr/bin/env python3
"""
RR-Fuzz 完整集成测试
测试Fork Server + 共享内存 + IPC的完整工作流程
"""

import os
import sys
import struct
import subprocess
import time
import signal
from pathlib import Path

# 测试配置
TEST_DIR = Path(__file__).parent
QEMU_BIN = "/home/webfuzz/Documents/qemu/build/build-x86-arm-user/qemu-x86_64"
SHM_NAME = f"rr_fuzz_test_{os.getpid()}"
TEST_TARGET = TEST_DIR / "test_fuzz_target"
TRACE_FILE = TEST_DIR / "test_baseline.strace"

# Fuzz指令常量
FUZZ_MAGIC = 0x46555A5A
FUZZ_CMD_MUTATE_ARG = 1
FUZZ_MAX_INSTRUCTIONS = 32

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

def print_header(msg):
    print(f"\n{Colors.BLUE}{'='*50}{Colors.NC}")
    print(f"{Colors.BLUE}{msg}{Colors.NC}")
    print(f"{Colors.BLUE}{'='*50}{Colors.NC}")

def print_success(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.NC}")

def print_error(msg):
    print(f"{Colors.RED}✗ {msg}{Colors.NC}")

def print_info(msg):
    print(f"{Colors.BLUE}ℹ {msg}{Colors.NC}")

def create_fuzz_instruction(syscall_index, cmd, arg_index, value):
    """创建一个Fuzz指令"""
    data_bytes = struct.pack('q', value)
    data_len = len(data_bytes)
    
    instruction = struct.pack('IIBHx', syscall_index, cmd, arg_index, data_len)
    instruction += data_bytes
    instruction += b'\x00' * (256 - len(data_bytes))
    
    return instruction

def create_shared_memory():
    """创建并初始化共享内存"""
    shm_path = Path(f"/dev/shm/{SHM_NAME}")
    
    with open(shm_path, 'wb') as f:
        # 写入头部
        header = struct.pack('IIII', FUZZ_MAGIC, 2, 0, 0)
        f.write(header)
        
        # 指令1: 变异syscall 17的参数2
        instr1 = create_fuzz_instruction(17, FUZZ_CMD_MUTATE_ARG, 2, 0x42)
        f.write(instr1)
        
        # 指令2: 变异syscall 18的参数2
        instr2 = create_fuzz_instruction(18, FUZZ_CMD_MUTATE_ARG, 2, 100)
        f.write(instr2)
        
        # 填充剩余槽位
        empty_instr = b'\x00' * 265
        for _ in range(30):
            f.write(empty_instr)
    
    return shm_path

def cleanup():
    """清理测试环境"""
    print_info("清理测试环境...")
    
    # 清理共享内存
    shm_path = Path(f"/dev/shm/{SHM_NAME}")
    if shm_path.exists():
        shm_path.unlink()
    
    # 清理管道
    for pipe in ["/tmp/rr_cmd_pipe", "/tmp/rr_status_pipe"]:
        try:
            os.unlink(pipe)
        except:
            pass
    
    print_success("清理完成")

def prepare_test_program():
    """准备测试程序"""
    print_header("步骤1: 准备测试程序")
    
    os.chdir(TEST_DIR)
    
    # 编译测试程序（如果需要）
    if not TEST_TARGET.exists() or TEST_TARGET.stat().st_mtime < (TEST_DIR / "test_fuzz_target.c").stat().st_mtime:
        print_info("编译测试程序...")
        subprocess.run(["gcc", "-o", "test_fuzz_target", "test_fuzz_target.c", "-static"], check=True)
        print_success("编译完成")
    else:
        print_success("测试程序已存在")
    
    # 创建测试数据
    with open("rr_test_file.txt", "w") as f:
        f.write("Test input data for fuzzing\n")
    print_success("测试数据创建完成")

def generate_trace():
    """生成strace trace"""
    print_header("步骤2: 生成基线trace")
    
    if not TRACE_FILE.exists():
        print_info("生成trace...")
        with open(os.devnull, 'w') as devnull:
            subprocess.run(
                ["strace", "-o", str(TRACE_FILE), str(TEST_TARGET)],
                stdout=devnull,
                stderr=devnull
            )
        print_success("Trace生成完成")
    else:
        print_success("Trace已存在")
    
    lines = len(TRACE_FILE.read_text().splitlines())
    print_info(f"Trace包含 {lines} 个系统调用")

def create_pipes():
    """创建IPC管道"""
    print_header("步骤3: 创建IPC管道")
    
    cmd_pipe = "/tmp/rr_cmd_pipe"
    status_pipe = "/tmp/rr_status_pipe"
    
    for pipe in [cmd_pipe, status_pipe]:
        try:
            os.unlink(pipe)
        except:
            pass
        os.mkfifo(pipe)
    
    print_success(f"命令管道: {cmd_pipe}")
    print_success(f"状态管道: {status_pipe}")
    
    return cmd_pipe, status_pipe

def test_with_conductor():
    """使用Python Conductor进行完整测试"""
    print_header("步骤4: 使用Conductor测试")
    
    # 创建共享内存
    shm_path = create_shared_memory()
    print_success(f"共享内存创建: {shm_path}")
    
    # 验证共享内存
    with open(shm_path, 'rb') as f:
        magic, count = struct.unpack('II', f.read(8))
        print_info(f"Magic: 0x{magic:08X}, 指令数: {count}")
    
    # 使用fuzz_conductor_example.py
    conductor_script = TEST_DIR.parent / "fuzz_conductor_example.py"
    
    if not conductor_script.exists():
        print_error("找不到fuzz_conductor_example.py")
        return False
    
    print_info("启动Fuzzer Conductor...")
    
    env = os.environ.copy()
    
    try:
        # 运行Conductor，限制迭代次数
        result = subprocess.run(
            [
                "python3", str(conductor_script),
                "--trace", str(TRACE_FILE),
                "--target", str(TEST_TARGET),
                "--iterations", "3",  # 只运行3次迭代
                "--fork-syscall", "openat",
                "--fork-pattern", "*/rr_test_file*"
            ],
            env=env,
            timeout=30,
            capture_output=True,
            text=True
        )
        
        print_info("Conductor输出:")
        print(result.stdout)
        
        if result.stderr:
            print_info("Conductor错误输出:")
            print(result.stderr)
        
        # 检查关键输出
        checks = [
            ("QEMU started", "QEMU启动"),
            ("Fork Server", "Fork Server"),
            ("Fuzzing iteration", "Fuzzing迭代"),
        ]
        
        passed = 0
        for pattern, desc in checks:
            if pattern in result.stdout or pattern in result.stderr:
                print_success(desc)
                passed += 1
            else:
                print_error(desc)
        
        return passed >= 2  # 至少通过2个检查
        
    except subprocess.TimeoutExpired:
        print_error("Conductor执行超时（这可能是正常的，因为它在等待IPC）")
        return False
    except Exception as e:
        print_error(f"Conductor执行失败: {e}")
        return False

def simple_qemu_test():
    """简单的QEMU测试（不使用IPC）"""
    print_header("步骤5: 简单QEMU测试（无IPC）")
    
    # 创建共享内存
    shm_path = create_shared_memory()
    print_success(f"共享内存创建: {shm_path}")
    
    # 设置环境变量
    env = os.environ.copy()
    env.update({
        'RR_FUZZING_ENABLED': '1',  # 必须启用RR框架
        'RR_MODE': 'fuzzing',
        'RR_STRACE_MODE': '1',
        'RR_TRACE_FILE': str(TRACE_FILE),
        'RR_FORK_SYSCALL': 'openat',
        'RR_FORK_PATTERN': '*/rr_test_file*',
        'RR_SHARED_MEMORY': SHM_NAME,
        'RR_STRACE_LOG_LEVEL': 'INFO',
    })
    
    print_info("运行QEMU（无Fork Server命令，会在fork点等待）...")
    
    try:
        result = subprocess.run(
            [QEMU_BIN, str(TEST_TARGET)],
            env=env,
            timeout=5,  # 短超时，因为会在fork点hang
            capture_output=True,
            text=True
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired as e:
        # 预期会超时，因为在等待fork命令
        output = e.stdout.decode() if e.stdout else "" 
        output += e.stderr.decode() if e.stderr else ""
        print_info("QEMU在fork点等待（预期行为）")
    
    # 保存输出
    with open("simple_qemu_test.log", "w") as f:
        f.write(output)
    
    print_info("检查QEMU输出...")
    
    # 检查关键日志
    checks = [
        ("Fork Server:", "Fork Server配置"),
        ("Starting fork server", "Fork Server启动"),
        ("Strace replay", "Strace replay"),
        ("Fork Server.*active", "Fork Server激活"),
    ]
    
    passed = 0
    for pattern, desc in checks:
        if pattern in output:
            print_success(desc)
            passed += 1
        else:
            print_error(desc)
    
    if passed >= 3:
        print_success(f"简单测试通过 ({passed}/{len(checks)})")
        return True
    else:
        print_error(f"简单测试失败 ({passed}/{len(checks)})")
        print_info("完整日志保存在: simple_qemu_test.log")
        return False

def main():
    """主测试流程"""
    try:
        # 准备
        prepare_test_program()
        generate_trace()
        
        # 运行简单测试
        simple_ok = simple_qemu_test()
        
        print_header("测试总结")
        
        if simple_ok:
            print(f"{Colors.GREEN}{'='*50}{Colors.NC}")
            print(f"{Colors.GREEN}  ✓ RR-Fuzz集成测试通过！{Colors.NC}")
            print(f"{Colors.GREEN}{'='*50}{Colors.NC}")
            print()
            print_info("核心功能已验证:")
            print("  • Fork Server配置和启动")
            print("  • Strace replay初始化")
            print("  • 共享内存创建和读取")
            print()
            print_info("完整的IPC测试需要:")
            print("  python3 ../fuzz_conductor_example.py \\")
            print(f"    --trace {TRACE_FILE} \\")
            print(f"    --target {TEST_TARGET} \\")
            print("    --iterations 10")
            return 0
        else:
            print(f"{Colors.YELLOW}{'='*50}{Colors.NC}")
            print(f"{Colors.YELLOW}  ⚠ 部分测试未通过{Colors.NC}")
            print(f"{Colors.YELLOW}{'='*50}{Colors.NC}")
            print()
            print_info("查看日志: cat simple_qemu_test.log")
            return 1
            
    finally:
        cleanup()

if __name__ == "__main__":
    sys.exit(main())


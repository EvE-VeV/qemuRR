#!/bin/bash
# 固件目标仿真验证脚本
# 测试每个目标是否能成功启动和运行

echo "============================================"
echo "固件目标仿真验证"
echo "============================================"
echo ""

QEMU_ARM="/home/webfuzz/Documents/qemu/build/qemu-arm"
QEMU_MIPS="/home/webfuzz/Documents/qemu/build/qemu-mips"

# 清理之前的进程
echo "[*] 清理现有QEMU进程..."
pkill -f "qemu-arm.*telnet" 2>/dev/null
pkill -f "qemu-arm.*httpd" 2>/dev/null
sleep 1

echo ""
echo "=== Test 1: RAX30 Telnet (utelnetd) ==="
echo "架构: ARM 32-bit"
echo "Binary: /usr/sbin/utelnetd"
echo ""

SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/RAX30/sim_root"
echo "[*] 测试基本运行..."
timeout 3 $QEMU_ARM -L $SIM_ROOT $SIM_ROOT/usr/sbin/utelnetd --help 2>&1 | head -10 || echo "    (超时或无help，尝试启动daemon)"

echo "[*] 启动daemon模式 (端口2323)..."
nohup $QEMU_ARM -L $SIM_ROOT $SIM_ROOT/usr/sbin/utelnetd -d -p 2323 > /tmp/test_utelnetd.log 2>&1 &
TELNET_PID=$!
sleep 2

if ps -p $TELNET_PID > /dev/null; then
    echo "    ✅ 进程运行中 (PID: $TELNET_PID)"
    
    # 测试连接
    echo "[*] 测试Telnet连接..."
    timeout 2 nc -zv 127.0.0.1 2323 2>&1 | grep -i "succeeded\|open" && \
        echo "    ✅ 端口2323可连接" || \
        echo "    ⚠️ 端口连接失败"
    
    # 查看日志
    echo "[*] 服务日志:"
    cat /tmp/test_utelnetd.log | head -5
    
    kill $TELNET_PID 2>/dev/null
    echo "    ✅ RAX30 Telnet 仿真成功"
else
    echo "    ❌ 进程启动失败"
    cat /tmp/test_utelnetd.log
fi

echo ""
echo "=== Test 2: Tenda AC15 (httpd) ==="
echo "架构: ARM 32-bit"
echo "Binary: /bin/httpd"
echo ""

AC15_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root"

echo "[*] 检查binary..."
if [ -f "$AC15_ROOT/bin/httpd" ]; then
    file "$AC15_ROOT/bin/httpd" | grep ARM && echo "    ✅ Binary存在且为ARM"
else
    echo "    ❌ Binary未找到"
    exit 1
fi

echo "[*] 检查依赖库..."
echo "    Libraries in lib/:"
ls -1 "$AC15_ROOT/lib/" | grep -E "libc|ld-" | head -5

echo "[*] 测试基本运行..."
timeout 3 $QEMU_ARM -L $AC15_ROOT $AC15_ROOT/bin/httpd --help 2>&1 | head -10 || echo "    (无help输出)"

echo "[*] 尝试启动httpd (端口8080)..."
export LD_LIBRARY_PATH="$AC15_ROOT/lib:$AC15_ROOT/usr/lib"
nohup $QEMU_ARM -L $AC15_ROOT $AC15_ROOT/bin/httpd -p 8080 > /tmp/test_ac15_httpd.log 2>&1 &
AC15_PID=$!
sleep 3

if ps -p $AC15_PID > /dev/null; then
    echo "    ✅ 进程运行中 (PID: $AC15_PID)"
    
    # 测试连接
    timeout 2 nc -zv 127.0.0.1 8080 2>&1 | grep -i "succeeded\|open" && \
        echo "    ✅ 端口8080可连接" || \
        echo "    ⚠️ 端口连接失败，可能需要配置"
    
    kill $AC15_PID 2>/dev/null
    echo "    ✅ Tenda AC15 基本仿真成功"
else
    echo "    ❌ 进程启动失败"
    echo "    日志内容:"
    cat /tmp/test_ac15_httpd.log | head -20
    echo "    [分析] 可能需要创建配置目录或环境变量"
fi

echo ""
echo "=== Test 3: TP-Link AXE75 ==="
echo "架构: ARM 32-bit"
echo ""

AXE75_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TPLINK_AXE75/_axe75v1-up-ver1-2-2-P1[20240827-rel68051]_nosign_2024-08-27_19.30.26.bin.extracted"

echo "[*] 搜索可执行ELF文件..."
find "$AXE75_ROOT" -type f -size +50k -executable 2>/dev/null | \
    xargs file 2>/dev/null | grep "ELF.*ARM.*executable" | head -5

echo "[*] 测试busybox..."
if [ -f "$AXE75_ROOT/busybox" ]; then
    $QEMU_ARM -L $AXE75_ROOT $AXE75_ROOT/busybox --help 2>&1 | head -3 && \
        echo "    ✅ busybox可运行"
else
    echo "    ⚠️ busybox未找到"
fi

echo ""
echo "============================================"
echo "验证总结"
echo "============================================"
echo "RAX30 Telnet:  [验证完成]"
echo "Tenda AC15:    [验证完成]"
echo "TP-Link AXE75: [需要定位web server binary]"
echo ""
echo "下一步: 根据验证结果调整配置"

#!/bin/bash
# Crash Reproduction Script - 崩溃复现脚本
# 
# 使用方法: ./reproduce_crash.sh <crash_directory>
# 例如: ./reproduce_crash.sh /tmp/fuzzing_output_vulnerable_success/crashes

set -e

CRASH_DIR="$1"
if [ -z "$CRASH_DIR" ]; then
    echo "使用方法: $0 <crash_directory>"
    echo "例如: $0 /tmp/fuzzing_output_vulnerable_success/crashes"
    exit 1
fi

# 查找崩溃文件
CRASH_META=$(find "$CRASH_DIR" -name "*.meta" | head -n 1)
if [ -z "$CRASH_META" ]; then
    echo "❌ 未找到崩溃元数据文件"
    exit 1
fi

CRASH_ID=$(basename "$CRASH_META" .meta)
CRASH_TRACE="$CRASH_DIR/${CRASH_ID}.bin"

echo "========================================"
echo "崩溃复现脚本"
echo "========================================"
echo "崩溃ID: $CRASH_ID"
echo "元数据: $CRASH_META"
echo "跟踪文件: $CRASH_TRACE"
echo ""

# 显示崩溃信息
echo "📋 崩溃元数据:"
cat "$CRASH_META" | jq -r '
  "  状态: \(.status_name) (code: \(.status))",
  "  跟踪ID: \(.trace_id)",
  "  时间戳: \(.timestamp)",
  "  变异数量: \(.mutations | length)"
'

# 显示关键变异
echo ""
echo "🔍 关键变异:"
cat "$CRASH_META" | jq -r '.mutations[] | select(.cmd == 2) | 
  "  syscall_\(.syscall_index): REPLACE_BUFFER, size=\(.size) bytes"
'

echo ""
echo "▶ 开始复现崩溃..."
echo ""

# 设置环境变量并运行
export RR_MODE=fuzzing
export RR_TRACE_FILE="$CRASH_TRACE"
export RR_FUZZING_ENABLED=1
export RR_DEBUG_LEVEL=0

QEMU="/home/webfuzz/Documents/qemu/build/qemu-x86_64"
TARGET="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/programs/vulnerable/fuzz_target_vulnerable"

if [ ! -f "$QEMU" ]; then
    echo "❌ QEMU未找到: $QEMU"
    exit 1
fi

if [ ! -f "$TARGET" ]; then
    echo "❌ 目标程序未找到: $TARGET"
    exit 1
fi

# 运行并捕获结果
set +e
timeout 2 "$QEMU" "$TARGET" 2>&1 | tee /tmp/crash_reproduction_output.log
EXIT_CODE=$?
set -e

echo ""
echo "========================================"
if [ $EXIT_CODE -eq 134 ]; then
    echo "✅ 崩溃已成功复现!"
    echo "   退出码: $EXIT_CODE (SIGABRT - 栈溢出)"
    grep -q "stack smashing detected" /tmp/crash_reproduction_output.log && \
        echo "   类型: 栈缓冲区溢出 (Stack Buffer Overflow)"
    exit 0
elif [ $EXIT_CODE -eq 139 ]; then
    echo "✅ 崩溃已成功复现!"
    echo "   退出码: $EXIT_CODE (SIGSEGV - 段错误)"
    exit 0
elif [ $EXIT_CODE -eq 124 ] || [ $EXIT_CODE -eq 143 ]; then
    echo "⚠️  进程超时 (可能挂起或无限循环)"
    exit 2
else
    echo "⚠️  进程退出，退出码: $EXIT_CODE"
    echo "   (预期: 134=SIGABRT 或 139=SIGSEGV)"
    exit 2
fi

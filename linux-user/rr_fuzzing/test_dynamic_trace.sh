#!/bin/bash
# 测试动态跟踪功能

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU_PATH="${SCRIPT_DIR}/../../build/build-x86-arm-user/bin/qemu-x86_64"
PIPE_PATH="/tmp/rr_dynamic_trace_test_$$"
OUTPUT_HTML="${HOME}/test_fuzzing_tree.html"

# 全局变量用于cleanup
VISUALIZER_PID=""
FUZZER_PID=""

# Cleanup函数
cleanup() {
    echo ""
    echo "🛑 收到中断信号，正在清理..."
    
    # 停止fuzzer
    if [ -n "$FUZZER_PID" ] && kill -0 $FUZZER_PID 2>/dev/null; then
        echo "   停止Fuzzer (PID=$FUZZER_PID)..."
        kill -SIGTERM $FUZZER_PID 2>/dev/null || true
        sleep 2
        kill -SIGKILL $FUZZER_PID 2>/dev/null || true
    fi
    
    # 停止可视化器
    if [ -n "$VISUALIZER_PID" ] && kill -0 $VISUALIZER_PID 2>/dev/null; then
        echo "   停止可视化器 (PID=$VISUALIZER_PID)..."
        kill -SIGTERM $VISUALIZER_PID 2>/dev/null || true
        sleep 1
    fi
    
    # 清理管道
    if [ -p "$PIPE_PATH" ]; then
        rm -f "$PIPE_PATH"
    fi
    
    echo "✅ 清理完成"
    exit 130
}

# 注册信号处理
trap cleanup SIGINT SIGTERM

echo "=========================================="
echo "  动态跟踪功能测试"
echo "=========================================="
echo ""

# 检查QEMU
if [ ! -f "$QEMU_PATH" ]; then
    echo "❌ QEMU not found: $QEMU_PATH"
    exit 1
fi

echo "✅ QEMU: $QEMU_PATH"
$QEMU_PATH --version | head -1
echo ""

# 检查trace文件
cd ~/Downloads
if [ ! -f strace-ls.txt ]; then
    echo "⚠️  Warning: strace-ls.txt not found in ~/Downloads"
    echo "   Running strace to generate it..."
    strace -o strace-ls.txt /usr/bin/ls 2>/dev/null
fi

echo "✅ Trace file: ~/Downloads/strace-ls.txt ($(wc -l < strace-ls.txt) lines)"
echo ""

# 清理旧管道
if [ -e "$PIPE_PATH" ]; then
    rm -f "$PIPE_PATH"
fi

echo "=========================================="
echo "  步骤1: 启动可视化器"
echo "=========================================="
echo ""

# 启动可视化器在后台
python3 "$SCRIPT_DIR/realtime_tree_visualizer.py" \
    --pipe "$PIPE_PATH" \
    --output "$OUTPUT_HTML" \
    --update-interval 1 &

VISUALIZER_PID=$!
echo "✅ 可视化器已启动 (PID=$VISUALIZER_PID)"
echo "   管道: $PIPE_PATH"
echo "   输出: $OUTPUT_HTML"
echo ""

# 等待管道创建
sleep 2

if [ ! -p "$PIPE_PATH" ]; then
    echo "❌ 管道未创建"
    kill $VISUALIZER_PID 2>/dev/null || true
    exit 1
fi

echo "✅ 管道已创建"
echo ""

echo "=========================================="
echo "  步骤2: 运行Fuzzing (5次迭代)"
echo "=========================================="
echo ""

# 设置环境变量
export RR_TRACE_PIPE="$PIPE_PATH"

# 运行fuzzing
cd ~/Downloads
python3 "$SCRIPT_DIR/fuzz_conductor.py" \
    --target /usr/bin/ls \
    --trace ./strace-ls.txt \
    --qemu "$QEMU_PATH" \
    2>&1 &

FUZZER_PID=$!
echo "✅ Fuzzer已启动 (PID=$FUZZER_PID)"
echo ""

# 等待fuzzing完成（或被中断）
echo "⏳ 等待fuzzing完成... (按Ctrl+C可提前停止)"
wait $FUZZER_PID 2>/dev/null
FUZZER_EXIT=$?

echo ""
if [ $FUZZER_EXIT -eq 0 ]; then
    echo "✅ Fuzzing完成 (exit code=$FUZZER_EXIT)"
else
    echo "⚠️  Fuzzing退出 (exit code=$FUZZER_EXIT)"
fi
echo ""

# 等待可视化器更新
sleep 2

# 停止可视化器
echo "停止可视化器..."
if [ -n "$VISUALIZER_PID" ] && kill -0 $VISUALIZER_PID 2>/dev/null; then
    kill -SIGTERM $VISUALIZER_PID 2>/dev/null || true
    wait $VISUALIZER_PID 2>/dev/null || true
fi

# 清理管道
if [ -p "$PIPE_PATH" ]; then
    rm -f "$PIPE_PATH"
fi

echo ""
echo "=========================================="
echo "  测试完成"
echo "=========================================="
echo ""

if [ -f "$OUTPUT_HTML" ]; then
    SIZE=$(du -h "$OUTPUT_HTML" | cut -f1)
    echo "✅ 树已生成: $OUTPUT_HTML ($SIZE)"
    echo ""
    echo "在浏览器中打开查看:"
    echo "  firefox $OUTPUT_HTML"
    echo "  或"
    echo "  google-chrome $OUTPUT_HTML"
else
    echo "⚠️  树文件未生成"
fi

echo ""
echo "注意: 如果看到动态跟踪相关的日志，说明功能已启用"
echo "      查找包含 'Dynamic trace' 的日志"
echo ""


#!/bin/bash
# 快速启动实时Fuzzing树可视化

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPE_PATH="/tmp/rr_dynamic_trace_$$"  # 使用PID避免冲突
OUTPUT_HTML="${HOME}/fuzzing_tree_realtime.html"

echo "=========================================="
echo "  Realtime Fuzzing Tree Visualizer"
echo "=========================================="
echo ""

# 检查Python脚本
if [ ! -f "$SCRIPT_DIR/realtime_tree_visualizer.py" ]; then
    echo "❌ Error: realtime_tree_visualizer.py not found"
    exit 1
fi

# 检查QEMU
QEMU_PATH="${SCRIPT_DIR}/../../../build/build-x86-arm-user/bin/qemu-x86_64"
if [ ! -f "$QEMU_PATH" ]; then
    echo "⚠️  Warning: QEMU not found at $QEMU_PATH"
    echo "   Please compile QEMU first:"
    echo "   cd $(dirname $QEMU_PATH)/.."
    echo "   ninja"
    echo ""
fi

# 清理旧管道
if [ -e "$PIPE_PATH" ]; then
    rm -f "$PIPE_PATH"
fi

echo "Configuration:"
echo "  Pipe: $PIPE_PATH"
echo "  Output: $OUTPUT_HTML"
echo ""

# 导出环境变量
export RR_TRACE_PIPE="$PIPE_PATH"

echo "Starting visualizer..."
echo ""

# 启动可视化器
python3 "$SCRIPT_DIR/realtime_tree_visualizer.py" \
    --pipe "$PIPE_PATH" \
    --output "$OUTPUT_HTML" \
    --update-interval 2

# 清理
if [ -e "$PIPE_PATH" ]; then
    rm -f "$PIPE_PATH"
fi

echo ""
echo "✅ Visualizer stopped"
echo "   Final tree: $OUTPUT_HTML"


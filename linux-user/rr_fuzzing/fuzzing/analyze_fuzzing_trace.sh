#!/bin/bash
# 分析Fuzzing过程中系统调用跟踪的完整性

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPE_PATH="/tmp/rr_trace_analyze_$$"
HTML_OUTPUT="/home/webfuzz/analyze_fuzzing_tree.html"
QEMU_PATH="/home/webfuzz/Documents/qemu/build/build-x86-arm-user/bin/qemu-x86_64"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        Fuzzing系统调用跟踪完整性分析                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Cleanup函数
cleanup() {
    echo ""
    echo "🛑 清理中..."
    
    if [ -n "$FUZZER_PID" ] && kill -0 $FUZZER_PID 2>/dev/null; then
        kill -SIGTERM $FUZZER_PID 2>/dev/null || true
        sleep 1
        kill -SIGKILL $FUZZER_PID 2>/dev/null || true
    fi
    
    if [ -n "$VISUALIZER_PID" ] && kill -0 $VISUALIZER_PID 2>/dev/null; then
        kill -SIGTERM $VISUALIZER_PID 2>/dev/null || true
        sleep 1
    fi
    
    [ -p "$PIPE_PATH" ] && rm -f "$PIPE_PATH"
    
    echo "✅ 清理完成"
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "═══════════════════════════════════════════════════════════════"
echo "  步骤1: 检查原始trace文件"
echo "═══════════════════════════════════════════════════════════════"
echo ""

TRACE_FILE="$HOME/Downloads/strace-ls.txt"
if [ ! -f "$TRACE_FILE" ]; then
    echo "❌ Trace文件不存在: $TRACE_FILE"
    exit 1
fi

TRACE_LINES=$(wc -l < "$TRACE_FILE")
echo "✅ Trace文件: $TRACE_FILE"
echo "📊 总行数: $TRACE_LINES"
echo ""

# 分析trace内容
echo "前10个系统调用:"
head -10 "$TRACE_FILE" | nl
echo ""

echo "═══════════════════════════════════════════════════════════════"
echo "  步骤2: 启动可视化器"
echo "═══════════════════════════════════════════════════════════════"
echo ""

rm -f "$HTML_OUTPUT"

python3 "$SCRIPT_DIR/realtime_tree_visualizer.py" \
    --pipe "$PIPE_PATH" \
    --output "$HTML_OUTPUT" \
    --update-interval 1 \
    2>&1 | grep -v "Waiting for pipe" &

VISUALIZER_PID=$!
echo "✅ 可视化器已启动 (PID=$VISUALIZER_PID)"

# 等待管道创建
for i in {1..10}; do
    if [ -p "$PIPE_PATH" ]; then
        break
    fi
    sleep 1
done

if [ ! -p "$PIPE_PATH" ]; then
    echo "❌ 管道未创建"
    kill $VISUALIZER_PID 2>/dev/null || true
    exit 1
fi

echo "✅ 管道已创建"
echo ""

echo "═══════════════════════════════════════════════════════════════"
echo "  步骤3: 运行Fuzzing (10次迭代)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

export RR_TRACE_PIPE="$PIPE_PATH"

cd ~/Downloads
python3 "$SCRIPT_DIR/fuzz_conductor.py" \
    --target /usr/bin/ls \
    --trace "$TRACE_FILE" \
    --qemu "$QEMU_PATH" \
    --iterations 10 \
    2>&1 | tee /tmp/fuzzing_analysis_$$.log &

FUZZER_PID=$!
echo "✅ Fuzzer已启动 (PID=$FUZZER_PID)"
echo ""

# 等待fuzzing完成
echo "⏳ 等待fuzzing完成..."
wait $FUZZER_PID 2>/dev/null
FUZZER_EXIT=$?

echo ""
echo "✅ Fuzzing完成 (exit code=$FUZZER_EXIT)"
echo ""

# 等待可视化器处理完
sleep 3

# 停止可视化器
echo "停止可视化器..."
kill -SIGTERM $VISUALIZER_PID 2>/dev/null || true
sleep 2

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  步骤4: 分析结果"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [ -f "$HTML_OUTPUT" ]; then
    HTML_SIZE=$(du -h "$HTML_OUTPUT" | cut -f1)
    echo "✅ HTML文件已生成: $HTML_OUTPUT ($HTML_SIZE)"
    
    # 统计HTML中的节点数
    if [ -f "$HTML_OUTPUT" ]; then
        SYSCALL_COUNT=$(grep -o '"syscall_name"' "$HTML_OUTPUT" | wc -l)
        FORK_COUNT=$(grep -o '"is_fork":true' "$HTML_OUTPUT" | wc -l)
        
        echo "📊 HTML中的节点统计:"
        echo "   • 系统调用节点: $SYSCALL_COUNT"
        echo "   • Fork节点: $FORK_COUNT"
    fi
else
    echo "❌ HTML文件未生成"
fi
echo ""

# 分析fuzzing日志
echo "═══════════════════════════════════════════════════════════════"
echo "  步骤5: 分析Fuzzing日志"
echo "═══════════════════════════════════════════════════════════════"
echo ""

FUZZING_LOG="/tmp/fuzzing_analysis_$$.log"
if [ -f "$FUZZING_LOG" ]; then
    echo "Fuzzing统计:"
    grep -E "Total executions|Crashes found" "$FUZZING_LOG" | tail -5
    echo ""
    
    echo "Crash详情:"
    grep -E "CRASH FOUND|CRASH DETECTED" "$FUZZING_LOG" | head -10
    echo ""
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  步骤6: 对比分析"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "对比数据:"
echo "  • 原始trace行数: $TRACE_LINES"
echo "  • HTML中syscall数: $SYSCALL_COUNT"
echo "  • 差异: $((TRACE_LINES - SYSCALL_COUNT)) 个系统调用未记录"
echo ""

if [ $SYSCALL_COUNT -lt $((TRACE_LINES / 2)) ]; then
    echo "⚠️  警告: HTML中记录的系统调用数量显著少于原始trace"
    echo ""
    echo "可能原因:"
    echo "  1. 子进程快速崩溃，未执行完整的系统调用序列"
    echo "  2. Fork后只有少量系统调用被执行"
    echo "  3. Fuzzing修改参数导致程序提前终止"
    echo "  4. 动态跟踪未捕获所有系统调用"
    echo ""
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  步骤7: 查看QEMU日志中的系统调用统计"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# 查找QEMU的统计输出
if [ -f "$FUZZING_LOG" ]; then
    echo "QEMU统计信息:"
    grep -E "STATISTICS|Total syscalls processed|Successfully matched" "$FUZZING_LOG" | tail -20
fi
echo ""

echo "═══════════════════════════════════════════════════════════════"
echo "  测试完成"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "📁 生成的文件:"
echo "   • HTML可视化: $HTML_OUTPUT"
echo "   • Fuzzing日志: $FUZZING_LOG"
echo ""

echo "🔍 查看HTML:"
echo "   firefox $HTML_OUTPUT"
echo ""

# Cleanup
rm -f "$PIPE_PATH"


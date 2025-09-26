#!/bin/bash
# RR-Fuzz构建和测试脚本

set -e

echo "=== RR-Fuzz Build and Test Script ==="

# 检查当前目录
if [ ! -f "rr_framework.h" ]; then
    echo "Error: Must run from fuzzing directory"
    exit 1
fi

echo "1. Building test target..."
gcc -o test_target test_target.c -static
echo "   Test target built: test_target"

echo "2. Building RR-Fuzz modules..."
make clean
make check-deps
make all
echo "   RR-Fuzz modules built successfully"

echo "3. Testing Record mode..."
export RR_FUZZING_ENABLED=1
export RR_MODE=record
export RR_TRACE_FILE=test_trace.dat

echo "   Running target in record mode..."
# 在实际环境中，这里应该通过QEMU运行
echo "   Note: In real usage, run with: qemu-x86_64 -rr-fuzzing ./test_target"

echo "4. Testing Replay mode..."
export RR_MODE=replay
echo "   Would run target in replay mode..."
echo "   Note: In real usage, run with: qemu-x86_64 -rr-fuzzing ./test_target"

echo "5. Testing Fuzzing mode..."
export RR_MODE=fuzzing
export RR_FORK_POINT=10
echo "   Would run target in fuzzing mode..."
echo "   Note: In real usage, run with: qemu-x86_64 -rr-fuzzing ./test_target"

echo ""
echo "=== Build Complete ==="
echo "Next steps:"
echo "1. Build QEMU with RR-Fuzz support:"
echo "   ./configure --enable-rr-fuzzing"
echo "   make"
echo ""
echo "2. Use the framework:"
echo "   # Record phase"
echo "   RR_FUZZING_ENABLED=1 RR_MODE=record RR_TRACE_FILE=app.trace qemu-x86_64 ./target_app"
echo ""
echo "   # Replay phase"
echo "   RR_FUZZING_ENABLED=1 RR_MODE=replay RR_TRACE_FILE=app.trace qemu-x86_64 ./target_app"
echo ""
echo "   # Fuzzing phase"
echo "   RR_FUZZING_ENABLED=1 RR_MODE=fuzzing RR_TRACE_FILE=app.trace RR_FORK_POINT=100 qemu-x86_64 ./target_app"
echo ""
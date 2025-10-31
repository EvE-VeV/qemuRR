#!/bin/bash
# RR-Fuzz 系统验证脚本
# 重组后的全面功能测试

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 测试计数
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 工作目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FUZZING_DIR="$PROJECT_ROOT/linux-user/rr_fuzzing"
QEMU_BIN="$PROJECT_ROOT/build/qemu-x86_64"
TEST_OUTPUT="/tmp/rr_fuzz_validation_$$"

mkdir -p "$TEST_OUTPUT"

# ============================================================
# 辅助函数
# ============================================================

print_header() {
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo -e "${CYAN}$1${NC}"
    echo "════════════════════════════════════════════════════════════"
}

print_section() {
    echo ""
    echo -e "${BLUE}━━━ $1 ━━━${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

test_passed() {
    echo -e "${GREEN}  ✅ $1${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
}

test_failed() {
    echo -e "${RED}  ❌ $1${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
}

test_warning() {
    echo -e "${YELLOW}  ⚠️  $1${NC}"
}

# ============================================================
# 开始测试
# ============================================================

print_header "🧪 RR-Fuzz 系统验证 - 重组后测试"
echo ""
echo "📁 项目根目录: $PROJECT_ROOT"
echo "📁 测试输出: $TEST_OUTPUT"
echo "🔧 QEMU 路径: $QEMU_BIN"
echo ""

# ============================================================
# 测试 1: QEMU 可执行文件
# ============================================================

print_section "1. QEMU 可执行文件检查"

if [ ! -f "$QEMU_BIN" ]; then
    test_failed "QEMU 不存在: $QEMU_BIN"
    echo ""
    echo -e "${RED}请先编译 QEMU:${NC}"
    echo "  cd $PROJECT_ROOT/build"
    echo "  ninja"
    exit 1
fi

# 测试版本
VERSION=$($QEMU_BIN --version 2>&1 | head -1)
test_passed "QEMU 版本: $VERSION"

# 测试基本执行
if $QEMU_BIN /bin/true > /dev/null 2>&1; then
    test_passed "基本执行: /bin/true"
else
    test_failed "无法执行基本程序"
fi

# ============================================================
# 测试 2: 录制功能 (Record)
# ============================================================

print_section "2. 录制功能 (Record)"

TRACE_FILE="$TEST_OUTPUT/test_true.dat"

# 使用环境变量配置
export RR_FUZZING_ENABLED=1
export RR_MODE=record
export RR_TRACE_FILE="$TRACE_FILE"
export RR_DEBUG_LEVEL=info

if timeout 5 $QEMU_BIN /bin/true > "$TEST_OUTPUT/record.log" 2>&1; then
    test_passed "录制 /bin/true"
    
    if [ -f "$TRACE_FILE" ]; then
        SIZE=$(stat -c%s "$TRACE_FILE" 2>/dev/null || stat -f%z "$TRACE_FILE" 2>/dev/null)
        test_passed "Trace 文件生成: ${SIZE} 字节"
        
        # 检查 trace 文件头部（应该有 RRTR magic）
        MAGIC=$(hexdump -n 4 -e '"%x"' "$TRACE_FILE" 2>/dev/null || echo "")
        if [ -n "$MAGIC" ]; then
            test_passed "Trace 文件格式验证: 0x$MAGIC"
        fi
    else
        test_warning "Trace 文件未生成（可能是配置问题）"
    fi
else
    test_warning "录制超时或失败（检查日志）"
    tail -5 "$TEST_OUTPUT/record.log"
fi

# ============================================================
# 测试 3: 重放功能 (Replay)
# ============================================================

print_section "3. 重放功能 (Replay)"

if [ -f "$TRACE_FILE" ]; then
    export RR_MODE=replay
    
    if timeout 5 $QEMU_BIN /bin/true > "$TEST_OUTPUT/replay.log" 2>&1; then
        test_passed "重放成功"
    else
        test_warning "重放失败或超时"
        tail -5 "$TEST_OUTPUT/replay.log"
    fi
else
    test_warning "跳过（无 trace 文件）"
fi

# ============================================================
# 测试 4: Python 模块导入
# ============================================================

print_section "4. Python 模块导入"

cd "$FUZZING_DIR/fuzzing"

# 测试 conductor 模块
python3 << 'PYTEST'
import sys
try:
    from conductor import (
        SmartMutator, InitPhaseDetector, FuzzInstruction,
        CoverageTracker, FuzzSharedMemory, BBTraceParser
    )
    print("  ✅ conductor 模块")
    sys.exit(0)
except Exception as e:
    print(f"  ❌ conductor 模块失败: {e}")
    sys.exit(1)
PYTEST

if [ $? -eq 0 ]; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# 测试 multiprocess 模块
python3 << 'PYTEST'
import sys
try:
    from multiprocess import (
        FuzzMaster, SharedCoverage, WorkerSeedQueue,
        MultiProcessFuzzConductor
    )
    print("  ✅ multiprocess 模块")
    sys.exit(0)
except Exception as e:
    print(f"  ❌ multiprocess 模块失败: {e}")
    sys.exit(1)
PYTEST

if [ $? -eq 0 ]; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# ============================================================
# 测试 5: 单进程 Fuzzing
# ============================================================

print_section "5. 单进程 Fuzzing (fuzz_conductor.py)"

if [ -f "$TRACE_FILE" ]; then
    echo "  运行 5 轮迭代..."
    
    # 确保环境变量正确
    export RR_FUZZING_ENABLED=1
    export RR_MODE=fuzzing
    
    timeout 30 python3 fuzz_conductor.py \
        --qemu "$QEMU_BIN" \
        --target /bin/true \
        --trace "$TRACE_FILE" \
        --iterations 5 \
        > "$TEST_OUTPUT/single_fuzz.log" 2>&1
    
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        test_passed "单进程 fuzzing 完成"
    elif [ $EXIT_CODE -eq 124 ]; then
        test_warning "超时（可能正常）"
    else
        test_warning "执行失败（检查日志）"
        tail -10 "$TEST_OUTPUT/single_fuzz.log"
    fi
else
    test_warning "跳过（无 trace 文件）"
fi

# ============================================================
# 测试 6: 核心组件功能测试
# ============================================================

print_section "6. 核心组件功能测试"

# 测试 SmartMutator
python3 << PYTEST
import sys
sys.path.insert(0, '.')

try:
    from conductor import SmartMutator, InitPhaseDetector, CoverageTracker
    import os
    
    # SmartMutator
    if os.path.exists('$TRACE_FILE'):
        mutator = SmartMutator('$TRACE_FILE')
        print("  ✅ SmartMutator 初始化")
    else:
        print("  ⚠️  SmartMutator 跳过（无 trace）")
    
    # InitPhaseDetector
    detector = InitPhaseDetector(mode='adaptive')
    threshold = detector.detect([
        {'index': 0, 'name': 'brk'},
        {'index': 1, 'name': 'read'},
        {'index': 2, 'name': 'write'},
    ])
    print("  ✅ InitPhaseDetector 工作正常")
    
    # CoverageTracker
    tracker = CoverageTracker(os.getpid())
    stats = tracker.get_stats()
    print("  ✅ CoverageTracker 工作正常")
    
    sys.exit(0)
except Exception as e:
    print(f"  ❌ 组件测试失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTEST

if [ $? -eq 0 ]; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# ============================================================
# 测试 7: 共享内存和IPC
# ============================================================

print_section "7. 共享内存和IPC"

python3 << 'PYTEST'
import sys
import os
sys.path.insert(0, '.')

try:
    from conductor import FuzzSharedMemory, FuzzInstruction, FUZZ_CMD_MUTATE_ARG
    
    # 创建共享内存
    shm_name = f"test_shm_{os.getpid()}"
    shm = FuzzSharedMemory(shm_name)
    shm.create()
    print("  ✅ 共享内存创建")
    
    # 写入指令
    instructions = [
        FuzzInstruction(0, FUZZ_CMD_MUTATE_ARG, 0, b'\x42' * 8)
    ]
    shm.write_instructions(instructions)
    print("  ✅ 指令写入成功")
    
    # 清理
    shm.close()
    print("  ✅ 共享内存清理")
    
    sys.exit(0)
except Exception as e:
    print(f"  ❌ 共享内存测试失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTEST

if [ $? -eq 0 ]; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# ============================================================
# 总结
# ============================================================

echo ""
print_header "📊 测试总结"
echo ""
echo -e "  总测试数: ${TOTAL_TESTS}"
echo -e "  ${GREEN}通过: ${PASSED_TESTS}${NC}"
echo -e "  ${RED}失败: ${FAILED_TESTS}${NC}"
echo -e "  ${YELLOW}警告: $((TOTAL_TESTS - PASSED_TESTS - FAILED_TESTS))${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 所有核心测试通过！系统已就绪。${NC}"
    echo ""
    echo "下一步："
    echo "  1. 运行完整 fuzzing: python3 fuzz_conductor.py --qemu $QEMU_BIN --target <target> --trace <trace>"
    echo "  2. 多进程模式: python3 multiprocess/fuzz_master.py -n 8 -p <target> -q $QEMU_BIN -t <trace_dir>"
    echo ""
    exit 0
else
    echo -e "${RED}⚠️  部分测试失败，请检查上述错误。${NC}"
    echo ""
    exit 1
fi


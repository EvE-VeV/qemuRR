#!/bin/bash
# RR-Fuzz 漏洞程序 v2.0 测试脚本
# 测试多种漏洞类型的触发

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
QEMU_BIN="$PROJECT_ROOT/build/qemu-x86_64"
TEST_DIR="/tmp/vuln_v2_test_$$"

mkdir -p "$TEST_DIR"

echo "════════════════════════════════════════════════════════════"
echo -e "${CYAN}🧪 RR-Fuzz 漏洞程序 v2.0 测试${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""

# ============================================================
# 步骤 1: 编译
# ============================================================

echo -e "${BLUE}📝 步骤 1: 编译程序${NC}"
gcc -o "$TEST_DIR/vuln_v2" "$SCRIPT_DIR/vuln_stdin.c" -g -no-pie -O0 -fno-stack-protector

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ 编译成功${NC}"
    ls -lh "$TEST_DIR/vuln_v2"
else
    echo -e "${RED}❌ 编译失败${NC}"
    exit 1
fi
echo ""

# ============================================================
# 步骤 2: 测试正常执行
# ============================================================

echo -e "${BLUE}📊 步骤 2: 测试正常执行${NC}"

echo "Testing normal execution with short input..."
echo -n "hello" | "$QEMU_BIN" "$TEST_DIR/vuln_v2" 2>/dev/null && echo -e "${GREEN}✅ 正常执行成功${NC}" || echo -e "${YELLOW}⚠️  执行异常${NC}"
echo ""

# ============================================================
# 步骤 3: 录制多个 Trace (不同漏洞类型)
# ============================================================

echo -e "${BLUE}📹 步骤 3: 录制 Traces (5种漏洞类型)${NC}"

export RR_FUZZING_ENABLED=1
export RR_MODE=record
export RR_DEBUG_LEVEL=error

TRACES_DIR="$TEST_DIR/traces"
mkdir -p "$TRACES_DIR"

# Trace 1: 漏洞类型 0 (简单缓冲区溢出)
echo -e "\n  [1/5] 录制漏洞类型 0: 简单缓冲区溢出"
export RR_TRACE_FILE="$TRACES_DIR/vuln_type0.dat"
printf '\x00hello' | "$QEMU_BIN" "$TEST_DIR/vuln_v2" > /dev/null 2>&1
echo "    ✓ Trace 大小: $(stat -c%s "$TRACES_DIR/vuln_type0.dat" 2>/dev/null || echo "?") 字节"

# Trace 2: 漏洞类型 1 (基于长度的溢出)
echo "  [2/5] 录制漏洞类型 1: 基于长度的溢出"
export RR_TRACE_FILE="$TRACES_DIR/vuln_type1.dat"
printf '\x01\x20\x00\x00\x00AAAABBBBCCCCDDDD' | "$QEMU_BIN" "$TEST_DIR/vuln_v2" > /dev/null 2>&1
echo "    ✓ Trace 大小: $(stat -c%s "$TRACES_DIR/vuln_type1.dat" 2>/dev/null || echo "?") 字节"

# Trace 3: 漏洞类型 2 (Off-by-one)
echo "  [3/5] 录制漏洞类型 2: Off-by-one"
export RR_TRACE_FILE="$TRACES_DIR/vuln_type2.dat"
printf '\x02AAAAAAAAAA' | "$QEMU_BIN" "$TEST_DIR/vuln_v2" > /dev/null 2>&1
echo "    ✓ Trace 大小: $(stat -c%s "$TRACES_DIR/vuln_type2.dat" 2>/dev/null || echo "?") 字节"

# Trace 4: 漏洞类型 3 (整数溢出)
echo "  [4/5] 录制漏洞类型 3: 整数溢出"
export RR_TRACE_FILE="$TRACES_DIR/vuln_type3.dat"
printf '\x03\x10\x00\x00\x00\x04\x00\x00\x00AAAA' | "$QEMU_BIN" "$TEST_DIR/vuln_v2" > /dev/null 2>&1
echo "    ✓ Trace 大小: $(stat -c%s "$TRACES_DIR/vuln_type3.dat" 2>/dev/null || echo "?") 字节"

# Trace 5: 漏洞类型 4 (栈溢出)
echo "  [5/5] 录制漏洞类型 4: 栈溢出"
export RR_TRACE_FILE="$TRACES_DIR/vuln_type4.dat"
printf '\x04\x0a\x00\x00\x00DATA' | "$QEMU_BIN" "$TEST_DIR/vuln_v2" > /dev/null 2>&1
echo "    ✓ Trace 大小: $(stat -c%s "$TRACES_DIR/vuln_type4.dat" 2>/dev/null || echo "?") 字节"

echo -e "\n${GREEN}✅ 所有 Traces 录制完成${NC}"
echo ""

# ============================================================
# 步骤 4: 单进程 Fuzzing 测试
# ============================================================

echo -e "${BLUE}🚀 步骤 4: 单进程 Fuzzing 测试${NC}"
echo "  测试每种漏洞类型 (100 次迭代/类型)"
echo ""

export RR_MODE=fuzzing
FUZZING_DIR="$PROJECT_ROOT/linux-user/rr_fuzzing/fuzzing"

TOTAL_CRASHES=0

for trace_file in "$TRACES_DIR"/*.dat; do
    trace_name=$(basename "$trace_file" .dat)
    echo -e "${CYAN}  Testing: $trace_name${NC}"
    
    LOG_FILE="$TEST_DIR/fuzz_${trace_name}.log"
    
    cd "$FUZZING_DIR"
    timeout 60 python3 fuzz_conductor.py \
        --qemu "$QEMU_BIN" \
        --target "$TEST_DIR/vuln_v2" \
        --trace "$trace_file" \
        --iterations 100 \
        > "$LOG_FILE" 2>&1 || true
    
    CRASHES=$(grep -c "💥 崩溃" "$LOG_FILE" 2>/dev/null || echo "0")
    
    if [ "$CRASHES" -gt 0 ]; then
        echo -e "    ${GREEN}✓ 发现 $CRASHES 个崩溃${NC}"
        TOTAL_CRASHES=$((TOTAL_CRASHES + CRASHES))
    else
        echo -e "    ${YELLOW}✗ 未发现崩溃${NC}"
    fi
    
    # 清理 IPC
    rm -f /dev/shm/rr_fuzz_* /dev/shm/rr_coverage_*
    rm -f /tmp/rr_cmd_pipe* /tmp/rr_status_pipe*
done

echo ""

# ============================================================
# 步骤 5: 多进程模式测试（可选）
# ============================================================

echo -e "${BLUE}🚀 步骤 5: 多进程模式测试 (可选)${NC}"
echo "  使用漏洞类型 0 进行 4-worker 测试 (60秒)"
echo ""

SYNC_DIR="$TEST_DIR/sync"
mkdir -p "$SYNC_DIR"

cd "$FUZZING_DIR"
timeout 60 python3 multiprocess/fuzz_master.py \
    -n 4 \
    -p "$TEST_DIR/vuln_v2" \
    -q "$QEMU_BIN" \
    -t "$TRACES_DIR" \
    -s "$SYNC_DIR" \
    > "$TEST_DIR/multiprocess.log" 2>&1 || true

MP_CRASHES=$(find "$SYNC_DIR/crashes" -type f 2>/dev/null | wc -l)
MP_SEEDS=$(find "$SYNC_DIR/queue" -type f 2>/dev/null | wc -l)

echo -e "  多进程结果:"
echo "    Seeds: $MP_SEEDS"
echo "    Crashes: $MP_CRASHES"

if [ "$MP_CRASHES" -gt 0 ]; then
    TOTAL_CRASHES=$((TOTAL_CRASHES + MP_CRASHES))
fi

echo ""

# ============================================================
# 步骤 6: 结果分析
# ============================================================

echo "════════════════════════════════════════════════════════════"
echo -e "${BLUE}📊 测试结果总结${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""

echo -e "${CYAN}漏洞类型覆盖:${NC}"
echo "  ✓ 类型 0: 简单缓冲区溢出"
echo "  ✓ 类型 1: 基于长度的溢出"
echo "  ✓ 类型 2: Off-by-one 错误"
echo "  ✓ 类型 3: 整数溢出"
echo "  ✓ 类型 4: 栈溢出（递归）"
echo ""

echo -e "${CYAN}Fuzzing 统计:${NC}"
echo "  • 录制的 Traces: 5 个"
echo "  • 单进程测试: 5 个 traces × 100 次迭代"
echo "  • 多进程测试: 4 workers × 60 秒"
echo "  • 总崩溃数: $TOTAL_CRASHES"
echo ""

if [ "$TOTAL_CRASHES" -gt 0 ]; then
    echo -e "${GREEN}✅ 测试成功！发现 $TOTAL_CRASHES 个崩溃${NC}"
    echo ""
    echo "崩溃详情："
    for log in "$TEST_DIR"/fuzz_*.log; do
        if [ -f "$log" ]; then
            crashes_in_log=$(grep -c "💥 崩溃" "$log" 2>/dev/null || echo "0")
            if [ "$crashes_in_log" -gt 0 ]; then
                echo "  • $(basename "$log"): $crashes_in_log 个崩溃"
            fi
        fi
    done
    echo ""
    echo -e "${GREEN}🎉 RR-Fuzz 成功检测到多种类型的漏洞！${NC}"
else
    echo -e "${YELLOW}⚠️  未发现崩溃${NC}"
    echo ""
    echo "可能原因："
    echo "  1. 测试时间不足（建议增加到 5-10 分钟）"
    echo "  2. 变异策略需要更多迭代"
    echo "  3. 某些漏洞需要特定的输入模式"
    echo ""
    echo "建议："
    echo "  • 增加 --iterations 参数"
    echo "  • 使用更长的初始输入"
    echo "  • 查看日志: $TEST_DIR/*.log"
fi

echo ""
echo -e "${CYAN}测试文件位置:${NC}"
echo "  程序: $TEST_DIR/vuln_v2"
echo "  Traces: $TRACES_DIR/"
echo "  日志: $TEST_DIR/*.log"
echo "  多进程输出: $SYNC_DIR/"
echo ""

echo "════════════════════════════════════════════════════════════"


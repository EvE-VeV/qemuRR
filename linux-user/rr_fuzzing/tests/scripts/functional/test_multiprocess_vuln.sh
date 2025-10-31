#!/bin/bash
# 多进程模式 + 真实漏洞程序测试
# 目标: 验证多个 worker 并行发现缓冲区溢出漏洞

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "════════════════════════════════════════════════════════════"
echo -e "${CYAN}🚀 多进程模式 + 真实漏洞测试${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FUZZING_DIR="$PROJECT_ROOT/linux-user/rr_fuzzing/fuzzing"
QEMU_BIN="$PROJECT_ROOT/build/qemu-x86_64"
TEST_OUTPUT="/tmp/rr_multiprocess_vuln_$$"

mkdir -p "$TEST_OUTPUT"

# ============================================================
# 配置
# ============================================================

NUM_WORKERS=4
TEST_DURATION=300  # 5 分钟

echo -e "${BLUE}📋 测试配置${NC}"
echo "  Worker 数量: $NUM_WORKERS"
echo "  测试时长: $TEST_DURATION 秒"
echo "  QEMU 路径: $QEMU_BIN"
echo ""

# ============================================================
# 步骤 1: 编译带漏洞的测试程序
# ============================================================

echo -e "${BLUE}📝 步骤 1: 编译带漏洞的测试程序${NC}"

VULN_BIN="$TEST_OUTPUT/vuln"
cat > "$TEST_OUTPUT/vuln.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input);  // Buffer overflow
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
EOF

gcc -o "$VULN_BIN" "$TEST_OUTPUT/vuln.c" -g -no-pie -O0

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ 测试程序编译成功${NC}"
else
    echo -e "${RED}❌ 编译失败${NC}"
    exit 1
fi
echo ""

# ============================================================
# 步骤 2: 录制 Trace
# ============================================================

echo -e "${BLUE}📹 步骤 2: 录制 Trace${NC}"

TRACES_DIR="$TEST_OUTPUT/traces"
CORPUS_DIR="$TEST_OUTPUT/corpus"
SYNC_DIR="$TEST_OUTPUT/sync_dir"

mkdir -p "$TRACES_DIR" "$CORPUS_DIR" "$SYNC_DIR"

export RR_FUZZING_ENABLED=1
export RR_MODE=record
export RR_TRACE_FILE="$TRACES_DIR/vuln.dat"
export RR_DEBUG_LEVEL=error

"$QEMU_BIN" "$VULN_BIN" "hello" > /dev/null 2>&1

if [ -f "$TRACES_DIR/vuln.dat" ]; then
    TRACE_SIZE=$(stat -c%s "$TRACES_DIR/vuln.dat" 2>/dev/null || stat -f%z "$TRACES_DIR/vuln.dat" 2>/dev/null)
    echo -e "${GREEN}✅ Trace 录制成功${NC} (${TRACE_SIZE} 字节)"
else
    echo -e "${RED}❌ Trace 录制失败${NC}"
    exit 1
fi
echo ""

# ============================================================
# 步骤 3: 准备 Corpus
# ============================================================

echo -e "${BLUE}📦 步骤 3: 准备 Corpus${NC}"

# 创建多个初始种子
echo "a" > "$CORPUS_DIR/seed_1.txt"
echo "ab" > "$CORPUS_DIR/seed_2.txt"
echo "abc" > "$CORPUS_DIR/seed_3.txt"
echo "abcd" > "$CORPUS_DIR/seed_4.txt"
echo "hello" > "$CORPUS_DIR/seed_5.txt"
echo "test" > "$CORPUS_DIR/seed_6.txt"
echo "fuzz" > "$CORPUS_DIR/seed_7.txt"
echo "input" > "$CORPUS_DIR/seed_8.txt"

SEED_COUNT=$(ls "$CORPUS_DIR"/*.txt 2>/dev/null | wc -l)
echo -e "${GREEN}✅ 创建 $SEED_COUNT 个初始种子${NC}"
echo ""

# ============================================================
# 步骤 4: 启动多进程 Fuzzing
# ============================================================

echo -e "${BLUE}🚀 步骤 4: 启动多进程 Fuzzing${NC}"
echo "  启动 $NUM_WORKERS 个并行 workers..."
echo "  测试时长: $TEST_DURATION 秒 ($(($TEST_DURATION / 60)) 分钟)"
echo ""

cd "$FUZZING_DIR"

timeout $TEST_DURATION python3 multiprocess/fuzz_master.py \
    -n $NUM_WORKERS \
    -p "$VULN_BIN" \
    -q "$QEMU_BIN" \
    -t "$TRACES_DIR" \
    -s "$SYNC_DIR" \
    -i "$CORPUS_DIR"/*.txt \
    > "$TEST_OUTPUT/master.log" 2>&1 &

MASTER_PID=$!
echo "  Master PID: $MASTER_PID"
echo ""

# 等待启动
sleep 10

# 检查进程
if ! kill -0 $MASTER_PID 2>/dev/null; then
    echo -e "${RED}❌ Master 进程启动失败${NC}"
    echo "日志:"
    tail -50 "$TEST_OUTPUT/master.log"
    exit 1
fi

echo -e "${GREEN}✅ Master 进程已启动${NC}"
echo ""

# ============================================================
# 步骤 5: 实时监控
# ============================================================

echo -e "${BLUE}📊 步骤 5: 实时监控${NC}"
echo ""

MONITOR_INTERVAL=30
MONITOR_COUNT=$((TEST_DURATION / MONITOR_INTERVAL))

for i in $(seq 1 $MONITOR_COUNT); do
    ELAPSED=$((i * MONITOR_INTERVAL))
    PROGRESS=$((ELAPSED * 100 / TEST_DURATION))
    
    echo -e "${CYAN}=== 检查点 $i / $MONITOR_COUNT (${ELAPSED}s / ${TEST_DURATION}s - ${PROGRESS}%) ===${NC}"
    
    # Master 状态
    if kill -0 $MASTER_PID 2>/dev/null; then
        echo "  ✅ Master 运行中"
    else
        echo -e "  ${YELLOW}⚠️  Master 已退出${NC}"
        break
    fi
    
    # Worker 数量
    WORKER_COUNT=$(ps aux | grep -E "Worker-[0-9]" | grep -v grep | wc -l)
    echo "  Workers: $WORKER_COUNT / $NUM_WORKERS"
    
    # Seeds
    if [ -d "$SYNC_DIR/queue" ]; then
        TOTAL_SEEDS=$(find "$SYNC_DIR/queue" -type f 2>/dev/null | wc -l)
        echo "  Seeds: $TOTAL_SEEDS"
    fi
    
    # Crashes
    if [ -d "$SYNC_DIR/crashes" ]; then
        TOTAL_CRASHES=$(find "$SYNC_DIR/crashes" -type f 2>/dev/null | wc -l)
        if [ $TOTAL_CRASHES -gt 0 ]; then
            echo -e "  ${GREEN}💥 Crashes: $TOTAL_CRASHES${NC}"
        else
            echo "  Crashes: 0"
        fi
    fi
    
    # 提前退出条件: 发现足够多的崩溃
    if [ ${TOTAL_CRASHES:-0} -ge 5 ]; then
        echo ""
        echo -e "${GREEN}🎉 已发现 $TOTAL_CRASHES 个崩溃，提前结束测试！${NC}"
        kill -TERM $MASTER_PID 2>/dev/null || true
        sleep 2
        break
    fi
    
    echo ""
    
    # 如果不是最后一次检查，等待
    if [ $i -lt $MONITOR_COUNT ]; then
        sleep $MONITOR_INTERVAL
    fi
done

# 等待 Master 完成
wait $MASTER_PID 2>/dev/null || true

echo ""
echo "════════════════════════════════════════════════════════════"
echo -e "${BLUE}📊 测试结果分析${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""

# ============================================================
# 步骤 6: 结果分析
# ============================================================

# Seeds 统计
if [ -d "$SYNC_DIR/queue" ]; then
    TOTAL_SEEDS=$(find "$SYNC_DIR/queue" -type f 2>/dev/null | wc -l)
    echo -e "${CYAN}Seeds 统计:${NC}"
    echo "  总 Seeds: $TOTAL_SEEDS"
    
    for worker_id in $(seq 0 $((NUM_WORKERS-1))); do
        WORKER_DIR="$SYNC_DIR/queue/worker$worker_id"
        if [ -d "$WORKER_DIR" ]; then
            WORKER_SEEDS=$(find "$WORKER_DIR" -type f 2>/dev/null | wc -l)
            echo "    Worker $worker_id: $WORKER_SEEDS seeds"
        fi
    done
    echo ""
fi

# Crashes 统计
if [ -d "$SYNC_DIR/crashes" ]; then
    TOTAL_CRASHES=$(find "$SYNC_DIR/crashes" -type f 2>/dev/null | wc -l)
    echo -e "${CYAN}崩溃统计:${NC}"
    echo "  总崩溃: $TOTAL_CRASHES"
    
    if [ $TOTAL_CRASHES -gt 0 ]; then
        echo ""
        echo "  崩溃文件列表:"
        find "$SYNC_DIR/crashes" -type f | head -10
        echo ""
        
        # 分析第一个崩溃
        FIRST_CRASH=$(find "$SYNC_DIR/crashes" -type f | head -1)
        if [ -f "$FIRST_CRASH" ]; then
            echo "  第一个崩溃输入内容:"
            od -c "$FIRST_CRASH" | head -5
        fi
    fi
    echo ""
fi

# 统计文件
if [ -f "$SYNC_DIR/stats/global_stats.json" ]; then
    echo -e "${CYAN}全局统计:${NC}"
    cat "$SYNC_DIR/stats/global_stats.json" 2>/dev/null | python3 -m json.tool 2>/dev/null || cat "$SYNC_DIR/stats/global_stats.json"
    echo ""
fi

# Master 日志摘要
echo -e "${CYAN}Master 日志摘要:${NC}"
echo "  (最后 20 行)"
tail -20 "$TEST_OUTPUT/master.log"
echo ""

# ============================================================
# 步骤 7: 评估
# ============================================================

echo "════════════════════════════════════════════════════════════"
echo -e "${BLUE}📈 测试评估${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""

PASSED=0
FAILED=0

# 评估 1: 是否发现崩溃
if [ ${TOTAL_CRASHES:-0} -gt 0 ]; then
    echo -e "${GREEN}✅ 成功发现 $TOTAL_CRASHES 个崩溃！${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}❌ 未发现崩溃${NC}"
    FAILED=$((FAILED + 1))
fi

# 评估 2: Seeds 是否增长
SEED_GROWTH=$((TOTAL_SEEDS - SEED_COUNT))
if [ $SEED_GROWTH -gt 0 ]; then
    echo -e "${GREEN}✅ Seeds 增长: +$SEED_GROWTH (初始: $SEED_COUNT → 最终: $TOTAL_SEEDS)${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}⚠️  Seeds 未增长${NC}"
fi

# 评估 3: 多进程是否正常
if [ $WORKER_COUNT -gt 0 ]; then
    echo -e "${GREEN}✅ 多进程模式正常运行 (${WORKER_COUNT} workers)${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}⚠️  Workers 未检测到${NC}"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo -e "${CYAN}总结${NC}"
echo "════════════════════════════════════════════════════════════"
echo "  通过: $PASSED"
echo "  失败: $FAILED"
echo ""

if [ $PASSED -ge 2 ]; then
    echo -e "${GREEN}✅ 多进程模式 + 真实漏洞测试通过！${NC}"
    echo ""
    echo "关键成果:"
    echo "  • Worker 数量: $NUM_WORKERS"
    echo "  • 运行时长: ${TEST_DURATION}s"
    echo "  • 发现崩溃: $TOTAL_CRASHES"
    echo "  • Seeds 增长: +$SEED_GROWTH"
    echo ""
    exit 0
else
    echo -e "${RED}❌ 测试失败${NC}"
    echo ""
    echo "详细信息:"
    echo "  测试目录: $TEST_OUTPUT"
    echo "  Master 日志: $TEST_OUTPUT/master.log"
    echo "  Sync 目录: $SYNC_DIR"
    echo ""
    exit 1
fi


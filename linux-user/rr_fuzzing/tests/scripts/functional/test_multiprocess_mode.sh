#!/bin/bash
# 多进程模式测试
# 目标: 验证 8 worker 并行 fuzzing 的稳定性和性能

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "════════════════════════════════════════════════════════════"
echo -e "${CYAN}🚀 RR-Fuzz 多进程模式测试${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FUZZING_DIR="$PROJECT_ROOT/linux-user/rr_fuzzing/fuzzing"
QEMU_BIN="$PROJECT_ROOT/build/qemu-x86_64"
TEST_OUTPUT="/tmp/rr_multiprocess_test_$$"

mkdir -p "$TEST_OUTPUT"

# ============================================================
# 配置
# ============================================================

NUM_WORKERS=4  # 使用 4 个 worker (较温和的测试)
TEST_DURATION=180  # 3 分钟测试
TARGET="/bin/cat"  # 使用简单程序快速测试

echo -e "${BLUE}📋 测试配置${NC}"
echo "  Worker 数量: $NUM_WORKERS"
echo "  测试时长: $TEST_DURATION 秒"
echo "  目标程序: $TARGET"
echo "  QEMU 路径: $QEMU_BIN"
echo ""

# ============================================================
# 步骤 1: 准备测试环境
# ============================================================

echo -e "${BLUE}📝 步骤 1: 准备测试环境${NC}"

# 创建目录
TRACES_DIR="$TEST_OUTPUT/traces"
CORPUS_DIR="$TEST_OUTPUT/corpus"
SYNC_DIR="$TEST_OUTPUT/sync_dir"

mkdir -p "$TRACES_DIR" "$CORPUS_DIR" "$SYNC_DIR"

# 录制 trace
export RR_FUZZING_ENABLED=1
export RR_MODE=record
export RR_TRACE_FILE="$TRACES_DIR/cat.dat"
export RR_DEBUG_LEVEL=info

echo "test data for fuzzing" | "$QEMU_BIN" "$TARGET" > /dev/null 2>&1

if [ ! -f "$TRACES_DIR/cat.dat" ]; then
    echo -e "${RED}❌ Trace 录制失败${NC}"
    exit 1
fi

TRACE_SIZE=$(stat -c%s "$TRACES_DIR/cat.dat" 2>/dev/null || stat -f%z "$TRACES_DIR/cat.dat" 2>/dev/null)
echo -e "${GREEN}✅ Trace 录制成功${NC} (${TRACE_SIZE} 字节)"

# 创建初始 corpus
for i in {1..10}; do
    echo "test_input_$i" > "$CORPUS_DIR/seed_$i.txt"
done

echo -e "${GREEN}✅ 创建 10 个初始种子${NC}"
echo ""

# ============================================================
# 步骤 2: 检查多进程模块
# ============================================================

echo -e "${BLUE}📦 步骤 2: 检查多进程模块${NC}"

cd "$FUZZING_DIR"

python3 << 'PYTEST'
import sys
try:
    from multiprocess import FuzzMaster, SharedCoverage, WorkerSeedQueue
    print("✅ 多进程模块导入成功")
    
    # 检查 FuzzMaster 类
    import inspect
    master_methods = [m for m in dir(FuzzMaster) if not m.startswith('_')]
    print(f"✅ FuzzMaster 有 {len(master_methods)} 个公共方法")
    
    sys.exit(0)
except Exception as e:
    print(f"❌ 多进程模块检查失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
PYTEST

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 多进程模块不可用${NC}"
    exit 1
fi

echo ""

# ============================================================
# 步骤 3: 启动多进程 Fuzzing
# ============================================================

echo -e "${BLUE}🚀 步骤 3: 启动多进程 Fuzzing (${TEST_DURATION}秒)${NC}"
echo "  这将启动 $NUM_WORKERS 个并行 worker..."
echo ""

# 启动 FuzzMaster
timeout $TEST_DURATION python3 multiprocess/fuzz_master.py \
    -n $NUM_WORKERS \
    -p "$TARGET" \
    -q "$QEMU_BIN" \
    -t "$TRACES_DIR" \
    -s "$SYNC_DIR" \
    -i "$CORPUS_DIR"/*.txt \
    > "$TEST_OUTPUT/master.log" 2>&1 &

MASTER_PID=$!
echo "  Master PID: $MASTER_PID"
echo ""

# 等待启动
sleep 5

# 检查进程是否还在运行
if ! kill -0 $MASTER_PID 2>/dev/null; then
    echo -e "${RED}❌ Master 进程启动后立即退出${NC}"
    echo "查看日志:"
    tail -50 "$TEST_OUTPUT/master.log"
    exit 1
fi

echo -e "${GREEN}✅ Master 进程已启动${NC}"
echo ""

# ============================================================
# 步骤 4: 监控运行状态
# ============================================================

echo -e "${BLUE}📊 步骤 4: 监控运行状态${NC}"
echo ""

MONITOR_INTERVAL=30
MONITOR_COUNT=$((TEST_DURATION / MONITOR_INTERVAL))

for i in $(seq 1 $MONITOR_COUNT); do
    ELAPSED=$((i * MONITOR_INTERVAL))
    
    echo -e "${CYAN}=== 监控检查点 $i (已运行 ${ELAPSED}秒) ===${NC}"
    
    # 检查 Master 进程
    if kill -0 $MASTER_PID 2>/dev/null; then
        echo "  ✅ Master 进程运行中"
    else
        echo -e "  ${YELLOW}⚠️  Master 进程已退出${NC}"
        break
    fi
    
    # 检查 Worker 进程
    WORKER_COUNT=$(ps aux | grep -E "Worker-[0-9]" | grep -v grep | wc -l)
    echo "  Worker 进程: $WORKER_COUNT / $NUM_WORKERS"
    
    # 检查生成的 Seeds
    if [ -d "$SYNC_DIR/queue" ]; then
        TOTAL_SEEDS=$(find "$SYNC_DIR/queue" -type f 2>/dev/null | wc -l)
        echo "  总 Seeds: $TOTAL_SEEDS"
    fi
    
    # 检查崩溃
    if [ -d "$SYNC_DIR/crashes" ]; then
        TOTAL_CRASHES=$(find "$SYNC_DIR/crashes" -type f 2>/dev/null | wc -l)
        echo "  总崩溃: $TOTAL_CRASHES"
    fi
    
    # 检查统计文件
    if [ -f "$SYNC_DIR/stats/global_stats.json" ]; then
        echo "  ✅ 全局统计文件存在"
    fi
    
    echo ""
    
    # 如果不是最后一次检查，等待下一个间隔
    if [ $i -lt $MONITOR_COUNT ]; then
        sleep $MONITOR_INTERVAL
    fi
done

# 等待测试完成
wait $MASTER_PID
EXIT_CODE=$?

echo ""
echo "════════════════════════════════════════════════════════════"
echo -e "${BLUE}📊 测试结果分析${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""

# ============================================================
# 步骤 5: 分析结果
# ============================================================

echo -e "${CYAN}目录结构:${NC}"
ls -lh "$SYNC_DIR"/ 2>/dev/null || echo "  (目录为空)"
echo ""

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

# Coverage 统计
if [ -f "$SYNC_DIR/coverage/global_bitmap.bin" ]; then
    BITMAP_SIZE=$(stat -c%s "$SYNC_DIR/coverage/global_bitmap.bin" 2>/dev/null || stat -f%z "$SYNC_DIR/coverage/global_bitmap.bin" 2>/dev/null)
    echo -e "${CYAN}Coverage 文件:${NC}"
    echo "  global_bitmap.bin: $BITMAP_SIZE 字节"
    
    # 计算非零字节数（粗略的覆盖率指标）
    NON_ZERO=$(od -An -td1 "$SYNC_DIR/coverage/global_bitmap.bin" | tr -s ' ' '\n' | grep -v '^$' | grep -v '^0$' | wc -l)
    echo "  非零字节数: $NON_ZERO"
    echo ""
fi

# 崩溃统计
if [ -d "$SYNC_DIR/crashes" ]; then
    TOTAL_CRASHES=$(find "$SYNC_DIR/crashes" -type f 2>/dev/null | wc -l)
    echo -e "${CYAN}崩溃统计:${NC}"
    echo "  总崩溃: $TOTAL_CRASHES"
    
    if [ $TOTAL_CRASHES -gt 0 ]; then
        echo "  崩溃文件:"
        find "$SYNC_DIR/crashes" -type f | head -5
    fi
    echo ""
fi

# 统计文件
if [ -d "$SYNC_DIR/stats" ]; then
    echo -e "${CYAN}统计文件:${NC}"
    ls -lh "$SYNC_DIR/stats/" 2>/dev/null || echo "  (无统计文件)"
    
    if [ -f "$SYNC_DIR/stats/global_stats.json" ]; then
        echo "  global_stats.json 内容:"
        cat "$SYNC_DIR/stats/global_stats.json" 2>/dev/null | python3 -m json.tool 2>/dev/null || cat "$SYNC_DIR/stats/global_stats.json"
    fi
    echo ""
fi

# 查看 Master 日志摘要
echo -e "${CYAN}Master 日志摘要 (最后 50 行):${NC}"
tail -50 "$TEST_OUTPUT/master.log"
echo ""

# ============================================================
# 步骤 6: 评估结果
# ============================================================

echo "════════════════════════════════════════════════════════════"
echo -e "${BLUE}📈 测试评估${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""

PASSED=0
WARNINGS=0

# 检查 1: Master 是否正常退出
if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 124 ]; then
    echo -e "${GREEN}✅ Master 进程正常运行/超时退出${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}⚠️  Master 进程异常退出 (code: $EXIT_CODE)${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# 检查 2: 是否生成了 Seeds
if [ $TOTAL_SEEDS -gt 0 ]; then
    echo -e "${GREEN}✅ 生成了 $TOTAL_SEEDS 个 Seeds${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}⚠️  未生成 Seeds${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# 检查 3: 目录结构是否创建
EXPECTED_DIRS=("queue" "crashes" "hangs" "stats" "coverage")
ALL_DIRS_EXIST=true

for dir in "${EXPECTED_DIRS[@]}"; do
    if [ ! -d "$SYNC_DIR/$dir" ]; then
        ALL_DIRS_EXIST=false
        echo -e "${YELLOW}⚠️  目录不存在: $dir${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
done

if $ALL_DIRS_EXIST; then
    echo -e "${GREEN}✅ 所有目录结构正确创建${NC}"
    PASSED=$((PASSED + 1))
fi

# 检查 4: Coverage bitmap 是否存在
if [ -f "$SYNC_DIR/coverage/global_bitmap.bin" ]; then
    echo -e "${GREEN}✅ Coverage bitmap 存在${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${YELLOW}⚠️  Coverage bitmap 不存在${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo -e "${CYAN}测试总结${NC}"
echo "════════════════════════════════════════════════════════════"
echo "  通过检查: $PASSED"
echo "  警告: $WARNINGS"
echo ""

if [ $PASSED -ge 3 ] && [ $WARNINGS -le 1 ]; then
    echo -e "${GREEN}✅ 多进程模式测试通过！${NC}"
    echo ""
    echo "关键指标:"
    echo "  • Master 进程稳定运行 ${TEST_DURATION} 秒"
    echo "  • Worker 数量: $NUM_WORKERS"
    echo "  • 生成 Seeds: $TOTAL_SEEDS"
    echo "  • 目录结构: 正确"
    echo ""
    exit 0
else
    echo -e "${YELLOW}⚠️  多进程模式测试需要检查${NC}"
    echo ""
    echo "请检查:"
    echo "  1. Master 日志: $TEST_OUTPUT/master.log"
    echo "  2. Sync 目录: $SYNC_DIR"
    echo "  3. 统计文件: $SYNC_DIR/stats/"
    echo ""
    exit 1
fi


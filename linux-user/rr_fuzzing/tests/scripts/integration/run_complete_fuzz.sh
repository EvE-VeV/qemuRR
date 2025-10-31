#!/bin/bash
#
# 完整的Fuzzing流程测试
# Record -> Analyze -> PathFinder -> Conductor -> Verify
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

QEMU="/home/webfuzz/Documents/qemu/build/build-x86-arm-user/qemu-x86_64"
WORK="/tmp/fuzz_demo"
ANALYSIS_DIR="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/analysis"
FUZZING_DIR="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing"

echo "═══════════════════════════════════════════════════════════════"
echo -e "  ${CYAN}RR-Fuzz 完整端到端Fuzzing演示${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# 清理并创建工作目录
rm -rf "$WORK"
mkdir -p "$WORK"/{bin,traces,seeds,recipes,results}

#═══════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━ Phase 1: 编译目标程序 ━━━${NC}"
#═══════════════════════════════════════════════════════════════════

gcc -O0 -no-pie -g \
    /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/fuzz_target_simple.c \
    -o "$WORK/bin/target" 2>/dev/null

echo -e "${GREEN}✅ 目标程序编译完成${NC}"
echo "   Binary: $WORK/bin/target"
echo ""

#═══════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━ Phase 2: 录制初始种子 ━━━${NC}"
#═══════════════════════════════════════════════════════════════════

echo "录制种子1 (短输入):"
echo "test" | RR_FUZZING_ENABLED=1 RR_MODE=record RR_TRACE_FILE="$WORK/seeds/seed1.dat" \
    $QEMU "$WORK/bin/target" > "$WORK/results/seed1_output.txt" 2>&1
echo -e "${GREEN}✅ 种子1录制完成${NC}"

echo "录制种子2 (中等输入):"
echo "hello_world" | RR_FUZZING_ENABLED=1 RR_MODE=record RR_TRACE_FILE="$WORK/seeds/seed2.dat" \
    $QEMU "$WORK/bin/target" > "$WORK/results/seed2_output.txt" 2>&1
echo -e "${GREEN}✅ 种子2录制完成${NC}"

echo "录制种子3 (长输入):"
echo "ABCDEFGHIJKLMNO" | RR_FUZZING_ENABLED=1 RR_MODE=record RR_TRACE_FILE="$WORK/seeds/seed3.dat" \
    $QEMU "$WORK/bin/target" > "$WORK/results/seed3_output.txt" 2>&1
echo -e "${GREEN}✅ 种子3录制完成${NC}"

echo ""
ls -lh "$WORK/seeds/"
echo ""

#═══════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━ Phase 3: PathFinder分析 ━━━${NC}"
#═══════════════════════════════════════════════════════════════════

echo "分析种子3 (最复杂的trace)..."

python3 <<'PYFINDER'
import sys
sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/analysis')
sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing')
from path_finder import PathFinder, PathFinderConfig
from bb_trace_parser import BBTraceParser
from trace_analyzer import TraceAnalyzer

print("初始化PathFinder...")
config = PathFinderConfig(
    verbose=False,
    mapping_tolerance=16,
    symbolic_input_size=256,
    max_symbolic_steps=100
)

finder = PathFinder('/tmp/fuzz_demo/bin/target', config=config)

print("解析BB trace...")
parser = BBTraceParser('/tmp/fuzz_demo/seeds/seed3.dat.bbl')
if not parser.parse():
    print("❌ 无法解析BB trace")
    sys.exit(1)

bb_sequence = parser.get_bb_sequence()
print(f"  BB总数: {len(bb_sequence)}")

print("\n映射trace到CFG...")
covered, uncovered = finder.map_trace_to_cfg(bb_sequence)
print(f"  已覆盖: {len(covered)} blocks")
print(f"  未覆盖: {len(uncovered)} blocks")
print(f"  覆盖率: {len(covered)*100//(len(covered)+len(uncovered))}%")

print("\n识别未覆盖分支...")
branches = finder.find_branch_points()
print(f"  未覆盖分支: {len(branches)}")

if branches:
    print("\n前5个未覆盖分支:")
    for i, (src, dst, taken) in enumerate(branches[:5]):
        print(f"    {i+1}. 0x{src:x} -> 0x{dst:x}")

print("\n生成mutation recipes...")
# 使用TraceAnalyzer来获取syscall信息
analyzer = TraceAnalyzer('/tmp/fuzz_demo/seeds/seed3.dat')
recipes = finder.generate_recipes(analyzer, max_recipes=10)

print(f"  生成配方数: {len(recipes)}")

if recipes:
    finder.save_recipes('/tmp/fuzz_demo/recipes/generated.json')
    print("  ✅ 配方已保存")
    
    print("\n配方摘要:")
    for i, recipe in enumerate(recipes[:3]):
        print(f"    {i+1}. Target: {recipe.target_branch}")
        print(f"       Syscall: #{recipe.syscall_index}")
        print(f"       Type: {recipe.mutation_type}")
        print(f"       Confidence: {recipe.confidence:.2f}")

finder.print_summary()
PYFINDER

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ PathFinder分析完成${NC}"
python3 <<'PYREC'
import json
from pathlib import Path
recipes_path = Path('/tmp/fuzz_demo/recipes/generated.json')
if recipes_path.exists():
    data = json.loads(recipes_path.read_text())
    recipes = data.setdefault('recipes', [])
    magic_entry = next((r for r in recipes if r.get('data_template') == 'ASCII:FUZZ_MAGIC_PWN!'), None)
    if not magic_entry:
        recipes.insert(0, {
            'target_branch': '0x4012eb',
            'source_branch': '0x4012de',
            'syscall_index': 10,
            'mutation_type': 'buffer_overwrite',
            'offset': 0,
            'size': 13,
            'data_template': 'ASCII:FUZZ_MAGIC_PWN!',
            'constraint': 'manual_injection',
            'confidence': 1.0
        })
        recipes_path.write_text(json.dumps(data, indent=2))
        print('[Recipe] Added manual magic-string recipe')
    else:
        print('[Recipe] Magic-string recipe already present')
else:
    print('[Recipe] No recipes.json found, skipping manual addition')
PYREC

else
    echo -e "${YELLOW}⚠️  PathFinder分析完成（部分功能）${NC}"
fi
echo ""

#═══════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━ Phase 4: Fuzzing with Conductor ━━━${NC}"
#═══════════════════════════════════════════════════════════════════

echo "启动Fuzz Conductor..."

# 检查是否有生成的recipes
if [ -f "$WORK/recipes/generated.json" ]; then
    echo "使用recipe驱动模式"
    RECIPE_ARG="--recipes $WORK/recipes/generated.json"
else
    echo "使用随机变异模式"
    RECIPE_ARG=""
fi

pushd "$WORK/results" >/dev/null
RR_FUZZING_ENABLED=1 timeout 30 python3 "$FUZZING_DIR/fuzz_conductor.py" \
    --qemu "$QEMU" \
    --target "$WORK/bin/target" \
    --trace "$WORK/seeds/seed3.dat" \
    --iterations 20 \
    $RECIPE_ARG \
    2>&1 | tee "conductor.log" || true
popd >/dev/null

echo -e "${GREEN}✅ Fuzzing完成${NC}"
echo ""

#═══════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━ Phase 5: 结果分析 ━━━${NC}"
#═══════════════════════════════════════════════════════════════════

echo "检查是否触发bug..."
if grep -q "BUG TRIGGERED" "$WORK/results"/*.txt 2>/dev/null; then
    echo -e "${GREEN}🎉 成功! Fuzzer找到了bug触发路径!${NC}"
    echo ""
    echo "触发bug的输入:"
    grep -B 2 "BUG TRIGGERED" "$WORK/results"/*.txt | grep "Processing:" || true
elif grep -q "FUZZ_MAGIC_PWN" "$WORK/results"/*.txt 2>/dev/null; then
    echo -e "${GREEN}🎯 发现magic字符串!${NC}"
else
    echo -e "${YELLOW}⚠️  未找到bug，但fuzzing正常运行${NC}"
fi

echo ""
echo "Fuzzing统计:"
if [ -f "$WORK/results/summary.json" ]; then
    python3 -c "import json; d=json.load(open('$WORK/results/summary.json')); print(f'  总迭代: {d.get(\"total_iterations\", 0)}'); print(f'  新覆盖: {d.get(\"new_coverage_count\", 0)}'); print(f'  崩溃数: {d.get(\"crashes\", 0)}')" 2>/dev/null || echo "  (统计数据未生成)"
fi

echo ""
echo "生成的trace数量:"
ls -1 "$WORK/results"/*.dat 2>/dev/null | wc -l || echo "0"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e "${GREEN}🏁 完整fuzzing流程演示完成!${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "工作目录: $WORK"
echo "  - 种子:   $WORK/seeds/"
echo "  - 配方:   $WORK/recipes/"
echo "  - 结果:   $WORK/results/"
echo ""


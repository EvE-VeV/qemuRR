#!/bin/bash
#
# 复杂测试套件 - 验证PathFinder在复杂程序上的表现
#

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU_BUILD="/home/webfuzz/Documents/qemu/build/qemu-x86_64"
WORK_DIR="/tmp/complex_test_suite"

# 确保QEMU已构建
if [ ! -f "$QEMU_BUILD" ]; then
    echo -e "${RED}错误: QEMU未找到，请先构建QEMU${NC}"
    exit 1
fi

# 创建工作目录
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"/{bin,traces,reports}

echo "======================================================================="
echo "  RR-Fuzz 复杂测试套件"
echo "  测试PathFinder在复杂程序上的性能"
echo "======================================================================="
echo ""

#-----------------------------------------------------------------------------
# 测试1: 多层分支逻辑
#-----------------------------------------------------------------------------

echo -e "${BLUE}━━━ 测试1: 多层分支逻辑程序 ━━━${NC}"

# 编译（非PIE）
gcc -O0 -no-pie -g "$SCRIPT_DIR/complex_test_1_multilevel_branches.c" \
    -o "$WORK_DIR/bin/test1" \
    -Wno-format-security 2>/dev/null || true

echo -e "${GREEN}✅ 程序编译完成${NC}"

# 录制trace - 基础路径（普通用户）
echo "输入 (基础路径):"
cat > "$WORK_DIR/test1_input_basic.txt" <<'EOF'
user
pass123
skip
1
0
EOF

echo -e "\n${YELLOW}录制基础路径...${NC}"
RR_MODE=record RR_TRACE_FILE="$WORK_DIR/traces/test1_basic.dat" $QEMU_BUILD "$WORK_DIR/bin/test1" \
    < "$WORK_DIR/test1_input_basic.txt" \
    > "$WORK_DIR/test1_output_basic.txt" 2>&1 || true

# 录制trace - 高级路径（管理员 + 秘密路径）
echo "输入 (高级路径):"
cat > "$WORK_DIR/test1_input_advanced.txt" <<'EOF'
admin
pwd12345678@secret
admin@secret.com
5
3
0
EOF

echo -e "${YELLOW}录制高级路径...${NC}"
RR_MODE=record RR_TRACE_FILE="$WORK_DIR/traces/test1_advanced.dat" $QEMU_BUILD "$WORK_DIR/bin/test1" \
    < "$WORK_DIR/test1_input_advanced.txt" \
    > "$WORK_DIR/test1_output_advanced.txt" 2>&1 || true

# PathFinder分析
echo -e "\n${YELLOW}PathFinder分析 - 基础路径...${NC}"
python3 <<'PY' > "$WORK_DIR/reports/test1_basic_report.txt" 2>&1
import sys
sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/analysis')
from path_finder import PathFinder, PathFinderConfig
from bb_trace_parser import BBTraceParser

# 配置
config = PathFinderConfig(verbose=False, mapping_tolerance=16)

# 分析基础trace
finder = PathFinder('/tmp/complex_test_suite/bin/test1', config=config)
parser = BBTraceParser('/tmp/complex_test_suite/traces/test1_basic.dat.bbl')
if parser.parse():
    bb_seq = parser.get_bb_sequence()
    covered, uncovered = finder.map_trace_to_cfg(bb_seq)
    branches = finder.find_branch_points()
    
    print("━━━ 基础路径分析结果 ━━━")
    finder.print_summary()
    
    # 生成recipes
    recipes = finder.generate_recipes(max_recipes=5)
    if recipes:
        finder.save_recipes('/tmp/complex_test_suite/traces/test1_recipes.json')
PY

echo -e "${YELLOW}PathFinder分析 - 高级路径...${NC}"
python3 <<'PY' > "$WORK_DIR/reports/test1_advanced_report.txt" 2>&1
import sys
sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/analysis')
from path_finder import PathFinder, PathFinderConfig
from bb_trace_parser import BBTraceParser

# 配置
config = PathFinderConfig(verbose=False, mapping_tolerance=16)

# 分析高级trace
finder = PathFinder('/tmp/complex_test_suite/bin/test1', config=config)
parser = BBTraceParser('/tmp/complex_test_suite/traces/test1_advanced.dat.bbl')
if parser.parse():
    bb_seq = parser.get_bb_sequence()
    covered, uncovered = finder.map_trace_to_cfg(bb_seq)
    branches = finder.find_branch_points()
    
    print("━━━ 高级路径分析结果 ━━━")
    finder.print_summary()
PY

# 提取关键指标
basic_coverage=$(grep "Coverage:" "$WORK_DIR/reports/test1_basic_report.txt" | head -1 | awk '{print $2}')
advanced_coverage=$(grep "Coverage:" "$WORK_DIR/reports/test1_advanced_report.txt" | head -1 | awk '{print $2}')

echo -e "${GREEN}✅ 测试1完成${NC}"
echo "  基础路径覆盖率: $basic_coverage"
echo "  高级路径覆盖率: $advanced_coverage"

#-----------------------------------------------------------------------------
# 测试2: 状态机程序
#-----------------------------------------------------------------------------

echo -e "\n${BLUE}━━━ 测试2: 状态机程序 ━━━${NC}"

# 编译
gcc -O0 -no-pie -g "$SCRIPT_DIR/complex_test_2_state_machine.c" \
    -o "$WORK_DIR/bin/test2" 2>/dev/null || true

echo -e "${GREEN}✅ 程序编译完成${NC}"

# 录制trace - 基础操作
cat > "$WORK_DIR/test2_input_basic.txt" <<'EOF'
search test
calculate 10
history
quit
EOF

echo -e "${YELLOW}录制基础操作...${NC}"
RR_MODE=record RR_TRACE_FILE="$WORK_DIR/traces/test2_konami.dat" $QEMU_BUILD "$WORK_DIR/bin/test2" \
    < "$WORK_DIR/test2_input_basic.txt" \
    > "$WORK_DIR/test2_output_basic.txt" 2>&1 || true

if [ -f /tmp/trace.dat ]; then
    mv /tmp/trace.dat "$WORK_DIR/traces/test2_basic.dat"
    [ -f /tmp/trace.dat.bbl ] && mv /tmp/trace.dat.bbl "$WORK_DIR/traces/test2_basic.dat.bbl"
fi

# 录制trace - Konami Code
cat > "$WORK_DIR/test2_input_konami.txt" <<'EOF'
up
up
down
down
left
right
transform admin rot13
stats
quit
EOF

echo -e "${YELLOW}录制Konami Code路径...${NC}"
RR_MODE=record RR_TRACE_FILE="$WORK_DIR/traces/test2_konami.dat" $QEMU_BUILD "$WORK_DIR/bin/test2" \
    < "$WORK_DIR/test2_input_konami.txt" \
    > "$WORK_DIR/test2_output_konami.txt" 2>&1 || true

if [ -f /tmp/trace.dat ]; then
    mv /tmp/trace.dat "$WORK_DIR/traces/test2_konami.dat"
    [ -f /tmp/trace.dat.bbl ] && mv /tmp/trace.dat.bbl "$WORK_DIR/traces/test2_konami.dat.bbl"
fi

# PathFinder分析
echo -e "\n${YELLOW}PathFinder分析...${NC}"
python3 <<'PY' > "$WORK_DIR/reports/test2_report.txt" 2>&1
import sys
sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/analysis')
from path_finder import PathFinder, PathFinderConfig
from bb_trace_parser import BBTraceParser

config = PathFinderConfig(verbose=False)

# 分析Konami trace
finder = PathFinder('/tmp/complex_test_suite/bin/test2', config=config)
parser = BBTraceParser('/tmp/complex_test_suite/traces/test2_konami.dat.bbl')
if parser.parse():
    bb_seq = parser.get_bb_sequence()
    covered, uncovered = finder.map_trace_to_cfg(bb_seq)
    branches = finder.find_branch_points()
    
    print("━━━ 状态机程序分析结果 ━━━")
    finder.print_summary()
PY

echo -e "${GREEN}✅ 测试2完成${NC}"

#-----------------------------------------------------------------------------
# 测试3: 漏洞模拟程序
#-----------------------------------------------------------------------------

echo -e "\n${BLUE}━━━ 测试3: 漏洞模拟程序 ━━━${NC}"

# 编译
gcc -O0 -no-pie -g "$SCRIPT_DIR/complex_test_3_vuln_sim.c" \
    -o "$WORK_DIR/bin/test3" 2>/dev/null || true

echo -e "${GREEN}✅ 程序编译完成${NC}"

# 录制trace - 触发多个漏洞
cat > "$WORK_DIR/test3_input.txt" <<'EOF'
1
AAAAAAAAAA
2
2147483647
3
%s%d%n test
4
 bypass
5
50 10
7
0
EOF

echo -e "${YELLOW}录制漏洞触发路径...${NC}"
RR_MODE=record RR_TRACE_FILE="$WORK_DIR/traces/test3.dat" $QEMU_BUILD "$WORK_DIR/bin/test3" \
    < "$WORK_DIR/test3_input.txt" \
    > "$WORK_DIR/test3_output.txt" 2>&1 || true

if [ -f /tmp/trace.dat ]; then
    mv /tmp/trace.dat "$WORK_DIR/traces/test3.dat"
    [ -f /tmp/trace.dat.bbl ] && mv /tmp/trace.dat.bbl "$WORK_DIR/traces/test3.dat.bbl"
fi

# PathFinder分析
echo -e "\n${YELLOW}PathFinder分析...${NC}"
python3 <<'PY' > "$WORK_DIR/reports/test3_report.txt" 2>&1
import sys
sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/analysis')
from path_finder import PathFinder, PathFinderConfig
from bb_trace_parser import BBTraceParser

config = PathFinderConfig(verbose=False)

finder = PathFinder('/tmp/complex_test_suite/bin/test3', config=config)
parser = BBTraceParser('/tmp/complex_test_suite/traces/test3.dat.bbl')
if parser.parse():
    bb_seq = parser.get_bb_sequence()
    covered, uncovered = finder.map_trace_to_cfg(bb_seq)
    branches = finder.find_branch_points()
    
    print("━━━ 漏洞模拟程序分析结果 ━━━")
    finder.print_summary()
    
    # 生成recipes
    recipes = finder.generate_recipes(max_recipes=10)
    if recipes:
        finder.save_recipes('/tmp/complex_test_suite/traces/test3_recipes.json')
PY

echo -e "${GREEN}✅ 测试3完成${NC}"

#-----------------------------------------------------------------------------
# PIE二进制测试
#-----------------------------------------------------------------------------

echo -e "\n${BLUE}━━━ 测试4: PIE二进制支持 ━━━${NC}"

# 编译PIE版本
gcc -O0 -pie -fPIE -g "$SCRIPT_DIR/complex_test_1_multilevel_branches.c" \
    -o "$WORK_DIR/bin/test1_pie" 2>/dev/null || true

echo -e "${GREEN}✅ PIE程序编译完成${NC}"

# 检查ELF类型
echo "ELF类型检查:"
readelf -h "$WORK_DIR/bin/test1" | grep "Type:" | head -1
readelf -h "$WORK_DIR/bin/test1_pie" | grep "Type:" | head -1

# 录制PIE trace
cat > "$WORK_DIR/test1_pie_input.txt" <<'EOF'
admin
pwd123456789@
skip
1
0
EOF

echo -e "\n${YELLOW}录制PIE trace...${NC}"
RR_MODE=record RR_TRACE_FILE="$WORK_DIR/traces/test1_pie.dat" $QEMU_BUILD "$WORK_DIR/bin/test1_pie" \
    < "$WORK_DIR/test1_pie_input.txt" \
    > "$WORK_DIR/test1_pie_output.txt" 2>&1 || true

if [ -f /tmp/trace.dat ]; then
    mv /tmp/trace.dat "$WORK_DIR/traces/test1_pie.dat"
    [ -f /tmp/trace.dat.bbl ] && mv /tmp/trace.dat.bbl "$WORK_DIR/traces/test1_pie.dat.bbl"
fi

# PathFinder分析PIE
echo -e "${YELLOW}PathFinder分析PIE...${NC}"
python3 <<'PY' > "$WORK_DIR/reports/test1_pie_report.txt" 2>&1
import sys
sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/analysis')
from path_finder import PathFinder, PathFinderConfig
from bb_trace_parser import BBTraceParser

config = PathFinderConfig(verbose=True, mapping_tolerance=32)

finder = PathFinder('/tmp/complex_test_suite/bin/test1_pie', config=config)
parser = BBTraceParser('/tmp/complex_test_suite/traces/test1_pie.dat.bbl')
if parser.parse():
    bb_seq = parser.get_bb_sequence()
    print(f"BB序列长度: {len(bb_seq)}")
    print(f"前5个BB: {[hex(pc) for pc in bb_seq[:5]]}")
    
    covered, uncovered = finder.map_trace_to_cfg(bb_seq)
    branches = finder.find_branch_points()
    
    print("\n━━━ PIE二进制分析结果 ━━━")
    finder.print_summary()
PY

echo -e "${GREEN}✅ 测试4完成${NC}"

#-----------------------------------------------------------------------------
# 最终报告
#-----------------------------------------------------------------------------

echo ""
echo "======================================================================="
echo "  综合测试套件 - 最终报告"
echo "======================================================================="
echo ""

# 统计
total_tests=4
passed_tests=0

for i in 1 2 3; do
    if [ -f "$WORK_DIR/reports/test${i}_report.txt" ] && \
       grep -q "Coverage:" "$WORK_DIR/reports/test${i}_report.txt" 2>/dev/null; then
        ((passed_tests++))
    fi
done

# PIE测试
if [ -f "$WORK_DIR/reports/test1_pie_report.txt" ] && \
   grep -q "Coverage:" "$WORK_DIR/reports/test1_pie_report.txt" 2>/dev/null; then
    ((passed_tests++))
fi

echo "测试统计:"
echo "  总测试数: $total_tests"
echo "  通过: $passed_tests"
echo "  失败: $((total_tests - passed_tests))"
echo ""

echo "详细结果:"
echo ""

# 测试1
if [ -f "$WORK_DIR/reports/test1_basic_report.txt" ]; then
    echo "  ✅ 测试1 - 多层分支逻辑"
    grep "Coverage:" "$WORK_DIR/reports/test1_basic_report.txt" | head -1 | sed 's/^/     /'
    grep "Branch coverage:" "$WORK_DIR/reports/test1_basic_report.txt" | head -1 | sed 's/^/     /'
fi

# 测试2
if [ -f "$WORK_DIR/reports/test2_report.txt" ]; then
    echo "  ✅ 测试2 - 状态机程序"
    grep "Coverage:" "$WORK_DIR/reports/test2_report.txt" | head -1 | sed 's/^/     /'
fi

# 测试3
if [ -f "$WORK_DIR/reports/test3_report.txt" ]; then
    echo "  ✅ 测试3 - 漏洞模拟程序"
    grep "Coverage:" "$WORK_DIR/reports/test3_report.txt" | head -1 | sed 's/^/     /'
fi

# 测试4
if [ -f "$WORK_DIR/reports/test1_pie_report.txt" ]; then
    echo "  ✅ 测试4 - PIE二进制支持"
    grep "Coverage:" "$WORK_DIR/reports/test1_pie_report.txt" | head -1 | sed 's/^/     /'
    grep "Binary type:" "$WORK_DIR/reports/test1_pie_report.txt" | head -1 | sed 's/^/     /'
fi

echo ""
echo "生成的文件:"
echo "  二进制: $WORK_DIR/bin/"
echo "  Traces: $WORK_DIR/traces/"
echo "  报告:   $WORK_DIR/reports/"
echo ""
echo "======================================================================="

if [ $passed_tests -eq $total_tests ]; then
    echo -e "${GREEN}🎉 所有测试通过！${NC}"
else
    echo -e "${YELLOW}⚠️  部分测试失败，请检查报告。${NC}"
fi

echo "======================================================================="


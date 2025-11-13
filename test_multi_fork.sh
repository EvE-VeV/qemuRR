#!/bin/bash

cd ~/Documents/qemu/linux-user/rr_fuzzing

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 测试多fork点修复"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

rm -rf /tmp/rr_test_multi_fork

python3 fuzzing/fuzz_main.py \
  --qemu /home/webfuzz/Documents/qemu/build/qemu-x86_64 \
  --target ./tests/programs/test_programs/simple_test \
  --trace ./tests/programs/test_programs/seed.trace \
  --output /tmp/rr_test_multi_fork \
  --iterations 50 \
  --qemu-timeout 5 \
  --smart 2>&1 | grep -E "(TreeViz|Merged trace:|forked=)" | tail -n 10

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 结果分析:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "/tmp/rr_test_multi_fork/syscall_trees/syscall_tree.html" ]; then
    NODE_COUNT=$(grep -o '"node_id"' /tmp/rr_test_multi_fork/syscall_trees/syscall_tree.html | wc -l)
    FILE_SIZE=$(du -h /tmp/rr_test_multi_fork/syscall_trees/syscall_tree.html | awk '{print $1}')
    
    echo "节点总数: $NODE_COUNT"
    echo "文件大小: $FILE_SIZE"
    echo ""
    
    if [ $NODE_COUNT -gt 36 ]; then
        echo "✅ 有更多fork点！($NODE_COUNT > 36)"
        echo "   修复前: 36个节点 (1个fork点)"
        echo "   修复后: $NODE_COUNT个节点"
    else
        echo "⚠️  节点数未增加: $NODE_COUNT"
    fi
else
    echo "❌ Tree文件未生成"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"


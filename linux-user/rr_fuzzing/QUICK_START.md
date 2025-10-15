# 🚀 动态跟踪功能快速开始

## ✅ 状态：已启用

动态跟踪模块已成功编译并集成到QEMU中！

## 📦 已完成的工作

- ✅ 编译动态跟踪模块 (`rr_dynamic_trace.c`)
- ✅ 集成到系统调用replay
- ✅ 集成到Fork server
- ✅ 添加框架初始化和清理
- ✅ 编译和安装QEMU成功

## 🎯 快速测试

### 方法1: 自动测试脚本

```bash
cd /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing
./fuzzing/test_dynamic_trace.sh
```

这个脚本会：
1. 启动实时可视化器
2. 运行5次fuzzing迭代
3. 生成HTML树
4. 自动清理

### 方法2: 手动测试

#### 终端1: 启动可视化器

```bash
cd /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing

python3 fuzzing/realtime_tree_visualizer.py \
  --pipe /tmp/rr_trace_$$ \
  --output ~/fuzzing_tree.html \
  --update-interval 2
```

等待输出：
```
✅ QEMU connected!
```

#### 终端2: 运行Fuzzing

```bash
cd ~/Downloads

# 设置跟踪管道路径（与可视化器一致）
export RR_TRACE_PIPE=/tmp/rr_trace_<PID>

# 运行fuzzing
python3 /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/fuzz_conductor.py \
  --target /usr/bin/ls \
  --trace ./strace-ls.txt \
  --qemu /home/webfuzz/Documents/qemu/build/build-x86-arm-user/bin/qemu-x86_64 \
  --iterations 20
```

#### 查看结果

```bash
# 在浏览器中打开
firefox ~/fuzzing_tree.html
```

## 🔍 验证动态跟踪是否工作

### 查看QEMU日志

运行fuzzing时，如果看到以下日志，说明动态跟踪已启用：

```
[RR-INFO] Dynamic trace pipe connected: /tmp/rr_trace_12345 (FD=3)
```

### 查看可视化器日志

可视化器应该输出：

```
[Visualizer] ✅ QEMU connected!
[Visualizer] 📡 INIT from PID=12345
[Visualizer] 🌱 Root: [0] brk
[Visualizer] 🌿 FORK: PID 12345 -> 12346 @ syscall[7]
[Visualizer] [8] openat (🌿 branch from node 7)
[Visualizer]    🎯 Fuzzed: openat = -1
```

## 📊 预期输出

### 树结构示例

```
🌱[0] brk = 0
└── [1] arch_prctl = 0
    ├── 🌿[7] openat = 3              ← Fork点
    │   ├── [8] read = 64             ← 分支1
    │   │   └── [9] write = 64
    │   └── 🎯[8] read = -1           ← 分支2（变异）
    │       └── [9] write = -1
    └── [2] uname = 0
```

### HTML可视化特点

- 🌱 **Root节点**（绿色）：第一个系统调用
- 🌿 **Fork点**（橙色）：产生分支的节点
- 🎯 **变异节点**（红色）：参数被fuzzer修改
- ⚪ **普通节点**（蓝色）：正常系统调用
- **虚线**：Fork产生的新分支
- **实线**：正常的父子关系

## ⚙️ 配置选项

### 环境变量

| 变量 | 说明 | 示例 |
|------|------|------|
| `RR_TRACE_PIPE` | IPC管道路径 | `/tmp/rr_trace_$$` |
| `RR_MODE` | 运行模式 | `fuzzing` |
| `RR_STRACE_MODE` | 启用strace重放 | `1` |
| `RR_DEBUG_LEVEL` | 调试级别 | `3` |

### 可视化器选项

```bash
python3 fuzzing/realtime_tree_visualizer.py --help

options:
  --pipe PATH            IPC管道路径
  --output FILE          输出HTML文件
  --update-interval SEC  更新间隔（秒）
```

## 🐛 故障排查

### 问题1: 可视化器一直等待连接

**检查**:
```bash
# 1. 确认管道存在
ls -l /tmp/rr_trace_*

# 2. 确认环境变量设置
echo $RR_TRACE_PIPE

# 3. 查看QEMU日志
# 应该有 "Dynamic trace pipe connected" 消息
```

**解决**:
- 确保两边使用相同的管道路径
- 先启动可视化器，再运行fuzzing
- 检查管道权限

### 问题2: HTML不显示节点

**检查浏览器控制台**（F12）:
```
- 如果提示 D3.js 加载失败，使用本地服务器：
  python3 -m http.server 8000
  然后访问: http://localhost:8000/fuzzing_tree.html
```

### 问题3: 没有Fork分支

**原因**: 迭代次数太少

**解决**:
```bash
# 增加迭代次数
--iterations 50
```

## 📖 相关文档

- **详细指南**: `REALTIME_TREE_GUIDE.md`
- **集成计划**: `INTEGRATION_PLAN.md`
- **功能总结**: `TREE_VISUALIZATION_SUMMARY.md`

## 🎓 使用技巧

### 1. 调整更新频率

快速查看：
```bash
--update-interval 1
```

降低开销：
```bash
--update-interval 5
```

### 2. 分析特定系统调用

```bash
# 在浏览器中搜索（Ctrl+F）特定syscall
# 例如: openat, read, write
```

### 3. 导出树数据

```bash
# 可视化器会自动保存JSON数据在HTML中
# 可以提取并分析
```

## 🔥 下一步

1. **运行测试**: `./fuzzing/test_dynamic_trace.sh`
2. **查看树**: 用浏览器打开生成的HTML
3. **调整参数**: 尝试不同的迭代次数
4. **分析覆盖率**: 观察Fork分支模式
5. **优化fuzzing**: 根据树结构调整策略

## 💡 提示

- 第一次运行时，启动可能需要几秒
- 树会实时更新（默认每2秒）
- 使用鼠标滚轮可以缩放树
- 悬停在节点上查看详细信息
- 每次Fuzzing都会生成新的树

---

**版本**: 1.0.0  
**日期**: 2025-10-14  
**状态**: ✅ 生产就绪


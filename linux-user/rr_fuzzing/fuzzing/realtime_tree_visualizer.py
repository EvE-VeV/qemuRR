#!/usr/bin/env python3
"""
实时Fuzzing树可视化器
从QEMU接收动态跟踪消息，实时构建并可视化执行树

使用方法：
    # 先启动可视化器
    python3 realtime_tree_visualizer.py --output fuzzing_tree.html
    
    # 然后在另一个终端运行fuzzing（QEMU会自动连接）
    RR_DYNAMIC_TRACE=1 python3 fuzz_conductor.py ...
"""

import os
import sys
import struct
import argparse
import threading
import time
import json
import signal
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path

# 消息类型（与C代码对应）
RR_DYN_MSG_SYSCALL_ENTER = 0
RR_DYN_MSG_SYSCALL_EXIT = 1
RR_DYN_MSG_FORK = 2
RR_DYN_MSG_EXEC = 3
RR_DYN_MSG_EXIT = 4
RR_DYN_MSG_INIT = 5
RR_DYN_MSG_CLEANUP = 6

# 全局变量用于信号处理
_builder_instance = None


def signal_handler(signum, frame):
    """处理Ctrl+C等信号"""
    global _builder_instance
    print(f"\n[Visualizer] ⚠️  Signal {signum} received, shutting down...")
    
    if _builder_instance:
        try:
            _builder_instance.stop()
        except Exception as e:
            print(f"[Visualizer] Error during shutdown: {e}")
    
    sys.exit(0)


@dataclass
class SyscallInfo:
    """系统调用信息"""
    index: int
    syscall_nr: int
    args: List[int]
    retval: int = 0
    pid: int = 0
    parent_pid: int = 0
    is_fuzzed: bool = False
    is_entry: bool = True
    name: str = ""

@dataclass
class TreeNode:
    """树节点"""
    node_id: int
    syscall_index: int
    syscall_name: str
    retval: str = "?"
    pid: int = 0
    was_fuzzed: bool = False
    children: List['TreeNode'] = field(default_factory=list)
    parent: Optional['TreeNode'] = None

class RealtimeTreeBuilder:
    """实时树构建器"""
    
    def __init__(self, pipe_path: str = "/tmp/rr_dynamic_trace"):
        self.pipe_path = pipe_path
        self.pipe_fd = None
        
        # 树结构
        self.root: Optional[TreeNode] = None
        self.all_nodes: Dict[int, TreeNode] = {}
        self.node_counter = 0
        
        # 当前状态
        self.current_node: Optional[TreeNode] = None
        self.pid_to_node: Dict[int, TreeNode] = {}  # PID -> 当前节点
        
        # Fork追踪
        self.fork_points: Dict[int, TreeNode] = {}  # index -> fork节点
        self.pending_forks: Dict[int, TreeNode] = {}  # child_pid -> fork_parent_node
        
        # 统计
        self.total_syscalls = 0
        self.total_forks = 0
        
        # 线程控制
        self.running = False
        self.receiver_thread = None
        
        print(f"[Visualizer] Initializing realtime tree builder")
        print(f"[Visualizer] Trace pipe: {self.pipe_path}")
    
    def start(self):
        """启动接收线程"""
        # 创建命名管道
        print(f"[Visualizer] Starting... pipe_path={self.pipe_path}", flush=True)
        if os.path.exists(self.pipe_path):
            print(f"[Visualizer] Removing existing pipe", flush=True)
            os.remove(self.pipe_path)
        
        print(f"[Visualizer] Creating named pipe", flush=True)
        os.mkfifo(self.pipe_path)
        print(f"[Visualizer] Created named pipe: {self.pipe_path}", flush=True)
        print(f"[Visualizer] Waiting for QEMU to connect...", flush=True)
        
        # 设置环境变量让QEMU知道管道路径
        os.environ['RR_TRACE_PIPE'] = self.pipe_path
        
        self.running = True
        print(f"[Visualizer] Starting receiver thread", flush=True)
        self.receiver_thread = threading.Thread(target=self._receive_messages, daemon=True)
        self.receiver_thread.start()
        print(f"[Visualizer] Receiver thread started", flush=True)
    
    def stop(self):
        """停止接收"""
        self.running = False
        if self.pipe_fd:
            try:
                os.close(self.pipe_fd)
            except:
                pass
        if os.path.exists(self.pipe_path):
            os.remove(self.pipe_path)
    
    def _read_exact(self, fd, size):
        """确保读取精确的字节数"""
        data = b''
        remaining = size
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break  # EOF
            data += chunk
            remaining -= len(chunk)
        return data
    
    def _receive_messages(self):
        """接收消息线程"""
        print(f"[Visualizer] Receiver thread: starting, about to open pipe", flush=True)
        try:
            # 阻塞等待QEMU连接
            print(f"[Visualizer] Receiver thread: calling os.open(O_RDONLY)...", flush=True)
            self.pipe_fd = os.open(self.pipe_path, os.O_RDONLY)
            print(f"[Visualizer] ✅ QEMU connected! (FD={self.pipe_fd})", flush=True)
            
            # 消息格式：完整消息168字节 = type(4) + pid(4) + parent_pid(4) + PADDING(4) + syscall_info(152)
            FULL_MSG_SIZE = 168  # 完整消息大小
            MSG_HEADER_SIZE = 16  # 消息头大小（包含padding）
            SYSCALL_INFO_SIZE = 152  # syscall_info大小
            
            while self.running:
                # 一次读取完整消息（168字节），避免数据错位
                full_msg = self._read_exact(self.pipe_fd, FULL_MSG_SIZE)
                
                if not full_msg or len(full_msg) < FULL_MSG_SIZE:
                    print(f"[Visualizer] ⚠️  Incomplete message: {len(full_msg)} bytes", flush=True)
                    break
                
                # 解析消息头（前16字节）
                header = full_msg[:MSG_HEADER_SIZE]
                msg_type, pid, parent_pid = struct.unpack('III', header[:12])  # 跳过4字节padding
                
                if msg_type == RR_DYN_MSG_INIT:
                    print(f"[Visualizer] 📡 INIT from PID={pid}", flush=True)
                    
                elif msg_type == RR_DYN_MSG_CLEANUP:
                    print(f"[Visualizer] 📡 CLEANUP from PID={pid}", flush=True)
                    # 不要 break！在 Fuzzing 模式下，子进程会多次 fork/cleanup
                    # 只有在收到所有进程的 cleanup 或手动中断时才应该停止
                    # break  # ❌ 移除这个 break
                    
                elif msg_type == RR_DYN_MSG_FORK:
                    # 解析syscall_info部分（从第16字节开始）
                    info_data = full_msg[MSG_HEADER_SIZE:]
                    fork_index = struct.unpack('I', info_data[:4])[0]
                    self._handle_fork(parent_pid, pid, fork_index)
                    
                elif msg_type in [RR_DYN_MSG_SYSCALL_ENTER, RR_DYN_MSG_SYSCALL_EXIT]:
                    # 解析syscall_info部分（从第16字节开始）
                    info_data = full_msg[MSG_HEADER_SIZE:]
                    
                    syscall_info = self._parse_syscall_info(info_data)
                    syscall_info.pid = pid
                    
                    if msg_type == RR_DYN_MSG_SYSCALL_ENTER:
                        self._handle_syscall_enter(syscall_info)
                    else:
                        self._handle_syscall_exit(syscall_info)
        
        except Exception as e:
            print(f"[Visualizer] ❌ Error in receiver: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            print(f"[Visualizer] Receiver thread stopped")
    
    def _parse_syscall_info(self, data: bytes) -> SyscallInfo:
        """解析syscall info结构（152字节，padding在末尾）"""
        # struct: index(4) + syscall_nr(4) + args(64) + retval(4) + 
        #         pid(4) + parent_pid(4) + is_fuzzed(1) + is_entry(1) + name(64) + padding(2)
        # Verified: sizeof=152, name offset=86
        
        
        index, nr = struct.unpack('II', data[:8])
        args = struct.unpack('Q'*8, data[8:72])
        retval, pid, parent_pid, is_fuzzed, is_entry = struct.unpack('IIIbb', data[72:86])
        name = data[86:150].decode('utf-8', errors='ignore').rstrip('\x00')
        # padding at data[150:152]
        
        return SyscallInfo(
            index=index,
            syscall_nr=nr,
            args=list(args),
            retval=retval,
            pid=pid,
            parent_pid=parent_pid,
            is_fuzzed=bool(is_fuzzed),
            is_entry=bool(is_entry),
            name=name
        )
    
    def _handle_fork(self, parent_pid: int, child_pid: int, fork_index: int):
        """处理Fork事件"""
        print(f"[Visualizer] 🌿 FORK: PID {parent_pid} -> {child_pid} @ syscall[{fork_index}]")
        self.total_forks += 1
        
        # 找到fork点节点（父进程当前节点）
        fork_node = self.pid_to_node.get(parent_pid, self.current_node)
        if fork_node:
            self.fork_points[fork_index] = fork_node
            print(f"[Visualizer]    Fork point: node {fork_node.node_id} [{fork_node.syscall_index}] {fork_node.syscall_name}")
            
            # 子进程的第一个syscall将作为fork点的新分支
            self.pending_forks[child_pid] = fork_node
            print(f"[Visualizer]    Child PID {child_pid} will branch from node {fork_node.node_id}")
        else:
            print(f"[Visualizer]    ⚠️  Fork point not found for PID {parent_pid}")
    
    def _handle_syscall_enter(self, info: SyscallInfo):
        """处理系统调用进入"""
        # 创建节点
        node = TreeNode(
            node_id=self.node_counter,
            syscall_index=info.index,
            syscall_name=info.name,
            pid=info.pid,
            was_fuzzed=info.is_fuzzed
        )
        self.all_nodes[self.node_counter] = node
        self.node_counter += 1
        self.total_syscalls += 1
        
        # 检查是否是fork后的第一个syscall（需要创建新分支）
        if info.pid in self.pending_forks:
            # 这是子进程的第一个syscall，作为fork点的新分支
            fork_parent = self.pending_forks[info.pid]
            fork_parent.children.append(node)
            node.parent = fork_parent
            self.pid_to_node[info.pid] = node
            del self.pending_forks[info.pid]
            print(f"[Visualizer] 🌿 New branch: [{info.index}] {info.name} (PID {info.pid}) from fork point {fork_parent.node_id}")
        else:
            # 正常的syscall处理
            parent = self.pid_to_node.get(info.pid, self.current_node)
            
            if self.root is None:
                # 第一个节点
                self.root = node
                print(f"[Visualizer] 🌱 Root: [{info.index}] {info.name}")
            elif parent:
                # 添加为子节点
                parent.children.append(node)
                node.parent = parent
                
                # 检查是否是fork分支
                if parent.syscall_index in self.fork_points:
                    print(f"[Visualizer] [{info.index}] {info.name} (🌿 branch from node {parent.node_id})")
                else:
                    print(f"[Visualizer] [{info.index}] {info.name} (child of node {parent.node_id})")
        
        # 更新当前节点
        self.current_node = node
        self.pid_to_node[info.pid] = node
    
    def _handle_syscall_exit(self, info: SyscallInfo):
        """处理系统调用退出"""
        # 更新返回值
        if self.current_node and self.current_node.syscall_index == info.index:
            self.current_node.retval = str(info.retval)
            if info.is_fuzzed:
                self.current_node.was_fuzzed = True
                print(f"[Visualizer]    🎯 Fuzzed: {info.name} = {info.retval}")
            else:
                print(f"[Visualizer]    {info.name} = {info.retval}")
    
    def _generate_js_code(self, tree_json):
        """生成JavaScript代码"""
        import json
        return f'''
        const treeData = {json.dumps(tree_json, indent=2)};
        
        const width = window.innerWidth;
        const height = window.innerHeight - 100;
        
        const svg = d3.select("#tree-container")
            .append("svg")
            .attr("width", width)
            .attr("height", height);
        
        const g = svg.append("g")
            .attr("transform", "translate(80, 40)");
        
        const zoom = d3.zoom()
            .scaleExtent([0.1, 5])
            .on("zoom", (event) => g.attr("transform", event.transform));
        svg.call(zoom);
        
        const tree = d3.tree()
            .nodeSize([30, 200])
            .separation((a, b) => {{
                if (a.parent === b.parent) {{
                    const siblings = a.parent ? a.parent.children.length : 1;
                    if (siblings > 80) return 0.5;
                    if (siblings > 40) return 0.7;
                    if (siblings > 20) return 1.0;
                    return 1.5;
                }}
                return 2;
            }});
        
        const root = d3.hierarchy(treeData);
        tree(root);
        
        // Links
        g.selectAll(".link")
            .data(root.links())
            .enter().append("path")
            .attr("class", d => {{
                const isFork = d.source.children && d.source.children.length > 1;
                return isFork ? "link fork-branch" : "link";
            }})
            .attr("d", d3.linkHorizontal()
                .x(d => d.y)
                .y(d => d.x));
        
        // Nodes
        const nodes = g.selectAll(".node")
            .data(root.descendants())
            .enter().append("g")
            .attr("class", d => {{
                let cls = "node";
                if (d.depth === 0) cls += " root";
                if (d.children && d.children.length > 1) cls += " fork-point";
                if (d.data.was_fuzzed) cls += " mutated";
                if (!d.children || d.children.length === 0) cls += " leaf";
                if (d.children && d.children.length === 1) cls += " continuing";
                return cls;
            }})
            .attr("transform", d => `translate(${{d.y}},${{d.x}})`);
        
        nodes.append("circle")
            .attr("r", d => {{
                if (d.depth === 0) return 10;
                if (d.children && d.children.length > 1) return 8;
                return 5;
            }});
        
        nodes.append("text")
            .attr("dy", -12)
            .text(d => {{
                let label = d.data.syscall_name;
                if (d.data.was_fuzzed) label = "🎯" + label;
                if (d.children && d.children.length > 1) label = "🌿" + label;
                return label;
            }});
        
        nodes.append("text")
            .attr("dy", 18)
            .style("font-size", "9px")
            .style("fill", "#888")
            .text(d => `[${{d.data.syscall_index}}]`);
        
        const tooltip = d3.select("#tooltip");
        nodes.on("mouseover", function(event, d) {{
            tooltip.style("display", "block")
                .html(`
                    <b>${{d.data.syscall_name}}</b><br>
                    Index: ${{d.data.syscall_index}}<br>
                    PID: ${{d.data.pid}}<br>
                    Return: ${{d.data.retval}}<br>
                    Fuzzed: ${{d.data.was_fuzzed ? "Yes" : "No"}}
                `)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px");
        }})
        .on("mouseout", function() {{
            tooltip.style("display", "none");
        }});
        '''
    
    def generate_html(self, output_file: str, verbose: bool = False):
        """生成HTML可视化
        
        Args:
            output_file: 输出HTML文件路径
            verbose: 是否打印生成消息（默认False，减少日志噪音）
        """
        if not self.root:
            print("[Visualizer] ⚠️  No tree data to visualize")
            return
        
        tree_json = self._node_to_json(self.root)
        stats = {
            'total_nodes': len(self.all_nodes),
            'forks': len(self.fork_points),
            'mutations': sum(1 for n in self.all_nodes.values() if n.was_fuzzed)
        }
        
        # 生成JavaScript代码
        js_code = self._generate_js_code(tree_json)
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Realtime Fuzzing Tree</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            color: #e0e0e0;
            overflow: hidden;
        }}
        #header {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: rgba(15, 12, 41, 0.95);
            padding: 15px 25px;
            border-bottom: 2px solid #667eea;
            z-index: 100;
        }}
        h1 {{
            font-size: 22px;
            color: #667eea;
            margin-bottom: 8px;
        }}
        #stats {{
            display: flex;
            gap: 20px;
            font-size: 13px;
        }}
        .stat-value {{
            font-weight: bold;
            color: #48c774;
        }}
        #tree-container {{
            position: absolute;
            top: 90px;
            left: 0;
            right: 0;
            bottom: 0;
        }}
        #legend {{
            position: fixed;
            top: 100px;
            right: 20px;
            background: rgba(15, 12, 41, 0.9);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #667eea;
            font-size: 12px;
            z-index: 200;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 8px;
        }}
        .legend-circle {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }}
        .node circle {{
            fill: #667eea;
            stroke: #5a4fcf;
            stroke-width: 2px;
            cursor: pointer;
        }}
        .node circle:hover {{
            fill: #764ba2;
        }}
        .node.root circle {{
            fill: #48c774;
            r: 10;
        }}
        .node.fork-point circle {{
            fill: #ff9f43;
            r: 8;
        }}
        .node.mutated circle {{
            fill: #ff6b6b;
        }}
        .node.leaf circle {{
            fill: #95a5a6;
            r: 3;
        }}
        .node.continuing circle {{
            fill: #2ecc71;
            stroke: #27ae60;
            stroke-width: 3px;
        }}
        .node text {{
            font-size: 10px;
            fill: #e0e0e0;
            text-anchor: start;
            pointer-events: none;
        }}
        .node text.main {{
            font-weight: bold;
        }}
        .node text.detail {{
            font-size: 8px;
            fill: #b0b0b0;
        }}
        .link {{
            fill: none;
            stroke: rgba(102, 126, 234, 0.4);
            stroke-width: 2px;
        }}
        .link.fork-branch {{
            stroke: rgba(255, 159, 67, 0.7);
            stroke-width: 3px;
            stroke-dasharray: 5,5;
        }}
        .tooltip {{
            position: absolute;
            background: rgba(15, 12, 41, 0.98);
            border: 1px solid #667eea;
            border-radius: 5px;
            padding: 12px;
            pointer-events: none;
            display: none;
            font-size: 13px;
            z-index: 200;
        }}
    </style>
</head>
<body>
    <div id="header">
        <h1>🌳 Realtime Fuzzing Execution Tree</h1>
        <div id="stats">
            <div>Nodes: <span class="stat-value">{stats['total_nodes']}</span></div>
            <div>Forks: <span class="stat-value">{stats['forks']}</span></div>
            <div>Mutations: <span class="stat-value">{stats['mutations']}</span></div>
        </div>
    </div>
    
    <div id="tree-container"></div>
    
    <div id="legend">
        <h3 style="margin-bottom: 10px; color: #667eea;">节点类型</h3>
        <div class="legend-item">
            <div class="legend-circle" style="background: #48c774;"></div>
            <span>根节点 (第一个系统调用)</span>
        </div>
        <div class="legend-item">
            <div class="legend-circle" style="background: #ff9f43;"></div>
            <span>Fork点 (产生多个分支)</span>
        </div>
        <div class="legend-item">
            <div class="legend-circle" style="background: #2ecc71; border: 2px solid #27ae60;"></div>
            <span>继续执行 (有后续系统调用)</span>
        </div>
        <div class="legend-item">
            <div class="legend-circle" style="background: #95a5a6;"></div>
            <span>叶子节点 (进程退出)</span>
        </div>
        <div class="legend-item">
            <div class="legend-circle" style="background: #ff6b6b;"></div>
            <span>🎯 被Fuzz的系统调用</span>
        </div>
    </div>
    <div class="tooltip" id="tooltip"></div>
    
    <script>
        const treeData = {json.dumps(tree_json, indent=2)};
        
        const width = window.innerWidth;
        const height = window.innerHeight - 100;
        
        const svg = d3.select("#tree-container")
            .append("svg")
            .attr("width", width)
            .attr("height", height);
        
        const g = svg.append("g")
            .attr("transform", "translate(80, 40)");
        
        const zoom = d3.zoom()
            .scaleExtent([0.1, 5])
            .on("zoom", (event) => g.attr("transform", event.transform));
        svg.call(zoom);
        
        const tree = d3.tree()
            .size([height - 120, width - 200])
            .separation((a, b) => a.parent == b.parent ? 1 : 2)
            .nodeSize([30, 200]);
        
        const root = d3.hierarchy(treeData);
        tree(root);
        
        // Links
        g.selectAll(".link")
            .data(root.links())
            .enter().append("path")
            .attr("class", d => {{
                const isFork = d.source.children && d.source.children.length > 1;
                return isFork ? "link fork-branch" : "link";
            }})
            .attr("d", d3.linkHorizontal()
                .x(d => d.y)
                .y(d => d.x));
        
        // Nodes
        const nodes = g.selectAll(".node")
            .data(root.descendants())
            .enter().append("g")
            .attr("class", d => {{
                let cls = "node";
                if (d.depth === 0) cls += " root";
                if (d.children && d.children.length > 1) cls += " fork-point";
                if (d.data.was_fuzzed) cls += " mutated";
                if (!d.children || d.children.length === 0) cls += " leaf";
                if (d.children && d.children.length === 1) cls += " continuing";
                return cls;
            }})
            .attr("transform", d => `translate(${{d.y}},${{d.x}})`);
        
        nodes.append("circle")
            .attr("r", d => {{
                if (d.depth === 0) return 10;
                if (d.children && d.children.length > 1) return 8;
                return 5;
            }});
        
        nodes.append("text")
            .attr("dy", -12)
            .text(d => {{
                let label = d.data.syscall_name;
                if (d.data.was_fuzzed) label = "🎯" + label;
                if (d.children && d.children.length > 1) label = "🌿" + label;
                return label;
            }});
        
        nodes.append("text")
            .attr("dy", 18)
            .style("font-size", "9px")
            .style("fill", "#888")
            .text(d => `[${{d.data.syscall_index}}]`);
        
        const tooltip = d3.select("#tooltip");
        nodes.on("mouseover", function(event, d) {{
            tooltip.style("display", "block")
                .html(`
                    <b>${{d.data.syscall_name}}</b><br>
                    Index: ${{d.data.syscall_index}}<br>
                    Return: ${{d.data.retval}}<br>
                    PID: ${{d.data.pid}}<br>
                    Children: ${{d.children ? d.children.length : 0}}
                `)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px");
        }})
        .on("mouseout", () => tooltip.style("display", "none"));
    </script>
</body>
</html>'''
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        if verbose:
            print(f"\n[Visualizer] ✅ HTML generated: {output_file}")
    
    def _node_to_json(self, node: TreeNode) -> dict:
        """节点转JSON"""
        return {
            'node_id': node.node_id,
            'syscall_index': node.syscall_index,
            'syscall_name': node.syscall_name,
            'retval': node.retval,
            'pid': node.pid,
            'was_fuzzed': node.was_fuzzed,
            'children': [self._node_to_json(child) for child in node.children]
        }

def main():
    global _builder_instance
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description='Realtime Fuzzing Tree Visualizer')
    parser.add_argument('--pipe', default='/tmp/rr_dynamic_trace', 
                       help='Named pipe path for IPC')
    parser.add_argument('--output', default='fuzzing_tree.html',
                       help='Output HTML file')
    parser.add_argument('--update-interval', type=float, default=2.0,
                       help='HTML update interval (seconds)')
    
    args = parser.parse_args()
    
    print("[Visualizer] Initializing realtime tree builder", flush=True)
    print(f"[Visualizer] Trace pipe: {args.pipe}", flush=True)
    print(f"[Visualizer] Press Ctrl+C to stop", flush=True)
    
    builder = RealtimeTreeBuilder(args.pipe)
    _builder_instance = builder  # 保存全局引用供信号处理器使用
    
    try:
        builder.start()
        
        print(f"\n{'='*70}")
        print(f"  Realtime Tree Visualizer Ready")
        print(f"{'='*70}")
        print(f"  Pipe: {args.pipe}")
        print(f"  Output: {args.output}")
        print(f"\n  Now start fuzzing in another terminal:")
        print(f"  export RR_TRACE_PIPE={args.pipe}")
        print(f"  python3 fuzz_conductor.py ...")
        print(f"{'='*70}\n")
        
        # 定期更新HTML
        last_update = time.time()
        while builder.running:
            time.sleep(0.5)
            
            if time.time() - last_update >= args.update_interval:
                if builder.total_syscalls > 0:
                    # 只在有新数据时更新
                    current_count = builder.total_syscalls
                    if not hasattr(builder, '_last_count') or current_count > builder._last_count:
                        builder.generate_html(args.output)
                        print(f"[Visualizer] 📊 Updated ({builder.total_syscalls} syscalls, {builder.total_forks} forks)", flush=True)
                        builder._last_count = current_count
                last_update = time.time()
    
    except KeyboardInterrupt:
        print("\n\n[Visualizer] ⚠️  Stopped by user")
    
    finally:
        # 最终保存时显示详细信息
        builder.generate_html(args.output, verbose=True)
        builder.stop()
        _builder_instance = None
        
        print(f"\n{'='*70}")
        print(f"  ✅ Final tree saved to: {args.output}")
        print(f"  Total syscalls: {builder.total_syscalls}")
        print(f"  Total forks: {builder.total_forks}")
        print(f"{'='*70}\n")

if __name__ == '__main__':
    sys.exit(main() or 0)


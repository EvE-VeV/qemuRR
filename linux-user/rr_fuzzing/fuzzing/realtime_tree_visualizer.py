#!/usr/bin/env python3
"""
Realtime Fuzzing Tree Visualizer
Receives dynamic trace messages from QEMU and builds/visualizes execution tree in real-time

Usage:
    python3 realtime_tree_visualizer.py --output fuzzing_tree.html
    
    Then in another terminal:
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

RR_DYN_MSG_SYSCALL_ENTER = 0
RR_DYN_MSG_SYSCALL_EXIT = 1
RR_DYN_MSG_FORK = 2
RR_DYN_MSG_EXEC = 3
RR_DYN_MSG_EXIT = 4
RR_DYN_MSG_INIT = 5
RR_DYN_MSG_CLEANUP = 6
RR_DYN_MSG_ITERATION = 7

_builder_instance = None


def signal_handler(signum, frame):
    """Handle Ctrl+C and other signals"""
    global _builder_instance
    print(f"\n[Visualizer] Warning: signal {signum} received, shutting down...")
    
    if _builder_instance:
        try:
            _builder_instance.stop()
        except Exception as e:
            print(f"[Visualizer] Error during shutdown: {e}")
    
    sys.exit(0)


@dataclass
class SyscallInfo:
    """Syscall information"""
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
    """Tree node supporting multiple node types"""
    node_id: int
    node_type: str = "syscall"
    
    syscall_index: int = -1
    syscall_name: str = ""
    retval: str = "?"
    pid: int = 0
    was_fuzzed: bool = False
    
    fork_index: int = -1
    fork_depth: int = 0
    
    variant_id: str = ""
    syscall_range: tuple = None
    
    iteration_id: int = -1
    
    children: List['TreeNode'] = field(default_factory=list)
    parent: Optional['TreeNode'] = None
    
    @property
    def is_iteration(self) -> bool:
        return self.node_type == "iteration"

class RealtimeTreeBuilder:
    """Realtime tree builder"""

    def __init__(self, pipe_path: str = "/tmp/rr_dynamic_trace", output_html: str = "/tmp/fuzzing_tree.html"):
        self.pipe_path = pipe_path
        self.pipe_fd = None
        self._output_file = output_html

        self.root: Optional[TreeNode] = None
        self.all_nodes: Dict[int, TreeNode] = {}
        self.node_counter = 0

        self.current_node: Optional[TreeNode] = None
        self.pid_to_node: Dict[int, TreeNode] = {}
        self.pid_to_variant: Dict[int, TreeNode] = {}

        # 添加简化的fork跟踪机制
        self.fork_child_to_parent: Dict[int, int] = {}  # child_pid -> parent_pid
        self.fork_child_to_fork_index: Dict[int, int] = {}  # child_pid -> fork_index
        self.pid_to_last_syscall: Dict[int, TreeNode] = {}  # pid -> last_syscall_node

        self.fork_points: Dict[int, TreeNode] = {}
        self.fork_nodes: Dict[tuple, TreeNode] = {}
        self.pending_forks: Dict[int, TreeNode] = {}
        self.current_iteration_id: int = -1
        self.current_iteration_node: Optional[TreeNode] = None

        self.total_syscalls = 0
        self.total_forks = 0
        self.tree_finalized = False

        self.running = False
        self.receiver_thread = None

        print(f"[Visualizer] Initializing realtime tree builder")
        print(f"[Visualizer] Trace pipe: {self.pipe_path}")
        print(f"[Visualizer] Output: {self._output_file}")
    
    def start(self):
        """Start receiver thread"""
        print(f"[Visualizer] Starting... pipe_path={self.pipe_path}", flush=True)
        if os.path.exists(self.pipe_path):
            print(f"[Visualizer] Removing existing pipe", flush=True)
            os.remove(self.pipe_path)
        
        print(f"[Visualizer] Creating named pipe", flush=True)
        os.mkfifo(self.pipe_path)
        print(f"[Visualizer] Created named pipe: {self.pipe_path}", flush=True)
        print(f"[Visualizer] Waiting for QEMU to connect...", flush=True)
        
        os.environ['RR_TRACE_PIPE'] = self.pipe_path
        
        self.running = True
        print(f"[Visualizer] Starting receiver thread", flush=True)
        self.receiver_thread = threading.Thread(target=self._receive_messages, daemon=True)
        self.receiver_thread.start()
        print(f"[Visualizer] Receiver thread started", flush=True)
    
    def stop(self):
        """Stop receiving"""
        self.running = False
        if self.pipe_fd:
            try:
                os.close(self.pipe_fd)
            except:
                pass
        if os.path.exists(self.pipe_path):
            os.remove(self.pipe_path)
    
    def _read_exact(self, fd, size):
        """Read exact number of bytes"""
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
        """Receive messages thread"""
        print("[Visualizer] Receiver thread: starting, waiting for pipe", flush=True)
        try:
            print("[Visualizer] Receiver thread: calling os.open(O_RDONLY)...", flush=True)
            self.pipe_fd = os.open(self.pipe_path, os.O_RDONLY)
            print(f"[Visualizer] QEMU connected (fd={self.pipe_fd})", flush=True)

            FULL_MSG_SIZE = 168
            MSG_HEADER_SIZE = 16
            SYSCALL_INFO_SIZE = 152

            while self.running:
                full_msg = self._read_exact(self.pipe_fd, FULL_MSG_SIZE)

                if not full_msg or len(full_msg) < FULL_MSG_SIZE:
                    print(f"[Visualizer] Warning: incomplete message ({len(full_msg)} bytes)", flush=True)
                    break

                header = full_msg[:MSG_HEADER_SIZE]
                msg_type, pid, parent_pid = struct.unpack('III', header[:12])

                if msg_type == RR_DYN_MSG_INIT:
                    print(f"[Visualizer] INIT message from pid={pid}", flush=True)

                elif msg_type == RR_DYN_MSG_CLEANUP:
                    print(f"[Visualizer] CLEANUP from pid={pid}", flush=True)

                elif msg_type == RR_DYN_MSG_ITERATION:
                    info_data = full_msg[MSG_HEADER_SIZE:]
                    iteration_id = struct.unpack('I', info_data[:4])[0]
                    self._handle_iteration(iteration_id, pid)

                elif msg_type == RR_DYN_MSG_FORK:
                    info_data = full_msg[MSG_HEADER_SIZE:]
                    fork_index = struct.unpack('I', info_data[:4])[0]
                    self._handle_fork(parent_pid, pid, fork_index)

                elif msg_type in [RR_DYN_MSG_SYSCALL_ENTER, RR_DYN_MSG_SYSCALL_EXIT]:
                    info_data = full_msg[MSG_HEADER_SIZE:]

                    syscall_info = self._parse_syscall_info(info_data)
                    syscall_info.pid = pid

                    if msg_type == RR_DYN_MSG_SYSCALL_ENTER:
                        self._handle_syscall_enter(syscall_info)
                    else:
                        self._handle_syscall_exit(syscall_info)

                # 定期打印进度
                if self.total_syscalls % 100 == 0 and self.total_syscalls > 0:
                    print(f"[Visualizer] Progress: {self.total_syscalls} syscalls received", flush=True)

                else:
                    print(f"[Visualizer] Warning: unknown message type {msg_type}", flush=True)

        except Exception as e:
            print(f"[Visualizer] Error in receiver: {e}")
            import traceback
            traceback.print_exc()

        finally:
            # 关键修复：确保在receiver线程结束时生成HTML
            print(f"[Visualizer] Receiver thread ended with {self.total_syscalls} syscalls")
            print(f"[Visualizer] Generating HTML from receiver thread...")
            try:
                self.generate_html(getattr(self, '_output_file', '/tmp/fuzzing_tree.html'), verbose=True)
                print(f"[Visualizer] HTML generated successfully")
            except Exception as e:
                print(f"[Visualizer] Error generating HTML: {e}")
                import traceback
                traceback.print_exc()

            # 设置running=False让主循环退出
            self.running = False
            print("[Visualizer] Receiver thread stopped")
    
    def _parse_syscall_info(self, data: bytes) -> SyscallInfo:
        """Parse syscall info structure (152 bytes with padding at end)"""
        index, nr = struct.unpack('II', data[:8])
        args = struct.unpack('Q'*8, data[8:72])
        retval, pid, parent_pid, is_fuzzed, is_entry = struct.unpack('IIIbb', data[72:86])
        name = data[86:150].decode('utf-8', errors='ignore').rstrip('\x00')
        
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
    
    def _handle_iteration(self, iteration_id: int, pid: int):
        """Handle iteration start event (简化版)"""
        print(f"[Visualizer] Iteration {iteration_id} started (pid={pid})", flush=True)
        self.current_iteration_id = iteration_id
        
    def _handle_fork(self, parent_pid: int, child_pid: int, fork_index: int):
        """Record fork relationship (简化版 - 采用simple_tree_visualizer方法)"""
        self.fork_child_to_parent[child_pid] = parent_pid
        self.fork_child_to_fork_index[child_pid] = fork_index
        self.total_forks += 1
        print(f"[Visualizer] Fork: parent {parent_pid} -> child {child_pid} @ [{fork_index}]", flush=True)
    
    def _find_node_at_index(self, start_node: TreeNode, target_index: int) -> TreeNode:
        """DFS to find node with matching syscall_index"""
        if start_node.syscall_index == target_index:
            return start_node
        
        for child in start_node.children:
            result = self._find_node_at_index(child, target_index)
            if result:
                return result
        
        return None
    
    def _find_parent_variant(self, node: TreeNode) -> Optional[TreeNode]:
        """Find nearest variant node by traversing up"""
        current = node.parent
        while current:
            if current.node_type == "variant":
                return current
            current = current.parent
        return None

    def _recalculate_variant_range(self, variant_node: TreeNode):
        if not variant_node.children:
            variant_node.syscall_range = None
            return
        indexes = [child.syscall_index for child in variant_node.children if child.syscall_index >= 0]
        if indexes:
            variant_node.syscall_range = (min(indexes), max(indexes))
        else:
            variant_node.syscall_range = None

    def _extract_baseline_from_fork(self, iteration_node: TreeNode, fork_node: TreeNode):
        """Extract baseline syscalls that appear before the fork point.
        
        Baseline syscalls are those that were added directly to the iteration node
        (from baseline execution) before the fork happened. We extract these and
        put them in a Baseline node.
        
        Args:
            iteration_node: The iteration node containing baseline syscalls
            fork_node: The fork node where variants diverge
        """
        if iteration_node.node_type != "iteration":
            return
        
        # 递归收集所有baseline syscalls（现在是链式结构）
        def collect_baseline_chain(node, fork_index):
            """递归收集index < fork_index的所有syscall nodes（链式）"""
            baseline = []
            for child in list(node.children):
                if child.node_type == "syscall":
                    if fork_index > 0 and child.syscall_index < fork_index:
                        baseline.append(child)
                        # 递归收集这个syscall的children（链式）
                        baseline.extend(collect_baseline_chain(child, fork_index))
                    # 如果syscall_index >= fork_index，停止
            return baseline
        
        baseline_syscalls = collect_baseline_chain(iteration_node, fork_node.fork_index)
        
        # 收集非syscall children（Fork nodes等）
        remaining_children = [c for c in iteration_node.children if c.node_type != "syscall"]
        
        if not baseline_syscalls:
            return
        
        indexes = [s.syscall_index for s in baseline_syscalls if s.syscall_index >= 0]
        if indexes:
            start_index = min(indexes)
            end_index = max(indexes)
            baseline_label = f"Baseline [{start_index}-{end_index}]"
        else:
            start_index = -1
            end_index = -1
            baseline_label = "Baseline"
        
        baseline_node = TreeNode(
            node_id=self.node_counter,
            node_type="baseline",
            syscall_name=baseline_label,
            syscall_range=(start_index, end_index) if start_index >= 0 else None
        )
        self.node_counter += 1
        self.all_nodes[baseline_node.node_id] = baseline_node
        
        # 将第一个baseline syscall作为baseline_node的唯一child（保持链式结构）
        if baseline_syscalls:
            first_baseline = baseline_syscalls[0]
            # 从原parent移除
            if first_baseline.parent and first_baseline in first_baseline.parent.children:
                first_baseline.parent.children.remove(first_baseline)
            # 添加到baseline_node
            baseline_node.children.append(first_baseline)
            first_baseline.parent = baseline_node
        
        try:
            fork_index = remaining_children.index(fork_node)
        except ValueError:
            fork_index = len(remaining_children)
        
        remaining_children.insert(fork_index, baseline_node)
        baseline_node.parent = iteration_node
        
        iteration_node.children = remaining_children

    def _finalize_tree(self):
        if self.tree_finalized or not self.root:
            return
        self._finalize_node(self.root)
        self.tree_finalized = True

    def _finalize_node(self, node: TreeNode):
        for child in list(node.children):
            self._finalize_node(child)
        if node.node_type == "fork" and node.parent is not None:
            self._extract_baseline_from_fork(node.parent, node)
    
    def _generate_variant_id(self, fork_node: TreeNode) -> str:
        """Generate variant ID like '0A', '0B', '0A-1', '0A-2'"""
        variant_count = len([c for c in fork_node.children if c.node_type == "variant"])
        
        parent_variant = self._find_parent_variant(fork_node)
        
        if parent_variant:
            return f"{parent_variant.variant_id}-{variant_count + 1}"
        else:
            letter = chr(ord('A') + variant_count)
            return f"0{letter}"
    
    def _update_variant_range(self, pid: int, syscall_index: int):
        """Update variant's syscall range"""
        if pid in self.pid_to_variant:
            variant_node = self.pid_to_variant[pid]
            if variant_node.syscall_range is None:
                variant_node.syscall_range = (syscall_index, syscall_index)
            else:
                start, _ = variant_node.syscall_range
                variant_node.syscall_range = (start, syscall_index)
    
    def _handle_syscall_enter(self, info: SyscallInfo):
        """Handle syscall enter (简化版 - 采用simple_tree_visualizer方法)"""
        self.total_syscalls += 1

        # Create syscall node
        node = TreeNode(
            node_id=self.node_counter,
            node_type="syscall",
            syscall_index=info.index,
            syscall_name=info.name,
            pid=info.pid,
            was_fuzzed=info.is_fuzzed
        )
        self.node_counter += 1
        self.all_nodes[node.node_id] = node

        # Determine parent
        parent_node = None

        if info.pid in self.pid_to_last_syscall:
            # Chain to previous syscall of same PID
            parent_node = self.pid_to_last_syscall[info.pid]
        elif info.pid in self.fork_child_to_parent:
            # This is first syscall of forked child
            # Find the fork point syscall as parent
            fork_index = self.fork_child_to_fork_index.get(info.pid, -1)

            # Search for syscall with index == fork_index in all nodes
            for candidate in self.all_nodes.values():
                if candidate.syscall_index == fork_index:
                    parent_node = candidate
                    break

            if not parent_node:
                # Fallback: chain to parent's last syscall
                parent_pid = self.fork_child_to_parent[info.pid]
                if parent_pid in self.pid_to_last_syscall:
                    parent_node = self.pid_to_last_syscall[parent_pid]

        if parent_node:
            parent_node.children.append(node)
            node.parent = parent_node
        else:
            # This is a root syscall
            if not self.root:
                # First syscall ever - create virtual root
                self.root = TreeNode(
                    node_id=-1,
                    node_type="syscall",
                    syscall_index=-1,
                    syscall_name="Root",
                    pid=0
                )
            self.root.children.append(node)
            node.parent = self.root

        # Update tracking
        self.pid_to_last_syscall[info.pid] = node
    
    def _handle_syscall_exit(self, info: SyscallInfo):
        """Handle syscall exit (简化版 - 采用simple_tree_visualizer方法)"""
        if info.pid in self.pid_to_last_syscall:
            node = self.pid_to_last_syscall[info.pid]
            if node.syscall_index == info.index:
                node.retval = str(info.retval)
                if info.is_fuzzed:
                    node.was_fuzzed = True
    
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
                if (d.data.is_iteration) return 12;  // iteration节点更大
                if (d.depth === 0) return 10;
                if (d.children && d.children.length > 1) return 8;
                return 5;
            }})
            .attr("fill", d => {{
                if (d.data.is_iteration) return "#9b59b6";  // iteration节点紫色
                if (d.data.was_fuzzed) return "#f39c12";    // fuzzed节点橙色
                if (d.depth === 0) return "#48c774";         // root绿色
                return "#3498db";                             // 其他蓝色
            }});
        
        nodes.append("text")
            .attr("dy", -12)
            .text(d => {{
                let label = d.data.syscall_name;
                if (d.data.is_iteration) label = "[Iteration] " + label;  // iteration标记
                else if (d.data.was_fuzzed) label = "[Mutated]" + label;
                if (d.children && d.children.length > 1) label = "[Branch]" + label;
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
        """Generate HTML visualization (简化版 - 采用simple_tree_visualizer方法)

        Args:
            output_file: Output HTML file path
            verbose: Whether to print generation message (default False)
        """
        if not self.root:
            if verbose:
                print("[Visualizer] No tree data to visualize")
            return

        # 简化：跳过复杂的tree finalization
        tree_json = self._node_to_json(self.root)

        # 使用简化的统计
        stats = {
            'total_syscalls': self.total_syscalls,
            'total_forks': self.total_forks,
            'mutations': sum(1 for n in self.all_nodes.values() if n.was_fuzzed)
        }
        # 采用simple_tree_visualizer的简化HTML模板
        import json

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Syscall Execution Tree</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Consolas', 'Monaco', monospace;
            background: #1a1a2e;
            color: #eee;
            overflow: hidden;
        }}
        #header {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: rgba(22, 22, 44, 0.95);
            padding: 15px 25px;
            border-bottom: 2px solid #4a9eff;
            z-index: 100;
        }}
        h1 {{
            font-size: 20px;
            color: #4a9eff;
            margin-bottom: 5px;
        }}
        #stats {{
            font-size: 12px;
            color: #aaa;
        }}
        .stat-value {{
            font-weight: bold;
            color: #48c774;
        }}
        #tree-container {{
            position: absolute;
            top: 80px;
            left: 0;
            right: 0;
            bottom: 0;
            overflow: auto;
        }}
        .node circle {{
            stroke: #4a9eff;
            stroke-width: 2px;
        }}
        .node.fuzzed circle {{
            stroke: #ff4757;
            stroke-width: 3px;
        }}
        .node text {{
            font-size: 11px;
            fill: #eee;
        }}
        .link {{
            fill: none;
            stroke: #555;
            stroke-width: 1.5px;
        }}
    </style>
</head>
<body>
    <div id="header">
        <h1>Syscall Execution Tree (Realtime)</h1>
        <div id="stats">
            Total syscalls: <span class="stat-value">{stats['total_syscalls']}</span> |
            Forks: <span class="stat-value">{stats['total_forks']}</span> |
            Mutations: <span class="stat-value">{stats['mutations']}</span>
        </div>
    </div>
    <div id="tree-container">
        <svg id="tree-svg"></svg>
    </div>

    <script>
        const treeData = {json.dumps(tree_json)};

        const width = window.innerWidth;
        const height = window.innerHeight - 100;

        const svg = d3.select("#tree-svg")
            .attr("width", width)
            .attr("height", height);

        const g = svg.append("g")
            .attr("transform", "translate(50,50)");

        const tree = d3.tree().nodeSize([30, 200]);
        const root = d3.hierarchy(treeData);
        const treeLayout = tree(root);

        // Draw links
        g.selectAll(".link")
            .data(treeLayout.links())
            .join("path")
            .attr("class", "link")
            .attr("d", d3.linkHorizontal()
                .x(d => d.y)
                .y(d => d.x));

        // Draw nodes
        const nodes = g.selectAll(".node")
            .data(treeLayout.descendants())
            .join("g")
            .attr("class", d => "node" + (d.data.was_fuzzed ? " fuzzed" : ""))
            .attr("transform", d => "translate(" + d.y + "," + d.x + ")");

        nodes.append("circle")
            .attr("r", 5)
            .attr("fill", d => d.data.was_fuzzed ? "#ff4757" : "#48c774");

        nodes.append("text")
            .attr("x", 10)
            .attr("y", 4)
            .text(d => "[" + d.data.syscall_index + "] " + d.data.syscall_name + " = " + d.data.retval);

        // Zoom
        svg.call(d3.zoom()
            .on("zoom", (event) => {{
                g.attr("transform", event.transform);
            }}));
    </script>
</body>
</html>'''
        with open(output_file, 'w') as f:
            f.write(html)

        if verbose:
            print(f"[Visualizer] Generated {output_file}")
            print(f"  Total syscalls: {stats['total_syscalls']}")
            print(f"  Total forks: {stats['total_forks']}")
            print(f"  Mutations: {stats['mutations']}")
    
    def _node_to_json(self, node: TreeNode) -> dict:
        """Convert tree node to JSON (简化版 - 采用simple_tree_visualizer方法)"""
        return {
            "node_id": node.node_id,
            "syscall_index": node.syscall_index,
            "syscall_name": node.syscall_name,
            "pid": node.pid,
            "retval": node.retval,
            "was_fuzzed": node.was_fuzzed,
            "children": [self._node_to_json(child) for child in node.children]
        }

def main():
    global _builder_instance
    
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
    print(f"[Visualizer] Output HTML: {args.output}", flush=True)
    print("[Visualizer] Press Ctrl+C to stop", flush=True)

    builder = RealtimeTreeBuilder(args.pipe, args.output)
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
                        print(f"[Visualizer] Updated ({builder.total_syscalls} syscalls, {builder.total_forks} forks)", flush=True)
                        builder._last_count = current_count
                last_update = time.time()
    
    except KeyboardInterrupt:
        print("\n\n[Visualizer] Stopped by user")
    
    finally:
        # 最终保存时显示详细信息
        builder.generate_html(args.output, verbose=True)
        builder.stop()
        _builder_instance = None
        
        print(f"\n{'='*70}")
        print(f"  Final tree saved to: {args.output}")
        print(f"  Total syscalls: {builder.total_syscalls}")
        print(f"  Total forks: {builder.total_forks}")
        print(f"{'='*70}\n")

if __name__ == '__main__':
    sys.exit(main() or 0)


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
    """Tree node representing a syscall execution or fork point"""
    node_id: int
    node_type: str = "syscall"  # "syscall" or "fork"
    syscall_index: int = -1
    syscall_name: str = ""
    retval: str = "?"
    pid: int = 0
    was_fuzzed: bool = False

    children: List['TreeNode'] = field(default_factory=list)
    parent: Optional['TreeNode'] = None

    @property
    def is_fork_node(self) -> bool:
        """Check if this is a fork node"""
        return self.node_type == "fork"

class RealtimeTreeBuilder:
    """Realtime tree builder"""

    def __init__(self, pipe_path: str = "/tmp/rr_dynamic_trace", output_html: str = "/tmp/fuzzing_tree.html"):
        self.pipe_path = pipe_path
        self.pipe_fd = None
        self._output_file = output_html

        # Tree structure
        self.root: Optional[TreeNode] = None
        self.all_nodes: Dict[int, TreeNode] = {}
        self.node_counter = 0

        # Fork tracking
        self.fork_child_to_parent: Dict[int, int] = {}  # child_pid -> parent_pid
        self.fork_child_to_fork_index: Dict[int, int] = {}  # child_pid -> fork_index
        self.pid_to_last_syscall: Dict[int, TreeNode] = {}  # pid -> last_syscall_node
        self.fork_nodes: Dict[tuple, TreeNode] = {}  # (parent_pid, fork_index) -> fork_node
        self.fork_child_to_fork_node: Dict[int, TreeNode] = {}  # child_pid -> fork_node

        # 🔥 Performance fix: O(1) index for syscall lookups (pid, syscall_index) -> node
        self.syscall_index: Dict[tuple, TreeNode] = {}  # (pid, syscall_index) -> syscall_node

        # Statistics
        self.total_forks = 0
        self.total_executions = 0
        self.current_iteration_id: int = -1  # For logging only

        # Threading
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

                else:
                    print(f"[Visualizer] Warning: unknown message type {msg_type}", flush=True)

        except Exception as e:
            print(f"[Visualizer] Error in receiver: {e}")
            import traceback
            traceback.print_exc()

        finally:
            # 关键修复：确保在receiver线程结束时生成HTML
            print(f"[Visualizer] Receiver thread ended, generating final tree visualization...")
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
        """Record fork relationship and create fork node for branching"""
        print(f"[Visualizer] 🍴 RECEIVED FORK message: parent={parent_pid} -> child={child_pid} @ syscall[{fork_index}]", flush=True)
        print(f"[Visualizer] DEBUG: _handle_fork started", flush=True)

        self.fork_child_to_parent[child_pid] = parent_pid
        self.fork_child_to_fork_index[child_pid] = fork_index
        self.total_forks += 1
        print(f"[Visualizer] DEBUG: Updated fork tracking, total_forks={self.total_forks}", flush=True)

        # Find or create fork node at this (parent_pid, fork_index)
        fork_key = (parent_pid, fork_index)
        print(f"[Visualizer] DEBUG: Checking fork_key={fork_key}, already exists={fork_key in self.fork_nodes}", flush=True)
        if fork_key not in self.fork_nodes:
            # 🔥 Performance fix: O(1) hash lookup instead of O(N) linear search
            syscall_key = (parent_pid, fork_index)
            fork_syscall_node = self.syscall_index.get(syscall_key)

            if fork_syscall_node:
                print(f"[Visualizer] DEBUG: Found syscall node via O(1) hash lookup", flush=True)
            else:
                print(f"[Visualizer] DEBUG: Syscall node not found (key={syscall_key}), may arrive later", flush=True)

            if fork_syscall_node:
                # Create fork node as a child of the fork_syscall_node
                fork_node = TreeNode(
                    node_id=self.node_counter,
                    node_type="fork",
                    syscall_index=fork_index,
                    syscall_name=f"Fork@{fork_index}",
                    pid=parent_pid
                )
                self.node_counter += 1
                self.all_nodes[fork_node.node_id] = fork_node

                # Insert fork node between fork_syscall_node and its children
                fork_node.parent = fork_syscall_node
                fork_syscall_node.children.append(fork_node)

                self.fork_nodes[fork_key] = fork_node
                print(f"[Visualizer] Created fork node[{fork_node.node_id}] @ [{fork_index}] for parent {parent_pid}", flush=True)
            else:
                print(f"[Visualizer] Warning: Could not find syscall node at [{fork_index}] for parent {parent_pid}", flush=True)

        # Record that this child should connect to the fork node
        fork_node = self.fork_nodes.get(fork_key)
        if fork_node:
            self.fork_child_to_fork_node[child_pid] = fork_node
            print(f"[Visualizer] Fork: parent {parent_pid} -> child {child_pid} @ [{fork_index}] (via fork_node)", flush=True)
        else:
            print(f"[Visualizer] Fork: parent {parent_pid} -> child {child_pid} @ [{fork_index}] (no fork_node)", flush=True)
    
    def _handle_syscall_enter(self, info: SyscallInfo):
        """Handle syscall enter - creates a tree node for this syscall execution"""
        # Create syscall node
        node = TreeNode(
            node_id=self.node_counter,
            syscall_index=info.index,
            syscall_name=info.name,
            pid=info.pid,
            was_fuzzed=info.is_fuzzed
        )
        self.node_counter += 1
        self.all_nodes[node.node_id] = node

        # 🔥 Performance fix: Add to O(1) index for fast fork lookups
        syscall_key = (info.pid, info.index)
        self.syscall_index[syscall_key] = node

        # Determine parent
        parent_node = None

        # Priority 1: Check if this is first syscall of forked child → connect to fork node
        if info.pid in self.fork_child_to_fork_node:
            fork_node = self.fork_child_to_fork_node[info.pid]
            parent_node = fork_node
            print(f"[Visualizer] Connecting child {info.pid} syscall[{info.index}] to fork_node[{fork_node.node_id}]", flush=True)
            # Remove from dict after first syscall (subsequent syscalls chain normally)
            del self.fork_child_to_fork_node[info.pid]

        # Priority 2: Chain to previous syscall of same PID
        elif info.pid in self.pid_to_last_syscall:
            parent_node = self.pid_to_last_syscall[info.pid]

        # Priority 3: Legacy fallback for fork children without fork_node
        elif info.pid in self.fork_child_to_parent:
            fork_index = self.fork_child_to_fork_index.get(info.pid, -1)
            parent_pid = self.fork_child_to_parent[info.pid]

            # Search for parent's syscall at fork_index
            for candidate in self.all_nodes.values():
                if (candidate.syscall_index == fork_index and
                    candidate.pid == parent_pid and
                    not candidate.is_fork_node):
                    parent_node = candidate
                    break

            if not parent_node:
                # Fallback: chain to parent's last syscall
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

        # 🔥 修复: 统计实际在树中的节点，而非all_nodes
        def count_nodes_in_tree(node):
            """递归统计树中实际节点数"""
            count = 1
            for child in node.children:
                count += count_nodes_in_tree(child)
            return count

        def collect_tree_nodes(node, result=None):
            """递归收集树中所有节点"""
            if result is None:
                result = []
            result.append(node)
            for child in node.children:
                collect_tree_nodes(child, result)
            return result

        nodes_in_tree = count_nodes_in_tree(self.root) if self.root else 0
        tree_nodes = collect_tree_nodes(self.root) if self.root else []
        fuzzed_in_tree = sum(1 for n in tree_nodes if n.was_fuzzed)

        # 🔥 修复: 使用树中实际节点的统计
        stats = {
            'total_nodes': nodes_in_tree,  # 树中实际节点数（真实的syscall执行）
            'total_forks': self.total_forks,
            'mutations': fuzzed_in_tree  # 树中被fuzz的节点数
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
            Total Syscalls: <span class="stat-value">{stats['total_nodes']}</span> |
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
            .attr("class", d => "node" +
                (d.data.is_fork ? " fork" : "") +
                (d.data.was_fuzzed ? " fuzzed" : ""))
            .attr("transform", d => "translate(" + d.y + "," + d.x + ")");

        // Fork nodes: draw diamond shape
        nodes.filter(d => d.data.is_fork)
            .append("rect")
            .attr("x", -6)
            .attr("y", -6)
            .attr("width", 12)
            .attr("height", 12)
            .attr("transform", "rotate(45)")
            .attr("fill", "#ff9f43")
            .attr("stroke", "#f39c12")
            .attr("stroke-width", 2);

        // Syscall nodes: draw circle
        nodes.filter(d => !d.data.is_fork)
            .append("circle")
            .attr("r", 5)
            .attr("fill", d => d.data.was_fuzzed ? "#ff4757" : "#48c774")
            .attr("stroke", d => d.data.was_fuzzed ? "#ee5a6f" : "#5ad178")
            .attr("stroke-width", 2);

        nodes.append("text")
            .attr("x", 10)
            .attr("y", 4)
            .text(d => d.data.is_fork ?
                d.data.syscall_name :
                "[" + d.data.syscall_index + "] " + d.data.syscall_name + " = " + d.data.retval);

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
            print(f"  Total syscalls (in tree): {stats['total_nodes']}")
            print(f"  Total forks: {stats['total_forks']}")
            print(f"  Mutations: {stats['mutations']}")
    
    def _node_to_json(self, node: TreeNode) -> dict:
        """Convert tree node to JSON"""
        return {
            "node_id": node.node_id,
            "node_type": node.node_type,
            "syscall_index": node.syscall_index,
            "syscall_name": node.syscall_name,
            "pid": node.pid,
            "retval": node.retval,
            "was_fuzzed": node.was_fuzzed,
            "is_fork": node.is_fork_node,
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
                if builder.total_executions > 0:
                    # 只在有新数据时更新
                    current_count = builder.total_executions
                    if not hasattr(builder, '_last_count') or current_count > builder._last_count:
                        builder.generate_html(args.output)
                        print(f"[Visualizer] Updated ({builder.total_executions} total execs, {builder.total_forks} forks)", flush=True)
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
        print(f"  Total executions processed: {builder.total_executions}")
        print(f"  Total forks: {builder.total_forks}")
        print(f"{'='*70}\n")

if __name__ == '__main__':
    sys.exit(main() or 0)


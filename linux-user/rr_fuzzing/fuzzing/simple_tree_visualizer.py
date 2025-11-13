#!/usr/bin/env python3
"""
Simplified Syscall Tree Visualizer - Only shows real syscalls, no container nodes
"""

import os
import sys
import struct
import threading
from dataclasses import dataclass, field
from typing import Optional, Dict, List

# Message types from C-side (MUST match rr_dynamic_trace.h exactly)
RR_DYN_MSG_SYSCALL_ENTER = 0
RR_DYN_MSG_SYSCALL_EXIT = 1
RR_DYN_MSG_FORK = 2
RR_DYN_MSG_EXEC = 3
RR_DYN_MSG_EXIT = 4
RR_DYN_MSG_INIT = 5
RR_DYN_MSG_CLEANUP = 6
RR_DYN_MSG_ITERATION = 7


@dataclass
class SyscallNode:
    """Represents a single syscall in the tree"""
    node_id: int
    syscall_index: int
    syscall_name: str
    pid: int
    retval: str = "?"
    was_fuzzed: bool = False
    parent: Optional['SyscallNode'] = None
    children: List['SyscallNode'] = field(default_factory=list)
    
    def add_child(self, child: 'SyscallNode'):
        """Add a child node"""
        self.children.append(child)
        child.parent = self


@dataclass
class SyscallInfo:
    """Syscall information from dynamic trace"""
    index: int
    syscall_nr: int
    args: List[int]
    retval: int
    pid: int
    parent_pid: int
    is_fuzzed: bool
    is_entry: bool
    name: str


class SimpleSyscallTreeVisualizer:
    """Simplified visualizer - only syscalls, no containers"""
    
    def __init__(self, pipe_path: str, output_html: str = "/tmp/fuzzing_tree.html"):
        self.pipe_path = pipe_path
        self.output_html = output_html
        
        self.pipe_fd = None
        self.running = False
        self.receiver_thread = None
        
        # Tree structure
        self.root: Optional[SyscallNode] = None
        self.all_nodes: Dict[int, SyscallNode] = {}
        self.node_counter = 0
        
        # Track last syscall per PID (for chaining)
        self.pid_to_last_syscall: Dict[int, SyscallNode] = {}
        
        # Track fork relationships
        self.fork_child_to_parent: Dict[int, int] = {}  # child_pid -> parent_pid
        self.fork_child_to_fork_index: Dict[int, int] = {}  # child_pid -> fork_index
        
        self.total_syscalls = 0
        
        print(f"[SimpleVisualizer] Initialized (syscalls only)")
        print(f"  Pipe: {pipe_path}")
        print(f"  Output: {output_html}")
    
    def start(self):
        """Start receiver thread"""
        if os.path.exists(self.pipe_path):
            os.remove(self.pipe_path)
        
        os.mkfifo(self.pipe_path)
        print(f"[SimpleVisualizer] Created pipe: {self.pipe_path}")
        
        os.environ['RR_TRACE_PIPE'] = self.pipe_path
        
        self.running = True
        self.receiver_thread = threading.Thread(target=self._receive_messages, daemon=True)
        self.receiver_thread.start()
        print(f"[SimpleVisualizer] Receiver started")
    
    def stop(self):
        """Stop receiving and generate HTML"""
        print("[SimpleVisualizer] Stopping...")
        self.running = False
        
        if self.pipe_fd:
            try:
                os.close(self.pipe_fd)
            except:
                pass
        
        if os.path.exists(self.pipe_path):
            os.remove(self.pipe_path)
        
        # Generate final HTML
        self._generate_html()
        print(f"[SimpleVisualizer] Stopped. HTML: {self.output_html}")
    
    def _read_exact(self, fd, size):
        """Read exact number of bytes"""
        data = b''
        remaining = size
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            data += chunk
            remaining -= len(chunk)
        return data
    
    def _receive_messages(self):
        """Receive messages from pipe"""
        print(f"[SimpleVisualizer] Receiver thread: waiting for QEMU to connect to {self.pipe_path}...")
        try:
            self.pipe_fd = os.open(self.pipe_path, os.O_RDONLY)
            print(f"[SimpleVisualizer] QEMU connected (fd={self.pipe_fd})")
            
            FULL_MSG_SIZE = 168
            MSG_HEADER_SIZE = 16
            
            while self.running:
                full_msg = self._read_exact(self.pipe_fd, FULL_MSG_SIZE)
                
                if not full_msg or len(full_msg) < FULL_MSG_SIZE:
                    print(f"[SimpleVisualizer] EOF or incomplete message, ending receiver loop")
                    break
                
                header = full_msg[:MSG_HEADER_SIZE]
                msg_type, pid, parent_pid = struct.unpack('III', header[:12])
                
                if msg_type == RR_DYN_MSG_FORK:
                    info_data = full_msg[MSG_HEADER_SIZE:]
                    fork_index = struct.unpack('I', info_data[:4])[0]
                    print(f"[SimpleVisualizer] DEBUG: Received FORK message - parent_pid={parent_pid}, child_pid={pid}, fork_index={fork_index}", flush=True)
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
                    print(f"[SimpleVisualizer] Progress: {self.total_syscalls} syscalls received", flush=True)
        
        except Exception as e:
            print(f"[SimpleVisualizer] Error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            # 关键修复：确保在receiver线程结束时生成HTML
            print(f"[SimpleVisualizer] Receiver thread ended with {self.total_syscalls} syscalls")
            print(f"[SimpleVisualizer] Generating HTML from receiver thread...")
            try:
                self._generate_html()
                print(f"[SimpleVisualizer] HTML generated: {self.output_html}")
            except Exception as e:
                print(f"[SimpleVisualizer] Error generating HTML: {e}")
                import traceback
                traceback.print_exc()
            
            # 设置running=False让主循环退出
            self.running = False
    
    def _parse_syscall_info(self, data: bytes) -> SyscallInfo:
        """Parse syscall info structure"""
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
    
    def _handle_fork(self, parent_pid: int, child_pid: int, fork_index: int):
        """Record fork relationship"""
        self.fork_child_to_parent[child_pid] = parent_pid
        self.fork_child_to_fork_index[child_pid] = fork_index
        print(f"[SimpleVisualizer] Fork: parent {parent_pid} -> child {child_pid} @ [{fork_index}]")
    
    def _handle_syscall_enter(self, info: SyscallInfo):
        """Create syscall node and chain it"""
        self.total_syscalls += 1
        
        # Create syscall node
        node = SyscallNode(
            node_id=self.node_counter,
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
            parent_node.add_child(node)
        else:
            # This is a root syscall
            if not self.root:
                # First syscall ever - create virtual root
                self.root = SyscallNode(
                    node_id=-1,
                    syscall_index=-1,
                    syscall_name="Root",
                    pid=0
                )
            self.root.add_child(node)
        
        # Update tracking
        self.pid_to_last_syscall[info.pid] = node
    
    def _handle_syscall_exit(self, info: SyscallInfo):
        """Update syscall retval"""
        if info.pid in self.pid_to_last_syscall:
            node = self.pid_to_last_syscall[info.pid]
            if node.syscall_index == info.index:
                node.retval = str(info.retval)
                if info.is_fuzzed:
                    node.was_fuzzed = True
    
    def _generate_html(self):
        """Generate HTML visualization"""
        if not self.root:
            print("[SimpleVisualizer] No data to visualize")
            return
        
        # Convert tree to JSON (JavaScript-compatible)
        import json
        tree_json = self._node_to_json(self.root)
        tree_json_str = json.dumps(tree_json)
        
        # Build HTML with proper JSON embedding
        html_before_data = f"""<!DOCTYPE html>
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
        <h1>Syscall Execution Tree (Simplified)</h1>
        <div id="stats">
            Total syscalls: <span class="stat-value">{self.total_syscalls}</span>
        </div>
    </div>
    <div id="tree-container">
        <svg id="tree-svg"></svg>
    </div>
    
    <script>
        const treeData = """
        
        html_after_data = """;
        
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
</html>"""
        
        # Build complete HTML with JSON data embedded
        html = html_before_data + tree_json_str + html_after_data
        
        with open(self.output_html, 'w') as f:
            f.write(html)
        
        print(f"[SimpleVisualizer] Generated {self.output_html}")
        print(f"  Total syscalls: {self.total_syscalls}")
    
    def _node_to_json(self, node: SyscallNode) -> dict:
        """Convert tree node to JSON"""
        return {
            "node_id": node.node_id,
            "syscall_index": node.syscall_index,
            "syscall_name": node.syscall_name,
            "pid": node.pid,
            "retval": node.retval,
            "was_fuzzed": node.was_fuzzed,
            "children": [self._node_to_json(child) for child in node.children]
        }


# Alias for compatibility
SyscallTreeBuilder = SimpleSyscallTreeVisualizer


if __name__ == '__main__':
    import argparse
    import signal
    import atexit
    
    parser = argparse.ArgumentParser(description='Simplified Syscall Tree Visualizer')
    parser.add_argument('--pipe', required=True, help='Named pipe path')
    parser.add_argument('--output', required=True, help='Output HTML path')
    parser.add_argument('--update-interval', type=float, default=3.0, help='Update interval (ignored in simple mode)')
    args = parser.parse_args()
    
    visualizer = SimpleSyscallTreeVisualizer(args.pipe, args.output)
    
    # Register cleanup handler
    def cleanup_handler():
        print("[SimpleVisualizer] atexit: Generating HTML...")
        try:
            visualizer._generate_html()
        except Exception as e:
            print(f"[SimpleVisualizer] atexit: Error generating HTML: {e}")
    
    atexit.register(cleanup_handler)
    
    def signal_handler(sig, frame):
        print("\n[SimpleVisualizer] Received signal, stopping...")
        visualizer.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    visualizer.start()
    
    # Keep running until signaled
    try:
        while visualizer.running:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("[SimpleVisualizer] KeyboardInterrupt received")
    except Exception as e:
        print(f"[SimpleVisualizer] Exception in main loop: {e}")
    finally:
        print("[SimpleVisualizer] Finalizing...")
        visualizer.stop()


#!/usr/bin/env python3
"""
Syscall Tree Visualizer for RR-Fuzz
从 trace 文件生成真正的树状可视化（使用 D3.js tree layout）

基于 realtime_tree_visualizer.py 的可视化代码
"""

import sys
import json
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field

# Add parent directory to path for trace_analyzer import
sys.path.insert(0, str(Path(__file__).parent.parent))
from trace_analyzer import TraceAnalyzer


@dataclass
class TreeNode:
    """树节点"""
    node_id: int
    syscall_index: int
    syscall_name: str
    retval: str = "?"
    is_pure: bool = False
    children: List['TreeNode'] = field(default_factory=list)
    trace_source: str = ""  # 来自哪个 trace


class TreeVisualizer:
    """树状可视化生成器"""
    
    def __init__(self):
        self.traces: List[Dict] = []  # 存储 {'label': ..., 'nodes': [TreeNode, ...]}
        self.node_counter = 0
    
    def add_trace(self, trace_file: str, label: Optional[str] = None) -> bool:
        """添加一个 trace 文件并解析"""
        if label is None:
            label = Path(trace_file).stem
        
        try:
            analyzer = TraceAnalyzer(trace_file)
            if not analyzer.syscalls:
                print(f"[TreeViz] ⚠️  No syscalls in {label}")
                return False
            
            # 构建树节点
            nodes = []
            for sc in analyzer.syscalls:
                is_pure = getattr(sc, 'has_aux_data', False) or sc.category == 'pure_replay'
                node = TreeNode(
                    node_id=self.node_counter,
                    syscall_index=sc.index,
                    syscall_name=sc.name,
                    retval=str(getattr(sc, 'retval', 0)),
                    is_pure=is_pure,
                    children=[],
                    trace_source=label
                )
                nodes.append(node)
                self.node_counter += 1
            
            # 构建树结构（简单的线性链，实际应用可以根据 fork 等构建真正的树）
            for i in range(len(nodes) - 1):
                nodes[i].children.append(nodes[i + 1])
            
            self.traces.append({
                'label': label,
                'nodes': nodes,
                'root': nodes[0] if nodes else None
            })
            
            print(f"[TreeViz] ✅ Added trace: {label} ({len(nodes)} syscalls)")
            return True
        
        except Exception as e:
            print(f"[TreeViz] ❌ Failed to parse {trace_file}: {e}")
            return False
    
    def generate_html(self, output_file: str) -> bool:
        """生成树状 HTML 可视化"""
        if not self.traces:
            print("[TreeViz] ⚠️  No traces to visualize")
            return False
        
        # 构建统一的根节点
        unified_root = TreeNode(
            node_id=-1,
            syscall_index=-1,
            syscall_name="RR-Fuzz Traces",
            retval="",
            is_pure=False,
            children=[],
            trace_source="root"
        )
        
        # 将所有 trace 的根节点作为统一根的子节点
        for trace_info in self.traces:
            if trace_info['root']:
                unified_root.children.append(trace_info['root'])
        
        # 转换为 JSON
        tree_json = self._node_to_json(unified_root)
        
        # 统计信息
        total_nodes = sum(len(t['nodes']) for t in self.traces)
        stats = {
            'total_traces': len(self.traces),
            'total_nodes': total_nodes,
            'trace_labels': [t['label'] for t in self.traces]
        }
        
        # 生成 HTML（使用 realtime_tree_visualizer.py 的样式和布局）
        html = self._generate_html_content(tree_json, stats)
        
        try:
            with open(output_file, 'w') as f:
                f.write(html)
            print(f"[TreeViz] ✅ Generated: {output_file}")
            return True
        except Exception as e:
            print(f"[TreeViz] ❌ Failed to write {output_file}: {e}")
            return False
    
    def _node_to_json(self, node: TreeNode, depth: int = 0, visited: set = None) -> dict:
        """节点转 JSON（带循环检测和深度保护）"""
        if visited is None:
            visited = set()
        
        if node.node_id in visited:
            return {
                'node_id': node.node_id,
                'syscall_name': f"⚠️ CIRCULAR: {node.syscall_name}",
                'error': 'circular_reference',
                'children': []
            }
        
        if depth > 500:
            return {
                'node_id': node.node_id,
                'syscall_name': f"⚠️ DEPTH_LIMIT: {node.syscall_name}",
                'error': 'max_depth_exceeded',
                'children': []
            }
        
        visited.add(node.node_id)
        
        children_json = []
        for child in node.children:
            child_json = self._node_to_json(child, depth + 1, visited.copy())
            children_json.append(child_json)
        
        return {
            'node_id': node.node_id,
            'syscall_index': node.syscall_index,
            'syscall_name': node.syscall_name,
            'retval': node.retval,
            'is_pure': node.is_pure,
            'trace_source': node.trace_source,
            'children': children_json
        }
    
    def _generate_html_content(self, tree_json: dict, stats: dict) -> str:
        """生成 HTML 内容（复用 realtime_tree_visualizer.py 的可视化代码）"""
        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RR-Fuzz Syscall Tree</title>
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
        }}
        .node.pure circle {{
            fill: #2ecc71;
        }}
        .node.hybrid circle {{
            fill: #ff9f43;
        }}
        .node text {{
            font-size: 10px;
            fill: #e0e0e0;
            text-anchor: start;
            pointer-events: none;
        }}
        .link {{
            fill: none;
            stroke: rgba(102, 126, 234, 0.4);
            stroke-width: 2px;
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
        <h1>🌳 RR-Fuzz Syscall Execution Tree</h1>
        <div id="stats">
            <div>Traces: <span class="stat-value">{stats['total_traces']}</span></div>
            <div>Total Syscalls: <span class="stat-value">{stats['total_nodes']}</span></div>
        </div>
    </div>
    
    <div id="tree-container"></div>
    
    <div id="legend">
        <h3 style="margin-bottom: 10px; color: #667eea;">节点类型</h3>
        <div class="legend-item">
            <div class="legend-circle" style="background: #48c774;"></div>
            <span>根节点</span>
        </div>
        <div class="legend-item">
            <div class="legend-circle" style="background: #2ecc71;"></div>
            <span>Pure Replay</span>
        </div>
        <div class="legend-item">
            <div class="legend-circle" style="background: #ff9f43;"></div>
            <span>Hybrid Replay</span>
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
            .attr("class", "link")
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
                else if (d.data.is_pure) cls += " pure";
                else cls += " hybrid";
                return cls;
            }})
            .attr("transform", d => `translate(${{d.y}},${{d.x}})`);
        
        nodes.append("circle")
            .attr("r", d => d.depth === 0 ? 10 : 5);
        
        nodes.append("text")
            .attr("dy", -12)
            .text(d => d.data.syscall_name);
        
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
                    Source: ${{d.data.trace_source}}<br>
                    Type: ${{d.data.is_pure ? "Pure Replay" : "Hybrid Replay"}}
                `)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px");
        }})
        .on("mouseout", () => tooltip.style("display", "none"));
    </script>
</body>
</html>'''


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate syscall tree visualization')
    parser.add_argument('traces', nargs='+', help='Trace files to visualize')
    parser.add_argument('--labels', nargs='+', help='Labels for traces')
    parser.add_argument('-o', '--output', default='syscall_tree.html', help='Output HTML file')
    
    args = parser.parse_args()
    
    viz = TreeVisualizer()
    
    labels = args.labels if args.labels else [None] * len(args.traces)
    
    for trace_file, label in zip(args.traces, labels):
        viz.add_trace(trace_file, label)
    
    if viz.generate_html(args.output):
        print(f"\n✅ Tree visualization generated: {args.output}")
        print(f"   Open in browser: file://{Path(args.output).absolute()}")
    else:
        print("\n❌ Failed to generate tree visualization")
        sys.exit(1)


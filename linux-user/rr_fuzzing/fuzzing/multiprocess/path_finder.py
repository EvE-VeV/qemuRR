#!/usr/bin/env python3
"""
PathFinder - CFG 分析和路径发现模块

功能:
1. 使用 angr 构建控制流图 (CFG)
2. 将运行时 BB 序列映射到静态 CFG
3. 识别未覆盖的分支
4. 生成针对性的变异配方 (Mutation Recipes)
5. 系统调用增强的 CFG (标注系统调用信息)

设计理念:
- 静态分析 (CFG) + 动态分析 (BB trace) 结合
- 针对系统调用的精准变异
- 自动化 recipe 生成
"""

import angr
from typing import List, Dict, Set, Tuple, Optional, Any
import json
import logging


class PathFinderConfig:
    """PathFinder 配置"""
    
    def __init__(
        self,
        verbose: bool = False,
        mapping_tolerance: int = 16,
        max_cfg_nodes: int = 10000,
        timeout: int = 300,
        enable_syscall_enhancement: bool = True,
        max_recipes: int = 20
    ):
        """
        Args:
            verbose: 详细日志输出
            mapping_tolerance: BB 地址映射容差（用于 PIE 程序）
            max_cfg_nodes: 最大 CFG 节点数（防止过大程序）
            timeout: CFG 构建超时（秒）
            enable_syscall_enhancement: 启用系统调用增强
            max_recipes: 最大生成的 recipe 数量
        """
        self.verbose = verbose
        self.mapping_tolerance = mapping_tolerance
        self.max_cfg_nodes = max_cfg_nodes
        self.timeout = timeout
        self.enable_syscall_enhancement = enable_syscall_enhancement
        self.max_recipes = max_recipes


class MutationRecipe:
    """变异配方 - 用于引导 SmartMutator"""
    
    def __init__(self, recipe_dict: Dict[str, Any]):
        """
        从字典构造 Recipe
        
        Args:
            recipe_dict: Recipe 数据字典
        """
        self.id = recipe_dict.get('id', 0)
        self.source_branch = recipe_dict.get('source_branch', '')
        self.target_branch = recipe_dict.get('target_branch', '')
        self.mutation_type = recipe_dict.get('mutation_type', 'FUZZ_CMD_MUTATE_ARG')
        self.syscall_index = recipe_dict.get('syscall_index', -1)
        self.syscall_name = recipe_dict.get('syscall_name', '')
        self.arg_index = recipe_dict.get('arg_index', 0)
        self.suggested_values = recipe_dict.get('suggested_values', [])
        self.priority = recipe_dict.get('priority', 5)
        self.reason = recipe_dict.get('reason', '')
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'id': self.id,
            'source_branch': self.source_branch,
            'target_branch': self.target_branch,
            'mutation_type': self.mutation_type,
            'syscall_index': self.syscall_index,
            'syscall_name': self.syscall_name,
            'arg_index': self.arg_index,
            'suggested_values': self.suggested_values,
            'priority': self.priority,
            'reason': self.reason,
        }
    
    def __repr__(self) -> str:
        return (f"Recipe(id={self.id}, target={self.target_branch}, "
                f"syscall={self.syscall_name}@{self.syscall_index}, "
                f"priority={self.priority})")


class PathFinder:
    """
    路径查找器 - CFG 分析和 Recipe 生成
    
    核心功能:
    1. 静态 CFG 构建
    2. 动态 trace 映射
    3. 未覆盖分支识别
    4. 系统调用增强 CFG
    5. 自动化 recipe 生成
    """
    
    def __init__(
        self,
        binary_path: str,
        config: Optional[PathFinderConfig] = None
    ):
        """
        初始化 PathFinder
        
        Args:
            binary_path: 目标二进制文件路径
            config: PathFinder 配置
        """
        self.binary_path = binary_path
        self.config = config or PathFinderConfig()
        self.logger = self._setup_logger()
        
        # 加载二进制文件
        self.logger.info(f"加载二进制文件: {binary_path}")
        try:
            self.project = angr.Project(
                binary_path,
                auto_load_libs=False,
                load_options={'main_opts': {'base_addr': 0}}
            )
        except Exception as e:
            self.logger.error(f"加载二进制失败: {e}")
            raise
        
        # 构建 CFG
        self.cfg = None
        self._build_cfg()
        
        # 统计信息
        self.stats = {
            'total_blocks': len(self.cfg.graph.nodes()) if self.cfg else 0,
            'total_edges': len(self.cfg.graph.edges()) if self.cfg else 0,
        }
        
        # 分析指标
        self.metrics = {}
        
        # 系统调用信息（如果启用增强）
        self.syscall_map = {}  # {cfg_node_addr: [syscall_info]}
    
    def _setup_logger(self) -> logging.Logger:
        """设置日志"""
        logger = logging.getLogger('PathFinder')
        if self.config.verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '[%(name)s] %(levelname)s: %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _build_cfg(self):
        """构建控制流图"""
        self.logger.info("开始构建 CFG...")
        
        try:
            # 使用 CFGFast (快速但不精确)
            # 对于精确分析可以使用 CFGEmulated，但更慢
            self.cfg = self.project.analyses.CFGFast(
                normalize=True,
                data_references=True,
                force_complete_scan=False
            )
            
            nodes_count = len(self.cfg.graph.nodes())
            edges_count = len(self.cfg.graph.edges())
            
            self.logger.info(f"CFG 构建完成")
            self.logger.info(f"  节点数: {nodes_count}")
            self.logger.info(f"  边数: {edges_count}")
            
            # 检查节点数是否过多
            if nodes_count > self.config.max_cfg_nodes:
                self.logger.warning(
                    f"CFG 节点数 ({nodes_count}) 超过限制 ({self.config.max_cfg_nodes})"
                )
        
        except Exception as e:
            self.logger.error(f"CFG 构建失败: {e}")
            raise
    
    def map_trace_to_cfg(
        self,
        bb_sequence: List[int],
        syscall_info: Optional[List[Dict]] = None
    ) -> Tuple[Set[int], Set[int]]:
        """
        将 BB 序列映射到 CFG 节点
        
        Args:
            bb_sequence: BB 地址序列（来自 BBTraceParser）
            syscall_info: 系统调用信息列表（可选）
        
        Returns:
            (covered_set, uncovered_set): 已覆盖和未覆盖的 CFG 节点地址集合
        """
        self.logger.info(f"映射 trace 到 CFG (BB 数量: {len(bb_sequence)})")
        
        covered_set = set()
        unmapped_count = 0
        
        # 映射每个 BB 地址到 CFG 节点
        for bb_addr in bb_sequence:
            node = self._find_cfg_node(bb_addr)
            if node:
                covered_set.add(node.addr)
            else:
                unmapped_count += 1
                if self.config.verbose and unmapped_count <= 5:
                    self.logger.debug(
                        f"未映射的 BB: 0x{bb_addr:x}"
                    )
        
        # 计算未覆盖节点
        all_nodes = set(n.addr for n in self.cfg.graph.nodes())
        uncovered_set = all_nodes - covered_set
        
        # 更新指标
        self.metrics['covered_nodes'] = len(covered_set)
        self.metrics['uncovered_nodes'] = len(uncovered_set)
        self.metrics['total_cfg_nodes'] = len(all_nodes)
        self.metrics['unmapped_bbs'] = unmapped_count
        self.metrics['mapping_rate'] = (
            len(bb_sequence) - unmapped_count
        ) / len(bb_sequence) * 100 if bb_sequence else 0
        
        coverage_rate = (
            len(covered_set) / len(all_nodes) * 100 if all_nodes else 0
        )
        
        self.logger.info(f"映射完成:")
        self.logger.info(f"  已覆盖节点: {len(covered_set)}")
        self.logger.info(f"  未覆盖节点: {len(uncovered_set)}")
        self.logger.info(f"  覆盖率: {coverage_rate:.1f}%")
        self.logger.info(f"  映射成功率: {self.metrics['mapping_rate']:.1f}%")
        
        if unmapped_count > 5:
            self.logger.warning(
                f"共 {unmapped_count} 个 BB 未能映射到 CFG"
            )
        
        # 如果提供了系统调用信息，增强 CFG
        if syscall_info and self.config.enable_syscall_enhancement:
            self._enhance_cfg_with_syscalls(covered_set, syscall_info)
        
        return covered_set, uncovered_set
    
    def _find_cfg_node(self, addr: int):
        """
        在 CFG 中查找地址对应的节点
        
        Args:
            addr: BB 地址
        
        Returns:
            CFG 节点或 None
        """
        # 1. 精确匹配
        try:
            node = self.cfg.model.get_any_node(addr)
            if node:
                return node
        except:
            pass
        
        # 2. 容差匹配（用于 PIE 程序）
        tolerance = self.config.mapping_tolerance
        for node in self.cfg.graph.nodes():
            if abs(node.addr - addr) <= tolerance:
                return node
        
        return None
    
    def _enhance_cfg_with_syscalls(
        self,
        covered_set: Set[int],
        syscall_info: List[Dict]
    ):
        """
        使用系统调用信息增强 CFG
        
        Args:
            covered_set: 已覆盖的 CFG 节点集合
            syscall_info: 系统调用信息列表
        """
        self.logger.info("增强 CFG（系统调用信息）...")
        
        # 这里需要更复杂的分析来将系统调用映射到 CFG 节点
        # 简化实现：假设系统调用信息包含 BB 地址
        for syscall in syscall_info:
            if 'bb_addr' in syscall:
                node = self._find_cfg_node(syscall['bb_addr'])
                if node and node.addr in covered_set:
                    if node.addr not in self.syscall_map:
                        self.syscall_map[node.addr] = []
                    self.syscall_map[node.addr].append(syscall)
        
        self.logger.info(
            f"  增强了 {len(self.syscall_map)} 个 CFG 节点"
        )
    
    def find_uncovered_branches(
        self,
        covered_set: Set[int]
    ) -> List[Dict[str, Any]]:
        """
        查找未覆盖的分支
        
        Args:
            covered_set: 已覆盖的 CFG 节点集合
        
        Returns:
            未覆盖分支列表
        """
        self.logger.info("查找未覆盖的分支...")
        
        uncovered_branches = []
        
        for node_addr in covered_set:
            node = self._find_cfg_node(node_addr)
            if not node:
                continue
            
            # 检查后继节点
            for successor in self.cfg.graph.successors(node):
                if successor.addr not in covered_set:
                    # 这是一个未覆盖的分支
                    branch = {
                        'from': node.addr,
                        'to': successor.addr,
                        'type': self._classify_branch(node, successor),
                        'distance': self._calculate_distance(node),
                        'has_syscall': node.addr in self.syscall_map,
                    }
                    
                    # 如果源节点有系统调用，记录下来
                    if node.addr in self.syscall_map:
                        branch['syscalls'] = self.syscall_map[node.addr]
                    
                    uncovered_branches.append(branch)
        
        self.logger.info(f"  发现 {len(uncovered_branches)} 个未覆盖分支")
        
        return uncovered_branches
    
    def _classify_branch(self, from_node, to_node) -> str:
        """
        分类分支类型
        
        Args:
            from_node: 源节点
            to_node: 目标节点
        
        Returns:
            分支类型: 'jump', 'true_branch', 'false_branch', 'switch'
        """
        successors = list(self.cfg.graph.successors(from_node))
        
        if len(successors) == 1:
            return 'jump'
        elif len(successors) == 2:
            # 假设第一个是 false 分支，第二个是 true 分支
            idx = successors.index(to_node)
            return 'true_branch' if idx == 1 else 'false_branch'
        else:
            return 'switch'
    
    def _calculate_distance(self, node) -> int:
        """
        计算节点距离（从入口点的深度）
        
        Args:
            node: CFG 节点
        
        Returns:
            距离值
        """
        # 简化实现：使用启发式
        # 更精确的实现需要 BFS/DFS 计算
        return 0
    
    def generate_recipes(
        self,
        uncovered_branches: List[Dict[str, Any]],
        max_recipes: Optional[int] = None
    ) -> List[MutationRecipe]:
        """
        生成变异配方
        
        Args:
            uncovered_branches: 未覆盖的分支列表
            max_recipes: 最大生成数量（None 则使用配置值）
        
        Returns:
            变异配方列表
        """
        max_count = max_recipes or self.config.max_recipes
        
        self.logger.info(f"生成变异配方（最多 {max_count} 个）...")
        
        recipes = []
        
        # 按优先级排序分支
        # 优先级：有系统调用的分支 > 距离近的分支
        sorted_branches = sorted(
            uncovered_branches,
            key=lambda b: (
                -int(b.get('has_syscall', False)),
                b.get('distance', 999)
            )
        )
        
        for i, branch in enumerate(sorted_branches[:max_count]):
            recipe_dict = {
                'id': i + 1,
                'source_branch': f"0x{branch['from']:x}",
                'target_branch': f"0x{branch['to']:x}",
                'mutation_type': 'FUZZ_CMD_MUTATE_ARG',
                'priority': 5,
            }
            
            # 如果分支有系统调用信息，生成更精确的 recipe
            if branch.get('has_syscall') and 'syscalls' in branch:
                syscalls = branch['syscalls']
                if syscalls:
                    syscall = syscalls[0]  # 使用第一个系统调用
                    recipe_dict.update({
                        'syscall_index': syscall.get('index', -1),
                        'syscall_name': syscall.get('name', ''),
                        'arg_index': 0,  # 默认变异第一个参数
                        'priority': 8,  # 提高优先级
                        'reason': f"触发 {branch['type']} 分支",
                    })
                    
                    # 根据系统调用类型选择变异策略
                    if syscall.get('name') in ['read', 'write', 'recv', 'send']:
                        recipe_dict['mutation_type'] = 'FUZZ_CMD_EXTEND'
                        recipe_dict['suggested_values'] = [0, 1, 16, 32, 64, 128, 256]
                    elif syscall.get('name') in ['open', 'openat']:
                        recipe_dict['mutation_type'] = 'FUZZ_CMD_MUTATE_FLAGS'
                    else:
                        recipe_dict['mutation_type'] = 'FUZZ_CMD_INTERESTING_VALUES'
            
            recipes.append(MutationRecipe(recipe_dict))
        
        self.logger.info(f"  生成了 {len(recipes)} 个 recipes")
        
        return recipes
    
    def export_recipes(
        self,
        recipes: List[MutationRecipe],
        output_path: str
    ):
        """
        导出 recipes 到 JSON 文件
        
        Args:
            recipes: 变异配方列表
            output_path: 输出文件路径
        """
        recipes_data = [r.to_dict() for r in recipes]
        
        with open(output_path, 'w') as f:
            json.dump(recipes_data, f, indent=2)
        
        self.logger.info(f"已导出 {len(recipes)} 个 recipes 到 {output_path}")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            **self.metrics,
        }


# 测试和演示代码
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python path_finder.py <binary_path> [bb_trace_file]")
        print("  binary_path: 目标二进制文件")
        print("  bb_trace_file: BB trace 文件（可选）")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    bb_trace_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # 创建 PathFinder
    config = PathFinderConfig(verbose=True)
    finder = PathFinder(binary_path, config)
    
    print("\n" + "="*60)
    print("CFG 统计:")
    print("="*60)
    print(f"节点数: {finder.stats['total_blocks']}")
    print(f"边数: {finder.stats['total_edges']}")
    
    # 如果提供了 BB trace 文件，进行映射
    if bb_trace_file:
        print("\n" + "="*60)
        print("Trace 映射:")
        print("="*60)
        
        # 简化的 BB 解析（实际应使用 BBTraceParser）
        bb_sequence = []
        with open(bb_trace_file, 'r') as f:
            for line in f:
                try:
                    addr = int(line.strip(), 16)
                    bb_sequence.append(addr)
                except:
                    continue
        
        print(f"加载了 {len(bb_sequence)} 个 BB 地址")
        
        # 映射
        covered, uncovered = finder.map_trace_to_cfg(bb_sequence)
        
        # 查找未覆盖分支
        uncovered_branches = finder.find_uncovered_branches(covered)
        
        # 生成 recipes
        recipes = finder.generate_recipes(uncovered_branches, max_recipes=10)
        
        print("\n" + "="*60)
        print("生成的 Recipes:")
        print("="*60)
        for recipe in recipes[:5]:  # 显示前 5 个
            print(f"  {recipe}")
        
        # 导出 recipes
        output_file = bb_trace_file + '.recipes.json'
        finder.export_recipes(recipes, output_file)
    
    print("\n✅ PathFinder 测试完成")


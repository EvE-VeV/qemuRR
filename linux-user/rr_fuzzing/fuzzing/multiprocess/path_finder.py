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
from collections import defaultdict
import json
import logging
import re
import sys
from pathlib import Path
import signal
import time


class PathFinderConfig:
    """PathFinder 配置"""
    
    def __init__(
        self,
        verbose: bool = False,
        mapping_tolerance: int = 16,
        max_cfg_nodes: int = 10000,
        timeout: int = 60,
        enable_syscall_enhancement: bool = True,
        max_recipes: int = 20,
        enable_auto_fast_mode: bool = True,
        graceful_disable: bool = True,
        restrict_to_main_object: bool = True
    ):
        """
        Args:
            verbose: 详细日志输出
            mapping_tolerance: BB 地址映射容差（用于 PIE 程序）
            max_cfg_nodes: 最大 CFG 节点数（防止过大程序）
            timeout: CFG 构建超时（秒）
            enable_syscall_enhancement: 启用系统调用增强
            max_recipes: 最大生成的 recipe 数量
            enable_auto_fast_mode: 节点超限时自动切换简化模式
            graceful_disable: 出现错误时自动禁用PathFinder而不是抛异常
            restrict_to_main_object: 仅分析目标二进制，不跟踪libc
        """
        self.verbose = verbose
        self.mapping_tolerance = mapping_tolerance
        self.max_cfg_nodes = max_cfg_nodes
        self.timeout = timeout
        self.enable_syscall_enhancement = enable_syscall_enhancement
        self.max_recipes = max_recipes
        self.enable_auto_fast_mode = enable_auto_fast_mode
        self.graceful_disable = graceful_disable
        self.restrict_to_main_object = restrict_to_main_object


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
        self.available = True
        self.disabled_reason: Optional[str] = None
        self.main_object = None
        self.graph_mode = "static"
        self.dynamic_nodes: Dict[int, int] = {}
        self.dynamic_edges: Dict[int, Set[int]] = {}
        self.dynamic_syscalls: Dict[int, List[Dict[str, Any]]] = {}
        self.node_samples: Dict[int, int] = {}
        self.last_trace_file: Optional[str] = None
        self.simplified_mode: bool = False
        
        # 加载二进制文件
        self.logger.info(f"加载二进制文件: {binary_path}")
        try:
            self.project = angr.Project(
                binary_path,
                auto_load_libs=False,
                load_options={'main_opts': {'base_addr': 0, 'force_rebase': True}}
            )
        except Exception as e:
            self.logger.error(f"加载二进制失败: {e}")
            raise
        self.main_object = self.project.loader.main_object
        
        # 构建 CFG（默认延迟，等待trace驱动）
        self.cfg = None
        self.stats = {'total_blocks': 0, 'total_edges': 0}

        # 🔥 新增：可选的自动CFG构建
        # if getattr(config, 'auto_build_cfg', False):
        #     try:
        #         self._build_cfg()
        #     except Exception as e:
        #         self.logger.warning(f"CFG自动构建失败，切换到延迟模式: {e}")
        
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

    def load_syscall_tree(self, tree_file: str = "/tmp/syscall_tree.json") -> bool:
        """
        Load syscall tree from JSON file exported by C side.

        This provides precise BB→Syscall mapping instead of estimation.

        Args:
            tree_file: Path to syscall tree JSON file

        Returns:
            True if loaded successfully, False otherwise
        """
        import os

        if not os.path.exists(tree_file):
            self.logger.warning(f"Syscall tree file not found: {tree_file}")
            return False

        try:
            with open(tree_file, 'r') as f:
                tree_data = json.load(f)

            # Extract nodes from tree
            nodes = tree_data.get('nodes', [])
            if not nodes:
                self.logger.warning(f"Syscall tree is empty: {tree_file}")
                return False

            # Build BB→Syscall mapping
            # Note: We need BB trace to connect BB addresses to syscall indices
            # The tree provides syscall_index directly from C side
            self.syscall_tree_data = tree_data
            self.bb_to_syscall_map = {}  # Will be populated when BB trace is available

            self.logger.info(f"✅ Loaded syscall tree: {len(nodes)} nodes from {tree_file}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to load syscall tree: {e}")
            return False

    def get_precise_syscall_index(self, bb_addr: int) -> int:
        """
        Get precise syscall index for a BB address using syscall tree.

        This replaces the rough estimation (source_addr >> 4) % 20.

        Args:
            bb_addr: Basic block address

        Returns:
            Syscall index, or -1 if not found
        """
        if not hasattr(self, 'bb_to_syscall_map'):
            return -1

        # Direct lookup from BB→Syscall map
        return self.bb_to_syscall_map.get(bb_addr, -1)

    def build_from_trace(self, trace_file: str) -> bool:
        """
        根据trace文件构建动态CFG（无需angr）
        """
        if not trace_file:
            return False
        if self.last_trace_file == trace_file and self.graph_mode == "dynamic":
            # 已经构建
            return True
        
        # 尝试加载trace
        try:
            from trace_analyzer import TraceAnalyzer
        except ImportError:
            # 添加fuzzing根目录到路径
            fuzzing_dir = Path(__file__).parent.parent  # fuzzing/multiprocess -> fuzzing/
            if str(fuzzing_dir) not in sys.path:
                sys.path.insert(0, str(fuzzing_dir))
            try:
                from trace_analyzer import TraceAnalyzer
            except ImportError:
                self.logger.error(f"无法导入TraceAnalyzer，请检查trace_analyzer.py是否在{fuzzing_dir}")
                return False
        
        analyzer = TraceAnalyzer(trace_file)
        if not analyzer.analyze():
            self.logger.warning(f"TraceAnalyzer解析失败: {trace_file}")
            return False

        # 🔥 临时修复：即使没有BB trace也允许继续（使用syscall-level分析）
        if not analyzer.has_bb_trace():
            self.logger.warning(f"Trace缺少BB信息: {trace_file}.bbl，使用syscall-level分析")
            # 继续处理，但标记为简化模式
            self.simplified_mode = True
        else:
            self.simplified_mode = False
        
        # 🔥 修复：检查BB trace是否可用
        entries = []
        if analyzer.has_bb_trace() and analyzer.bb_trace_parser:
            entries = analyzer.bb_trace_parser.entries

        if not entries:
            if not self.simplified_mode:
                self.logger.warning("BB trace为空，无法构建动态CFG")
                return False
            else:
                # 简化模式：使用syscall信息构建基本图
                self.logger.info("使用简化模式：基于syscall构建基础路径图")
                entries = []  # 空entries，稍后基于syscall构建
        
        nodes = {}
        edges = defaultdict(set)
        syscalls = defaultdict(list)

        # ✅ 2025-11-17: Initialize BB→Syscall mapping for precise mutation targeting
        if not hasattr(self, 'bb_to_syscall_map'):
            self.bb_to_syscall_map = {}

        prev_node = None
        for entry in entries:
            node_id = entry.pc & 0xFFFF  # 与覆盖率bitmap一致的索引
            if node_id not in nodes:
                nodes[node_id] = entry.pc
            if entry.syscall_idx >= 0:
                # ✅ 2025-11-17: Build BB→Syscall mapping for precise PathFinder targeting
                self.bb_to_syscall_map[entry.pc] = entry.syscall_idx

                while len(analyzer.syscalls) <= entry.syscall_idx:
                    break
                if 0 <= entry.syscall_idx < len(analyzer.syscalls):
                    syscall = analyzer.syscalls[entry.syscall_idx]
                    sys_info = {
                        'index': syscall.index,
                        'name': syscall.name,
                        'syscall_nr': syscall.syscall_nr,
                        'args': getattr(syscall, 'args', []),
                        'retval': getattr(syscall, 'retval', 0),
                        'bb_addr': entry.pc,
                    }
                    syscalls[node_id].append(sys_info)
            if prev_node is not None:
                edges[prev_node].add(node_id)
            prev_node = node_id
        
        self.dynamic_nodes = nodes
        self.dynamic_edges = edges
        self.dynamic_syscalls = syscalls
        self.syscall_map = dict(syscalls)
        self.graph_mode = "dynamic"
        self.available = True
        self.disabled_reason = None
        self.stats = {
            'total_blocks': len(nodes),
            'total_edges': sum(len(v) for v in edges.values()),
        }
        self.last_trace_file = trace_file
        self.logger.info(f"动态CFG构建完成: 节点={self.stats['total_blocks']} 边={self.stats['total_edges']}")
        return True

    def _collect_main_regions(self) -> List[Tuple[int, int]]:
        if not self.main_object or not self.config.restrict_to_main_object:
            return []
        regions = []
        for section in self.main_object.sections:
            if getattr(section, "is_executable", False) and section.memsize:
                start = section.vaddr
                end = section.vaddr + section.memsize
                regions.append((start, end))
        if not regions:
            regions.append((self.main_object.min_addr, self.main_object.max_addr))
        return regions

    def _is_node_in_scope(self, node) -> bool:
        if not node:
            return False
        if not self.config.restrict_to_main_object:
            return True
        return getattr(node, "obj", None) == self.main_object

    def is_available(self) -> bool:
        """🔥 修复: 改进可用性检查逻辑"""
        # 基本可用性检查
        if not self.available or not self.project:
            return False

        if self.graph_mode == "dynamic":
            # 动态模式：检查是否有动态节点
            return bool(self.dynamic_nodes)
        elif self.graph_mode == "static":
            # 静态模式：project加载成功就算可用(延迟构建)
            return True

        return False

    def ensure_cfg_ready(self) -> bool:
        """🔥 新增: 确保CFG就绪（按需构建）"""
        # 🔥 性能修复：如果使用动态模式，跳过静态CFG构建
        if self.graph_mode == "dynamic":
            return True  # 动态模式不需要静态CFG

        if self.cfg is not None:
            return True  # 已经有CFG

        if not self.available or not hasattr(self, 'project') or not self.project:
            return False

        try:
            self._build_cfg()
            return self.cfg is not None
        except Exception as e:
            self.logger.error(f"CFG构建失败: {e}")
            self.disabled_reason = f"CFG build failed: {e}"
            self.available = False
            return False

    def _build_cfg(self):
        """构建控制流图"""
        self.logger.info("开始构建 CFG...")
        self.available = True
        self.disabled_reason = None
        
        regions = self._collect_main_regions()

        def run_cfg(fast_mode: bool = False):
            kwargs = dict(
                normalize=True,
                data_references=True,
                force_complete_scan=False
            )
            if fast_mode:
                kwargs.update({
                    'normalize': False,
                    'data_references': False
                })
            if regions:
                kwargs['regions'] = regions
            return self.project.analyses.CFGFast(**kwargs)
        
        def run_with_timeout(fn):
            if not self.config.timeout:
                return fn()
            
            def handler(signum, frame):
                raise TimeoutError(f"CFG 分析超过 {self.config.timeout} 秒")
            
            previous = signal.signal(signal.SIGALRM, handler)
            signal.setitimer(signal.ITIMER_REAL, self.config.timeout)
            try:
                return fn()
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
        
        try:
            self.cfg = run_with_timeout(lambda: run_cfg(fast_mode=False))
            nodes_count = len([n for n in self.cfg.graph.nodes() if self._is_node_in_scope(n)])
            edges_count = len([
                edge for edge in self.cfg.graph.edges()
                if self._is_node_in_scope(edge[0]) and self._is_node_in_scope(edge[1])
            ])
            
            if nodes_count > self.config.max_cfg_nodes and self.config.enable_auto_fast_mode:
                self.logger.warning(
                    f"CFG 节点数 ({nodes_count}) 超过限制 ({self.config.max_cfg_nodes})，尝试快速模式"
                )
                self.cfg = run_with_timeout(lambda: run_cfg(fast_mode=True))
                nodes_count = len([n for n in self.cfg.graph.nodes() if self._is_node_in_scope(n)])
                edges_count = len([
                    edge for edge in self.cfg.graph.edges()
                    if self._is_node_in_scope(edge[0]) and self._is_node_in_scope(edge[1])
                ])
            
            if self.cfg and nodes_count > self.config.max_cfg_nodes:
                msg = f"CFG size {nodes_count} exceeds limit {self.config.max_cfg_nodes}"
                self.logger.warning(msg)
                if self.config.graceful_disable:
                    self.available = False
                    self.disabled_reason = msg
                    self.cfg = None
                else:
                    raise RuntimeError(msg)
            elif self.cfg:
                # 🔥 修复：更新stats字典
                self.stats = {
                    'total_blocks': nodes_count,
                    'total_edges': edges_count
                }
                self.logger.info("CFG 构建完成")
                self.logger.info(f"  节点数: {nodes_count}")
                self.logger.info(f"  边数: {edges_count}")
        
        except TimeoutError as e:
            msg = f"CFG 构建超时: {e}"
            self.logger.warning(msg)
            if self.config.graceful_disable:
                self.available = False
                self.disabled_reason = msg
                self.cfg = None
            else:
                raise
        except Exception as e:
            self.logger.error(f"CFG 构建失败: {e}")
            if self.config.graceful_disable:
                self.available = False
                self.disabled_reason = str(e)
                self.cfg = None
            else:
                raise
        
        if not self.available:
            self.logger.warning(f"PathFinder已禁用: {self.disabled_reason}")
            self.stats = {'total_blocks': 0, 'total_edges': 0}
    
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
        if not self.is_available():
            self.logger.debug("PathFinder不可用，map_trace_to_cfg返回空结果")
            return set(), set()
        
        self.logger.info(f"映射 trace 到 CFG (BB 数量: {len(bb_sequence)})")
        
        covered_set = set()
        unmapped_count = 0
        
        if self.graph_mode == "dynamic":
            for bb_addr in bb_sequence:
                node_id = bb_addr & 0xFFFF
                if node_id in self.dynamic_nodes:
                    covered_set.add(node_id)
                else:
                    unmapped_count += 1
                    if self.config.verbose and unmapped_count <= 5:
                        self.logger.debug(f"未映射的 BB: 0x{bb_addr:x}")
            all_nodes = set(self.dynamic_nodes.keys())
        else:
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
        if self.graph_mode == "dynamic":
            node_id = addr & 0xFFFF
            return node_id if node_id in self.dynamic_nodes else None
        
        # 1. 精确匹配
        try:
            node = self.cfg.model.get_any_node(addr)
            if node and self._is_node_in_scope(node):
                return node
        except Exception:
            pass
        
        # 2. 容差匹配（用于 PIE 程序）
        tolerance = self.config.mapping_tolerance
        for node in self.cfg.graph.nodes():
            if not self._is_node_in_scope(node):
                continue
            if abs(node.addr - addr) <= tolerance:
                return node
        
        return None
    
    def _parse_bb_trace(self, bb_trace_file: str) -> List[Dict[str, Any]]:
        """
        解析BB trace文件
        
        Args:
            bb_trace_file: BB trace文件路径 (rr_bb_trace.log)
        
        Returns:
            BB entries列表，每个entry包含: {pc, syscall_idx}
        
        格式示例:
            PC=0x401000 syscall_idx=5
            PC=0x401010 syscall_idx=5
            PC=0x401020 syscall_idx=6
        """
        bb_entries = []
        
        try:
            with open(bb_trace_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # 尝试解析: PC=0x401000 syscall_idx=5
                    match = re.match(r'PC=(0x[0-9a-fA-F]+)\s+syscall_idx=(\d+)', line)
                    if match:
                        pc = int(match.group(1), 16)
                        syscall_idx = int(match.group(2))
                        bb_entries.append({
                            'pc': pc,
                            'syscall_idx': syscall_idx
                        })
                    else:
                        # 尝试只有地址的格式
                        try:
                            pc = int(line, 16)
                            bb_entries.append({
                                'pc': pc,
                                'syscall_idx': -1  # 未知
                            })
                        except ValueError:
                            continue
            
            self.logger.info(f"  解析了 {len(bb_entries)} 个BB entries")
        
        except Exception as e:
            self.logger.error(f"  解析BB trace失败: {e}")
        
        return bb_entries
    
    def _parse_syscall_trace(self, syscall_trace_file: str) -> List[Dict[str, Any]]:
        """
        解析syscall trace文件
        
        Args:
            syscall_trace_file: Syscall trace文件路径
        
        Returns:
            Syscall列表，每个entry包含: {index, name, args, retval}
        """
        syscalls = []
        
        try:
            # 使用TraceAnalyzer解析
            # 添加analysis目录到path
            parent_dir = Path(__file__).parent.parent.parent
            analysis_dir = parent_dir / 'analysis'
            if str(analysis_dir) not in sys.path:
                sys.path.insert(0, str(analysis_dir))
            
            from trace_analyzer import TraceAnalyzer
            
            analyzer = TraceAnalyzer(syscall_trace_file)
            if analyzer.analyze():
                syscalls = [{
                    'index': sc.index,
                    'name': sc.name,
                    'syscall_nr': sc.syscall_nr,
                    'args': sc.args if hasattr(sc, 'args') else [],
                    'retval': sc.retval if hasattr(sc, 'retval') else None
                } for sc in analyzer.syscalls]
                
                self.logger.info(f"  解析了 {len(syscalls)} 个syscalls")
            else:
                self.logger.error(f"  TraceAnalyzer分析失败")
        
        except Exception as e:
            self.logger.error(f"  解析syscall trace失败: {e}")
        
        return syscalls
    
    def enhance_from_trace_files(
        self,
        syscall_trace_file: str,
        bb_trace_file: str,
        covered_set: Optional[Set[int]] = None
    ) -> int:
        """
        从实际trace文件增强CFG（修复版本）
        
        这是修复后的方法，正确连接BB trace和syscall trace到CFG节点。
        
        Args:
            syscall_trace_file: Syscall trace文件路径
            bb_trace_file: BB trace文件路径
            covered_set: 已覆盖的CFG节点集合（可选）
        
        Returns:
            成功映射的CFG节点数量
        
        工作流程:
        1. 解析syscall trace → 得到syscall序列
        2. 解析BB trace → 得到BB序列（每个BB记录syscall_idx）
        3. 建立映射：BB地址 → syscall
        4. 将syscall映射到CFG节点
        """
        self.logger.info("从trace文件增强CFG...")
        if self.graph_mode == "dynamic":
            # 已直接在 build_from_trace 中处理
            return len(self.dynamic_syscalls)
        
        # Step 1: 解析syscall trace
        syscalls = self._parse_syscall_trace(syscall_trace_file)
        if not syscalls:
            self.logger.warning("  未能解析syscall trace")
            return 0
        
        # Step 2: 解析BB trace
        bb_entries = self._parse_bb_trace(bb_trace_file)
        if not bb_entries:
            self.logger.warning("  未能解析BB trace")
            return 0
        
        # Step 3: 建立BB → Syscall映射
        mapped_count = 0
        
        for bb in bb_entries:
            pc = bb['pc']
            syscall_idx = bb['syscall_idx']
            
            # 跳过无效的syscall索引
            if syscall_idx < 0 or syscall_idx >= len(syscalls):
                continue
            
            # 找到对应的CFG节点
            node = self._find_cfg_node(pc)
            if node is None:
                continue
            node_key = node if self.graph_mode == "dynamic" else node.addr
            
            # 如果提供了covered_set，只映射已覆盖的节点
            if covered_set and node_key not in covered_set:
                continue
            
            # 添加syscall信息到CFG节点
            if node_key not in self.syscall_map:
                self.syscall_map[node_key] = []
            
            syscall_info = syscalls[syscall_idx].copy()
            syscall_info['bb_addr'] = pc  # 添加BB地址
            
            # 避免重复添加
            if syscall_info not in self.syscall_map[node_key]:
                self.syscall_map[node_key].append(syscall_info)
                mapped_count += 1
        
        self.logger.info(
            f"  ✅ 成功映射 {len(self.syscall_map)} 个CFG节点 "
            f"({mapped_count} 个syscall条目)"
        )
        
        return len(self.syscall_map)
    
    def _enhance_cfg_with_syscalls(
        self,
        covered_set: Set[int],
        syscall_info: List[Dict]
    ):
        """
        使用系统调用信息增强 CFG（旧版本，已废弃）
        
        ⚠️ 废弃警告: 此方法有设计缺陷（假设syscall_info包含'bb_addr'字段）
        
        请使用 enhance_from_trace_files() 方法替代。
        
        Args:
            covered_set: 已覆盖的 CFG 节点集合
            syscall_info: 系统调用信息列表
        """
        self.logger.warning(
            "⚠️ _enhance_cfg_with_syscalls() 已废弃，请使用 enhance_from_trace_files()"
        )
        
        if not syscall_info:
            return
        
        # 保留旧逻辑以兼容
        for syscall in syscall_info:
            if 'bb_addr' in syscall:
                node = self._find_cfg_node(syscall['bb_addr'])
                if self.graph_mode == "dynamic":
                    node_id = node
                    if node_id and node_id in covered_set:
                        if node_id not in self.syscall_map:
                            self.syscall_map[node_id] = []
                        self.syscall_map[node_id].append(syscall)
                else:
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
        if not self.is_available():
            self.logger.debug("PathFinder不可用，find_uncovered_branches返回空列表")
            return []
        
        self.logger.info("查找未覆盖的分支...")
        
        uncovered_branches = []
        
        if self.graph_mode == "dynamic":
            for node_id, succs in self.dynamic_edges.items():
                for succ in succs:
                    if succ not in covered_set:
                        branch = {
                            'from': self.dynamic_nodes.get(node_id, node_id),
                            'to': self.dynamic_nodes.get(succ, succ),
                            'type': 'trace_edge',
                            'distance': 0,
                            'has_syscall': node_id in self.dynamic_syscalls,
                        }
                        if node_id in self.dynamic_syscalls:
                            branch['syscalls'] = self.dynamic_syscalls[node_id]
                        uncovered_branches.append(branch)
            self.logger.info(f"  发现 {len(uncovered_branches)} 个未覆盖分支 (动态CFG)")
            return uncovered_branches
        
        for node_addr in covered_set:
            node = self._find_cfg_node(node_addr)
            if not node:
                continue
            
            # 检查后继节点
            for successor in self.cfg.graph.successors(node):
                if not self._is_node_in_scope(successor):
                    continue
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
        if not self.is_available():
            self.logger.debug("PathFinder不可用，generate_recipes返回空列表")
            return []
        
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
                    syscall_name = syscall.get('name', '')
                    
                    # ✅ 使用启发式规则推断arg_index和suggested_values
                    arg_index, suggested_values = self._infer_mutation_target(
                        syscall_name, syscall
                    )
                    
                    recipe_dict.update({
                        'syscall_index': syscall.get('index', -1),
                        'syscall_name': syscall_name,
                        'arg_index': arg_index,  # ✅ 改进：使用推断的参数索引
                        'suggested_values': suggested_values,  # ✅ 新增：建议值
                        'priority': 8,  # 提高优先级
                        'reason': f"触发 {branch['type']} 分支 (启发式分析)",
                    })
                    
                    # 根据系统调用类型选择变异策略
                    if syscall_name in ['read', 'write', 'recv', 'send']:
                        recipe_dict['mutation_type'] = 'FUZZ_CMD_EXTEND'
                    elif syscall_name in ['open', 'openat']:
                        recipe_dict['mutation_type'] = 'FUZZ_CMD_MUTATE_FLAGS'
                    else:
                        recipe_dict['mutation_type'] = 'FUZZ_CMD_INTERESTING_VALUES'
            
            # ✅ 如果没有直接的syscall信息，尝试回溯分析
            elif self.syscall_map and 'from' in branch:
                branch_addr = branch['from']
                covered_set = set(self.syscall_map.keys())
                
                syscall_index, syscall_name, arg_index, suggested_values = \
                    self._simple_syscall_backtrack(branch_addr, covered_set)
                
                if syscall_index >= 0:
                    recipe_dict.update({
                        'syscall_index': syscall_index,
                        'syscall_name': syscall_name,
                        'arg_index': arg_index,
                        'suggested_values': suggested_values,
                        'priority': 6,  # 中等优先级（回溯分析不如直接信息可靠）
                        'reason': f"回溯分析: 距离分支最近的syscall是{syscall_name}",
                    })
                    
                    if syscall_name in ['read', 'recv']:
                        recipe_dict['mutation_type'] = 'FUZZ_CMD_EXTEND'
                    elif syscall_name in ['open', 'openat']:
                        recipe_dict['mutation_type'] = 'FUZZ_CMD_MUTATE_FLAGS'
            
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
    
    def generate_html_report(
        self,
        output_file: str,
        recipes: List[MutationRecipe],
        covered_set: Set[int] = None,
        uncovered_branches: List[Dict] = None,
        recipe_stats: Dict = None
    ):
        """
        生成PathFinder分析的HTML可视化报告
        
        Args:
            output_file: HTML输出文件路径
            recipes: Recipe列表
            covered_set: 已覆盖节点集合（可选）
            uncovered_branches: 未覆盖分支列表（可选）
            recipe_stats: Recipe统计信息（来自RecipePool，可选）
        """
        self.logger.info(f"生成HTML报告: {output_file}")
        
        # 生成HTML内容
        html = self._generate_html_content(
            recipes, covered_set, uncovered_branches, recipe_stats
        )
        
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.logger.info(f"✅ HTML报告已保存: {output_file}")
    
    def _generate_html_content(
        self,
        recipes: List[MutationRecipe],
        covered_set: Set[int],
        uncovered_branches: List[Dict],
        recipe_stats: Dict
    ) -> str:
        """生成HTML内容"""
        
        # 基本统计
        total_nodes = self.stats['total_blocks']
        total_edges = self.stats['total_edges']
        covered_nodes = len(covered_set) if covered_set else 0
        coverage_rate = (covered_nodes / total_nodes * 100) if total_nodes > 0 else 0
        uncovered_count = len(uncovered_branches) if uncovered_branches else 0
        recipe_count = len(recipes)
        
        # 统计有syscall信息的recipes
        recipes_with_syscall = sum(1 for r in recipes if r.syscall_index >= 0)
        syscall_rate = (recipes_with_syscall / recipe_count * 100) if recipe_count > 0 else 0
        
        # HTML模板（简化版）
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>PathFinder分析报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #4CAF50; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        .stat {{ display: inline-block; margin: 10px 20px; }}
        .priority-high {{ background: #ff5252; color: white; padding: 3px 8px; border-radius: 3px; }}
        .priority-medium {{ background: #ffc107; padding: 3px 8px; border-radius: 3px; }}
        .priority-low {{ background: #2196F3; color: white; padding: 3px 8px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 PathFinder分析报告</h1>
        <hr>
        <h2>统计信息</h2>
        <div class="stat">CFG节点: <strong>{total_nodes}</strong></div>
        <div class="stat">CFG边: <strong>{total_edges}</strong></div>
        <div class="stat">已覆盖: <strong>{covered_nodes}</strong></div>
        <div class="stat">未覆盖分支: <strong>{uncovered_count}</strong></div>
        <div class="stat">Recipes: <strong>{recipe_count}</strong></div>
        <div class="stat">Syscall映射: <strong>{len(self.syscall_map)}</strong></div>
        <hr>
        
        <h2>🧪 Mutation Recipes</h2>
        <p>共 {recipe_count} 个recipes，其中 {recipes_with_syscall} 个({syscall_rate:.1f}%)包含syscall信息</p>
        <table>
            <tr>
                <th>ID</th>
                <th>目标分支</th>
                <th>Syscall</th>
                <th>变异类型</th>
                <th>优先级</th>
            </tr>
"""
        
        # 添加recipes
        for recipe in recipes[:50]:
            priority_class = 'priority-high' if recipe.priority >= 7 else \
                           'priority-medium' if recipe.priority >= 5 else 'priority-low'
            syscall_info = f'{recipe.syscall_index}:{recipe.syscall_name}' if recipe.syscall_index >= 0 else '-'
            html += f"""
            <tr>
                <td>{recipe.id}</td>
                <td>{recipe.target_branch[:20]}...</td>
                <td>{syscall_info}</td>
                <td>{recipe.mutation_type}</td>
                <td><span class="{priority_class}">{recipe.priority}</span></td>
            </tr>
"""
        
        html += """
        </table>
    </div>
</body>
</html>
"""
        return html
    
    def _simple_syscall_backtrack(
        self,
        branch_addr: int,
        covered_set: Set[int],
        max_lookback: int = 5
    ) -> Tuple[int, str, int, List]:
        """
        简单启发式syscall回溯分析
        
        从分支地址往前查找最近的syscall，并推断参数索引和建议值。
        
        Args:
            branch_addr: 分支地址
            covered_set: 已覆盖节点集合
            max_lookback: 最多往前查找几个节点
        
        Returns:
            (syscall_index, syscall_name, arg_index, suggested_values)
            如果未找到返回(-1, '', 0, [])
        
        启发式规则:
        - read/recv: arg_index=1(buffer), suggested=[特定字节模式]
        - open: arg_index=0(path), suggested=[特殊路径]
        - write/send: arg_index=1(buffer)
        - 其他: arg_index=0(默认)
        """
        
        # 从branch_addr往前遍历CFG
        # 简化：在syscall_map中查找最近的syscall
        
        closest_syscall = None
        closest_distance = float('inf')
        closest_node_addr = None
        
        # 遍历所有有syscall信息的节点
        for node_addr, syscalls in self.syscall_map.items():
            if node_addr not in covered_set:
                continue
            
            node_addr_real = node_addr
            if self.graph_mode == "dynamic":
                node_addr_real = self.dynamic_nodes.get(node_addr, node_addr)
            
            # 简单距离度量：地址差
            distance = abs(branch_addr - node_addr_real)
            
            if distance < closest_distance:
                closest_distance = distance
                closest_node_addr = node_addr_real
                # 选择第一个syscall
                if syscalls:
                    closest_syscall = syscalls[0]
        
        if not closest_syscall:
            return (-1, '', 0, [])
        
        # 应用启发式规则
        syscall_name = closest_syscall.get('name', 'unknown')
        syscall_index = closest_syscall.get('index', -1)
        
        arg_index, suggested_values = self._infer_mutation_target(
            syscall_name, closest_syscall
        )
        
        return (syscall_index, syscall_name, arg_index, suggested_values)
    
    def _infer_mutation_target(
        self,
        syscall_name: str,
        syscall_info: Dict
    ) -> Tuple[int, List]:
        """
        根据syscall名字推断变异目标
        
        Args:
            syscall_name: Syscall名字
            syscall_info: Syscall信息
        
        Returns:
            (arg_index, suggested_values)
        """
        
        # 规则库
        rules = {
            # 文件读取类
            'read': (1, [
                b'MAGIC',
                b'FUZZ',
                b'\x00' * 16,
                b'\xff' * 16,
                b'A' * 32,
                bytes(range(256)),  # 所有字节
            ]),
            'recv': (1, [
                b'GET / HTTP/1.1\r\n',
                b'POST / HTTP/1.1\r\n',
                b'\x00' * 8,
            ]),
            'recvfrom': (1, [
                b'\x00' * 8,
                b'TEST',
            ]),
            
            # 文件打开类
            'open': (0, [
                '/dev/null',
                '/dev/zero',
                '/tmp/test',
                '../etc/passwd',
                'nonexistent',
            ]),
            'openat': (1, [
                '/dev/null',
                'test.txt',
            ]),
            
            # 文件写入类（也可变异）
            'write': (1, [
                b'TEST\n',
                b'\x00' * 16,
            ]),
            'send': (1, [
                b'TEST',
            ]),
            
            # 内存操作
            'mmap': (0, [
                0x0,  # NULL
                0x1000,  # 页对齐
                0xffffffff,  # 大地址
            ]),
            
            # ioctl
            'ioctl': (1, [
                0x0,
                0x1,
                0x5401,  # TCGETS
            ]),
        }
        
        # 查找规则
        if syscall_name in rules:
            arg_index, values = rules[syscall_name]
            # 将bytes转为十六进制字符串（便于JSON序列化）
            suggested_values = []
            for v in values:
                if isinstance(v, bytes):
                    suggested_values.append(v.hex())
                else:
                    suggested_values.append(str(v))
            
            return (arg_index, suggested_values)
        
        # 默认：第0个参数，一些通用值
        return (0, ['0', '1', '-1', '0xffffffff'])


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
    
    if not finder.is_available():
        print(f"\n⚠️  PathFinder已禁用: {finder.disabled_reason}")
        sys.exit(0)
    
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

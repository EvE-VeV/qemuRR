#!/usr/bin/env python3
"""
RR-Fuzz 综合分析工具

功能:
1. 模块依赖关系分析
2. 程序功能流程分析
3. 各部分有效性验证
4. 生成可视化报告
"""

import os
import sys
import ast
import json
import importlib.util
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

# 添加路径
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class ModuleDependencyAnalyzer:
    """模块依赖关系分析器"""
    
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.modules = {}
        self.dependencies = defaultdict(set)
        self.imports = defaultdict(list)
        
    def analyze(self):
        """分析所有Python模块"""
        print("🔍 分析模块依赖关系...")
        
        # 扫描所有Python文件
        for py_file in self.root_dir.rglob("*.py"):
            if "test" in str(py_file) or "__pycache__" in str(py_file):
                continue
            
            rel_path = py_file.relative_to(self.root_dir)
            module_name = str(rel_path).replace("/", ".").replace(".py", "")
            
            self.modules[module_name] = {
                'path': str(py_file),
                'size': py_file.stat().st_size,
                'lines': self._count_lines(py_file)
            }
            
            # 分析导入
            imports = self._extract_imports(py_file)
            self.imports[module_name] = imports
            
            for imp in imports:
                self.dependencies[module_name].add(imp)
        
        print(f"  ✓ 找到 {len(self.modules)} 个模块")
        print(f"  ✓ 分析 {sum(len(v) for v in self.dependencies.values())} 个依赖关系")
        
        return self.modules, dict(self.dependencies)
    
    def _count_lines(self, file_path: Path) -> int:
        """统计代码行数"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return len([l for l in f if l.strip() and not l.strip().startswith('#')])
        except:
            return 0
    
    def _extract_imports(self, file_path: Path) -> List[str]:
        """提取import语句"""
        imports = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=str(file_path))
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
        except:
            pass
        
        return imports
    
    def generate_dependency_graph(self) -> str:
        """生成依赖关系图（Mermaid格式）"""
        graph = ["graph TD"]
        
        # 核心模块分组
        groups = {
            'conductor': [],
            'multiprocess': [],
            'core': []
        }
        
        for module in self.modules:
            if 'conductor' in module:
                groups['conductor'].append(module)
            elif 'multiprocess' in module:
                groups['multiprocess'].append(module)
            else:
                groups['core'].append(module)
        
        # 生成节点和边
        node_id = {}
        counter = 0
        
        for group, modules in groups.items():
            if not modules:
                continue
            graph.append(f"    subgraph {group}")
            for module in modules:
                node_id[module] = f"M{counter}"
                counter += 1
                short_name = module.split('.')[-1]
                graph.append(f"        {node_id[module]}[{short_name}]")
            graph.append("    end")
        
        # 生成依赖关系
        for module, deps in self.dependencies.items():
            if module not in node_id:
                continue
            for dep in deps:
                if dep in node_id:
                    graph.append(f"    {node_id[module]} --> {node_id[dep]}")
        
        return "\n".join(graph)


class FunctionFlowAnalyzer:
    """程序功能流程分析器"""
    
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.flows = {}
    
    def analyze(self):
        """分析主要功能流程"""
        print("\n🔄 分析程序功能流程...")
        
        flows = {
            'fuzzing_flow': self._analyze_fuzzing_flow(),
            'worker_flow': self._analyze_worker_flow(),
            'seed_management': self._analyze_seed_management(),
            'coverage_tracking': self._analyze_coverage_tracking(),
        }
        
        self.flows = flows
        return flows
    
    def _analyze_fuzzing_flow(self) -> Dict:
        """分析Fuzzing主流程"""
        return {
            'name': 'Fuzzing主流程',
            'steps': [
                '1. FuzzMaster初始化',
                '2. 创建sync_dir目录结构',
                '3. 初始化高级功能（可选）',
                '4. 生成初始seeds',
                '5. 分发seeds到各worker',
                '6. 启动worker进程',
                '7. 监控和统计',
                '8. 收集结果',
            ],
            'entry': 'fuzzing.multiprocess.fuzz_master.FuzzMaster.start()',
            'modules': ['fuzz_master', 'shared_resources', 'multiprocess_extensions']
        }
    
    def _analyze_worker_flow(self) -> Dict:
        """分析Worker工作流程"""
        return {
            'name': 'Worker工作流程',
            'steps': [
                '1. Worker进程启动',
                '2. 创建FuzzConductor实例',
                '3. 从队列获取seed',
                '4. 加载trace文件',
                '5. 执行QEMU fuzzing',
                '6. 收集覆盖率',
                '7. 保存新seed',
                '8. 更新统计',
                '9. 循环执行',
            ],
            'entry': 'fuzzing.multiprocess.fuzz_master.FuzzMaster._worker_process()',
            'modules': ['fuzz_conductor', 'coverage', 'mutator']
        }
    
    def _analyze_seed_management(self) -> Dict:
        """分析Seed管理流程"""
        return {
            'name': 'Seed管理流程',
            'steps': [
                '1. Seed生成/发现',
                '2. Seed去重',
                '3. 覆盖率计算',
                '4. 能量调度（可选）',
                '5. 优先级排序',
                '6. 队列管理',
                '7. Seed持久化',
            ],
            'modules': ['seed_queue_advanced', 'energy_scheduler', 'corpus_manager']
        }
    
    def _analyze_coverage_tracking(self) -> Dict:
        """分析覆盖率追踪流程"""
        return {
            'name': '覆盖率追踪流程',
            'steps': [
                '1. QEMU记录基本块执行',
                '2. 共享内存更新',
                '3. CoverageTracker统计',
                '4. 新覆盖检测',
                '5. CoverageFeedback分析（可选）',
                '6. 覆盖率同步',
            ],
            'modules': ['coverage', 'shared_resources', 'coverage_feedback']
        }


class ComponentValidator:
    """组件有效性验证器"""
    
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.results = {}
    
    def validate(self):
        """验证所有组件"""
        print("\n✅ 验证各组件有效性...")
        
        validations = {
            'imports': self._validate_imports(),
            'class_definitions': self._validate_classes(),
            'function_signatures': self._validate_functions(),
            'integration': self._validate_integration(),
        }
        
        self.results = validations
        return validations
    
    def _validate_imports(self) -> Dict:
        """验证导入完整性"""
        print("  检查导入...")
        
        key_modules = [
            'fuzzing.fuzz_conductor',
            'fuzzing.conductor',
            'fuzzing.multiprocess.fuzz_master',
            'fuzzing.multiprocess.shared_resources',
        ]
        
        results = {}
        for module in key_modules:
            try:
                # 尝试导入
                spec = importlib.util.find_spec(module)
                results[module] = spec is not None
            except:
                results[module] = False
        
        passed = sum(1 for v in results.values() if v)
        print(f"    ✓ {passed}/{len(results)} 模块可导入")
        
        return {
            'modules': results,
            'passed': passed,
            'total': len(results)
        }
    
    def _validate_classes(self) -> Dict:
        """验证核心类定义"""
        print("  检查类定义...")
        
        key_classes = [
            ('fuzzing.fuzz_conductor', 'FuzzConductor'),
            ('fuzzing.multiprocess.fuzz_master', 'FuzzMaster'),
            ('fuzzing.conductor.mutator', 'SmartMutator'),
            ('fuzzing.conductor.coverage', 'CoverageTracker'),
        ]
        
        results = {}
        for module, class_name in key_classes:
            key = f"{module}.{class_name}"
            try:
                spec = importlib.util.find_spec(module)
                if spec:
                    # 检查文件中是否定义了类
                    with open(spec.origin, 'r') as f:
                        content = f.read()
                    results[key] = f"class {class_name}" in content
                else:
                    results[key] = False
            except:
                results[key] = False
        
        passed = sum(1 for v in results.values() if v)
        print(f"    ✓ {passed}/{len(results)} 核心类存在")
        
        return {
            'classes': results,
            'passed': passed,
            'total': len(results)
        }
    
    def _validate_functions(self) -> Dict:
        """验证关键函数签名"""
        print("  检查函数签名...")
        
        # 简化验证
        return {
            'status': 'skipped',
            'reason': '需要深入AST分析，已跳过'
        }
    
    def _validate_integration(self) -> Dict:
        """验证模块集成"""
        print("  检查模块集成...")
        
        # 检查高级功能是否正确集成到 FuzzMaster
        try:
            fuzz_master_file = self.root_dir / "fuzzing" / "multiprocess" / "fuzz_master.py"
            with open(fuzz_master_file, 'r') as f:
                content = f.read()
            
            checks = {
                'pathfinder': '--pathfinder' in content,
                'corpus_manager': '--corpus-manager' in content,
                'crash_analyzer': '--crash-analyzer' in content,
                'coverage_feedback': '--coverage-feedback' in content,
                'energy_scheduler': '--energy-scheduler' in content,
                'advanced_queue': '--advanced-queue' in content,
            }
            
            passed = sum(1 for v in checks.values() if v)
            print(f"    ✓ {passed}/{len(checks)} 高级功能已集成")
            
            return {
                'features': checks,
                'passed': passed,
                'total': len(checks)
            }
        except:
            return {'error': 'Failed to validate integration'}


def main():
    """主函数"""
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║          RR-Fuzz 综合分析工具                                        ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print()
    
    fuzzing_dir = PROJECT_ROOT / "fuzzing"
    
    # 1. 模块依赖分析
    dep_analyzer = ModuleDependencyAnalyzer(fuzzing_dir)
    modules, dependencies = dep_analyzer.analyze()
    
    # 2. 功能流程分析
    flow_analyzer = FunctionFlowAnalyzer(fuzzing_dir)
    flows = flow_analyzer.analyze()
    
    # 3. 组件验证
    validator = ComponentValidator(PROJECT_ROOT)
    validation = validator.validate()
    
    # 4. 生成报告
    print("\n📄 生成分析报告...")
    
    report = {
        'timestamp': importlib.import_module('datetime').datetime.now().isoformat(),
        'summary': {
            'total_modules': len(modules),
            'total_dependencies': sum(len(v) for v in dependencies.values()),
            'validation_passed': validation['imports']['passed'] + validation['class_definitions']['passed'],
            'validation_total': validation['imports']['total'] + validation['class_definitions']['total'],
        },
        'modules': modules,
        'dependencies': {k: list(v) for k, v in dependencies.items()},
        'flows': flows,
        'validation': validation,
    }
    
    # 保存报告
    output_file = PROJECT_ROOT / "tests" / "comprehensive_analysis_report.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"  ✓ 报告已保存: {output_file}")
    
    # 生成依赖关系图
    graph = dep_analyzer.generate_dependency_graph()
    graph_file = PROJECT_ROOT / "tests" / "module_dependency_graph.mmd"
    with open(graph_file, 'w', encoding='utf-8') as f:
        f.write(graph)
    
    print(f"  ✓ 依赖图已保存: {graph_file}")
    
    # 打印总结
    print("\n" + "="*70)
    print("📊 分析总结")
    print("="*70)
    print(f"模块总数: {report['summary']['total_modules']}")
    print(f"依赖关系: {report['summary']['total_dependencies']}")
    print(f"验证通过: {report['summary']['validation_passed']}/{report['summary']['validation_total']}")
    print("="*70)
    
    # 返回状态码
    if validation['imports']['passed'] == validation['imports']['total']:
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())


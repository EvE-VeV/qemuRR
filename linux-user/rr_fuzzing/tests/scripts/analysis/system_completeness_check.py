#!/usr/bin/env python3
"""
RR-Fuzz 系统完整性检查脚本

功能：
1. 检查所有模块是否可导入
2. 分析模块间依赖关系
3. 识别重复实现
4. 检测功能缺失
5. 验证接口一致性
"""

import sys
import os
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any
import json

# 设置路径
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
FUZZING_DIR = PROJECT_ROOT / "fuzzing"
sys.path.insert(0, str(FUZZING_DIR))

# 颜色输出
class Colors:
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

def print_header(text: str):
    print(f"\n{Colors.CYAN}{'='*70}{Colors.NC}")
    print(f"{Colors.CYAN}{text}{Colors.NC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.NC}\n")

def print_success(text: str):
    print(f"{Colors.GREEN}✅{Colors.NC} {text}")

def print_warning(text: str):
    print(f"{Colors.YELLOW}⚠️{Colors.NC}  {text}")

def print_error(text: str):
    print(f"{Colors.RED}❌{Colors.NC} {text}")

def print_info(text: str):
    print(f"{Colors.BLUE}ℹ️{Colors.NC}  {text}")


class SystemAnalyzer:
    """系统分析器"""
    
    def __init__(self):
        self.modules = {}
        self.import_errors = []
        self.dependencies = {}
        self.functions_map = {}
        self.duplicates = []
        self.missing_features = []
        
    def check_module_imports(self):
        """检查所有模块导入"""
        print_header("📦 模块导入检查")
        
        modules_to_check = [
            # Conductor 模块
            ("conductor.constants", "常量定义"),
            ("conductor.instruction", "Fuzz 指令"),
            ("conductor.bb_trace_parser", "BB Trace 解析器"),
            ("conductor.init_detector", "初始化检测器"),
            ("conductor.coverage", "覆盖率追踪"),
            ("conductor.shared_memory", "共享内存"),
            ("conductor.mutation_strategies", "变异策略"),
            ("conductor.mutator", "智能变异器"),
            
            # Multiprocess 模块
            ("multiprocess.fuzz_master", "多进程协调器"),
            ("multiprocess.path_finder", "路径查找器"),
            ("multiprocess.corpus_manager", "Corpus 管理器"),
            ("multiprocess.crash_analyzer", "崩溃分析器"),
            ("multiprocess.coverage_feedback", "覆盖率反馈"),
            ("multiprocess.energy_scheduler", "能量调度器"),
            ("multiprocess.seed_queue_advanced", "高级种子队列"),
            ("multiprocess.shared_resources", "共享资源"),
            ("multiprocess.syscall_extractor", "系统调用提取器"),
            ("multiprocess.multiprocess_extensions", "多进程扩展"),
            
            # 顶层模块
            ("fuzz_conductor", "Fuzz Conductor"),
            ("trace_analyzer", "Trace 分析器"),
            ("log_analyzer", "日志分析器"),
            ("realtime_tree_visualizer", "实时可视化器"),
        ]
        
        success_count = 0
        for module_name, description in modules_to_check:
            try:
                module = importlib.import_module(module_name)
                self.modules[module_name] = module
                print_success(f"{description:30s} [{module_name}]")
                success_count += 1
            except Exception as e:
                self.import_errors.append((module_name, str(e)))
                print_error(f"{description:30s} [{module_name}] - {e}")
        
        print(f"\n{Colors.BLUE}导入统计:{Colors.NC}")
        print(f"  成功: {success_count}/{len(modules_to_check)}")
        print(f"  失败: {len(self.import_errors)}/{len(modules_to_check)}")
        
        return len(self.import_errors) == 0
    
    def analyze_module_dependencies(self):
        """分析模块依赖关系"""
        print_header("🔗 模块依赖分析")
        
        for module_name, module in self.modules.items():
            imports = []
            
            # 获取模块源文件
            try:
                source_file = inspect.getsourcefile(module)
                if source_file:
                    with open(source_file, 'r') as f:
                        content = f.read()
                        # 简单的 import 解析
                        for line in content.split('\n'):
                            line = line.strip()
                            if line.startswith('from ') or line.startswith('import '):
                                if 'conductor' in line or 'multiprocess' in line:
                                    imports.append(line)
                
                self.dependencies[module_name] = imports
                
                if imports:
                    print(f"\n{Colors.BLUE}{module_name}{Colors.NC}:")
                    for imp in imports[:3]:  # 只显示前3个
                        print(f"  → {imp}")
                    if len(imports) > 3:
                        print(f"  ... (+{len(imports)-3} more)")
            
            except Exception as e:
                print_warning(f"无法分析 {module_name}: {e}")
    
    def check_class_methods(self):
        """检查主要类的方法"""
        print_header("🔍 核心类方法检查")
        
        classes_to_check = [
            ("fuzz_conductor", "FuzzConductor", [
                "start_qemu", "stop_qemu", "run", "cleanup",
                "_generate_instructions", "_send_instructions"
            ]),
            ("conductor.mutator", "SmartMutator", [
                "build_instructions", "_flip_bits_mutation",
                "_extend_mutation", "_mutate_syscall_arg"
            ]),
            ("conductor.bb_trace_parser", "BBTraceParser", [
                "parse", "get_bb_sequence", "get_syscall_sequence"
            ]),
            ("multiprocess.fuzz_master", "FuzzMaster", [
                "start", "_init_sync_dir", "_generate_initial_seeds",
                "_distribute_initial_seeds", "_worker_main"
            ]),
            ("multiprocess.path_finder", "PathFinder", [
                "build_cfg", "map_trace_to_cfg",
                "find_uncovered_branches", "generate_recipes"
            ]),
        ]
        
        for module_name, class_name, expected_methods in classes_to_check:
            if module_name not in self.modules:
                print_error(f"模块 {module_name} 未加载，跳过 {class_name}")
                continue
            
            try:
                cls = getattr(self.modules[module_name], class_name)
                print(f"\n{Colors.GREEN}✓{Colors.NC} {class_name} (from {module_name})")
                
                missing_methods = []
                for method in expected_methods:
                    if hasattr(cls, method):
                        print(f"  ✓ {method}")
                    else:
                        print(f"  ✗ {method} {Colors.RED}(缺失){Colors.NC}")
                        missing_methods.append(method)
                
                if missing_methods:
                    self.missing_features.append({
                        'class': class_name,
                        'missing_methods': missing_methods
                    })
            
            except AttributeError as e:
                print_error(f"类 {class_name} 在 {module_name} 中不存在")
    
    def check_for_duplicates(self):
        """检查重复实现"""
        print_header("🔄 重复实现检查")
        
        # 收集所有函数和方法
        function_signatures = {}
        
        for module_name, module in self.modules.items():
            for name in dir(module):
                if name.startswith('_'):
                    continue
                
                obj = getattr(module, name)
                
                # 检查函数
                if inspect.isfunction(obj):
                    sig_key = f"func_{name}"
                    if sig_key in function_signatures:
                        function_signatures[sig_key].append(module_name)
                    else:
                        function_signatures[sig_key] = [module_name]
                
                # 检查类
                elif inspect.isclass(obj):
                    sig_key = f"class_{name}"
                    if sig_key in function_signatures:
                        function_signatures[sig_key].append(module_name)
                    else:
                        function_signatures[sig_key] = [module_name]
        
        # 找出重复
        duplicates_found = False
        for sig_key, locations in function_signatures.items():
            if len(locations) > 1:
                duplicates_found = True
                kind, name = sig_key.split('_', 1)
                print_warning(f"{kind.capitalize()} '{name}' 出现在多个位置:")
                for loc in locations:
                    print(f"    → {loc}")
                self.duplicates.append({
                    'name': name,
                    'type': kind,
                    'locations': locations
                })
        
        if not duplicates_found:
            print_success("未发现明显的重复实现")
    
    def check_multiprocess_features(self):
        """检查多进程高级功能是否被使用"""
        print_header("🚀 多进程高级功能使用情况")
        
        # 检查 FuzzMaster 是否使用高级模块
        if "multiprocess.fuzz_master" in self.modules:
            master_module = self.modules["multiprocess.fuzz_master"]
            source_file = inspect.getsourcefile(master_module)
            
            if source_file:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                advanced_features = [
                    ("CorpusManager", "corpus_manager", "Corpus 持久化"),
                    ("CrashAnalyzer", "crash_analyzer", "崩溃分析"),
                    ("CoverageFeedback", "coverage_feedback", "覆盖率反馈"),
                    ("EnergyScheduler", "energy_scheduler", "能量调度"),
                    ("SeedQueueAdvanced", "seed_queue_advanced", "高级队列"),
                    ("PathFinder", "path_finder", "CFG 分析"),
                ]
                
                print("FuzzMaster 使用的高级功能:")
                for class_name, module_name, description in advanced_features:
                    if class_name in content or module_name in content:
                        print_success(f"{description:20s} [{class_name}]")
                    else:
                        print_warning(f"{description:20s} [{class_name}] - 未使用")
    
    def generate_report(self):
        """生成分析报告"""
        print_header("📊 分析报告总结")
        
        import time
        report = {
            "modules_loaded": len(self.modules),
            "import_errors": len(self.import_errors),
            "duplicates": len(self.duplicates),
            "missing_features": len(self.missing_features),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        print(f"{Colors.BLUE}模块加载:{Colors.NC}")
        print(f"  成功加载: {report['modules_loaded']}")
        print(f"  导入错误: {report['import_errors']}")
        
        if self.import_errors:
            print(f"\n{Colors.RED}导入错误详情:{Colors.NC}")
            for module, error in self.import_errors:
                print(f"  • {module}: {error}")
        
        print(f"\n{Colors.BLUE}代码质量:{Colors.NC}")
        print(f"  重复实现: {report['duplicates']}")
        print(f"  功能缺失: {report['missing_features']}")
        
        if self.duplicates:
            print(f"\n{Colors.YELLOW}重复实现详情:{Colors.NC}")
            for dup in self.duplicates:
                print(f"  • {dup['type']} '{dup['name']}' 在 {len(dup['locations'])} 个位置")
        
        if self.missing_features:
            print(f"\n{Colors.RED}功能缺失详情:{Colors.NC}")
            for missing in self.missing_features:
                print(f"  • {missing['class']}: {', '.join(missing['missing_methods'])}")
        
        # 保存报告
        report_file = PROJECT_ROOT / "tests" / "system_analysis_report.json"
        with open(report_file, 'w') as f:
            json.dump({
                **report,
                'import_errors_detail': self.import_errors,
                'duplicates_detail': self.duplicates,
                'missing_features_detail': self.missing_features
            }, f, indent=2)
        
        print(f"\n{Colors.GREEN}完整报告已保存:{Colors.NC} {report_file}")
        
        # 总体评估
        print(f"\n{Colors.CYAN}{'='*70}{Colors.NC}")
        if report['import_errors'] == 0 and report['missing_features'] == 0:
            print(f"{Colors.GREEN}✅ 系统完整性检查通过！{Colors.NC}")
            return 0
        else:
            print(f"{Colors.RED}❌ 发现 {report['import_errors']} 个导入错误, "
                  f"{report['missing_features']} 个功能缺失{Colors.NC}")
            return 1


def main():
    """主函数"""
    print(f"\n{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.CYAN}║  RR-Fuzz 系统完整性深度分析                              ║{Colors.NC}")
    print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════════╝{Colors.NC}")
    
    analyzer = SystemAnalyzer()
    
    # 执行各项检查
    analyzer.check_module_imports()
    analyzer.analyze_module_dependencies()
    analyzer.check_class_methods()
    analyzer.check_for_duplicates()
    analyzer.check_multiprocess_features()
    
    # 生成报告
    exit_code = analyzer.generate_report()
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())


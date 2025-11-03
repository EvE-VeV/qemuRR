#!/usr/bin/env python3
"""
系统健康检查工具
执行全面的代码分析，生成详细报告
"""

import os
import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent
FUZZING_DIR = PROJECT_ROOT / "fuzzing"
TESTS_DIR = PROJECT_ROOT / "tests"


class SystemHealthChecker:
    """系统健康检查器"""
    
    def __init__(self):
        self.results = {
            "advanced_features_usage": {},
            "code_duplication": {},
            "test_coverage": {},
            "fuzz_conductor_analysis": {},
            "worker_crash_handling": {},
            "monitoring_status": {},
            "config_parameters": {},
            "todos_and_fixmes": {},
            "risk_assessment": {}
        }
    
    def check_advanced_features_usage(self):
        """检查高级功能的实际使用情况"""
        print("=== 检查高级功能使用情况 ===\n")
        
        features = {
            "PathFinder": "pathfinder",
            "CorpusManager": "corpus_manager",
            "CrashAnalyzer": "crash_analyzer",
            "CoverageFeedback": "coverage_feedback",
            "EnergyScheduler": "energy_scheduler",
            "AdvancedQueue": "advanced_queue"
        }
        
        master_file = FUZZING_DIR / "multiprocess" / "fuzz_master.py"
        content = master_file.read_text()
        
        for class_name, attr_name in features.items():
            print(f"检查 {class_name} ({attr_name}):")
            
            # 检查初始化
            init_pattern = rf"self\.{attr_name}\s*=\s*{class_name}\("
            init_count = len(re.findall(init_pattern, content))
            
            # 检查使用（除初始化外的调用）
            usage_pattern = rf"self\.{attr_name}\."
            all_matches = re.findall(usage_pattern, content)
            
            # 排除初始化行
            lines = content.split('\n')
            usage_lines = []
            for i, line in enumerate(lines, 1):
                if f"self.{attr_name}." in line and f"self.{attr_name} =" not in line:
                    usage_lines.append((i, line.strip()))
            
            self.results["advanced_features_usage"][class_name] = {
                "initialized": init_count > 0,
                "usage_count": len(usage_lines),
                "usage_lines": usage_lines,
                "status": "ACTIVE" if len(usage_lines) > 0 else "ZOMBIE"
            }
            
            print(f"  初始化: {'✓' if init_count > 0 else '✗'}")
            print(f"  实际使用次数: {len(usage_lines)}")
            print(f"  状态: {'🟢 ACTIVE' if len(usage_lines) > 0 else '🔴 ZOMBIE (初始化但未使用)'}")
            
            if usage_lines:
                print(f"  使用位置:")
                for line_num, line_content in usage_lines[:3]:  # 只显示前3个
                    print(f"    L{line_num}: {line_content[:80]}")
            print()
    
    def analyze_code_duplication(self):
        """分析代码重复"""
        print("=== 分析代码重复 ===\n")
        
        master_file = FUZZING_DIR / "multiprocess" / "fuzz_master.py"
        fixed_file = FUZZING_DIR / "multiprocess" / "fuzz_master_fixed.py"
        
        master_lines = master_file.read_text().split('\n')
        fixed_lines = fixed_file.read_text().split('\n')
        
        # 计算相似度
        master_set = set(line.strip() for line in master_lines if line.strip())
        fixed_set = set(line.strip() for line in fixed_lines if line.strip())
        
        common_lines = master_set & fixed_set
        similarity = len(common_lines) / max(len(master_set), len(fixed_set)) * 100
        
        print(f"fuzz_master.py: {len(master_lines)} 行")
        print(f"fuzz_master_fixed.py: {len(fixed_lines)} 行")
        print(f"相似度: {similarity:.1f}%")
        print(f"共同行数: {len(common_lines)}")
        print(f"仅在 fuzz_master.py 中: {len(master_set - fixed_set)} 行")
        print(f"仅在 fuzz_master_fixed.py 中: {len(fixed_set - master_set)} 行")
        
        self.results["code_duplication"] = {
            "master_lines": len(master_lines),
            "fixed_lines": len(fixed_lines),
            "similarity_percent": round(similarity, 1),
            "common_lines": len(common_lines),
            "master_only": len(master_set - fixed_set),
            "fixed_only": len(fixed_set - master_set),
            "recommendation": "DELETE fuzz_master_fixed.py" if similarity > 90 else "KEEP BOTH"
        }
        print(f"\n建议: {self.results['code_duplication']['recommendation']}\n")
    
    def analyze_test_coverage(self):
        """分析测试覆盖"""
        print("=== 分析测试覆盖 ===\n")
        
        test_scripts = list(TESTS_DIR.glob("scripts/**/*.sh"))
        print(f"总测试脚本数: {len(test_scripts)}")
        
        references = {
            "fuzz_master.py": [],
            "fuzz_master_fixed.py": [],
            "fuzz_conductor.py": [],
            "realtime_tree_visualizer.py": []
        }
        
        for script in test_scripts:
            content = script.read_text()
            for module in references.keys():
                if module in content or module.replace('.py', '') in content:
                    references[module].append(script.name)
        
        for module, scripts in references.items():
            print(f"\n{module}:")
            print(f"  被 {len(scripts)} 个测试引用")
            if scripts:
                for s in scripts[:5]:  # 只显示前5个
                    print(f"    - {s}")
        
        self.results["test_coverage"] = {
            "total_scripts": len(test_scripts),
            "references": {k: len(v) for k, v in references.items()},
            "detailed_references": references
        }
        print()
    
    def analyze_fuzz_conductor(self):
        """分析 fuzz_conductor 完整性"""
        print("=== 分析 fuzz_conductor 完整性 ===\n")
        
        conductor_file = FUZZING_DIR / "fuzz_conductor.py"
        content = conductor_file.read_text()
        
        # 提取公共方法
        methods = re.findall(r'def ([a-z_]+)\(self', content)
        public_methods = [m for m in methods if not m.startswith('_')]
        private_methods = [m for m in methods if m.startswith('_')]
        
        # 查找 TODO
        todos = []
        for i, line in enumerate(content.split('\n'), 1):
            if 'TODO' in line or 'FIXME' in line or 'XXX' in line:
                todos.append((i, line.strip()))
        
        print(f"总行数: {len(content.split(chr(10)))}")
        print(f"公共方法: {len(public_methods)}")
        print(f"  {', '.join(public_methods)}")
        print(f"私有方法: {len(private_methods)}")
        print(f"未完成 TODO: {len(todos)}")
        
        if todos:
            print("\nTODO 列表:")
            for line_num, line_content in todos[:5]:
                print(f"  L{line_num}: {line_content[:80]}")
        
        self.results["fuzz_conductor_analysis"] = {
            "total_lines": len(content.split('\n')),
            "public_methods": public_methods,
            "private_methods": private_methods,
            "todo_count": len(todos),
            "todos": todos
        }
        print()
    
    def analyze_worker_crash_handling(self):
        """分析 Worker 崩溃处理机制"""
        print("=== 分析 Worker 崩溃处理 ===\n")
        
        master_file = FUZZING_DIR / "multiprocess" / "fuzz_master.py"
        content = master_file.read_text()
        
        # 检查关键方法
        has_check_alive = "_check_workers_alive" in content
        has_restart = "restart" in content.lower() and "worker" in content.lower()
        has_recovery = "recover" in content.lower()
        
        # 提取 _check_workers_alive 实现
        check_alive_impl = ""
        in_method = False
        for line in content.split('\n'):
            if 'def _check_workers_alive' in line:
                in_method = True
            if in_method:
                check_alive_impl += line + '\n'
                if line.strip() and not line.startswith(' ') and 'def _check_workers_alive' not in line:
                    break
        
        print(f"检测worker存活: {'✓' if has_check_alive else '✗'}")
        print(f"自动重启机制: {'✓' if has_restart else '✗'}")
        print(f"状态恢复: {'✓' if has_recovery else '✗'}")
        
        if check_alive_impl:
            print("\n当前实现:")
            print("```python")
            print(check_alive_impl.strip())
            print("```")
        
        # 检查死亡后的处理
        dead_worker_handling = "Some workers have died" in content
        print(f"\nWorker死亡后的处理: {'检测到但停止fuzzing' if dead_worker_handling else '无处理'}")
        
        self.results["worker_crash_handling"] = {
            "has_detection": has_check_alive,
            "has_restart": has_restart,
            "has_recovery": has_recovery,
            "current_behavior": "STOP_ALL" if dead_worker_handling else "UNKNOWN",
            "recommendation": "需要添加自动重启机制"
        }
        print()
    
    def analyze_monitoring_status(self):
        """分析监控状态"""
        print("=== 分析监控状态 ===\n")
        
        master_file = FUZZING_DIR / "multiprocess" / "fuzz_master.py"
        content = master_file.read_text()
        
        # 提取 _display_status_from_shared 方法
        display_method = ""
        in_method = False
        indent_level = 0
        for line in content.split('\n'):
            if 'def _display_status_from_shared' in line:
                in_method = True
                indent_level = len(line) - len(line.lstrip())
            if in_method:
                current_indent = len(line) - len(line.lstrip())
                if line.strip() and current_indent <= indent_level and 'def _display_status_from_shared' not in line:
                    break
                display_method += line + '\n'
        
        # 分析显示的指标
        metrics = []
        if 'execs' in display_method.lower():
            metrics.append("执行次数 (execs)")
        if 'crashes' in display_method.lower():
            metrics.append("崩溃数 (crashes)")
        if 'seeds' in display_method.lower():
            metrics.append("种子数 (seeds)")
        if 'coverage' in display_method.lower():
            metrics.append("覆盖率 (coverage)")
        if 'runtime' in display_method.lower():
            metrics.append("运行时间 (runtime)")
        if 'speed' in display_method.lower() or 'exec/s' in display_method.lower():
            metrics.append("执行速度 (exec/s)")
        
        # 检查更新频率
        update_interval = re.search(r'update_interval\s*=\s*(\d+)', content)
        interval = int(update_interval.group(1)) if update_interval else "未知"
        
        print(f"当前显示的指标 ({len(metrics)}):")
        for m in metrics:
            print(f"  ✓ {m}")
        
        print(f"\n更新频率: {interval} 秒")
        
        # 缺失的指标
        missing = []
        if "覆盖率增长趋势" not in metrics:
            missing.append("覆盖率增长趋势")
        if "内存使用" not in metrics:
            missing.append("内存使用")
        if "CPU使用率" not in metrics:
            missing.append("CPU使用率")
        if "ETA" not in metrics:
            missing.append("预计完成时间 (ETA)")
        
        if missing:
            print(f"\n缺失的指标 ({len(missing)}):")
            for m in missing:
                print(f"  ✗ {m}")
        
        self.results["monitoring_status"] = {
            "current_metrics": metrics,
            "update_interval": interval,
            "missing_metrics": missing,
            "recommendation": "改进现有显示" if len(metrics) >= 4 else "需要完整监控系统"
        }
        print()
    
    def analyze_config_parameters(self):
        """分析配置参数"""
        print("=== 分析配置参数 ===\n")
        
        master_file = FUZZING_DIR / "multiprocess" / "fuzz_master.py"
        content = master_file.read_text()
        
        # 提取 __init__ 参数
        init_match = re.search(r'def __init__\(.*?\):', content, re.DOTALL)
        if init_match:
            init_content = init_match.group(0)
            params = re.findall(r'(\w+):\s*\w+.*?=.*?[,)]', init_content, re.DOTALL)
            
            print(f"总参数数: {len(params)}")
            print("\n必需参数:")
            for p in ['program_path', 'qemu_path', 'trace_file']:
                if p in init_content:
                    print(f"  - {p}")
            
            print("\n可选参数:")
            optional_params = []
            for match in re.finditer(r'(\w+):\s*\w+\s*=\s*([^,\n]+)', init_content):
                param_name = match.group(1)
                default_value = match.group(2).strip()
                if param_name not in ['self', 'program_path', 'qemu_path', 'trace_file']:
                    optional_params.append((param_name, default_value))
                    print(f"  - {param_name} (默认: {default_value})")
            
            print(f"\n总计: {len(optional_params)} 个可选参数")
        
        # 提取命令行参数
        argparse_matches = re.findall(r'parser\.add_argument\([\'"]([^\'\"]+)', content)
        print(f"\n命令行参数数: {len(argparse_matches)}")
        
        # 分类
        required_args = [a for a in argparse_matches if 'required=True' in content.split(a)[1].split('\n')[0]]
        optional_args = [a for a in argparse_matches if a not in required_args]
        
        print(f"  必需: {len(required_args)}")
        print(f"  可选: {len(optional_args)}")
        
        self.results["config_parameters"] = {
            "total_params": len(optional_params) if init_match else 0,
            "cli_args": len(argparse_matches),
            "required_args": required_args,
            "optional_args": optional_args,
            "complexity": "HIGH" if len(argparse_matches) > 15 else "MEDIUM" if len(argparse_matches) > 10 else "LOW",
            "recommendation": "需要配置文件" if len(argparse_matches) > 15 else "参数文档即可"
        }
        print()
    
    def generate_report(self):
        """生成最终报告"""
        print("\n" + "="*70)
        print("生成报告...")
        print("="*70 + "\n")
        
        # 执行所有检查
        self.check_advanced_features_usage()
        self.analyze_code_duplication()
        self.analyze_test_coverage()
        self.analyze_fuzz_conductor()
        self.analyze_worker_crash_handling()
        self.analyze_monitoring_status()
        self.analyze_config_parameters()
        
        # 保存 JSON 报告
        output_file = PROJECT_ROOT / "SYSTEM_HEALTH_REPORT.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"✓ JSON 报告已保存: {output_file}")
        
        return self.results


def main():
    """主函数"""
    print("\n" + "="*70)
    print("RR-Fuzz 系统健康检查")
    print("="*70 + "\n")
    
    checker = SystemHealthChecker()
    results = checker.generate_report()
    
    print("\n" + "="*70)
    print("检查完成！")
    print("="*70)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())


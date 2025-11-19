#!/usr/bin/env python3
"""
Stats Consistency Checker

自动验证final_stats.json中的数据一致性，检测"Multiple Sources of Truth"问题。

用法:
    python3 check_stats_consistency.py <stats_file>
    python3 check_stats_consistency.py fuzzing_output/final_stats.json
"""

import sys
import json
from pathlib import Path


class StatsConsistencyChecker:
    """Stats一致性检查器"""

    def __init__(self, stats_file):
        self.stats_file = Path(stats_file)
        self.data = None
        self.errors = []
        self.warnings = []

    def load_stats(self):
        """加载stats文件"""
        try:
            with open(self.stats_file, 'r') as f:
                self.data = json.load(f)
            return True
        except FileNotFoundError:
            print(f"❌ Error: Stats file not found: {self.stats_file}")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ Error: Invalid JSON: {e}")
            return False

    def check_execution_counters(self):
        """检查执行计数器一致性"""
        execution = self.data.get('execution', {})
        executor = self.data.get('executor', {})

        total_execs = execution.get('total_execs', None)
        total_executions = executor.get('total_executions', None)

        if total_execs is None or total_executions is None:
            self.errors.append("Missing execution counters")
            return False

        # 允许一定的差异 (因为DynamicFork会增加额外的执行)
        # 但total_execs应该 >= total_executions
        if total_execs < total_executions:
            self.errors.append(
                f"❌ Execution counter inconsistency: "
                f"execution.total_execs ({total_execs}) < "
                f"executor.total_executions ({total_executions})"
            )
            return False

        # 如果差异过大，发出警告
        diff = total_execs - total_executions
        if diff > total_executions * 0.5:  # 超过50%差异
            self.warnings.append(
                f"⚠️  Large difference between counters: "
                f"total_execs={total_execs}, total_executions={total_executions}, diff={diff}"
            )

        return True

    def check_crash_counts(self):
        """检查crash计数一致性"""
        execution = self.data.get('execution', {})
        executor = self.data.get('executor', {})

        crashes_found = execution.get('crashes_found', 0)
        total_crashes = executor.get('total_crashes', 0)

        # Crashes应该一致
        if crashes_found != total_crashes:
            self.warnings.append(
                f"⚠️  Crash count mismatch: "
                f"execution.crashes_found ({crashes_found}) != "
                f"executor.total_crashes ({total_crashes})"
            )
            return False

        return True

    def check_timeout_counts(self):
        """检查超时计数一致性"""
        execution = self.data.get('execution', {})
        executor = self.data.get('executor', {})

        timeouts = execution.get('timeouts', 0)
        total_timeouts = executor.get('total_timeouts', 0)

        # Timeouts应该一致
        if timeouts != total_timeouts:
            self.warnings.append(
                f"⚠️  Timeout count mismatch: "
                f"execution.timeouts ({timeouts}) != "
                f"executor.total_timeouts ({total_timeouts})"
            )
            return False

        return True

    def check_coverage_consistency(self):
        """检查覆盖率数据一致性"""
        coverage = self.data.get('coverage', {})

        total_edges = coverage.get('total_edges', 0)
        new_edges = coverage.get('new_edges_this_run', 0)

        # new_edges应该 <= total_edges
        if new_edges > total_edges:
            self.errors.append(
                f"❌ Coverage inconsistency: "
                f"new_edges_this_run ({new_edges}) > total_edges ({total_edges})"
            )
            return False

        return True

    def check_rates(self):
        """检查各种比率的合理性"""
        executor = self.data.get('executor', {})

        crash_rate = executor.get('crash_rate', 0)
        timeout_rate = executor.get('timeout_rate', 0)

        # 比率应该在0-1之间
        if not (0 <= crash_rate <= 1):
            self.errors.append(f"❌ Invalid crash_rate: {crash_rate}")
            return False

        if not (0 <= timeout_rate <= 1):
            self.errors.append(f"❌ Invalid timeout_rate: {timeout_rate}")
            return False

        return True

    def run_checks(self):
        """运行所有检查"""
        if not self.load_stats():
            return False

        print(f"\n{'='*60}")
        print(f"Stats Consistency Check: {self.stats_file}")
        print(f"{'='*60}\n")

        checks = [
            ("Execution Counters", self.check_execution_counters),
            ("Crash Counts", self.check_crash_counts),
            ("Timeout Counts", self.check_timeout_counts),
            ("Coverage Data", self.check_coverage_consistency),
            ("Rates Validation", self.check_rates),
        ]

        passed = 0
        failed = 0

        for name, check_func in checks:
            try:
                result = check_func()
                if result:
                    print(f"✅ {name}: PASS")
                    passed += 1
                else:
                    print(f"⚠️  {name}: WARNING")
                    failed += 1
            except Exception as e:
                print(f"❌ {name}: ERROR - {e}")
                failed += 1

        print(f"\n{'='*60}")
        print(f"Summary: {passed} passed, {failed} failed/warning")
        print(f"{'='*60}\n")

        # 显示详细错误和警告
        if self.errors:
            print("❌ Errors:")
            for error in self.errors:
                print(f"  {error}")
            print()

        if self.warnings:
            print("⚠️  Warnings:")
            for warning in self.warnings:
                print(f"  {warning}")
            print()

        # 显示关键统计信息
        execution = self.data.get('execution', {})
        print(f"📊 Key Statistics:")
        print(f"  total_execs: {execution.get('total_execs', 'N/A')}")
        print(f"  execs_per_sec: {execution.get('execs_per_sec', 'N/A'):.2f}")
        print(f"  crashes_found: {execution.get('crashes_found', 'N/A')}")
        print(f"  paths_found: {execution.get('paths_found', 'N/A')}")
        print(f"  timeouts: {execution.get('timeouts', 'N/A')}")
        print()

        # 返回True如果没有错误
        return len(self.errors) == 0


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 check_stats_consistency.py <stats_file>")
        print("Example: python3 check_stats_consistency.py fuzzing_output/final_stats.json")
        sys.exit(1)

    stats_file = sys.argv[1]
    checker = StatsConsistencyChecker(stats_file)

    if checker.run_checks():
        print("✅ All checks passed! Stats are consistent.")
        sys.exit(0)
    else:
        print("❌ Some checks failed. Please review the errors above.")
        sys.exit(1)


if __name__ == "__main__":
    main()

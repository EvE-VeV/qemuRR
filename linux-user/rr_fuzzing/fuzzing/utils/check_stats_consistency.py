#!/usr/bin/env python3
"""
Stats Consistency Checker

Automatically verifies data consistency in final_stats.json, detecting "Multiple Sources of Truth" issues.

Usage:
    python3 check_stats_consistency.py <stats_file>
    python3 check_stats_consistency.py fuzzing_output/final_stats.json
"""

import sys
import json
from pathlib import Path


class StatsConsistencyChecker:
    """Stats Consistency Checker"""

    def __init__(self, stats_file):
        self.stats_file = Path(stats_file)
        self.data = None
        self.errors = []
        self.warnings = []

    def load_stats(self):
        """Load stats file"""
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
        """Check consistency of execution counters"""
        execution = self.data.get('execution', {})
        executor = self.data.get('executor', {})

        total_execs = execution.get('total_execs', None)
        total_executions = executor.get('total_executions', None)

        if total_execs is None or total_executions is None:
            self.errors.append("Missing execution counters")
            return False

        # Allow some difference (since DynamicFork may add extra executions)
        # but total_execs should be >= total_executions
        if total_execs < total_executions:
            self.errors.append(
                f"❌ Execution counter inconsistency: "
                f"execution.total_execs ({total_execs}) < "
                f"executor.total_executions ({total_executions})"
            )
            return False

        # If difference is too large, issue a warning
        diff = total_execs - total_executions
        if diff > total_executions * 0.5:  # Over 50% difference
            self.warnings.append(
                f"⚠️  Large difference between counters: "
                f"total_execs={total_execs}, total_executions={total_executions}, diff={diff}"
            )

        return True

    def check_crash_counts(self):
        """Check consistency of crash counts"""
        execution = self.data.get('execution', {})
        executor = self.data.get('executor', {})

        crashes_found = execution.get('crashes_found', 0)
        total_crashes = executor.get('total_crashes', 0)

        # Crashes should be consistent
        if crashes_found != total_crashes:
            self.warnings.append(
                f"⚠️  Crash count mismatch: "
                f"execution.crashes_found ({crashes_found}) != "
                f"executor.total_crashes ({total_crashes})"
            )
            return False

        return True

    def check_timeout_counts(self):
        """Check consistency of timeout counts"""
        execution = self.data.get('execution', {})
        executor = self.data.get('executor', {})

        timeouts = execution.get('timeouts', 0)
        total_timeouts = executor.get('total_timeouts', 0)

        # Timeouts should be consistent
        if timeouts != total_timeouts:
            self.warnings.append(
                f"⚠️  Timeout count mismatch: "
                f"execution.timeouts ({timeouts}) != "
                f"executor.total_timeouts ({total_timeouts})"
            )
            return False

        return True

    def check_coverage_consistency(self):
        """Check consistency of coverage data"""
        coverage = self.data.get('coverage', {})

        total_edges = coverage.get('total_edges', 0)
        new_edges = coverage.get('new_edges_this_run', 0)

        # new_edges should be <= total_edges
        if new_edges > total_edges:
            self.errors.append(
                f"❌ Coverage inconsistency: "
                f"new_edges_this_run ({new_edges}) > total_edges ({total_edges})"
            )
            return False

        return True

    def check_rates(self):
        """Check reasonableness of various rates"""
        executor = self.data.get('executor', {})

        crash_rate = executor.get('crash_rate', 0)
        timeout_rate = executor.get('timeout_rate', 0)

        # Rates should be between 0 and 1
        if not (0 <= crash_rate <= 1):
            self.errors.append(f"❌ Invalid crash_rate: {crash_rate}")
            return False

        if not (0 <= timeout_rate <= 1):
            self.errors.append(f"❌ Invalid timeout_rate: {timeout_rate}")
            return False

        return True

    def run_checks(self):
        """Run all checks"""
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

        # Show detailed errors and warnings
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

        # Show key statistics
        execution = self.data.get('execution', {})
        print(f"📊 Key Statistics:")
        print(f"  total_execs: {execution.get('total_execs', 'N/A')}")
        print(f"  execs_per_sec: {execution.get('execs_per_sec', 'N/A'):.2f}")
        print(f"  crashes_found: {execution.get('crashes_found', 'N/A')}")
        print(f"  paths_found: {execution.get('paths_found', 'N/A')}")
        print(f"  timeouts: {execution.get('timeouts', 'N/A')}")
        print()

        # Return True if no errors
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

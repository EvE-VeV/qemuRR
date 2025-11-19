#!/usr/bin/env python3
"""
IterationResult - 显式的迭代结果返回值

目的：消除静默失败，提供明确的成功/失败状态和错误信息
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum


class IterationStatus(Enum):
    """迭代状态枚举"""
    SUCCESS = "success"                 # 成功完成
    FAILURE = "failure"                 # 失败（通用）

    # 具体失败类型
    NO_TRACE = "no_trace"              # 无可用trace
    NO_MUTATIONS = "no_mutations"       # 无法生成mutations
    EXECUTION_FAILED = "exec_failed"    # 执行失败
    EXECUTION_TIMEOUT = "exec_timeout"  # 执行超时
    EXECUTION_CRASH = "exec_crash"      # 执行崩溃
    CFG_ANALYSIS_FAILED = "cfg_failed"  # CFG分析失败
    FORK_FAILED = "fork_failed"         # Fork失败

    # 部分成功
    PARTIAL_SUCCESS = "partial_success" # 部分执行成功


@dataclass
class IterationResult:
    """
    单次迭代的结果

    提供明确的成功/失败状态，消除静默失败问题
    """

    # 基本状态
    status: IterationStatus
    iteration_id: int

    # 成功指标
    new_coverage: bool = False
    new_paths: int = 0
    crashes_found: int = 0

    # 执行统计
    execs_performed: int = 0
    mutations_applied: int = 0

    # 失败信息
    error_message: Optional[str] = None
    error_component: Optional[str] = None
    error_details: Dict[str, Any] = field(default_factory=dict)

    # 额外上下文
    trace_id: Optional[str] = None
    fork_point: Optional[int] = None
    recipe_used: Optional[int] = None

    def is_success(self) -> bool:
        """是否成功"""
        return self.status == IterationStatus.SUCCESS or self.status == IterationStatus.PARTIAL_SUCCESS

    def is_failure(self) -> bool:
        """是否失败"""
        return not self.is_success()

    def has_new_coverage(self) -> bool:
        """是否发现新覆盖"""
        return self.new_coverage

    def has_crashes(self) -> bool:
        """是否发现crash"""
        return self.crashes_found > 0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于日志/序列化）"""
        return {
            'status': self.status.value,
            'iteration_id': self.iteration_id,
            'new_coverage': self.new_coverage,
            'new_paths': self.new_paths,
            'crashes_found': self.crashes_found,
            'execs_performed': self.execs_performed,
            'mutations_applied': self.mutations_applied,
            'error_message': self.error_message,
            'error_component': self.error_component,
            'trace_id': self.trace_id,
            'fork_point': self.fork_point,
            'recipe_used': self.recipe_used,
        }

    def __str__(self) -> str:
        """友好的字符串表示"""
        if self.is_success():
            parts = [f"Iteration {self.iteration_id}: ✅ {self.status.value}"]
            if self.new_coverage:
                parts.append(f"(+{self.new_paths} paths)")
            if self.crashes_found > 0:
                parts.append(f"(💥 {self.crashes_found} crashes)")
            return " ".join(parts)
        else:
            return (f"Iteration {self.iteration_id}: ❌ {self.status.value} - "
                   f"{self.error_component}: {self.error_message}")


@dataclass
class BatchIterationResult:
    """
    批量迭代的汇总结果

    用于multi-fork等批量执行场景
    """

    total_iterations: int
    successful: int
    failed: int

    # 汇总指标
    total_new_coverage: bool
    total_new_paths: int
    total_crashes: int
    total_execs: int

    # 详细结果
    results: List[IterationResult] = field(default_factory=list)

    # 失败汇总
    failure_breakdown: Dict[IterationStatus, int] = field(default_factory=dict)

    def success_rate(self) -> float:
        """成功率"""
        if self.total_iterations == 0:
            return 0.0
        return self.successful / self.total_iterations

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'total_iterations': self.total_iterations,
            'successful': self.successful,
            'failed': self.failed,
            'success_rate': self.success_rate(),
            'total_new_coverage': self.total_new_coverage,
            'total_new_paths': self.total_new_paths,
            'total_crashes': self.total_crashes,
            'total_execs': self.total_execs,
            'failure_breakdown': {
                status.value: count
                for status, count in self.failure_breakdown.items()
            },
        }

    def __str__(self) -> str:
        """友好的字符串表示"""
        return (f"Batch: {self.successful}/{self.total_iterations} success "
               f"({self.success_rate()*100:.1f}%), "
               f"+{self.total_new_paths} paths, "
               f"{self.total_crashes} crashes")


def create_success_result(
    iteration_id: int,
    new_coverage: bool = False,
    new_paths: int = 0,
    crashes_found: int = 0,
    execs_performed: int = 1,
    mutations_applied: int = 1,
    trace_id: Optional[str] = None,
    fork_point: Optional[int] = None,
    recipe_used: Optional[int] = None
) -> IterationResult:
    """创建成功结果的便捷函数"""
    return IterationResult(
        status=IterationStatus.SUCCESS,
        iteration_id=iteration_id,
        new_coverage=new_coverage,
        new_paths=new_paths,
        crashes_found=crashes_found,
        execs_performed=execs_performed,
        mutations_applied=mutations_applied,
        trace_id=trace_id,
        fork_point=fork_point,
        recipe_used=recipe_used,
    )


def create_failure_result(
    iteration_id: int,
    status: IterationStatus,
    error_message: str,
    error_component: str,
    error_details: Optional[Dict[str, Any]] = None,
    trace_id: Optional[str] = None
) -> IterationResult:
    """创建失败结果的便捷函数"""
    return IterationResult(
        status=status,
        iteration_id=iteration_id,
        error_message=error_message,
        error_component=error_component,
        error_details=error_details or {},
        trace_id=trace_id,
    )


def aggregate_results(results: List[IterationResult]) -> BatchIterationResult:
    """
    汇总多个迭代结果

    Args:
        results: 迭代结果列表

    Returns:
        批量汇总结果
    """
    total = len(results)
    successful = sum(1 for r in results if r.is_success())
    failed = total - successful

    # 汇总指标
    total_new_coverage = any(r.new_coverage for r in results)
    total_new_paths = sum(r.new_paths for r in results)
    total_crashes = sum(r.crashes_found for r in results)
    total_execs = sum(r.execs_performed for r in results)

    # 失败分类
    failure_breakdown = {}
    for r in results:
        if r.is_failure():
            if r.status not in failure_breakdown:
                failure_breakdown[r.status] = 0
            failure_breakdown[r.status] += 1

    return BatchIterationResult(
        total_iterations=total,
        successful=successful,
        failed=failed,
        total_new_coverage=total_new_coverage,
        total_new_paths=total_new_paths,
        total_crashes=total_crashes,
        total_execs=total_execs,
        results=results,
        failure_breakdown=failure_breakdown,
    )

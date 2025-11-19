#!/usr/bin/env python3
"""
FuzzingMetrics - 统一的fuzzing指标和失败追踪

目的：消除静默失败，统一追踪所有错误和失败原因
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import time


class FailureReason(Enum):
    """失败原因分类"""
    # 执行失败
    EXEC_TIMEOUT = "execution_timeout"
    EXEC_CRASH = "execution_crash"
    EXEC_SIGNAL = "execution_signal"
    EXEC_INVALID_STATE = "invalid_state"

    # Mutation失败
    MUTATION_NO_CANDIDATES = "no_mutation_candidates"
    MUTATION_GENERATION_FAILED = "mutation_generation_failed"
    MUTATION_INVALID_INDEX = "invalid_syscall_index"

    # Replay失败
    REPLAY_MISMATCH = "replay_mismatch"
    REPLAY_DIVERGENCE = "replay_divergence"
    REPLAY_TIMEOUT = "replay_timeout"

    # Fork失败
    FORK_POINT_INVALID = "invalid_fork_point"
    FORK_SERVER_FAILED = "fork_server_failed"
    FORK_CHILD_DIED = "fork_child_died"

    # 资源问题
    RESOURCE_SHM_FULL = "shared_memory_full"
    RESOURCE_FD_EXHAUSTED = "fd_exhausted"
    RESOURCE_MEMORY_ERROR = "memory_error"

    # 配置问题
    CONFIG_INVALID_TRACE = "invalid_trace_file"
    CONFIG_MISSING_BINARY = "missing_binary"
    CONFIG_PERMISSION_DENIED = "permission_denied"

    # 其他
    UNKNOWN = "unknown"


@dataclass
class FailureEvent:
    """单次失败事件记录"""
    timestamp: float
    reason: FailureReason
    iteration: int
    component: str  # 发生失败的组件名
    details: str
    context: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return (f"[{self.component}@iter{self.iteration}] {self.reason.value}: "
                f"{self.details}")


class FuzzingMetrics:
    """
    统一的fuzzing指标追踪器

    职责：
    1. 追踪所有失败事件（消除静默失败）
    2. 统计各类失败的频率
    3. 提供失败趋势分析
    4. 生成诊断报告
    """

    def __init__(self):
        # 失败事件历史
        self.failure_events: List[FailureEvent] = []

        # 失败统计
        self.failure_counts: Dict[FailureReason, int] = {
            reason: 0 for reason in FailureReason
        }

        # 成功统计
        self.success_counts = {
            'total_iterations': 0,
            'successful_iterations': 0,
            'successful_mutations': 0,
            'successful_forks': 0,
        }

        # 性能指标
        self.performance = {
            'total_time': 0.0,
            'avg_iteration_time': 0.0,
            'last_iteration_time': 0.0,
        }

        # 组件失败统计
        self.component_failures: Dict[str, int] = {}

        # 开始时间
        self.start_time = time.time()

    def record_failure(
        self,
        reason: FailureReason,
        component: str,
        details: str,
        iteration: int = -1,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        记录失败事件

        Args:
            reason: 失败原因
            component: 发生失败的组件 (如 "QEMUExecutor", "SmartMutator")
            details: 详细描述
            iteration: 迭代次数
            context: 额外上下文信息
        """
        event = FailureEvent(
            timestamp=time.time(),
            reason=reason,
            iteration=iteration,
            component=component,
            details=details,
            context=context or {}
        )

        self.failure_events.append(event)
        self.failure_counts[reason] += 1

        # 组件统计
        if component not in self.component_failures:
            self.component_failures[component] = 0
        self.component_failures[component] += 1

    def record_success(self, metric_name: str):
        """
        记录成功事件

        Args:
            metric_name: 指标名称 (如 "successful_mutations")
        """
        if metric_name in self.success_counts:
            self.success_counts[metric_name] += 1

    def update_performance(self, metric_name: str, value: float):
        """更新性能指标"""
        if metric_name in self.performance:
            self.performance[metric_name] = value

    def get_failure_rate(self) -> float:
        """
        计算总体失败率

        Returns:
            失败率 (0.0-1.0)
        """
        total = self.success_counts['total_iterations']
        if total == 0:
            return 0.0

        failed = total - self.success_counts['successful_iterations']
        return failed / total

    def get_top_failures(self, n: int = 5) -> List[tuple]:
        """
        获取top N失败原因

        Returns:
            [(FailureReason, count), ...]
        """
        sorted_failures = sorted(
            self.failure_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return [(reason, count) for reason, count in sorted_failures[:n] if count > 0]

    def get_recent_failures(self, n: int = 10) -> List[FailureEvent]:
        """获取最近N次失败"""
        return self.failure_events[-n:]

    def get_component_failure_rate(self, component: str) -> float:
        """获取特定组件的失败率"""
        total_failures = sum(self.failure_counts.values())
        if total_failures == 0:
            return 0.0

        component_failures = self.component_failures.get(component, 0)
        return component_failures / total_failures

    def generate_report(self) -> str:
        """
        生成诊断报告

        Returns:
            格式化的报告文本
        """
        elapsed = time.time() - self.start_time

        report = []
        report.append("=" * 70)
        report.append("Fuzzing Metrics Report")
        report.append("=" * 70)

        # 基本统计
        report.append("\n📊 Basic Statistics:")
        report.append(f"  Total iterations:      {self.success_counts['total_iterations']}")
        report.append(f"  Successful iterations: {self.success_counts['successful_iterations']}")
        report.append(f"  Failure rate:          {self.get_failure_rate()*100:.1f}%")
        report.append(f"  Total time:            {elapsed:.1f}s")

        # Top失败原因
        report.append("\n❌ Top Failure Reasons:")
        top_failures = self.get_top_failures(5)
        if top_failures:
            for reason, count in top_failures:
                report.append(f"  {reason.value:30s} {count:5d} times")
        else:
            report.append("  No failures recorded ✅")

        # 组件失败统计
        report.append("\n🔧 Component Failures:")
        if self.component_failures:
            sorted_components = sorted(
                self.component_failures.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for component, count in sorted_components[:5]:
                rate = self.get_component_failure_rate(component)
                report.append(f"  {component:20s} {count:5d} times ({rate*100:.1f}%)")
        else:
            report.append("  No component failures ✅")

        # 最近失败
        report.append("\n🕒 Recent Failures (last 5):")
        recent = self.get_recent_failures(5)
        if recent:
            for event in recent:
                report.append(f"  {event}")
        else:
            report.append("  No recent failures ✅")

        # 性能指标
        report.append("\n⚡ Performance:")
        if self.performance['avg_iteration_time'] > 0:
            report.append(f"  Avg iteration time: {self.performance['avg_iteration_time']:.3f}s")
        if self.performance['last_iteration_time'] > 0:
            report.append(f"  Last iteration time: {self.performance['last_iteration_time']:.3f}s")

        report.append("=" * 70)

        return "\n".join(report)

    def to_dict(self) -> Dict[str, Any]:
        """导出为字典（用于JSON序列化）"""
        return {
            'failure_counts': {
                reason.value: count
                for reason, count in self.failure_counts.items()
            },
            'success_counts': self.success_counts,
            'performance': self.performance,
            'component_failures': self.component_failures,
            'total_failures': len(self.failure_events),
            'failure_rate': self.get_failure_rate(),
            'elapsed_time': time.time() - self.start_time,
        }

    def reset(self):
        """重置所有指标"""
        self.failure_events.clear()
        self.failure_counts = {reason: 0 for reason in FailureReason}
        self.success_counts = {k: 0 for k in self.success_counts}
        self.component_failures.clear()
        self.start_time = time.time()


# 全局单例（可选）
_global_metrics: Optional[FuzzingMetrics] = None


def get_global_metrics() -> FuzzingMetrics:
    """获取全局metrics实例"""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = FuzzingMetrics()
    return _global_metrics


def reset_global_metrics():
    """重置全局metrics"""
    global _global_metrics
    if _global_metrics:
        _global_metrics.reset()
    else:
        _global_metrics = FuzzingMetrics()

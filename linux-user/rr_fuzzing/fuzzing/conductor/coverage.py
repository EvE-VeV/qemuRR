#!/usr/bin/env python3
"""
CoverageTracker - Enhanced Coverage Tracking

This module provides advanced coverage tracking including:
- Edge coverage tracking
- Hit count tracking (8-bit buckets like AFL)
- Hotspot analysis
- Coverage-guided mutation
- Stability tracking

For multi-process coverage, see shared_resources.py.
"""

from .constants import COVERAGE_MAP_SIZE
from collections import defaultdict
import time
import os
import threading  # ✅ Task #10: Thread-safe coverage tracking


class CoverageTracker:
    """
    Enhanced Coverage Tracker (Phase 3+)
    
    Provides comprehensive coverage analysis including:
    - Edge discovery
    - Hit count tracking (AFL-style buckets)
    - Hotspot identification
    - Coverage-guided feedback
    - Stability metrics
    """
    
    # AFL-style hit count buckets
    HIT_COUNT_BUCKETS = [1, 2, 3, 4, 8, 16, 32, 128]
    
    def __init__(self, pid=None):
        self.pid = pid if pid else os.getpid()
        # QEMU 创建的 coverage 共享内存路径
        # 注意：这是 QEMU 子进程的 PID，需要动态获取
        self.shm_path = None  # 将在首次读取时设置
        self.shm_base_name = "rr_coverage"

        # ✅ Task #10: Thread-safe lock for concurrent access
        # 保护global_bitmap和统计数据的并发访问
        self._lock = threading.Lock()

        # Coverage bitmaps
        self.global_bitmap = bytearray(COVERAGE_MAP_SIZE)
        self.virgin_bits = bytearray([255] * COVERAGE_MAP_SIZE)  # AFL-style virgin map
        
        # Statistics
        self.new_edges_found = 0
        self.total_executions = 0
        self.edges_per_execution = []
        self.total_edges_cached = 0  # 🔥 优化: 缓存total_edges避免重复计算

        # Hit count tracking
        self.edge_hit_counts = defaultdict(int)  # edge_id -> total hits
        self.edge_first_seen = {}  # edge_id -> timestamp
        
        # Hotspot tracking
        self.hotspots = set()  # Frequently hit edges
        self.rare_edges = set()  # Rarely hit edges
        
        # Stability tracking
        self.stable_edges = set()  # Edges that always appear
        self.unstable_edges = set()  # Edges that appear/disappear
        
        # Coverage history
        self.coverage_history = []  # [(timestamp, total_edges)]
        self.last_new_coverage = time.time()
        
    def read_coverage(self):
        """Read current coverage map"""
        try:
            with open(self.shm_path, 'rb') as f:
                return bytearray(f.read(COVERAGE_MAP_SIZE))
        except FileNotFoundError:
            # Coverage may not be initialized yet
            return None
        except Exception as e:
            # Silently fail for now
            return None
    
    def _classify_hit_count(self, count):
        """Classify hit count into AFL-style buckets"""
        if count == 0:
            return 0
        for bucket in self.HIT_COUNT_BUCKETS:
            if count <= bucket:
                return bucket
        return 128
    
    def has_new_coverage(self, current_map):
        """
        Check if there is new coverage.

        Returns True if:
        1. New edges are discovered (0 -> non-zero)
        2. Existing edges have new hit count buckets

        🔥 Phase 1优化: 减少bitmap遍历，使用缓存计数器
        ✅ Task #10: Thread-safe with locking protection
        """
        if not current_map or len(current_map) != COVERAGE_MAP_SIZE:
            return False

        # ✅ Task #10: Acquire lock for thread-safe bitmap updates
        with self._lock:
            self.total_executions += 1
            new_coverage = False
            new_edges = 0
            current_edge_count = 0
            current_timestamp = time.time()

            # 🔥 优化: 只遍历一次bitmap
            for i in range(COVERAGE_MAP_SIZE):
                current_val = current_map[i]

                if current_val > 0:
                    current_edge_count += 1
                    old_val = self.global_bitmap[i]

                    # New edge discovered
                    if old_val == 0:
                        new_edges += 1
                        new_coverage = True
                        self.total_edges_cached += 1  # 🔥 增量更新缓存
                        # ✅ Task #10: Atomic update with lock protection
                        self.global_bitmap[i] = current_val
                        self.edge_first_seen[i] = current_timestamp
                        self.last_new_coverage = current_timestamp

                        # Update virgin bits (AFL-style) for new edge
                        if self.virgin_bits[i] > 0:
                            self.virgin_bits[i] = 0

                    # 🔥 优化: 只有当值变化时才检查hit count bucket
                    # 这避免了对每个edge的重复bucket计算
                    elif current_val > old_val:
                        # Check for new hit count bucket
                        old_bucket = self._classify_hit_count(old_val)
                        new_bucket = self._classify_hit_count(current_val)

                        if new_bucket > old_bucket:
                            new_coverage = True
                            # ✅ Task #10: Atomic update with lock protection
                            self.global_bitmap[i] = current_val

                            # Update virgin bits (AFL-style)
                            if self.virgin_bits[i] > 0:
                                self.virgin_bits[i] = 0

                    # 🔥 优化: 减少hit count更新频率（仅在新coverage时）
                    if new_coverage and i not in self.edge_hit_counts:
                        self.edge_hit_counts[i] = current_val
                    elif new_coverage:
                        self.edge_hit_counts[i] += current_val

            # Record coverage history (使用缓存的total_edges)
            if new_coverage:
                self.new_edges_found += new_edges
                self.coverage_history.append((current_timestamp, self.total_edges_cached))

            # Track edges per execution
            self.edges_per_execution.append(current_edge_count)

            # 🔥 优化: 降低统计更新频率 (100 -> 500)
            if self.total_executions % 500 == 0:
                self._update_hotspots()
                self._update_stability()

        return new_coverage  # ✅ Task #10: Return outside lock
    
    def _update_hotspots(self):
        """Identify hotspots (frequently hit edges) and rare edges"""
        if not self.edge_hit_counts:
            return
        
        # Calculate average hit count
        total_hits = sum(self.edge_hit_counts.values())
        avg_hits = total_hits / len(self.edge_hit_counts)
        
        # Hotspots: edges hit > 10x average
        # Rare edges: edges hit < 0.1x average
        self.hotspots.clear()
        self.rare_edges.clear()
        
        for edge_id, hits in self.edge_hit_counts.items():
            if hits > avg_hits * 10:
                self.hotspots.add(edge_id)
            elif hits < avg_hits * 0.1:
                self.rare_edges.add(edge_id)
    
    def _update_stability(self):
        """Track edge stability"""
        if len(self.edges_per_execution) < 10:
            return
        
        # Analyze last 10 executions
        recent_executions = self.edges_per_execution[-10:]
        avg_edges = sum(recent_executions) / len(recent_executions)
        variance = sum((x - avg_edges) ** 2 for x in recent_executions) / len(recent_executions)
        
        # Low variance = stable
        if variance < avg_edges * 0.1:
            # Most edges are stable
            for i in range(COVERAGE_MAP_SIZE):
                if self.global_bitmap[i] > 0:
                    self.stable_edges.add(i)
        else:
            # High variance = unstable
            for i in range(COVERAGE_MAP_SIZE):
                if self.global_bitmap[i] > 0:
                    self.unstable_edges.add(i)
    
    def get_interesting_edges(self):
        """
        Get edges that are interesting for mutation guidance.
        
        Returns:
            dict: {
                'rare': set of rare edge IDs,
                'recent': set of recently discovered edge IDs,
                'unstable': set of unstable edge IDs
            }
        """
        current_time = time.time()
        recent_threshold = current_time - 60  # Last 60 seconds
        
        recent_edges = {
            edge_id for edge_id, timestamp in self.edge_first_seen.items()
            if timestamp > recent_threshold
        }
        
        return {
            'rare': self.rare_edges.copy(),
            'recent': recent_edges,
            'unstable': self.unstable_edges.copy()
        }
    
    def get_coverage_trend(self):
        """
        Analyze coverage growth trend.
        
        Returns:
            dict: {
                'growing': bool,
                'stagnant': bool,
                'rate': float (edges per second)
            }
        """
        if len(self.coverage_history) < 2:
            return {'growing': False, 'stagnant': True, 'rate': 0.0}
        
        # Check if we've found new coverage recently
        time_since_last = time.time() - self.last_new_coverage
        stagnant = time_since_last > 300  # 5 minutes
        
        # Calculate growth rate
        if len(self.coverage_history) >= 2:
            first_time, first_edges = self.coverage_history[0]
            last_time, last_edges = self.coverage_history[-1]
            
            time_diff = last_time - first_time
            if time_diff > 0:
                rate = (last_edges - first_edges) / time_diff
            else:
                rate = 0.0
        else:
            rate = 0.0
        
        return {
            'growing': rate > 0,
            'stagnant': stagnant,
            'rate': rate
        }
    
    def get_stats(self):
        """
        Get comprehensive coverage statistics

        🔥 Phase 1优化: 使用缓存的total_edges，避免重复遍历bitmap
        ✅ Task #10: Thread-safe read of statistics
        """
        # ✅ Task #10: Acquire lock for consistent state read
        with self._lock:
            # 🔥 优化: 使用缓存的total_edges，只在需要时重新计算virgin_bits
            virgin_bits_count = sum(1 for b in self.virgin_bits if b == 255)

            trend = self.get_coverage_trend()

            return {
                'total_edges': self.total_edges_cached,  # 🔥 使用缓存
                'new_edges_this_run': self.new_edges_found,
                'bitmap_density': self.total_edges_cached * 100.0 / COVERAGE_MAP_SIZE,
                'virgin_bits': virgin_bits_count,
                'virgin_bits_percent': virgin_bits_count * 100.0 / COVERAGE_MAP_SIZE,
                'total_executions': self.total_executions,
                'hotspots': len(self.hotspots),
                'rare_edges': len(self.rare_edges),
                'stable_edges': len(self.stable_edges),
                'unstable_edges': len(self.unstable_edges),
                'coverage_trend': trend,
                'avg_edges_per_exec': sum(self.edges_per_execution) / len(self.edges_per_execution) if self.edges_per_execution else 0
            }
    
    def should_prioritize_exploration(self):
        """
        Determine if we should prioritize exploration over exploitation.
        
        Returns True if:
        - Coverage is still growing
        - We have many virgin bits
        - We recently found new coverage
        """
        stats = self.get_stats()
        trend = stats['coverage_trend']
        
        # Prioritize exploration if:
        # 1. Coverage is growing
        # 2. > 50% virgin bits remain
        # 3. Found new coverage in last 60 seconds
        time_since_last = time.time() - self.last_new_coverage
        
        return (trend['growing'] or 
                stats['virgin_bits_percent'] > 50 or 
                time_since_last < 60)


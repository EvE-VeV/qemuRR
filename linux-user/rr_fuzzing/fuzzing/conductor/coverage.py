#!/usr/bin/env python3
"""
CoverageTracker - Basic Coverage Tracking

This module provides basic coverage tracking by reading the coverage bitmap
from QEMU's shared memory.

For advanced coverage-guided fuzzing, see coverage_feedback.py.
"""

from .constants import COVERAGE_MAP_SIZE


class CoverageTracker:
    """
    Coverage Tracker (Phase 3)
    
    Reads and analyzes QEMU's coverage shared memory.
    """
    
    def __init__(self, pid):
        self.pid = pid
        self.shm_path = f"/dev/shm/rr_coverage_{pid}"
        self.global_bitmap = bytearray(COVERAGE_MAP_SIZE)
        self.new_edges_found = 0
        
    def read_coverage(self):
        """Read current coverage map"""
        try:
            with open(self.shm_path, 'rb') as f:
                return bytearray(f.read(COVERAGE_MAP_SIZE))
        except FileNotFoundError:
            # Coverage may not be initialized yet
            return None
        except Exception as e:
            print(f"[Coverage] Failed to read coverage map: {e}")
            return None
    
    def has_new_coverage(self, current_map):
        """Check if there is new coverage"""
        if not current_map or len(current_map) != COVERAGE_MAP_SIZE:
            return False
        
        new_edges = 0
        for i in range(COVERAGE_MAP_SIZE):
            if current_map[i] > 0 and self.global_bitmap[i] == 0:
                new_edges += 1
                self.global_bitmap[i] = 1  # Mark as covered
        
        if new_edges > 0:
            self.new_edges_found += new_edges
            return True
        
        return False
    
    def get_stats(self):
        """Get coverage statistics"""
        total_edges = sum(1 for b in self.global_bitmap if b > 0)
        return {
            'total_edges': total_edges,
            'new_edges_this_run': self.new_edges_found,
            'bitmap_density': total_edges * 100.0 / COVERAGE_MAP_SIZE
        }


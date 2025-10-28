#!/usr/bin/env python3
"""
RR-Fuzz Phase 3: Corpus Manager

管理有价值的 Fuzzing 样本（corpus），用于：
1. 保存导致新覆盖率的 trace
2. 去重（基于哈希或相似度）
3. 优先级排序

TODO Phase 3 完整实现：
- TLSH 相似度检测
- 基于覆盖率的优先级队列
- Corpus 最小化
"""

import os
import hashlib
import json
from pathlib import Path
from typing import Dict, Optional, List


class CorpusManager:
    """
    Corpus 管理器
    
    管理 Fuzzing 过程中发现的有价值样本
    """
    
    def __init__(self, corpus_dir: str):
        """
        Args:
            corpus_dir: Corpus 存储目录
        """
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        
        # 覆盖率映射：trace_hash -> coverage_count
        self.coverage_map: Dict[str, int] = {}
        
        # 已知的 trace 哈希（用于快速去重）
        self.known_hashes = set()
        
        # 加载现有 corpus
        self._load_existing_corpus()
        
        print(f"[CorpusManager] Initialized with {len(self.known_hashes)} existing samples")
    
    def _load_existing_corpus(self):
        """加载目录中已有的 corpus"""
        for trace_file in self.corpus_dir.glob("*.trace"):
            trace_hash = trace_file.stem
            self.known_hashes.add(trace_hash)
            
            # 尝试加载元数据
            meta_file = trace_file.with_suffix('.trace.json')
            if meta_file.exists():
                try:
                    with open(meta_file, 'r') as f:
                        meta = json.load(f)
                        if 'coverage' in meta and 'edges' in meta['coverage']:
                            self.coverage_map[trace_hash] = meta['coverage']['edges']
                except Exception as e:
                    print(f"[CorpusManager] Warning: Failed to load metadata for {trace_hash}: {e}")
    
    def compute_trace_hash(self, trace_data: bytes) -> str:
        """
        计算 trace 数据的哈希
        
        Args:
            trace_data: Trace 二进制数据
        
        Returns:
            SHA256 哈希（十六进制字符串）
        """
        return hashlib.sha256(trace_data).hexdigest()
    
    def should_save(self, trace_data: bytes, coverage_info: Dict) -> bool:
        """
        判断是否应保存此 trace
        
        Args:
            trace_data: Trace 数据
            coverage_info: 覆盖率信息，格式：{'edges': int, 'blocks': int}
        
        Returns:
            True 表示应保存，False 表示应丢弃
        """
        # 1. 计算哈希
        trace_hash = self.compute_trace_hash(trace_data)
        
        # 2. 检查是否重复
        if trace_hash in self.known_hashes:
            return False
        
        # 3. 检查是否有新覆盖率
        if not coverage_info or 'edges' not in coverage_info:
            # 没有覆盖率信息，暂时保存
            return True
        
        current_edges = coverage_info['edges']
        max_edges = max(self.coverage_map.values()) if self.coverage_map else 0
        
        if current_edges > max_edges:
            # 新的最大覆盖率
            print(f"[CorpusManager] 🎯 New maximum coverage: {current_edges} edges (prev: {max_edges})")
            return True
        
        # 4. TODO Phase 3: TLSH 相似度检测
        # if self.is_unique_path_tlsh(trace_data):
        #     return True
        
        # 5. 默认策略：保留 10% 的随机样本（探索）
        import random
        if random.random() < 0.1:
            print(f"[CorpusManager] 🎲 Random sample saved (exploration)")
            return True
        
        return False
    
    def save_interesting_case(self, trace_data: bytes, metadata: Dict) -> Optional[str]:
        """
        保存有价值的样本
        
        Args:
            trace_data: Trace 数据
            metadata: 元数据（iteration, coverage, mutation 等）
        
        Returns:
            保存的文件路径，如果保存失败则返回 None
        """
        try:
            trace_hash = self.compute_trace_hash(trace_data)
            
            # 保存 trace 文件
            trace_file = self.corpus_dir / f"{trace_hash}.trace"
            with open(trace_file, 'wb') as f:
                f.write(trace_data)
            
            # 保存元数据
            meta_file = self.corpus_dir / f"{trace_hash}.trace.json"
            with open(meta_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # 更新内部状态
            self.known_hashes.add(trace_hash)
            if 'coverage' in metadata and 'edges' in metadata['coverage']:
                self.coverage_map[trace_hash] = metadata['coverage']['edges']
            
            print(f"[CorpusManager] ✅ Saved interesting case: {trace_hash[:12]}...")
            
            return str(trace_file)
        
        except Exception as e:
            print(f"[CorpusManager] ❌ Failed to save case: {e}")
            return None
    
    def get_best_samples(self, n: int = 10) -> List[str]:
        """
        获取 top-N 覆盖率最高的样本
        
        Args:
            n: 返回的样本数量
        
        Returns:
            文件路径列表（按覆盖率降序）
        """
        sorted_samples = sorted(
            self.coverage_map.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            str(self.corpus_dir / f"{hash}.trace")
            for hash, _ in sorted_samples[:n]
        ]
    
    def get_stats(self) -> Dict:
        """
        获取 corpus 统计信息
        
        Returns:
            统计信息字典
        """
        return {
            'total_samples': len(self.known_hashes),
            'max_coverage': max(self.coverage_map.values()) if self.coverage_map else 0,
            'avg_coverage': sum(self.coverage_map.values()) / len(self.coverage_map) if self.coverage_map else 0,
            'corpus_size_mb': sum(f.stat().st_size for f in self.corpus_dir.glob("*.trace")) / (1024 * 1024)
        }
    
    def print_stats(self):
        """打印统计信息"""
        stats = self.get_stats()
        print(f"\n[CorpusManager] Statistics:")
        print(f"  Total samples:  {stats['total_samples']}")
        print(f"  Max coverage:   {stats['max_coverage']} edges")
        print(f"  Avg coverage:   {stats['avg_coverage']:.1f} edges")
        print(f"  Corpus size:    {stats['corpus_size_mb']:.2f} MB")


# 简单测试
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: corpus_manager.py <corpus_dir>")
        sys.exit(1)
    
    corpus_dir = sys.argv[1]
    manager = CorpusManager(corpus_dir)
    manager.print_stats()
    
    # 测试保存
    test_trace = b"test trace data"
    test_meta = {
        'iteration': 1,
        'coverage': {'edges': 100, 'blocks': 50},
        'mutation': 'flip_bits'
    }
    
    if manager.should_save(test_trace, test_meta['coverage']):
        saved_path = manager.save_interesting_case(test_trace, test_meta)
        print(f"\nTest: Saved to {saved_path}")
    else:
        print("\nTest: Sample not interesting enough")
    
    manager.print_stats()


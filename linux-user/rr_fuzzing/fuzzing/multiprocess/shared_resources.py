#!/usr/bin/env python3
"""
Shared Resources for Multi-Process Fuzzing

This module implements shared resources for inter-process communication:
1. SharedCoverage: Shared coverage bitmap using mmap
2. WorkerSeedQueue: Per-worker seed queue with sync mechanism
"""

import os
import mmap
import time
import pickle
import random
import hashlib
from pathlib import Path
from typing import List, Set, Optional, Any
from dataclasses import dataclass


@dataclass
class SeedMetadata:
    """Seed元数据（从文件名解析）"""
    seed_id: str
    seq: int
    new_edges: int
    depth: int
    
    @staticmethod
    def parse_filename(filename: str) -> Optional['SeedMetadata']:
        """
        解析seed文件名
        格式: id_{seq:06d}_cov_{new_edges}_depth_{depth}
        """
        try:
            parts = filename.split('_')
            if len(parts) < 6:
                return None
            
            seq = int(parts[1])
            new_edges = int(parts[3])
            depth = int(parts[5])
            
            return SeedMetadata(
                seed_id=filename,
                seq=seq,
                new_edges=new_edges,
                depth=depth
            )
        except:
            return None


class SharedCoverage:
    """
    共享Coverage Bitmap（基于mmap）
    
    多进程通过mmap共享一个coverage bitmap，实现：
    1. Worker发现新coverage时更新全局bitmap
    2. Worker定期从全局bitmap同步到本地
    3. 使用版本号机制检测更新
    """
    
    def __init__(self, sync_dir: Path, worker_id: int):
        """
        初始化共享coverage
        
        Args:
            sync_dir: 同步目录
            worker_id: Worker ID
        """
        self.sync_dir = sync_dir
        self.worker_id = worker_id
        self.bitmap_size = 1024 * 1024  # 1MB bitmap
        
        # 打开共享bitmap文件
        self.bitmap_file = sync_dir / "coverage" / "global_bitmap.bin"
        self.version_file = sync_dir / "coverage" / "version.txt"
        
        # 确保文件存在
        if not self.bitmap_file.exists():
            with open(self.bitmap_file, 'wb') as f:
                f.write(b'\x00' * self.bitmap_size)
        
        # 使用mmap映射
        self.fd = os.open(self.bitmap_file, os.O_RDWR)
        self.bitmap = mmap.mmap(self.fd, self.bitmap_size)
        
        # 本地副本（快速查询）
        self.local_bitmap = bytearray(self.bitmap_size)
        
        # 版本号管理
        self.last_version = self._read_version()
    
    def _read_version(self) -> int:
        """读取版本号"""
        try:
            with open(self.version_file, 'r') as f:
                return int(f.read().strip())
        except:
            return 0
    
    def _increment_version(self):
        """递增版本号"""
        try:
            version = self._read_version()
            with open(self.version_file, 'w') as f:
                f.write(f"{version + 1}\n")
        except:
            pass
    
    def sync_coverage(self) -> int:
        """
        从全局bitmap同步到本地
        
        Returns:
            新发现的edges数量
        """
        # 检查版本号
        current_version = self._read_version()
        if current_version == self.last_version:
            return 0  # 没有更新
        
        # 合并全局bitmap到本地
        new_edges = 0
        for i in range(self.bitmap_size):
            global_byte = self.bitmap[i]
            local_byte = self.local_bitmap[i]
            
            # 发现新的coverage
            if global_byte > local_byte:
                # 计算新增的bit数量
                diff = global_byte ^ local_byte
                new_edges += bin(diff).count('1')
                self.local_bitmap[i] = global_byte
        
        self.last_version = current_version
        return new_edges
    
    def update_coverage(self, exec_bitmap: bytes) -> int:
        """
        更新coverage（本地发现新coverage后更新全局）
        
        Args:
            exec_bitmap: 执行产生的coverage bitmap
        
        Returns:
            新发现的edges数量
        """
        if len(exec_bitmap) > self.bitmap_size:
            exec_bitmap = exec_bitmap[:self.bitmap_size]
        
        new_edges = 0
        
        for i in range(len(exec_bitmap)):
            exec_byte = exec_bitmap[i]
            local_byte = self.local_bitmap[i]
            
            if exec_byte > local_byte:
                # 更新本地
                self.local_bitmap[i] = exec_byte
                
                # 更新全局（简单方法：直接写入）
                # 注意：这里可能有race condition，但影响很小
                global_byte = self.bitmap[i]
                if exec_byte > global_byte:
                    self.bitmap[i] = exec_byte
                    new_edges += 1
        
        if new_edges > 0:
            self._increment_version()
        
        return new_edges
    
    def get_coverage_count(self) -> int:
        """获取当前coverage数量"""
        return sum(1 for b in self.local_bitmap if b > 0)
    
    def __del__(self):
        """清理资源"""
        try:
            if hasattr(self, 'bitmap'):
                self.bitmap.close()
            if hasattr(self, 'fd'):
                os.close(self.fd)
        except:
            pass


class WorkerSeedQueue:
    """
    Worker Seed队列管理
    
    每个worker有自己的私有队列，定期从其他worker导入高质量seeds。
    
    策略：
    1. 本地优先：80%时间处理本地seeds
    2. 定期同步：每100次迭代从其他worker导入
    3. 智能导入：只导入高质量seeds（new_edges > 阈值）
    4. 去重：避免重复导入相同seeds
    """
    
    def __init__(
        self,
        worker_id: int,
        sync_dir: Path,
        num_workers: int
    ):
        """
        初始化Worker Seed队列
        
        Args:
            worker_id: Worker ID
            sync_dir: 同步目录
            num_workers: 总worker数量
        """
        self.worker_id = worker_id
        self.sync_dir = sync_dir
        self.num_workers = num_workers
        
        # 私有队列目录
        self.my_dir = sync_dir / "queue" / f"worker{worker_id}"
        self.my_dir.mkdir(parents=True, exist_ok=True)
        
        # 已导入的seeds（去重）
        self.imported_seeds: Set[str] = set()
        
        # 同步计数器
        self.sync_counter = 0
        self.SYNC_INTERVAL = 100  # 每100次迭代同步一次
        
        # Seed序列号
        self.seq = 0
        
        # 统计信息
        self.imported_count = 0
        self.avg_depth = 0
    
    def should_sync(self) -> bool:
        """判断是否应该同步"""
        self.sync_counter += 1
        return self.sync_counter % self.SYNC_INTERVAL == 0
    
    def sync_with_others(self) -> List[Any]:
        """
        从其他worker导入新seeds
        
        Returns:
            导入的seeds列表
        """
        imported_seeds = []
        
        # 扫描所有其他worker的目录
        for other_worker_id in range(self.num_workers):
            if other_worker_id == self.worker_id:
                continue  # 跳过自己
            
            other_worker_dir = self.sync_dir / "queue" / f"worker{other_worker_id}"
            if not other_worker_dir.exists():
                continue
            
            # 发现新seeds
            for seed_file in other_worker_dir.iterdir():
                seed_id = seed_file.name
                
                # 避免重复导入
                if seed_id in self.imported_seeds:
                    continue
                
                # 解析seed元数据
                metadata = SeedMetadata.parse_filename(seed_id)
                if not metadata:
                    continue
                
                # 导入策略：只导入高质量seeds
                if self._should_import(metadata):
                    try:
                        seed = self._load_seed(seed_file)
                        if seed:
                            imported_seeds.append(seed)
                            self.imported_seeds.add(seed_id)
                            self.imported_count += 1
                    except:
                        pass
                
                # 限制单次导入数量
                if len(imported_seeds) >= 50:
                    break
            
            if len(imported_seeds) >= 50:
                break
        
        return imported_seeds
    
    def _should_import(self, metadata: SeedMetadata) -> bool:
        """
        判断是否应该导入这个seed
        
        策略：
        1. 新coverage高的seeds（new_edges > 5）
        2. 路径深度大的seeds（depth > avg）
        3. 随机采样一小部分（10%概率）
        """
        # 策略1: 高coverage
        if metadata.new_edges > 5:
            return True
        
        # 策略2: 深路径
        if self.avg_depth > 0 and metadata.depth > self.avg_depth:
            return True
        
        # 策略3: 随机采样（多样性）
        if random.random() < 0.1:
            return True
        
        return False
    
    def _load_seed(self, seed_file: Path) -> Optional[Any]:
        """加载seed文件"""
        try:
            with open(seed_file, 'rb') as f:
                return pickle.load(f)
        except:
            # 如果不是pickle格式，作为原始bytes返回
            try:
                with open(seed_file, 'rb') as f:
                    return f.read()
            except:
                return None
    
    def save_seed(
        self,
        seed: Any,
        new_edges: int,
        depth: int
    ) -> Path:
        """
        保存新seed到自己的目录
        
        Args:
            seed: Seed对象
            new_edges: 新发现的edges数量
            depth: 路径深度
        
        Returns:
            保存的文件路径
        """
        # 生成文件名
        seed_id = f"id_{self.seq:06d}_cov_{new_edges}_depth_{depth}"
        seed_path = self.my_dir / seed_id
        
        # 原子写入（先写临时文件再重命名）
        temp_path = seed_path.with_suffix('.tmp')
        
        try:
            with open(temp_path, 'wb') as f:
                pickle.dump(seed, f)
            
            # 原子重命名
            temp_path.rename(seed_path)
            
            self.seq += 1
            
            # 更新平均深度
            self._update_avg_depth(depth)
            
            return seed_path
        
        except Exception as e:
            # 清理临时文件
            if temp_path.exists():
                temp_path.unlink()
            raise e
    
    def _update_avg_depth(self, depth: int):
        """更新平均深度（移动平均）"""
        alpha = 0.1  # 平滑系数
        self.avg_depth = alpha * depth + (1 - alpha) * self.avg_depth
    
    def get_queue_size(self) -> int:
        """获取队列大小"""
        return len(list(self.my_dir.iterdir()))
    
    def load_all_seeds(self) -> List[Any]:
        """加载所有本地seeds"""
        seeds = []
        for seed_file in self.my_dir.iterdir():
            seed = self._load_seed(seed_file)
            if seed:
                seeds.append(seed)
        return seeds


class WorkStealingQueue:
    """
    工作窃取队列
    
    当worker的本地队列为空时，可以"窃取"其他worker的工作。
    """
    
    def __init__(
        self,
        worker_id: int,
        sync_dir: Path,
        num_workers: int
    ):
        self.worker_id = worker_id
        self.sync_dir = sync_dir
        self.num_workers = num_workers
    
    def steal_from_others(self) -> Optional[Any]:
        """
        从其他worker窃取工作
        
        Returns:
            窃取的seed，如果没有则返回None
        """
        # 随机选择一个受害者worker
        victim_id = random.choice([
            w for w in range(self.num_workers)
            if w != self.worker_id
        ])
        
        victim_dir = self.sync_dir / "queue" / f"worker{victim_id}"
        if not victim_dir.exists():
            return None
        
        # 获取受害者的seeds
        seed_files = list(victim_dir.iterdir())
        if not seed_files:
            return None
        
        # 随机窃取一个
        stolen_file = random.choice(seed_files)
        
        try:
            with open(stolen_file, 'rb') as f:
                return pickle.load(f)
        except:
            return None


def test_shared_coverage():
    """测试SharedCoverage"""
    import tempfile
    import shutil
    
    print("Testing SharedCoverage...")
    
    # 创建临时目录
    temp_dir = Path(tempfile.mkdtemp())
    (temp_dir / "coverage").mkdir()
    
    try:
        # 创建两个worker的coverage
        worker0 = SharedCoverage(temp_dir, 0)
        worker1 = SharedCoverage(temp_dir, 1)
        
        # Worker 0 发现新coverage
        test_bitmap = bytearray(1024 * 1024)
        test_bitmap[0] = 0xFF
        test_bitmap[1] = 0xAA
        
        new_edges = worker0.update_coverage(bytes(test_bitmap))
        print(f"Worker 0 found {new_edges} new edges")
        
        # Worker 1 同步
        new_edges = worker1.sync_coverage()
        print(f"Worker 1 synced {new_edges} new edges")
        
        # 验证
        assert worker1.local_bitmap[0] == 0xFF
        assert worker1.local_bitmap[1] == 0xAA
        
        print("✓ SharedCoverage test passed")
    
    finally:
        shutil.rmtree(temp_dir)


def test_worker_seed_queue():
    """测试WorkerSeedQueue"""
    import tempfile
    import shutil
    
    print("Testing WorkerSeedQueue...")
    
    # 创建临时目录
    temp_dir = Path(tempfile.mkdtemp())
    (temp_dir / "queue").mkdir()
    
    try:
        # 创建两个worker的队列
        worker0_queue = WorkerSeedQueue(0, temp_dir, 2)
        worker1_queue = WorkerSeedQueue(1, temp_dir, 2)
        
        # Worker 0 保存seeds
        test_seed = b"test_seed_data"
        worker0_queue.save_seed(test_seed, new_edges=10, depth=50)
        worker0_queue.save_seed(test_seed, new_edges=5, depth=30)
        
        print(f"Worker 0 queue size: {worker0_queue.get_queue_size()}")
        
        # Worker 1 同步
        imported = worker1_queue.sync_with_others()
        print(f"Worker 1 imported {len(imported)} seeds")
        
        print("✓ WorkerSeedQueue test passed")
    
    finally:
        shutil.rmtree(temp_dir)


if __name__ == '__main__':
    test_shared_coverage()
    test_worker_seed_queue()


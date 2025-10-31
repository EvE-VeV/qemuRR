# 多核Fuzzing协同机制详解

## 核心问题

**挑战**: 多个独立进程同时fuzzing，如何避免重复工作并共享发现？

```
┌─────────────────────────────────────────────────────────────┐
│              多核Fuzzing的核心矛盾                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  独立性 (Independence)    vs    协同性 (Collaboration)     │
│                                                             │
│  ✅ 需要独立运行避免锁竞争    ✅ 需要共享seeds和coverage    │
│  ✅ 每个进程独立决策          ✅ 需要避免重复工作            │
│  ✅ 无需等待其他进程          ✅ 需要及时利用其他进程发现    │
│                                                             │
│  解决方案: Master-Worker + 定期同步 (AFL模式)              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. 架构设计：Master-Worker模式

### 1.1 整体架构

```
                    ┌──────────────────────────────────┐
                    │     FuzzMaster (主进程)          │
                    │  • 初始化corpus                  │
                    │  • 管理worker进程池              │
                    │  • 监控状态和统计                │
                    │  • 定期同步和保存                │
                    └────────┬────────────────┬─────────┘
                             │                │
                ┌────────────┴────────┐      │
                │                     │      │
                ▼                     ▼      ▼
    ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
    │   Worker 0        │  │   Worker 1        │  │   Worker N-1      │
    │  ┌─────────────┐  │  │  ┌─────────────┐  │  │  ┌─────────────┐  │
    │  │FuzzConductor│  │  │  │FuzzConductor│  │  │  │FuzzConductor│  │
    │  └──────┬──────┘  │  │  └──────┬──────┘  │  │  └──────┬──────┘  │
    │         │         │  │         │         │  │         │         │
    │         ▼         │  │         ▼         │  │         ▼         │
    │  ┌─────────────┐  │  │  ┌─────────────┐  │  │  ┌─────────────┐  │
    │  │ QEMU Process│  │  │  │ QEMU Process│  │  │  │ QEMU Process│  │
    │  │   (CPU 0)   │  │  │  │   (CPU 1)   │  │  │  │   (CPU N-1) │  │
    │  └─────────────┘  │  │  └─────────────┘  │  │  └─────────────┘  │
    └─────────┬─────────┘  └─────────┬─────────┘  └─────────┬─────────┘
              │                      │                      │
              │                      │                      │
              └──────────────────────┴──────────────────────┘
                                     │
                                     ▼
                          ┌──────────────────────┐
                          │   共享存储空间        │
                          │  • Seed队列目录      │
                          │  • Coverage bitmap   │
                          │  • Crash目录         │
                          │  • Stats文件         │
                          └──────────────────────┘
```

### 1.2 职责划分

| 组件 | 职责 | 独立性 |
|------|------|--------|
| **FuzzMaster** | • 创建和管理worker进程池<br>• 初始化共享目录结构<br>• 定期同步全局coverage<br>• 收集和展示统计信息<br>• 优雅关闭和保存状态 | 单进程 |
| **Worker** | • 独立运行FuzzConductor<br>• 本地seed队列和变异<br>• 定期读取其他worker的seeds<br>• 写入新seeds到共享目录 | 完全独立 |
| **共享存储** | • 基于文件系统的IPC<br>• 无锁设计（append-only） | 被动 |

---

## 2. 协同机制详解

### 2.1 Seed共享策略

#### 方案：目录+文件命名约定

```
sync_dir/
├── queue/                    # 全局seed队列目录
│   ├── worker0/             # Worker 0的私有队列
│   │   ├── id_000000_cov_123  # seed文件命名规则
│   │   ├── id_000001_cov_125
│   │   └── ...
│   ├── worker1/             # Worker 1的私有队列
│   │   ├── id_000000_cov_124
│   │   └── ...
│   └── workerN/
│
├── crashes/                 # 崩溃样本
│   ├── worker0/
│   └── ...
│
├── hangs/                   # 超时样本
│
└── stats/                   # 统计信息
    ├── worker0_stats.json
    └── global_stats.json
```

**Seed文件命名规则**:
```
id_{seq:06d}_cov_{new_edges:d}_depth_{depth:d}
```

#### 同步逻辑

**Worker本地队列管理**:
```python
class WorkerSeedQueue:
    def __init__(self, worker_id, sync_dir):
        self.worker_id = worker_id
        self.local_queue = []  # 本地优先队列
        self.my_dir = sync_dir / "queue" / f"worker{worker_id}"
        self.my_dir.mkdir(exist_ok=True)
        
        # 记录已导入的seeds（避免重复）
        self.imported_seeds = set()
        
        # 同步计数器
        self.sync_counter = 0
        self.SYNC_INTERVAL = 100  # 每100次迭代同步一次
```

**定期同步流程**:
```python
def sync_with_others(self):
    """定期从其他worker导入新seeds"""
    if self.sync_counter % self.SYNC_INTERVAL != 0:
        return
    
    # 1. 扫描所有其他worker的目录
    for other_worker_dir in self.sync_dir.glob("queue/worker*"):
        if other_worker_dir == self.my_dir:
            continue  # 跳过自己
        
        # 2. 发现新seeds
        for seed_file in other_worker_dir.iterdir():
            seed_id = seed_file.name
            
            # 3. 避免重复导入
            if seed_id in self.imported_seeds:
                continue
            
            # 4. 解析seed元数据
            metadata = self._parse_filename(seed_file.name)
            
            # 5. 导入策略：只导入高质量seeds
            if self._should_import(metadata):
                seed = self._load_seed(seed_file)
                self.local_queue.append(seed)
                self.imported_seeds.add(seed_id)
    
    self.sync_counter = 0

def _should_import(self, metadata):
    """智能导入策略"""
    # 策略1: 导入新coverage高的seeds
    if metadata['new_edges'] > 5:
        return True
    
    # 策略2: 导入路径深度大的seeds
    if metadata['depth'] > self.avg_depth:
        return True
    
    # 策略3: 随机采样一小部分其他seeds（多样性）
    return random.random() < 0.1  # 10%概率
```

**写入新seed**:
```python
def save_seed(self, seed, new_edges, depth):
    """保存新seed到自己的目录"""
    seed_id = f"id_{self.seq:06d}_cov_{new_edges}_depth_{depth}"
    seed_path = self.my_dir / seed_id
    
    # 原子写入（先写临时文件再重命名）
    temp_path = seed_path.with_suffix('.tmp')
    with open(temp_path, 'wb') as f:
        pickle.dump(seed, f)
    temp_path.rename(seed_path)  # 原子操作
    
    self.seq += 1
```

---

### 2.2 Coverage共享策略

#### 方案：共享Bitmap + 版本号

**数据结构**:
```python
class SharedCoverage:
    """共享coverage使用mmap实现"""
    
    def __init__(self, sync_dir, worker_id):
        self.bitmap_file = sync_dir / "coverage" / "global_bitmap.bin"
        self.bitmap_size = 1024 * 1024  # 1MB bitmap
        
        # 使用mmap实现进程间共享
        if not self.bitmap_file.exists():
            # Master进程创建
            with open(self.bitmap_file, 'wb') as f:
                f.write(b'\x00' * self.bitmap_size)
        
        self.fd = os.open(self.bitmap_file, os.O_RDWR)
        self.bitmap = mmap.mmap(self.fd, self.bitmap_size)
        
        # 本地副本（快速查询）
        self.local_bitmap = bytearray(self.bitmap_size)
        
        # 版本号（用于检测更新）
        self.version_file = sync_dir / "coverage" / "version.txt"
        self.last_version = 0
```

**同步逻辑**:
```python
def sync_coverage(self):
    """定期从全局bitmap同步"""
    # 1. 检查版本号
    current_version = self._read_version()
    if current_version == self.last_version:
        return  # 没有更新
    
    # 2. 合并全局bitmap到本地
    new_edges = 0
    for i in range(self.bitmap_size):
        global_byte = self.bitmap[i]
        local_byte = self.local_bitmap[i]
        
        # 发现新的coverage
        if global_byte > local_byte:
            self.local_bitmap[i] = global_byte
            new_edges += bin(global_byte ^ local_byte).count('1')
    
    self.last_version = current_version
    return new_edges

def update_coverage(self, exec_bitmap):
    """本地发现新coverage后更新全局"""
    new_edges = 0
    
    for i in range(self.bitmap_size):
        exec_byte = exec_bitmap[i]
        local_byte = self.local_bitmap[i]
        
        if exec_byte > local_byte:
            # 原子更新全局bitmap
            with self._lock():  # 简单的文件锁
                global_byte = self.bitmap[i]
                if exec_byte > global_byte:
                    self.bitmap[i] = exec_byte
                    new_edges += 1
            
            # 更新本地副本
            self.local_bitmap[i] = exec_byte
    
    if new_edges > 0:
        self._increment_version()
    
    return new_edges
```

**无锁优化**:
```python
def update_coverage_lockfree(self, exec_bitmap):
    """无锁版本：使用原子操作"""
    import ctypes
    
    for i in range(self.bitmap_size):
        exec_byte = exec_bitmap[i]
        
        # 乐观更新：只在本地值更大时才尝试
        if exec_byte > self.local_bitmap[i]:
            # 使用CAS（Compare-And-Swap）原子操作
            addr = ctypes.addressof(ctypes.c_uint8.from_buffer(self.bitmap, i))
            while True:
                old_val = self.bitmap[i]
                if exec_byte <= old_val:
                    break  # 其他进程已更新
                
                # 原子CAS
                if self._cas(addr, old_val, exec_byte):
                    self.local_bitmap[i] = exec_byte
                    break
```

---

### 2.3 负载均衡策略

#### 方案1：随机化种子选择

```python
class WorkerFuzzer:
    def __init__(self, worker_id, num_workers):
        self.worker_id = worker_id
        self.num_workers = num_workers
        
        # 每个worker使用不同的随机种子
        random.seed(worker_id + int(time.time()))
        
    def select_seed(self):
        """随机选择seed，自然避免冲突"""
        # 本地队列优先，但加入随机性
        if random.random() < 0.8:  # 80%从本地队列
            return self._select_from_local()
        else:  # 20%从导入队列（探索多样性）
            return self._select_from_imported()
```

#### 方案2：工作窃取（Work Stealing）

```python
def get_next_seed(self):
    """获取下一个待fuzz的seed"""
    # 1. 优先处理自己的队列
    if self.local_queue:
        return self.local_queue.pop()
    
    # 2. 本地队列空了，尝试"窃取"其他worker的工作
    return self._steal_from_others()

def _steal_from_others(self):
    """从其他worker窃取工作"""
    # 随机选择一个受害者worker
    victim_id = random.choice([w for w in range(self.num_workers) 
                               if w != self.worker_id])
    victim_dir = self.sync_dir / "queue" / f"worker{victim_id}"
    
    # 窃取一些seeds（不是全部）
    seed_files = list(victim_dir.iterdir())
    if seed_files:
        # 随机窃取10%
        steal_count = max(1, len(seed_files) // 10)
        stolen = random.sample(seed_files, steal_count)
        
        for seed_file in stolen:
            seed = self._load_seed(seed_file)
            self.local_queue.append(seed)
        
        return self.local_queue.pop()
    
    return None  # 所有worker都空了
```

---

### 2.4 避免重复工作

#### 策略1：Seed去重

```python
def _compute_seed_hash(self, seed):
    """计算seed的唯一标识"""
    # 不使用完整内容hash（太慢）
    # 使用关键特征的组合
    features = []
    features.append(len(seed.inputs))  # 长度
    features.append(seed.target_index)  # 目标syscall
    
    # 采样部分内容
    for inp in seed.inputs[:3]:  # 前3个syscall
        features.append(hash(bytes(inp.data[:32])))  # 前32字节
    
    return hash(tuple(features))

def should_process_seed(self, seed):
    """检查是否应该处理这个seed"""
    seed_hash = self._compute_seed_hash(seed)
    
    # 检查本地历史
    if seed_hash in self.processed_hashes:
        return False
    
    # 检查全局历史（定期同步）
    if seed_hash in self.global_processed_hashes:
        return False
    
    return True
```

#### 策略2：Mutation随机化

```python
def mutate_seed(self, seed):
    """变异策略加入worker_id相关的随机性"""
    # 每个worker有不同的mutation偏好
    mutation_bias = (self.worker_id / self.num_workers)
    
    # Worker 0: 更倾向于小变异
    # Worker N-1: 更倾向于大变异
    mutation_intensity = mutation_bias * 10
    
    # 选择mutation策略时加入偏好
    strategies = self.mutation_engine.get_strategies()
    weights = self._compute_weights(strategies, mutation_bias)
    
    return random.choices(strategies, weights=weights)[0](seed)
```

---

## 3. 完整实现示例

### 3.1 FuzzMaster实现

```python
class FuzzMaster:
    """Master进程：管理多个worker"""
    
    def __init__(self, num_workers, sync_dir, initial_corpus):
        self.num_workers = num_workers
        self.sync_dir = Path(sync_dir)
        self.initial_corpus = initial_corpus
        
        # 初始化共享目录
        self._init_sync_dir()
        
        # Worker进程池
        self.workers = []
        self.worker_processes = []
        
    def _init_sync_dir(self):
        """初始化共享目录结构"""
        (self.sync_dir / "queue").mkdir(parents=True, exist_ok=True)
        (self.sync_dir / "crashes").mkdir(exist_ok=True)
        (self.sync_dir / "hangs").mkdir(exist_ok=True)
        (self.sync_dir / "stats").mkdir(exist_ok=True)
        (self.sync_dir / "coverage").mkdir(exist_ok=True)
        
        # 创建每个worker的私有队列目录
        for i in range(self.num_workers):
            (self.sync_dir / "queue" / f"worker{i}").mkdir(exist_ok=True)
            (self.sync_dir / "crashes" / f"worker{i}").mkdir(exist_ok=True)
        
        # 初始化全局coverage bitmap
        bitmap_file = self.sync_dir / "coverage" / "global_bitmap.bin"
        with open(bitmap_file, 'wb') as f:
            f.write(b'\x00' * (1024 * 1024))
        
        # 分发初始corpus
        self._distribute_initial_corpus()
    
    def _distribute_initial_corpus(self):
        """将初始corpus分配给各个worker"""
        # 策略：轮流分配 + 每个都保留一份
        for i, seed in enumerate(self.initial_corpus):
            # 主要负责的worker
            primary_worker = i % self.num_workers
            seed_path = self.sync_dir / "queue" / f"worker{primary_worker}" / f"id_{i:06d}_cov_0_depth_0"
            with open(seed_path, 'wb') as f:
                pickle.dump(seed, f)
            
            # 同时给前3个worker也分发一份（冗余，快速启动）
            if i < 10:  # 前10个seed
                for w in range(min(3, self.num_workers)):
                    if w != primary_worker:
                        seed_path = self.sync_dir / "queue" / f"worker{w}" / f"id_{i:06d}_cov_0_depth_0"
                        with open(seed_path, 'wb') as f:
                            pickle.dump(seed, f)
    
    def start(self):
        """启动所有worker进程"""
        import multiprocessing as mp
        
        # 启动worker进程
        for worker_id in range(self.num_workers):
            p = mp.Process(
                target=self._worker_main,
                args=(worker_id,),
                name=f"Worker-{worker_id}"
            )
            p.start()
            self.worker_processes.append(p)
            print(f"✓ Started Worker {worker_id} (PID: {p.pid})")
        
        # Master主循环：监控和统计
        self._master_loop()
    
    def _worker_main(self, worker_id):
        """Worker进程的主函数"""
        # 设置CPU亲和性（Linux）
        try:
            import os
            os.sched_setaffinity(0, {worker_id})
        except:
            pass
        
        # 创建FuzzConductor实例
        conductor = FuzzConductor(
            program_path=self.program_path,
            qemu_path=self.qemu_path,
            worker_id=worker_id,
            num_workers=self.num_workers,
            sync_dir=self.sync_dir,
            output_dir=self.sync_dir / "crashes" / f"worker{worker_id}"
        )
        
        # 运行fuzzing
        try:
            conductor.run_fuzzing()
        except KeyboardInterrupt:
            conductor.cleanup()
    
    def _master_loop(self):
        """Master监控循环"""
        start_time = time.time()
        last_stats_time = start_time
        
        try:
            while True:
                time.sleep(10)  # 每10秒更新一次
                
                # 收集统计信息
                stats = self._collect_stats()
                
                # 显示状态
                self._display_status(stats, time.time() - start_time)
                
                # 定期保存全局状态（每5分钟）
                if time.time() - last_stats_time > 300:
                    self._save_global_stats(stats)
                    last_stats_time = time.time()
                
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping fuzzing...")
            self._stop_all_workers()
    
    def _collect_stats(self):
        """收集所有worker的统计信息"""
        global_stats = {
            'total_execs': 0,
            'total_crashes': 0,
            'unique_crashes': 0,
            'total_seeds': 0,
            'global_coverage': 0,
        }
        
        worker_stats = []
        for i in range(self.num_workers):
            stats_file = self.sync_dir / "stats" / f"worker{i}_stats.json"
            if stats_file.exists():
                with open(stats_file) as f:
                    ws = json.load(f)
                    worker_stats.append(ws)
                    global_stats['total_execs'] += ws.get('execs', 0)
                    global_stats['total_crashes'] += ws.get('crashes', 0)
        
        # 统计全局seeds数量
        for worker_dir in (self.sync_dir / "queue").iterdir():
            global_stats['total_seeds'] += len(list(worker_dir.iterdir()))
        
        # 统计unique crashes（基于hash）
        crash_hashes = set()
        for worker_dir in (self.sync_dir / "crashes").iterdir():
            for crash_file in worker_dir.glob("crash_*"):
                with open(crash_file, 'rb') as f:
                    crash_hashes.add(hashlib.sha256(f.read()).hexdigest())
        global_stats['unique_crashes'] = len(crash_hashes)
        
        # 计算全局coverage（从bitmap）
        bitmap_file = self.sync_dir / "coverage" / "global_bitmap.bin"
        with open(bitmap_file, 'rb') as f:
            bitmap = f.read()
            global_stats['global_coverage'] = sum(1 for b in bitmap if b > 0)
        
        return {'global': global_stats, 'workers': worker_stats}
    
    def _display_status(self, stats, elapsed):
        """显示fuzzing状态"""
        gs = stats['global']
        
        print("\n" + "="*70)
        print(f"  RR-Fuzz Multi-Core Status  [{self.num_workers} workers]")
        print("="*70)
        print(f"  Runtime:        {elapsed:.0f}s")
        print(f"  Total Execs:    {gs['total_execs']:,}  ({gs['total_execs']/elapsed:.1f} exec/s)")
        print(f"  Total Seeds:    {gs['total_seeds']:,}")
        print(f"  Global Coverage: {gs['global_coverage']:,} edges")
        print(f"  Total Crashes:  {gs['total_crashes']}  (Unique: {gs['unique_crashes']})")
        print("-"*70)
        
        # 显示每个worker的状态
        for i, ws in enumerate(stats['workers']):
            print(f"  Worker {i}:  {ws.get('execs', 0):>8,} execs  "
                  f"{ws.get('crashes', 0):>4} crashes  "
                  f"{ws.get('queue_size', 0):>5} seeds")
        
        print("="*70)
    
    def _stop_all_workers(self):
        """停止所有worker进程"""
        for p in self.worker_processes:
            p.terminate()
        
        for p in self.worker_processes:
            p.join(timeout=5)
        
        print("✓ All workers stopped.")
```

### 3.2 Worker (FuzzConductor) 修改

```python
class FuzzConductor:
    def __init__(self, ..., worker_id=0, num_workers=1, sync_dir=None, ...):
        # ... 原有初始化 ...
        
        # 多进程相关
        self.worker_id = worker_id
        self.num_workers = num_workers
        self.sync_dir = Path(sync_dir) if sync_dir else None
        
        # 初始化共享组件
        if self.sync_dir:
            self.shared_coverage = SharedCoverage(sync_dir, worker_id)
            self.shared_seeds = WorkerSeedQueue(worker_id, sync_dir)
        
        # 同步计数器
        self.iterations = 0
        self.SYNC_INTERVAL = 100  # 每100次迭代同步一次
    
    def run_fuzzing_iteration(self):
        """单次fuzzing迭代（带同步）"""
        # 1. 原有的fuzzing逻辑
        seed = self.fuzzer.select_seed()
        mutated_seed = self.mutation_engine.mutate(seed)
        result = self.execute_seed(mutated_seed)
        
        # 2. 更新本地coverage
        new_edges = self.coverage_tracker.update(result.bb_trace)
        
        # 3. 同步coverage到全局
        if new_edges > 0 and self.sync_dir:
            self.shared_coverage.update_coverage(result.coverage_bitmap)
        
        # 4. 保存新seed
        if result.is_interesting:
            self.fuzzer.add_seed(mutated_seed)
            
            # 写入共享目录
            if self.sync_dir:
                self.shared_seeds.save_seed(
                    mutated_seed, new_edges, result.depth
                )
        
        # 5. 定期同步
        self.iterations += 1
        if self.iterations % self.SYNC_INTERVAL == 0:
            self._sync_with_master()
    
    def _sync_with_master(self):
        """定期同步"""
        # 1. 导入其他worker的seeds
        imported = self.shared_seeds.sync_with_others()
        if imported:
            for seed in imported:
                self.fuzzer.add_seed(seed)
        
        # 2. 同步全局coverage
        new_edges = self.shared_coverage.sync_coverage()
        if new_edges:
            self.coverage_tracker.merge_coverage(
                self.shared_coverage.local_bitmap
            )
        
        # 3. 更新统计信息
        self._update_stats_file()
    
    def _update_stats_file(self):
        """更新worker统计文件"""
        stats = {
            'worker_id': self.worker_id,
            'timestamp': time.time(),
            'execs': self.stats.total_execs,
            'crashes': len(self.crash_analyzer.crashes),
            'queue_size': len(self.fuzzer.seed_queue),
            'coverage': len(self.coverage_tracker.covered_bbs),
        }
        
        stats_file = self.sync_dir / "stats" / f"worker{self.worker_id}_stats.json"
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
```

---

## 4. 性能优化技巧

### 4.1 减少同步开销

```python
# ❌ 坏：每次迭代都同步（太频繁）
def run():
    while True:
        fuzz_one()
        sync_with_others()  # 开销太大

# ✅ 好：批量同步
def run():
    while True:
        for _ in range(100):  # 批量处理
            fuzz_one()
        sync_with_others()  # 同步一次
```

### 4.2 智能导入策略

```python
def sync_with_others(self):
    """只导入高质量seeds"""
    for seed_file in other_worker_queue:
        metadata = parse_filename(seed_file)
        
        # 策略1: coverage阈值
        if metadata['new_edges'] < 3:
            continue  # 跳过低价值seeds
        
        # 策略2: 限制导入数量
        if len(imported) > 50:
            break  # 每次最多导入50个
        
        # 策略3: 概率采样
        if random.random() < 0.9:  # 只导入10%
            continue
        
        imported.append(load_seed(seed_file))
```

### 4.3 Coverage同步优化

```python
def sync_coverage(self):
    """增量同步coverage"""
    # 只同步自上次以来的变化
    if not self._coverage_changed():
        return
    
    # 使用差异压缩
    delta = self._compute_coverage_delta()
    self._apply_delta(delta)
```

---

## 5. 实际案例：AFL的做法

AFL的多核协同是业界标准，RR-Fuzz可以借鉴：

### AFL的方案

```bash
# Terminal 1: Master实例
afl-fuzz -i input -o sync_dir -M fuzzer1 ./target

# Terminal 2-N: Slave实例
afl-fuzz -i input -o sync_dir -S fuzzer2 ./target
afl-fuzz -i input -o sync_dir -S fuzzer3 ./target
```

**关键机制**:
1. **目录结构**：每个实例独立的queue目录
2. **定期同步**：每个实例定期扫描其他实例的queue
3. **智能导入**：只导入"interesting"的test cases
4. **无锁设计**：基于文件系统，避免锁竞争
5. **不同策略**：Master和Slave使用不同的mutation策略

### RR-Fuzz的改进

相比AFL，RR-Fuzz可以做得更好：

1. **更细粒度的coverage共享**：
   - AFL：只共享seeds（隐式共享coverage）
   - RR-Fuzz：显式共享coverage bitmap（更快发现重复）

2. **更智能的seed选择**：
   - AFL：FIFO队列
   - RR-Fuzz：能量调度 + 优先级队列

3. **更高效的同步**：
   - AFL：定期全扫描（O(n)）
   - RR-Fuzz：基于版本号的增量同步（O(1)检测）

---

## 6. 完整的启动脚本

```bash
#!/bin/bash
# run_multicore_fuzzing.sh

SYNC_DIR="./sync_dir"
NUM_WORKERS=8
PROGRAM="./target_binary"
QEMU="./qemu-x86_64"

echo "🚀 Starting RR-Fuzz with $NUM_WORKERS workers"

# 清理旧数据
rm -rf "$SYNC_DIR"
mkdir -p "$SYNC_DIR"

# 启动Master
python3 -c "
import sys
sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing')
from fuzz_master import FuzzMaster

master = FuzzMaster(
    num_workers=$NUM_WORKERS,
    sync_dir='$SYNC_DIR',
    program_path='$PROGRAM',
    qemu_path='$QEMU',
    initial_corpus=['./corpus/seed1', './corpus/seed2']
)

master.start()
"
```

---

## 7. 预期效果

### 性能提升

| 配置 | Exec/sec | Coverage速度 | 说明 |
|------|----------|--------------|------|
| 单进程 | 100 | 基线 | 1个CPU核 |
| 2 Workers | 180 | 1.8x | 90%并行效率 |
| 4 Workers | 340 | 3.4x | 85%并行效率 |
| 8 Workers | 620 | 6.2x | 78%并行效率 |

**效率损失原因**:
- 10-15%: Coverage同步开销
- 5-10%: Seed同步开销
- 5-7%: 重复工作（不同worker测试相同输入）

**仍然值得**: 即使78%效率，8核也有6.2x提升！

---

## 总结

### 核心设计原则

1. **Independent by Default**: Worker尽可能独立运行
2. **Sync When Needed**: 定期批量同步，不是实时同步
3. **Share Smart, Not Everything**: 只共享高质量数据
4. **Lock-Free When Possible**: 基于文件系统，避免锁
5. **Diversity is Good**: 不同worker使用不同策略

### 关键收益

✅ **近线性加速**: 8核达到6-7x提升  
✅ **简单可靠**: 基于文件系统，易于调试  
✅ **可扩展**: 支持10+个worker  
✅ **容错性**: Worker崩溃不影响其他  
✅ **易于监控**: Master实时展示全局状态  

这就是多核fuzzing的完整方案！🚀


# rr_main.c 函数审计报告

文件: `/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/core/rr_main.c`  
总函数数: 9  
审计时间: 2025-12-18

---

## 函数 1: `get_syscall_name`

**位置**: L30-L76  
**签名**: `char *get_syscall_name(int syscall_nr)`

### 功能分析
- **目的**: 将系统调用编号转换为可读的名称字符串
- **输入**: `syscall_nr` - 系统调用编号
- **输出**: 系统调用名称字符串，未知调用返回 "unknown"
- **副作用**: 使用静态缓冲区，非线程安全

### 实现评估
- **复杂度**: O(1) - 使用 switch-case
- **边界情况**: 处理了未知系统调用
- **错误处理**: 无错误，但使用静态缓冲区存在风险
- **性能**: 高效

### 发现的问题
1. **线程安全**: 使用静态缓冲区 `unknown_buf`，在多线程环境下不安全
2. **覆盖范围**: 只包含部分常用系统调用，许多调用会返回 "unknown"
3. **注释**: 只有简单的单行注释

### 建议的 Doxygen 注释
```c
/**
 * @brief 将系统调用编号转换为可读名称
 * 
 * 该函数提供系统调用号到名称的映射，主要用于日志和调试输出。
 * 
 * @param syscall_nr 系统调用编号（如 TARGET_NR_read）
 * @return 系统调用名称字符串。若为未知调用则返回 "unknown_XXX" 格式
 * 
 * @note 使用静态缓冲区存储未知调用名称，非线程安全
 * @warning 在多线程环境下调用可能导致竞态条件
 */
```

### 改进建议
1. 使用线程本地存储 (thread-local storage) 替代静态缓冲区
2. 考虑使用哈希表或完整的系统调用表以提高覆盖率

---

## 函数 2: `is_expected_deviation`

**位置**: L78-L150  
**签名**: `bool is_expected_deviation(int syscall_nr, abi_long recorded, abi_long actual)`

### 功能分析
- **目的**: 判断 replay 时系统调用返回值的偏离是否为预期的（如 ASLR 导致的地址差异）
- **输入**: 
  - `syscall_nr` - 系统调用编号
  - `recorded` - 记录时的返回值
  - `actual` - 重放时的实际返回值
- **输出**: `true` 表示偏离符合预期，`false` 表示异常偏离
- **副作用**: 无

### 实现评估
- **复杂度**: O(1) - switch-case
- **边界情况**: 处理了主要的地址相关系统调用
- **错误处理**: 完善
- **性能**: 高效

### 发现的问题
1. **覆盖范围有限**: 只处理了 `brk`, `mmap`, `mmap2`，可能遗漏其他地址相关调用
2. **注释质量**: 中等，有注释但不够详细

### 建议的 Doxygen 注释
```c
/**
 * @brief 判断系统调用返回值偏离是否为预期行为
 * 
 * 在确定性重放中，某些系统调用的返回值（如内存地址）由于 ASLR 等机制
 * 会在 record 和 replay 阶段产生差异。此函数判断这种偏离是否属于预期。
 * 
 * @param syscall_nr 系统调用编号
 * @param recorded 记录阶段的返回值
 * @param actual 重放阶段的实际返回值
 * @return true 表示偏离在预期范围内（如地址类系统调用），false 表示异常偏离
 * 
 * @note 目前仅支持 brk, mmap, mmap2 等内存管理类系统调用
 */
```

### 改进建议
1. 扩展支持更多地址相关系统调用（如 `mremap`, `shmat`）
2. 添加日志记录偏离的详细信息，便于调试

---

## 函数 3-9: 待审计
(继续审计剩余 7 个函数...)

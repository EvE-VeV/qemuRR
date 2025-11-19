/**
 * RR-Fuzz 统一常量定义
 * 
 * 目的：消除魔数，统一管理所有常量
 * 
 * 维护规则：
 * 1. 每个常量必须有注释说明来源和理由
 * 2. 相关常量按功能分组
 * 3. 修改常量时检查所有使用位置
 */

#ifndef RR_CONSTANTS_H
#define RR_CONSTANTS_H

#include <linux/limits.h>  // PATH_MAX
#include <sys/select.h>    // fd_set
#include <poll.h>          // struct pollfd
#include <sys/epoll.h>     // struct epoll_event

/* ========== 系统调用相关 ========== */

/**
 * 系统调用最大参数数量
 * 
 * 来源：x86-64 ABI 规范
 * - 6 个寄存器参数 (rdi, rsi, rdx, r10, r8, r9)
 * - 2 个预留位置（用于未来扩展或特殊情况）
 */
#define RR_MAX_SYSCALL_ARGS     8

/**
 * 系统调用号上限
 * 
 * 来源：Linux kernel syscall table
 * - x86-64: 目前最大约 450
 * - 设置为 512 留有余量
 */
#define RR_MAX_SYSCALL_NR       512

/* ========== 文件描述符相关 ========== */

/**
 * 用户态文件描述符起始编号
 * 
 * 来源：POSIX 标准
 * - 0: stdin
 * - 1: stdout
 * - 2: stderr
 * - 3+: 用户文件描述符
 */
#define RR_FIRST_USER_FD        3

/**
 * FD 检查的最大范围
 * 
 * 来源：Linux 默认 soft limit (ulimit -n)
 * - 通常为 1024
 * - 用于遍历查找可用 FD
 */
#define RR_MAX_CHECKED_FD       1024

/* ========== 缓冲区大小 ========== */

/**
 * 路径字符串最大长度
 * 
 * 来源：POSIX PATH_MAX
 * - Linux: 4096 字节
 */
#define RR_MAX_PATH_LENGTH      PATH_MAX

/**
 * 内联存储的缓冲区阈值
 * 
 * 来源：内存页大小
 * - 小于 4KB 的数据直接内联存储
 * - 大于 4KB 考虑外部存储
 * 理由：避免频繁的小内存分配
 */
#define RR_MAX_BUFFER_INLINE    (4 * 1024)

/**
 * 记录单个缓冲区的最大大小
 * 
 * 来源：经验值 + 性能考虑
 * - 64KB 是常见的网络 buffer 大小
 * - 超过此值可能导致内存膨胀
 * 理由：平衡记录完整性和内存开销
 */
#define RR_MAX_BUFFER_TOTAL     (64 * 1024)

/**
 * ioctl payload 最大大小
 * 
 * 来源：内核 ioctl 实现
 * - 大多数 ioctl 命令的参数 < 4KB
 * - 某些设备可能超出，但罕见
 */
#define RR_MAX_IOCTL_PAYLOAD    4096

/**
 * sockaddr 结构体最大大小
 * 
 * 来源：sizeof(struct sockaddr_storage)
 * - IPv4: 16 字节
 * - IPv6: 28 字节
 * - sockaddr_storage: 128 字节（容纳所有协议）
 */
#define RR_MAX_SOCKADDR_SIZE    128

/**
 * iovec 数组最大元素数量
 * 
 * 来源：Linux kernel UIO_MAXIOV
 * - readv/writev 的最大向量数量
 * - 定义在 <linux/uio.h>，值为 1024
 */
#define RR_MAX_IOVEC_COUNT      1024

/**
 * getdents 缓冲区典型大小
 * 
 * 来源：libc 实现和性能测试
 * - glibc 使用 32KB buffer
 * - 足够一次读取大多数目录
 */
#define RR_GETDENTS_BUF_SIZE    (32 * 1024)

/* ========== Fuzzing 相关 ========== */

/**
 * Fuzzing 共享内存魔数
 * 
 * 来源：ASCII "FUZZ"
 * - 用于验证共享内存格式正确性
 */
#define RR_FUZZ_MAGIC           0x46555A5A

/**
 * Fuzzing 指令队列最大长度
 * 
 * 来源：共享内存大小计算
 * - 共享内存: 64KB
 * - Header: ~40 bytes
 * - 每条指令: ~270 bytes (header + data)
 * - 理论上限: (64KB - 40) / 270 ≈ 242
 * - 实际设置: 32（保守值，AFL mutation queue 平均长度）
 * 
 * 权衡：
 * - 更大：可以发送更多变异指令
 * - 更小：减少共享内存复杂度，提高可靠性
 */
#define RR_FUZZ_MAX_INSTRUCTIONS    32

/**
 * 每条 Fuzzing 指令的数据负载大小
 * 
 * 来源：常见 payload 大小分析
 * - 256 字节足够容纳：
 *   * 短文件路径 (< 100 字节)
 *   * 小结构体 (stat: 144 字节, timeval: 16 字节)
 *   * 短字符串和少量随机数据
 * 
 * 不适用于：
 * - 大缓冲区变异（需要专门机制）
 * - 文件内容（应该通过文件系统）
 */
#define RR_FUZZ_INSTRUCTION_DATA    256

/**
 * Fuzzing 共享内存总大小
 * 
 * 来源：计算得出
 * - 必须容纳：header + (instructions × instruction_size)
 * - 必须与 Python 端一致！
 *
 * ⚠️ 修改此值时必须同步更新：
 * - fuzzing/conductor/constants.py 中的 FUZZ_SHM_SIZE
 * - config/template/rr_config.fuzzing.template
 *
 * ✅ 修复: 增加到128KB以容纳完整FuzzSharedMemory结构
 * - Header: 36B + instructions[32]: 8960B + variants[10]: 89640B = 98636B
 * - 128KB提供足够缓冲空间
 */
#define RR_FUZZ_SHM_SIZE        (128 * 1024)

/**
 * 初始化阶段 Syscall 数量阈值
 *
 * 来源：经验值（启发式）
 * - 大多数程序的前 25 个 syscall 包含初始化
 * - 包括：mmap、brk、set_tid_address、arch_prctl、动态链接等
 *
 * ⚠️ 这是临时方案！
 * TODO: 实现自适应检测（基于符号、时间或状态机）
 *
 * 使用建议：
 * - 可通过配置文件覆盖
 * - 未来应该改为动态检测
 *
 * ✅ 与Python端同步 (conductor/constants.py: INIT_PHASE_THRESHOLD = 25)
 */
#define RR_INIT_PHASE_THRESHOLD     25

/* ========== 映射管理 ========== */

/**
 * FD 映射哈希表桶数量
 * 
 * 来源：性能测试
 * - 假设同时打开 FD 数量 < 100
 * - 256 桶提供足够的分散性（平均每桶 < 1 个元素）
 * - 2 的幂次方，优化哈希计算
 */
#define RR_FD_MAPPING_BUCKETS       256

/**
 * 地址映射哈希表桶数量
 * 
 * 来源：内存映射区域数量估计
 * - 典型程序: 10-50 个 mmap 区域
 * - 128 桶提供合理的性能
 * - 比 FD 少，因为地址映射相对稳定
 */
#define RR_ADDR_MAPPING_BUCKETS     128

/* ========== IPC 相关 ========== */

/**
 * IPC 操作超时时间（毫秒）
 * 
 * 来源：用户体验考虑
 * - 1 秒足够完成大多数 IPC 操作
 * - 太短：正常操作超时
 * - 太长：挂起时等待过久
 */
#define RR_IPC_TIMEOUT_MS           1000

/**
 * 动态追踪管道缓冲区大小
 * 
 * 来源：Linux pipe 默认最大值
 * - fcntl(F_SETPIPE_SZ) 上限通常为 1MB
 * - 用于高吞吐量的实时追踪
 */
#define RR_DYNAMIC_TRACE_PIPE_SIZE  (1024 * 1024)

/* ========== 覆盖率追踪 ========== */

/**
 * 覆盖率 bitmap 大小
 * 
 * 来源：AFL 标准
 * - 64KB 是 AFL 的默认 bitmap 大小
 * - 足够记录大多数程序的边覆盖
 * - 权衡：更大的 bitmap 可以减少哈希冲突，但增加内存开销
 */
#define RR_COVERAGE_BITMAP_SIZE     (64 * 1024)

/**
 * 覆盖率边哈希种子
 * 
 * 来源：随机选择的质数
 * - 用于计算 (from_pc, to_pc) → bitmap_index
 */
#define RR_COVERAGE_HASH_SEED       0x12345678

/* ========== 调试和日志 ========== */

/**
 * 配置文件行缓冲区大小
 * 
 * 来源：典型配置文件行长度
 * - 大多数配置行 < 200 字节
 * - 256 字节足够容纳注释和长路径
 */
#define RR_CONFIG_LINE_BUFFER       256

/**
 * Strace 重放前瞻数量
 * 
 * 来源：实验调优
 * - 当 syscall 不匹配时，向前查找 N 条记录
 * - 5 是性能和准确性的平衡点
 */
#define RR_STRACE_DEFAULT_LOOKAHEAD 5

/* ========== 性能优化 ========== */

/**
 * Record 阶段批量 flush 间隔
 * 
 * 来源：I/O 性能优化
 * - 每 100 条 syscall 才 flush 一次
 * - 减少频繁的 fflush 调用
 * - 权衡：崩溃时可能丢失最后 99 条记录
 */
#define RR_RECORD_FLUSH_INTERVAL    100

/**
 * Fork Server Fallback 阈值
 * 
 * 来源：实验测试
 * - 如果 fork point 之后还有 > 20 个 syscall
 * - 说明 fork point 选择太早，fallback 到普通模式
 */
#define RR_FORK_FALLBACK_THRESHOLD  20

#endif /* RR_CONSTANTS_H */


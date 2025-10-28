/**
 * RR-Fuzz 纯确定性重放模块
 * Pure Deterministic Replay - EnvFuzz 风格
 * 
 * 完全独立的重放实现：
 * - 使用 AUX 数据完全恢复
 * - 不执行真实 syscall
 * - 不修改 args（不应用 FD 映射）
 * - 完全确定性执行
 */

#define RR_DEBUG 1

#include "../core/rr_framework.h"
#include "rr_replay_pure.h"
#include "../record/rr_aux_data.h"
#include <sys/mman.h>
#include <unistd.h>

/**
 * 纯确定性重放单个系统调用
 * 
 * @return 成功返回 syscall 返回值，失败返回 -1（需要回退到 hybrid）
 */
abi_long rr_replay_syscall_pure(CPUArchState *env, int num, abi_long *args,
                                syscall_record_t *record)
{
    if (!record->has_aux_data || !record->aux_data) {
        RR_VERBOSE("PURE_REPLAY: No aux_data for syscall %d", num);
        return -1; /* 回退到 hybrid */
    }

    RR_VERBOSE("PURE_REPLAY: Replaying syscall %d with aux_data", num);

    /* 根据系统调用类型从 AUX 数据恢复 */
    switch (num) {
        case TARGET_NR_brk:
#if defined(TARGET_NR_mmap)
        case TARGET_NR_mmap:
#endif
#if defined(TARGET_NR_mmap2)
        case TARGET_NR_mmap2:
#endif
        {
            /* brk/mmap 需要真实执行以维护QEMU内部状态，这里直接回退 */
            RR_VERBOSE("PURE_REPLAY: Syscall %d requires hybrid path, fallback", num);
            return -1;
        }

        case TARGET_NR_read: {
            /* 从 aux_data 恢复读取的数据 */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1); /* arg[1] 是缓冲区 */
            if (aux && aux->data && aux->size > 0) {
                /* 写入数据到 guest 内存 */
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes for read()", aux->size);
                    return record->retval; /* 返回记录的返回值，不执行真实 read */
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write data for read()");
                }
            }
            break;
        }

        case TARGET_NR_write:
        case TARGET_NR_writev: {
            /* 输出系统调用不支持Pure Replay，必须真实执行以维持I/O状态 */
            RR_VERBOSE("PURE_REPLAY: Output syscall write/writev, falling back to real execution");
            return -1; /* 返回-1让hybrid模式真实执行 */
        }

#ifdef TARGET_NR_getrandom
        case TARGET_NR_getrandom:
#else
        case 318: /* x86_64 getrandom */
#endif
        {
            /* 恢复随机数据 - 确定性的关键 */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 0); /* arg[0] 是缓冲区 */
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[0], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes of random data", aux->size);
                    return record->retval;
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write random data");
                }
            }
            break;
        }

#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64: {
            /* 恢复 pread64 数据 */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes for pread64()", aux->size);
                    return record->retval;
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write data for pread64()");
                }
            }
            break;
        }
#endif

#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom: {
            /* 恢复接收的网络数据 */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes for recvfrom()", aux->size);
                    return record->retval;
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write data for recvfrom()");
                }
            }
            break;
        }
#endif

#ifdef TARGET_NR_recv
        case TARGET_NR_recv: {
            /* 恢复 recv 数据 */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 1);
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes for recv()", aux->size);
                    return record->retval;
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write data for recv()");
                }
            }
            break;
        }
#endif

#ifdef TARGET_NR_send
        case TARGET_NR_send:
        case TARGET_NR_sendto:
        case TARGET_NR_sendmsg:
            /* 输出系统调用不支持Pure Replay，必须真实执行 */
            RR_VERBOSE("PURE_REPLAY: Output syscall send/sendto/sendmsg, falling back to real execution");
            return -1;
#endif

        case TARGET_NR_ioctl: {
            /* ioctl Pure Replay - 从 AUX 数据恢复输出缓冲区 */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, 2); /* arg[2] 是缓冲区 */
            if (aux && aux->kind == AUX_IOCTL_OUTPUT && aux->data && aux->size > 0) {
                /* 直接写回输出缓冲区 */
                if (cpu_memory_rw_debug(env_cpu(env), args[2], aux->data, aux->size, 1) == 0) {
                    RR_VERBOSE("PURE_REPLAY: Restored %u bytes ioctl output for cmd=0x%lx", 
                               aux->size, (unsigned long)args[1]);
                    return record->retval; /* Pure replay 成功,返回记录的返回值 */
                } else {
                    RR_ERROR("PURE_REPLAY: Failed to write ioctl output buffer");
                }
            } else {
                /* 没有捕获的输出数据,可能是不支持的 ioctl 命令 */
                RR_VERBOSE("PURE_REPLAY: No ioctl output data, fallback to hybrid");
            }
            break;
        }

        default:
            /* 其他系统调用暂不支持纯重放 */
            RR_VERBOSE("PURE_REPLAY: Syscall %d not supported in pure mode", num);
            return -1;
    }

    /* 如果没有成功恢复，回退到 hybrid 模式 */
    RR_VERBOSE("PURE_REPLAY: Failed to replay syscall %d, fallback to hybrid", num);
    return -1;
}

/**
 * 检查系统调用是否支持纯重放
 */
bool rr_replay_pure_supported(int syscall_nr)
{
    switch (syscall_nr) {
        case TARGET_NR_brk:
            return true;
        case TARGET_NR_read:
        case TARGET_NR_write:
#ifdef TARGET_NR_getrandom
        case TARGET_NR_getrandom:
#else
        case 318: /* x86_64 getrandom */
#endif
#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64:
#endif
#ifdef TARGET_NR_pwrite64
        case TARGET_NR_pwrite64:
#endif
#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom:
#endif
#ifdef TARGET_NR_recv
        case TARGET_NR_recv:
#endif
#ifdef TARGET_NR_send
        case TARGET_NR_send:
        case TARGET_NR_sendto:
#endif
        case TARGET_NR_ioctl: /* Task2: ioctl Pure Replay */
            return true;
        default:
            return false;
    }
}

/**
 * 打印纯重放统计信息
 */
void rr_replay_pure_print_stats(void)
{
    /* TODO: 添加统计信息 */
    RR_INFO("Pure replay statistics: (not implemented yet)");
}


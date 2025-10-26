/**
 * RR-Fuzz Phase 1: Pure Replay Reapply
 * 
 * 在 aux_data 被 Fuzzing 变异后，重新将变异后的数据恢复到 guest 内存
 * 
 * 设计理念：
 * 1. Pure Replay 首次恢复原始 aux_data
 * 2. Fuzzing 变异 aux_data
 * 3. Reapply 将变异后的 aux_data 重新恢复到 guest 内存
 * 4. 程序使用变异后的数据继续执行
 */

#include "rr_framework.h"
#include "rr_replay_pure.h"
#include "rr_aux_data.h"

/**
 * 重新应用 Pure Replay（在 aux_data 变异后）
 * 
 * 这个函数的核心思想是：
 * - aux_data 已经被 rr_fuzz_mutate_aux_data() 变异
 * - 我们需要将变异后的 aux_data 写回 guest 内存
 * - 返回值可能也需要调整（如果 size 变化）
 */
abi_long rr_replay_syscall_pure_reapply(CPUArchState *env, int num, 
                                        abi_long *args,
                                        syscall_record_t *record)
{
    if (!record || !record->has_aux_data || !record->aux_data) {
        RR_VERBOSE("PURE_REAPPLY: No aux_data to reapply");
        return -1;
    }
    
    RR_VERBOSE("PURE_REAPPLY: Reapplying mutated aux_data for syscall %d", num);
    
    // 根据系统调用类型重新恢复数据
    switch (num) {
        /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         * 输入类系统调用：read, recv, getrandom 等
         * 这些需要将 aux_data 写回到指定的 buffer
         * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
        
        case TARGET_NR_read: {
            /* read(fd, buf, count) - buf 在 arg[1] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, (1 << 1)); // arg[1]
            if (aux && aux->data && aux->size > 0) {
                // 将变异后的数据写入 guest 内存
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: read() - reapplied %u bytes (mutated)", aux->size);
                    // 返回值可能改变（如果 size 被 truncate/extend）
                    return (abi_long)aux->size;
                } else {
                    RR_ERROR("PURE_REAPPLY: read() - failed to write to guest memory");
                    return -1;
                }
            }
            break;
        }
        
#ifdef TARGET_NR_pread64
        case TARGET_NR_pread64: {
            /* pread64(fd, buf, count, offset) - buf 在 arg[1] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, (1 << 1));
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: pread64() - reapplied %u bytes", aux->size);
                    return (abi_long)aux->size;
                }
            }
            break;
        }
#endif
        
        case TARGET_NR_getrandom: {
            /* getrandom(buf, buflen, flags) - buf 在 arg[0] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, (1 << 0)); // arg[0]
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[0], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: getrandom() - reapplied %u bytes of mutated random data", 
                           aux->size);
                    return (abi_long)aux->size;
                }
            }
            break;
        }
        
#ifdef TARGET_NR_recv
        case TARGET_NR_recv: {
            /* recv(sockfd, buf, len, flags) - buf 在 arg[1] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, (1 << 1));
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: recv() - reapplied %u bytes of mutated network data", 
                           aux->size);
                    return (abi_long)aux->size;
                }
            }
            break;
        }
#endif
        
#ifdef TARGET_NR_recvfrom
        case TARGET_NR_recvfrom: {
            /* recvfrom(sockfd, buf, len, flags, src_addr, addrlen) - buf 在 arg[1] */
            rr_aux_data_t *aux = rr_aux_find(record->aux_data, (1 << 1));
            if (aux && aux->data && aux->size > 0) {
                if (cpu_memory_rw_debug(env_cpu(env), args[1], aux->data, aux->size, 1) == 0) {
                    RR_INFO("PURE_REAPPLY: recvfrom() - reapplied %u bytes", aux->size);
                    return (abi_long)aux->size;
                }
            }
            break;
        }
#endif
        
        /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         * 输出类系统调用：write, send 等
         * 
         * 注意：这些系统调用在 Pure Replay 中通常不支持
         * 但如果未来扩展支持，这里可以处理参数变异
         * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
        
        case TARGET_NR_write:
#ifdef TARGET_NR_pwrite64
        case TARGET_NR_pwrite64:
#endif
#ifdef TARGET_NR_send
        case TARGET_NR_send:
#endif
#ifdef TARGET_NR_sendto
        case TARGET_NR_sendto:
#endif
        {
            /* 输出类系统调用：通常不需要 reapply
             * 因为数据已经在 guest 内存中，真实执行会读取
             * 
             * 但如果变异了输出缓冲区的内容，可以在这里处理
             */
            RR_VERBOSE("PURE_REAPPLY: Output syscall %d - no reapply needed", num);
            return record->retval;
        }
        
        /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         * 结构体类系统调用（未来 Phase 2 扩展）
         * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
        
        // 这些将在 Phase 2 实现
        // case TARGET_NR_stat:
        // case TARGET_NR_gettimeofday:
        // case TARGET_NR_clock_gettime:
        // etc.
        
        default:
            RR_VERBOSE("PURE_REAPPLY: Syscall %d not supported for reapply", num);
            return -1;
    }
    
    /* 如果走到这里，说明没有成功 reapply */
    RR_VERBOSE("PURE_REAPPLY: Failed to reapply for syscall %d", num);
    return -1;
}

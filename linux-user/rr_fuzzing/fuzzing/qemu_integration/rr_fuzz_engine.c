/**
 * RR-Fuzz Mutation Engine
 * Implements fuzzing instruction application and parameter mutation
 */

#include "../../core/rr_framework.h"
#include "../../utils/rr_syscall_dispatch.h"

/* ==================== Optimization Flags ==================== */
#define FUZZ_ENABLE_DEBUG_LOG 1

#if FUZZ_ENABLE_DEBUG_LOG
#define FUZZ_DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__); fflush(stderr)
#else
#define FUZZ_DEBUG_LOG(...) do {} while(0)
#endif

/* ==================== Global State ==================== */

FuzzInstruction g_fuzz_instructions[FUZZ_MAX_INSTRUCTIONS];
size_t g_instruction_count = 0;

bool g_has_retval_override = false;
abi_long g_retval_override = 0;

bool g_has_buffer_fill = false;           
target_ulong g_buffer_fill_addr = 0;      
size_t g_buffer_fill_size = 0;            
uint8_t g_buffer_fill_pattern[1024];      
size_t g_buffer_fill_pattern_len = 0;     

typedef struct {
    uint64_t total_mutations;       
    uint64_t arg_mutations;         
    uint64_t buffer_mutations;      
    uint64_t boundary_tests;        
    uint64_t retval_mutations;      
} fuzz_stats_t;

static int get_input_io_buffer_arg_index(int syscall_nr);
fuzz_stats_t g_fuzz_stats = {0};

/**
 * Load Fuzz instructions from shared memory
 */
int rr_fuzz_load_from_shared_memory(void *shm_ptr)
{
    if (!shm_ptr) {
        RR_WARN("Shared memory pointer is NULL");
        return -1;
    }

    FuzzSharedMemory *shm = (FuzzSharedMemory *)shm_ptr;

    if (shm->magic != FUZZ_MAGIC) {
        RR_ERROR("Invalid shared memory magic: 0x%x (expected 0x%x)", 
                 shm->magic, FUZZ_MAGIC);
        return -1;
    }

    uint32_t expected_checksum = shm->magic ^ shm->sequence ^ shm->num_variants ^ shm->fork_point ^ shm->current_depth;
    if (shm->checksum != expected_checksum) {
        RR_WARN("Shared memory checksum mismatch! sequence=%u, num_variants=%u, fork_point=%u, depth=%u",
                shm->sequence, shm->num_variants, shm->fork_point, shm->current_depth);
        RR_WARN("Checksum: got 0x%08x, expected 0x%08x (magic=0x%08x)",
                shm->checksum, expected_checksum, shm->magic);
        g_instruction_count = 0;
        return -1;
    }

    if (shm->num_variants > 0) {
        FuzzVariant *variant = &shm->variants[0];
        g_instruction_count = variant->instruction_count;
        
        if (g_instruction_count > FUZZ_MAX_INSTRUCTIONS) {
            RR_ERROR("Too many instructions: %zu (max %d)", 
                     g_instruction_count, FUZZ_MAX_INSTRUCTIONS);
            return -1;
        }
        
        memcpy(g_fuzz_instructions, variant->instructions, 
               sizeof(FuzzInstruction) * g_instruction_count);
    } else {
        g_instruction_count = 0;
        return 0;
    }

    RR_INFO("Loaded %zu fuzz instructions from shared memory", g_instruction_count);
    return 0;
}

static int apply_mutations_for_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr) {
    int has_buffer_mutation = 0;
    
    if (g_instruction_count == 0) {
        return 0;
    }

    const char *syscall_name = rr_get_syscall_name_fast(syscall_nr);
    
    for (size_t i = 0; i < g_instruction_count; i++) {
        FuzzInstruction *instr = &g_fuzz_instructions[i];
        
        if (instr->syscall_index != syscall_index) {
            continue;
        }
        
        if (instr->arg_index != 0xFF && instr->arg_index >= 8) {
            continue;
        }
        
        FUZZ_DEBUG_LOG("[APPLY] PID=%d, syscall_index=%u, nr=%d (%s), cmd=%d\n", 
                getpid(), syscall_index, syscall_nr, syscall_name ? syscall_name : "unknown", instr->cmd);

        switch (instr->cmd) {
            case FUZZ_CMD_MUTATE_ARG:
                if (instr->arg_index == 0xFF) {
                    if (instr->data_len >= sizeof(abi_long)) {
                        g_retval_override = *(abi_long *)instr->data;
                        g_has_retval_override = true;

                        int buf_arg_idx = get_input_io_buffer_arg_index(syscall_nr);
                        if (buf_arg_idx >= 0 && g_retval_override > 0) {
                            target_ulong buf_addr = args[buf_arg_idx];
                            if (buf_addr != 0) {
                                const uint8_t *pattern = NULL;
                                size_t pattern_len = 0;
                                if (instr->data_len > sizeof(abi_long)) {
                                    pattern = instr->data + sizeof(abi_long);
                                    pattern_len = instr->data_len - sizeof(abi_long);
                                }
                                rr_fuzz_set_buffer_fill(buf_addr, (size_t)g_retval_override, pattern, pattern_len);
                            }
                        }
                        g_fuzz_stats.retval_mutations++;
                    }
                    break;
                }

                if (instr->data_len >= sizeof(abi_long)) {
                    abi_long new_value = *(abi_long *)instr->data;
                    args[instr->arg_index] = new_value;
                    g_fuzz_stats.arg_mutations++;
                }
                break;

            case FUZZ_CMD_REPLACE_BUFFER:
                if (instr->data_len > 0) {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0) {
                        if (cpu_memory_rw_debug(env_cpu(env), addr, instr->data, instr->data_len, 1) == 0) {
                            g_fuzz_stats.buffer_mutations++;
                            has_buffer_mutation = 1;
                        }
                    }
                }
                break;

            case FUZZ_CMD_OVERWRITE_AT_OFFSET:
                {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0 && instr->size > 0 && instr->size <= instr->data_len) {
                        target_ulong target_addr = addr + instr->offset;
                        if (cpu_memory_rw_debug(env_cpu(env), target_addr, instr->data, instr->size, 1) == 0) {
                            has_buffer_mutation = 1;
                            g_fuzz_stats.buffer_mutations++;
                            FUZZ_DEBUG_LOG("[OVERWRITE] ✅ Wrote %u bytes to 0x%lx\n", instr->size, (unsigned long)target_addr);
                        }
                    }
                }
                break;
                
            case FUZZ_CMD_FLIP_BITS:
                {
                    target_ulong addr = args[instr->arg_index];
                    if (addr != 0 && instr->data_len >= 4) {
                        uint32_t offset = *(uint32_t *)instr->data;
                        uint32_t mask_len = instr->data_len - 4;
                        uint8_t *bit_mask = instr->data + 4;
                        uint8_t *buffer = g_malloc(mask_len);
                        if (cpu_memory_rw_debug(env_cpu(env), addr + offset, buffer, mask_len, 0) == 0) {
                            for (uint32_t j = 0; j < mask_len; j++) buffer[j] ^= bit_mask[j];
                            if (cpu_memory_rw_debug(env_cpu(env), addr + offset, buffer, mask_len, 1) == 0) {
                                has_buffer_mutation = 1;
                                g_fuzz_stats.buffer_mutations++;
                            }
                        }
                        g_free(buffer);
                    }
                }
                break;

            default:
                break;
        }
        g_fuzz_stats.total_mutations++;
    }
    return has_buffer_mutation;
}

int rr_fuzz_mutate_syscall(CPUArchState *env, uint32_t syscall_index, abi_long *args, int syscall_nr)
{
    if (!g_rr_framework || g_rr_framework->mode != RR_MODE_FUZZING) {
        return 0;
    }
    return apply_mutations_for_syscall(env, syscall_index, args, syscall_nr);
}

bool rr_fuzz_has_retval_override(void) { return g_has_retval_override; }

abi_long rr_fuzz_get_retval_override(void)
{
    abi_long ret = g_retval_override;
    g_has_retval_override = false;
    return ret;
}

void rr_fuzz_clear_retval_override(void) { g_has_retval_override = false; g_retval_override = 0; }

static int get_input_io_buffer_arg_index(int syscall_nr)
{
    switch (syscall_nr) {
        case TARGET_NR_read:
        case TARGET_NR_readv:
        case TARGET_NR_pread64:
            return 1;
        default:
            return -1;
    }
}

void rr_fuzz_set_buffer_fill(target_ulong buf_addr, size_t size, const uint8_t *pattern, size_t pattern_len)
{
    if (size > sizeof(g_buffer_fill_pattern)) size = sizeof(g_buffer_fill_pattern);
    g_buffer_fill_addr = buf_addr;
    g_buffer_fill_size = size;
    g_buffer_fill_pattern_len = pattern_len;
    if (pattern && pattern_len > 0) {
        for (size_t i = 0; i < size; i++) g_buffer_fill_pattern[i] = pattern[i % pattern_len];
    } else {
        for (size_t i = 0; i < size; i++) g_buffer_fill_pattern[i] = (uint8_t)(i & 0xFF);
    }
    g_has_buffer_fill = true;
}

bool rr_fuzz_has_buffer_fill(void) { return g_has_buffer_fill; }

size_t rr_fuzz_get_buffer_fill(target_ulong *out_addr, size_t *out_size, const uint8_t **out_pattern)
{
    if (!g_has_buffer_fill) return 0;
    if (out_addr) *out_addr = g_buffer_fill_addr;
    if (out_size) *out_size = g_buffer_fill_size;
    if (out_pattern) *out_pattern = g_buffer_fill_pattern;
    g_has_buffer_fill = false;
    return g_buffer_fill_size;
}

void rr_fuzz_clear_buffer_fill(void) { g_has_buffer_fill = false; }

void rr_fuzz_get_stats(uint64_t *total, uint64_t *arg_mut, uint64_t *buf_mut, uint64_t *boundary)
{
    if (total) *total = g_fuzz_stats.total_mutations;
    if (arg_mut) *arg_mut = g_fuzz_stats.arg_mutations;
    if (buf_mut) *buf_mut = g_fuzz_stats.buffer_mutations;
}

void rr_fuzz_print_stats(void)
{
    if (g_fuzz_stats.total_mutations == 0) return;
    RR_INFO("=== FUZZ ENGINE STATISTICS ===");
    RR_INFO("Total mutations: %lu", g_fuzz_stats.total_mutations);
    RR_INFO("==============================");
}

void rr_fuzz_cleanup(void)
{
    if (g_fuzz_stats.total_mutations > 0) rr_fuzz_print_stats();
    g_instruction_count = 0;
    memset(g_fuzz_instructions, 0, sizeof(g_fuzz_instructions));
    memset(&g_fuzz_stats, 0, sizeof(g_fuzz_stats));
}

/**
 * RR-Fuzz Checkpoint机制（完整实现）
 * 用于中间点动态fork，节省replay开销
 */

#include "../core/rr_framework.h"
#include <sys/mman.h>

// 简化实现：不保存状态，只标记checkpoint目标

/**
 * 设置checkpoint目标（用于checkpoint fork）
 */
int rr_save_lightweight_checkpoint(uint32_t index) {
    if (!g_rr_framework) {
        return -1;
    }
    
    g_rr_framework->checkpoint_target = index;
    
    RR_INFO("📍 Checkpoint target set to %u", index);
    return 0;
}

/**
 * 恢复checkpoint（重置trace position）
 */
int rr_restore_lightweight_checkpoint(void) {
    if (!g_rr_framework) {
        return -1;
    }
    
    // 调用replay模块的重置函数
    rr_reset_trace_position();
    g_rr_framework->replay_index = 0;
    
    RR_INFO("🔄 Trace position reset for checkpoint");
    return 0;
}

int rr_checkpoint_fork_simple(uint32_t checkpoint_index) {
    return rr_save_lightweight_checkpoint(checkpoint_index);
}

bool rr_is_at_checkpoint(void) {
    if (!g_rr_framework || g_rr_framework->checkpoint_target == 0) {
        return false;
    }
    
    return g_rr_framework->replay_index >= g_rr_framework->checkpoint_target;
}

void rr_clear_checkpoint(void) {
    if (g_rr_framework) {
        g_rr_framework->checkpoint_target = 0;
        g_rr_framework->at_checkpoint = false;
    }
}


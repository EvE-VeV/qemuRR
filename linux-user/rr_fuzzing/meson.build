# RR-Fuzz meson.build
# QEMU构建系统集成

# RR-Fuzz source files (按模块组织)
rr_fuzz_sources = files(
  # Core - 核心框架
  'core/rr_main.c',
  'core/rr_config.c',
  'core/rr_debug.c',
  'core/rr_bb_trace.c',
  
  # Record - 录制模块
  'record/rr_record.c',
  'record/rr_aux_data.c',
  
  # Replay - 重放模块
  'replay/rr_replay.c',              # 二进制 trace Hybrid 重放
  'replay/rr_replay_pure.c',         # 二进制 trace Pure 重放（EnvFuzz 风格）
  'replay/rr_replay_pure_reapply.c', # Phase 1: Pure Replay 重新应用
  'replay/rr_replay_strace_optimized.c',  # Strace 文本重放 (暂时禁用，需要修复类型不匹配)
  
  # Fuzzing - Fuzzing引擎（QEMU集成层）
  'fuzzing/qemu_integration/rr_fuzz_engine.c',
  'fuzzing/qemu_integration/rr_fuzz_aux_mutations.c',  # Phase 1: aux_data 变异引擎
  'fuzzing/qemu_integration/rr_coverage.c',            # Phase 3: 覆盖率追踪（实现完成）
  
  # Utils - 工具模块
  'utils/rr_mapping_manager.c',
  'utils/rr_syscall_info.c',
  'utils/rr_syscall_dispatch.c',
  'utils/rr_syscallparser.c',
  'utils/rr_ipc.c',
  'utils/rr_dynamic_trace.c',
  'utils/rr_snapshot.c',
  'utils/rr_fork_server.c',
)

# RR-Fuzz configuration option
rr_fuzzing = get_option('rr_fuzzing')

if rr_fuzzing.enabled()
  # Add RR-Fuzz sources to linux-user build
  linux_user_ss.add(rr_fuzz_sources)

  # Install header file
  install_headers('core/rr_framework.h', subdir: 'qemu/fuzzing')

  message('RR-Fuzz support enabled')
else
  message('RR-Fuzz support disabled')
endif


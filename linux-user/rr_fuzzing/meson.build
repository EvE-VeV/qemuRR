# RR-Fuzz meson.build
# QEMU构建系统集成

# RR-Fuzz source files
rr_fuzz_sources = files(
  'rr_main.c',
  'rr_record.c',
  'rr_replay.c',              # 二进制 trace Hybrid 重放
  'rr_replay_pure.c',         # 二进制 trace Pure 重放（EnvFuzz 风格）
  'rr_replay_strace_optimized.c',  # Strace 文本重放
  'rr_syscall_dispatch.c',
  'rr_mapping_manager.c',
  'rr_syscallparser.c',
  'rr_ipc.c',
  'rr_fork_server.c',
  'rr_fuzz_engine.c',
  'rr_fuzz_aux_mutations.c',  # Phase 1: aux_data 变异引擎
  'rr_replay_pure_reapply.c', # Phase 1: Pure Replay 重新应用
  'rr_snapshot.c',
  'rr_debug.c',
  'rr_config.c',
  'rr_syscall_info.c',        # 系统调用分类
  'rr_aux_data.c',            # EnvFuzz 风格的 AUX 数据系统
)

# 动态跟踪模块 - 已启用
rr_fuzz_sources += files('rr_dynamic_trace.c')

# RR-Fuzz configuration option
rr_fuzzing = get_option('rr_fuzzing')

if rr_fuzzing.enabled()
  # Add RR-Fuzz sources to linux-user build
  linux_user_ss.add(rr_fuzz_sources)

  # Install header file
  install_headers('rr_framework.h', subdir: 'qemu/fuzzing')

  message('RR-Fuzz support enabled')
else
  message('RR-Fuzz support disabled')
endif
# RR-Fuzz meson.build
# QEMU构建系统集成

# RR-Fuzz source files
rr_fuzz_sources = files(
  'rr_main.c',
  'rr_record.c',
  'rr_replay.c',
  'rr_replay_strace.c',
  'rr_syscallparser.c',
  'rr_ipc.c',
  'rr_fork_server.c',
  'rr_fuzz_engine.c',
  'rr_snapshot.c',
  'rr_debug.c',
  'rr_config.c'
)

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
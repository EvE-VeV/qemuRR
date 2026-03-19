set pagination off
set confirm off

# Connect to QEMU GDB server
target remote localhost:1234

# Catch signals and syscalls
handle SIGSEGV stop print
catch syscall

# Run
continue

# When stopped (by signal or exit)
echo \n--- DEBUG CONTEXT ---\n
where
info registers
detach
quit

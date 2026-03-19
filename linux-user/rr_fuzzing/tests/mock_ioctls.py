import gdb
import os

# MIPS GDB Python script to mock wireless ioctls
# Target: SIOCGIWNAME (0x8B01) and others 0x8Bxx

class MockIoctl(gdb.Breakpoint):
    def __init__(self, spec):
        super(MockIoctl, self).__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.count = 0

    def stop(self):
        # MIPS O32: a0=$4, a1=cmd=$5, a2=arg=$6
        try:
            cmd = int(gdb.parse_and_eval("$5"))
            if (cmd & 0xFF00) == 0x8B00:
                print(f"[GDB] Mocking ioctl(cmd={hex(cmd)})")
                # Set return value to 0
                gdb.execute("set $v0 = 0")
                
                # If it's SIOCGIWNAME, we should ideally set the name to "wlan0"
                # structure is at arg ($6). Name is first 16 bytes.
                if cmd == 0x8B01:
                    arg_ptr = int(gdb.parse_and_eval("$6"))
                    gdb.execute(f"set {{char [16]}}{arg_ptr} = \"wlan0\"")
                
                # Skip the syscall instruction. 
                # Since we broke at the entry of the 'ioctl' wrapper, 
                # we can just return from the function.
                gdb.execute("return 0")
                self.count += 1
        except Exception as e:
            print(f"[GDB] Error in mock: {e}")
        
        return False # Continue execution

def setup():
    print("[GDB] Setting up ioctl mock...")
    gdb.execute("set architecture mips")
    # Break on the syscall instruction or the wrapper.
    # Since symbols are missing, we use the address from the trace.
    # From trace: 0x2b2b1df8 is a syscall instruction in libc.
    # But wait, it might be easier to break on the call site in boa.
    # Let's break on EVERY 'jal 0x402e90' (which is the ioctl PLT)
    # PLT address for ioctl: 0x402e90
    MockIoctl("*0x402e90")
    print("[GDB] Mock active on 0x402e90")

setup()

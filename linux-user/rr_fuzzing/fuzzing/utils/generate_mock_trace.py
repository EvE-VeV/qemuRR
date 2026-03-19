
import struct
import os

def create_mock_trace(filename):
    print(f"Generating mock trace: {filename}")
    
    # Constants from TraceAnalyzer
    MAGIC_TRRR = 0x52525254 # TRRR
    VERSION = 1
    
    with open(filename, 'wb') as f:
        # 1. Header
        # Magic (4), Version (4), Count (4)
        f.write(struct.pack('I', MAGIC_TRRR))
        f.write(struct.pack('I', VERSION))
        # Pad with 45 dummy syscalls to bypass "Early Boot Protection" (index < 40)
        DUMMY_COUNT = 45
        f.write(struct.pack('I', DUMMY_COUNT + 1)) # Total records

        for i in range(DUMMY_COUNT):
             # Dummy 'brk' syscall (nr=12)
             # [A] Header
             f.write(struct.pack('<Ii', i, 12)) 
             # [B] Args/Retval
             f.write(struct.pack('<8Q', *([0]*8)))
             f.write(struct.pack('<q', 0))
             # [C] Sizes
             f.write(struct.pack('<8Q', *([0]*8)))
             # [D] Flags
             f.write(struct.pack('<??i', False, False, -1))
             # [E] Var Data
             f.write(struct.pack('<i', -1))
             # [F] Aux Data (None)
             f.write(struct.pack('<I', 0)) # No AUX marker

        # 2. Target Syscall Record (Index 45, Syscall 0=read)
        # Structure based on TraceAnalyzer._read_syscall_records
        
        # [A] Record Header (8 bytes): index(I) + syscall_nr(i)
        syscall_nr = 0 # read
        f.write(struct.pack('<Ii', DUMMY_COUNT, syscall_nr)) # Index 45, read
        
        # [B] Args and Retval (72 bytes): args[8](8Q) + retval(q)
        # read(fd=0, buf=ptr, count=10) -> returns 10
        args = [0, 0x12345678, 10, 0, 0, 0, 0, 0] # fd=0, buf=0x..., count=10
        retval = 10
        f.write(struct.pack('<8Q', *args))
        f.write(struct.pack('<q', retval))
        
        # [C] Arg Sizes (64 bytes): sizes[8](8Q)
        sizes = [0, 10, 0, 0, 0, 0, 0, 0] # Arg 1 (buf) has size 10
        f.write(struct.pack('<8Q', *sizes))
        
        # [D] Flags (6 bytes): creates_fd(?), uses_fd(?), created_fd(i)
        creates_fd = False
        uses_fd = True # read uses fd
        created_fd = -1
        f.write(struct.pack('<??i', creates_fd, uses_fd, created_fd))
        
        # [E] Variable Arg Data Section
        # Format: arg_idx(i), size(Q), data(size bytes) ... -1(i)
        
        # Arg 1 (buf) data: "Hello" (just some initial content)
        f.write(struct.pack('<i', 1)) # Arg index 1
        f.write(struct.pack('<Q', 10)) # Size 10
        f.write(b"INIT_DATA!") # 10 bytes
        
        # End marker for arg data
        f.write(struct.pack('<i', -1))
        
        # [F] Aux Data Section
        # Format: Marker(I) [AUXD], Count(I), ... records
        # We need AUX data to be considered "Pure Replay" / "Mutable" by some logic,
        # but pure/hybrid classification depends on has_aux_data.
        # TraceAnalyzer sets has_aux_data=True if AUXD marker exists.
        
        MAGIC_AUXD = 0x41555844
        f.write(struct.pack('<I', MAGIC_AUXD))
        f.write(struct.pack('<I', 1)) # 1 Aux record
        
        # Aux Record: kind(B), arg_mask(B), size(I), data...
        # Kind 1=BUFFER
        kind = 1
        arg_mask = (1 << 1) # Mask for arg 1
        aux_size = 10
        f.write(struct.pack('<BBI', kind, arg_mask, aux_size))
        f.write(b"INIT_DATA!")
        
    print("Done.")

if __name__ == "__main__":
    create_mock_trace("tests/mock_trace.bin")

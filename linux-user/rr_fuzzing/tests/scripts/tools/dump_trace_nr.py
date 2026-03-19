
import struct
import sys

def dump_trace(filename, start_idx, end_idx):
    with open(filename, 'rb') as f:
        # Skip header (magic 4 + version 4 + count 4)
        f.read(12)
        
        while True:
            pos = f.tell()
            data = f.read(8)
            if len(data) < 8: break
            idx, nr = struct.unpack('<II', data)
            
            if idx >= start_idx and idx <= end_idx:
                print(f"Index: {idx}, Syscall NR: {nr}")
            
            if idx > end_idx: break
            
            # Skip the rest of the fixed record
            # args[8]*8 (64) + retval 8 + arg_sizes[8]*8 (64) + creates_fd 1 + uses_fd 1 + created_fd 4
            f.read(64 + 8 + 64 + 1 + 1 + 4)
            
            # Skip variable length parameter data
            while True:
                marker = struct.unpack('<i', f.read(4))[0]
                if marker == -1: break # End marker
                # arg_idx (marker), arg_size (uint64)
                size = struct.unpack('<Q', f.read(8))[0]
                f.read(size)
            
            # Skip aux data
            magic = struct.unpack('<I', f.read(4))[0]
            if magic == 0x41555844: # "AUXD"
                count = struct.unpack('<I', f.read(4))[0]
                for _ in range(count):
                    kind = f.read(1)
                    mask = f.read(1)
                    size = struct.unpack('<I', f.read(4))[0]
                    f.read(size)
            elif magic == 0:
                pass

if __name__ == "__main__":
    dump_trace(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))

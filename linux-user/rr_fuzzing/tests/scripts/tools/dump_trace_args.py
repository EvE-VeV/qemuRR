
import struct
import sys

def dump_trace_args(filename, start_idx, end_idx):
    with open(filename, 'rb') as f:
        f.read(12)
        while True:
            pos = f.tell()
            data = f.read(8)
            if len(data) < 8: break
            idx, nr = struct.unpack('<II', data)
            
            args = struct.unpack('<8Q', f.read(64))
            retval = struct.unpack('<q', f.read(8))[0]
            
            if idx >= start_idx and idx <= end_idx:
                print(f"Index: {idx}, Syscall NR: {nr}, Args: {args}, Retval: {retval}")
            
            if idx > end_idx: break
            
            f.read(64 + 1 + 1 + 4) # arg_sizes(64) + creates_fd + uses_fd + created_fd
            while True:
                marker = struct.unpack('<i', f.read(4))[0]
                if marker == -1: break
                size = struct.unpack('<Q', f.read(8))[0]
                f.read(size)
            magic = struct.unpack('<I', f.read(4))[0]
            if magic == 0x41555844:
                count = struct.unpack('<I', f.read(4))[0]
                for _ in range(count):
                    f.read(2)
                    size = struct.unpack('<I', f.read(4))[0]
                    f.read(size)
            elif magic == 0: pass

if __name__ == "__main__":
    dump_trace_args(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))

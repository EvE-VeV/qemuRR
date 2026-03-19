import pickle, sys, os
import pickle

sys.path.insert(0, '/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing')
from conductor.trace_analyzer import TraceAnalyzer

try:
    with open('/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/crashes/real_world_repro/TOTOLINK/boa_totolink.trace.analyzer.pkl', 'rb') as f:
        data = pickle.load(f)
        records = getattr(data, 'syscalls', data.get('records', []))
        
        print("--- Loaded syscalls ---")
        for i, s in enumerate(records[:80]):
             nr = getattr(s, 'nr', getattr(s, 'syscall_nr', -1))
             args = getattr(s, 'args', [])
             fd = args[0] if args else -1
             data_bytes = getattr(s, 'arg_data', {}).get(1, b'')[:100]
             aux_len = len(getattr(s, 'aux_entries', []))
             if s.name in ['read', 'recv', 'recvfrom', 'readv', 'pread64'] or fd == 0:
                 print(f"{s.index}: {s.name}({nr}) fd={fd} aux={aux_len} dt={data_bytes}")
             
except Exception as e:
    print(f"Error reading pkl: {e}")

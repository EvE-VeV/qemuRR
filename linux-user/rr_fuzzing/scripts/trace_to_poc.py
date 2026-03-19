#!/usr/bin/env python3
import sys
import os
import argparse
from pathlib import Path

# Setup project path to import from fuzzing modules
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "fuzzing/conductor"))

try:
    from trace_analyzer import TraceAnalyzer
except ImportError:
    print("[-] Error: Cannot import TraceAnalyzer. Please ensure you are running this from the correct directory.")
    sys.exit(1)

POC_TEMPLATE = """#!/usr/bin/env python3
# AUTO-GENERATED POC BY RR-FUZZ trace_to_poc.py
# Target: {target_ip}:{target_port}

import socket
import sys
import time

TARGET_IP = "{target_ip}"
TARGET_PORT = {target_port}

# The payload extracted from the crash trace
PAYLOAD = {payload_bytes_repr}

def exploit():
    print(f"[*] Attacking {{TARGET_IP}}:{{TARGET_PORT}}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((TARGET_IP, TARGET_PORT))
        
        print(f"[*] Sending {{len(PAYLOAD)}} bytes of malicious payload...")
        s.sendall(PAYLOAD)
        
        print("[+] Payload sent successfully.")
        
        # Optional: wait for a response
        try:
            resp = s.recv(4096)
            print("[*] Received response:")
            print(resp.decode('utf-8', errors='ignore'))
        except socket.timeout:
            print("[*] Socket timed out (This might mean the target crashed as expected!).")
            
        s.close()
    except Exception as e:
        print(f"[-] Exploit failed: {{e}}")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        TARGET_IP = sys.argv[1]
        TARGET_PORT = int(sys.argv[2])
    exploit()
"""

def extract_payload_with_analyzer(analyzer):
    # 1. Architecture-aware syscall identification
    # We define sets of syscall names that we are interested in (inc. unmapped MIPS/ARM ids)
    SOCKET_SYSCALLS = {'socket', 'accept', 'accept4', 'syscall_4183', 'syscall_4030', 'syscall_4364'}
    RECV_SYSCALLS = {'read', 'recv', 'recvfrom', 'recvmsg', 'syscall_4003', 'syscall_4045', 'syscall_4125', 'syscall_4127'}
    
    network_fds = set()
    payload_chunks = []
    
    print("[*] Filtering trace for valid network payload...")
    
    for sc in analyzer.syscalls:
        # Simple heuristic: If it creates a socket, track the FD
        if sc.name in SOCKET_SYSCALLS:
            if sc.retval >= 0:
                network_fds.add(sc.retval)
                # print(f"    [+] Found network FD: {sc.retval} (via {sc.name})")

        # If it's a receive/read syscall on a network FD, extract data
        if sc.name in RECV_SYSCALLS:
            # Use getattr for robustness against older cached .pkl files
            args = getattr(sc, 'args', [0]*8)
            fd = args[0]
            
            # Heuristic: If it's a known network FD, or if it's a common FD like 3+, or 0 (for CGI)
            if fd in network_fds or ((fd >= 3 or fd == 0) and sc.name in ['read', 'recv', 'recvfrom']):
                data = b""
                # Check aux entries first
                aux_entries = getattr(sc, 'aux_entries', [])
                for kind, mask, d in aux_entries:
                    data += d
                # Check arg_data 
                arg_data = getattr(sc, 'arg_data', {})
                for idx, d in arg_data.items():
                    if idx == 1: # Buffer is usually arg 1
                        data += d
                
                if data:
                    # HEURISTIC: Skip ELF headers and configuration file reads
                    if data.startswith(b"\x7fELF") or b"Boa v0.94 configuration file" in data or b"MIME type" in data:
                        # print(f"    [-] Skipping noise on FD {fd}")
                        continue
                    
                    print(f"    [!] Found chunk on FD {fd} (len={len(data)}) - {sc.name}: {repr(data[:60])}")
                        
                    # HEURISTIC: Skip very small chunks or noise if needed
                    payload_chunks.append(data)
                    # if b"POST" in data or b"GET" in data:
                    #    print(f"    [!] Found potential HTTP header in chunk (len={len(data)})")

    if not payload_chunks:
        print("[-] Error: No network payload data found in the trace.")
        print("[*] DEBUG: Printing all parsed syscalls to help identify the payload:")
        for sc in analyzer.syscalls:
            args = getattr(sc, 'args', [0]*8)
            fd = args[0]
            aux_len = sum(len(d) for _, _, d in getattr(sc, 'aux_entries', []))
            arg_len = sum(len(d) for idx, d in getattr(sc, 'arg_data', {}).items() if idx == 1)
            nr = getattr(sc, 'nr', getattr(sc, 'syscall_nr', -1))
            print(f"    --> Index {sc.index}: {sc.name}({nr}) | fd={fd} | aux_bytes={aux_len} | arg1_bytes={arg_len}")
        return None
        
    full_payload = b"".join(payload_chunks)
    print(f"[+] Successfully extracted {len(full_payload)} bytes of payload (from {len(payload_chunks)} chunks).")
    return full_payload

def generate_poc(payload, out_file, ip="192.168.1.1", port=80):
    content = POC_TEMPLATE.format(
        target_ip=ip,
        target_port=port,
        payload_bytes_repr=repr(payload)
    )
    
    with open(out_file, "w") as f:
        f.write(content)
        
    # Make executable
    os.chmod(out_file, 0o755)
    print(f"[+] PoC successfully generated at: {out_file}")
    print(f"[*] Usage: python3 {out_file} [target_ip] [target_port]")

def main():
    parser = argparse.ArgumentParser(description="Convert RR-Fuzz Crash Trace to a Python Exploit script.")
    parser.add_argument("trace_file", help="Path to the .trace file (e.g. crash_123.trace)")
    parser.add_argument("-o", "--output", default="poc_generated.py", help="Output Script Path (default: poc_generated.py)")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Default target IP in the PoC")
    parser.add_argument("-p", "--port", type=int, default=80, help="Default target Port in the PoC")
    parser.add_argument("-w", "--word-size", type=int, default=0, help="Force word size (32 or 64). Default: auto")
    
    args = parser.parse_args()
    
    # We use the existing TraceAnalyzer to parse the binary payload format
    analyzer = TraceAnalyzer(args.trace_file, word_size=args.word_size)
    print(f"[*] Trace Analysis: WordSize={analyzer.detected_word_size}, Endian={analyzer.detected_endian}")
    print(f"[*] Loaded {len(analyzer.syscalls)} syscall records.")
    
    payload = extract_payload_with_analyzer(analyzer)
    if payload:
        generate_poc(payload, args.output, args.target, args.port)

if __name__ == "__main__":
    main()

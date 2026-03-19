#!/usr/bin/env python3
import socket
import psutil
import threading
import time
import random
import os

# Identify active QEMU instances and their bound ports
def get_targets():
    targets = []
    # Simplified logic: Trust all listening ports > 1024
    # QEMU User mode often inherits weird permissions or process names
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN' and conn.laddr.port > 1024:
            targets.append(conn.laddr.port)
    
    # Fallback/Hardcoded validation from previous netstat if psutil fails
    # Let's add known ports if not found
    known_ports = [8080, 8888, 10508] 
    for p in known_ports:
        if p not in targets:
            # Check if actually open using socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            try:
                s.connect(('127.0.0.1', p))
                s.close()
                targets.append(p)
            except:
                pass

    return list(set(targets))

def mutate(payload):
    # Simple Radamsa-like mutations
    mutated = bytearray(payload)
    op = random.randint(0, 3)
    if op == 0: # Flip bit
        idx = random.randint(0, len(mutated)-1)
        mutated[idx] ^= random.randint(1, 255)
    elif op == 1: # Insert huge chunk
        idx = random.randint(0, len(mutated))
        chunk = b"A" * random.randint(10, 1000)
        mutated[idx:idx] = chunk
    elif op == 2: # Delete chunk
        if len(mutated) > 10:
            start = random.randint(0, len(mutated)-10)
            end = random.randint(start, len(mutated))
            del mutated[start:end]
    return bytes(mutated)

def fuzz_worker(port, stop_event):
    base_request = b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    
    while not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect(('127.0.0.1', port))
            
            payload = base_request
            if random.random() > 0.1: # 90% mutation
                payload = mutate(base_request)
            
            sock.send(payload)
            sock.recv(1024)
            sock.close()
        except:
            pass
        time.sleep(0.01) # High speed

if __name__ == "__main__":
    active_ports = get_targets()
    print(f"[*] Found {len(active_ports)} active fuzzing targets: {active_ports}")
    
    if not active_ports:
        print("[!] No active targets found. Is the cluster running?")
        exit(1)

    stop_event = threading.Event()
    threads = []
    
    print("[*] Launching Mass Fuzz Injectors...")
    for port in active_ports:
        t = threading.Thread(target=fuzz_worker, args=(port, stop_event))
        t.start()
        threads.append(t)
        print(f"    -> Injecting traffic to port {port}")

    try:
        while True:
            time.sleep(5)
            # Monitor crash logs
            crashes = os.popen("ls /tmp/mass_fuzz/*/crash_*.log 2>/dev/null | wc -l").read().strip()
            print(f"[*] Fuzzing Active. Total Crashes Found: {crashes}")
    except KeyboardInterrupt:
        print("[!] Stopping...")
        stop_event.set()
        for t in threads:
            t.join()

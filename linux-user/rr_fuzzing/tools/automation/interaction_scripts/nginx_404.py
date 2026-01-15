#!/usr/bin/env python3
import socket
import time

def send_request(host, port, path):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        response = s.recv(4096)
        s.close()
        return response
    except Exception as e:
        print(f"Error requesting {path}: {e}")
        return None

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 4001 # Nginx port
    
    paths = [
        "/nonexistent_fuzz_1",
        "/forbidden_test",
        "/directory/not_found",
        "/very/long/path/to/trigger/overflow/checks/in/error/handler/test"
    ]
    
    print(f"[Nginx-404] Sending multiple 404 requests to exercise error handler...")
    for path in paths:
        res = send_request(host, port, path)
        if res:
            print(f"  -> Path: {path}, Status: {res.split(b' ')[1].decode() if b' ' in res else 'Unknown'}")
        time.sleep(0.1)

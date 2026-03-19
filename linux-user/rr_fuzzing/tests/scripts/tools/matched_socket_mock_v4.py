import socket
import os
import sys
import time

SOCK_PATH = "/tmp/novasock"

if os.path.exists(SOCK_PATH):
    os.remove(SOCK_PATH)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(SOCK_PATH)
sock.listen(1)

print(f"Mock supervisor listening on {SOCK_PATH}")

while True:
    conn, addr = sock.accept()
    print("Accepted connection!")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received: {data}")
            # Identify protocol? Just echo OK for now?
            # Or send nothing and let it hang (better than abort).
            
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        conn.close()

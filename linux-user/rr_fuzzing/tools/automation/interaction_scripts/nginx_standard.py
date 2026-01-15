import socket
import time
import sys

def interact():
    host = "localhost"
    port = 4001

    print(f"[*] Connecting to {host}:{port}...")
    try:
        # Retry logic for connection (wait for server startup)
        for i in range(5):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                break
            except ConnectionRefusedError:
                time.sleep(1)
        else:
            print("[!] Could not connect to Nginx")
            sys.exit(1)
        
        # Request 1: Valid Path
        print("[*] Sending Request 1 (Valid)...")
        req1 = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        s.sendall(req1)
        resp1 = s.recv(4096)
        print(f"[*] Response 1 length: {len(resp1)}")

        time.sleep(0.1)

        # Request 2: Invalid Path (404)
        print("[*] Sending Request 2 (404)...")
        req2 = b"GET /notfound_fuzz HTTP/1.1\r\nHost: localhost\r\n\r\n"
        s.sendall(req2)
        resp2 = s.recv(4096)
        print(f"[*] Response 2 length: {len(resp2)}")
        
        s.close()
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    interact()

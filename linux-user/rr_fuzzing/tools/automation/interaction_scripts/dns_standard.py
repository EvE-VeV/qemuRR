import socket
import sys
import time

def send_dns_query(host="localhost", port=5353):
    # A simple DNS query for google.com (Type A)
    # Transaction ID: 0x1234
    # Flags: 0x0100 (Standard query)
    # Questions: 1
    # Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
    # Query: google.com (06 67 6f 6f 67 6c 65 03 63 6f 6d 00), Type: 0001, Class: 0001
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"

    time.sleep(1) # Wait for server
    print(f"Connecting to {host}:{port} (UDP)...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        print("Sending DNS query...")
        sock.sendto(query, (host, port))
        
        try:
            data, addr = sock.recvfrom(512)
            print(f"Received {len(data)} bytes from {addr}")
        except socket.timeout:
            print("Query timed out (expected if no upstream)")
        
        sock.close()
        print("Done")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    test_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5353
    send_dns_query(test_host, test_port)

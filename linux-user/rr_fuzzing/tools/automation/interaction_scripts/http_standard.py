import http.client
import sys
import time

def test_http(method="GET", path="/index.html", data=None):
    host = "localhost"
    port = 4000
    
    time.sleep(1) # Wait for server
    print(f"Connecting to {host}:{port}...")
    try:
        conn = http.client.HTTPConnection(host, port)
        headers = {}
        if data:
            headers = {"Content-type": "application/x-www-form-urlencoded"}
        
        print(f"Sending {method} {path}...")
        conn.request(method, path, data, headers)
        
        response = conn.getresponse()
        print(f"Response: {response.status} {response.reason}")
        print(f"Body: {response.read().decode()[:50]}...")
        
        conn.close()
        print("Done")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    m = sys.argv[1] if len(sys.argv) > 1 else "GET"
    p = sys.argv[2] if len(sys.argv) > 2 else "/index.html"
    d = sys.argv[3] if len(sys.argv) > 3 else None
    test_http(m, p, d)

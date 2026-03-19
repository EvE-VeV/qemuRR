#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import glob
import shutil
import json
from pathlib import Path

# Configuration
SEARCH_ROOTS = [
    "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images",
    "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets"
]
QEMU_BUILD_ROOT = "/home/webfuzz/Documents/qemu/build"
REPORT_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_onboard_report.json"

# Signatures for web servers
WEB_SERVERS = ["httpd", "boa", "lighttpd", "goahead", "mini_httpd", "nginx", "appweb", "uhttpd"]

# Architecture Mapping (ELF Machine -> QEMU Arch)
ARCH_MAP = {
    "ARM": "arm",
    "MIPS": "mips",     # Be careful with Endianness
    "MIPS_RS3_LE": "mipsel",
    "X86_64": "x86_64",
    "Intel 80386": "i386",
    "PowerPC": "ppc"
}

def run_cmd(cmd, timeout=None):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""

def extract_firmware(file_path):
    """Automatically extract firmware archives."""
    p = Path(file_path)
    extract_dir = p.parent / (p.name + ".extracted")
    
    # Skip if already extracted
    if extract_dir.exists():
        return extract_dir

    print(f"[*] Extracting {p.name}...")
    try:
        extract_dir.mkdir(exist_ok=True)
        
        # 1. Zip
        if p.suffix.lower() == ".zip":
            subprocess.run(["unzip", "-o", str(p), "-d", str(extract_dir)], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        # 2. Binwalk (Universal fallback)
        else:
            # Binwalk extracts to _{filename}.extracted by default
            # We run it inside the parent dir
            subprocess.run(["binwalk", "-eM", str(p)], cwd=str(p.parent),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Binwalk output dir convention is _{name}.extracted
            bw_out = p.parent / f"_{p.name}.extracted"
            if bw_out.exists():
                # Move contents to our standard dir and remove binwalk dir
                shutil.move(str(bw_out), str(extract_dir))
                # Cleanup if move resulted in nested dir, but shutil.move usually handles it.
                # Actually, shutil.move into existing dir might put it inside.
                # Let's just update extract_dir to point to binwalk's output if it exists
                # Simplify: Just use binwalk's default output if exists
                if not any(extract_dir.iterdir()): # if unzip failed or didn't run
                    extract_dir.rmdir()
                    return bw_out
            
        return extract_dir
    except Exception as e:
        print(f"[-] Extraction failed for {p.name}: {e}")
        return None

def get_elf_arch(binary_path):
    """Detect architecture using readelf."""
    try:
        result = subprocess.run(
            ["readelf", "-h", binary_path], 
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "Machine:" in line:
                if "ARM" in line: return "arm"
                if "MIPS" in line:
                    encoding = subprocess.run(
                        ["readelf", "-h", binary_path], 
                        capture_output=True, text=True
                    ).stdout
                    if "little endian" in encoding: return "mipsel"
                    return "mips"
                if "X86-64" in line: return "x86_64"
                if "Intel 80386" in line: return "i386"
                if "PowerPC" in line: return "ppc"
    except Exception:
        return None
    return None

def find_web_server(rootfs_path):
    """Scan /bin, /usr/bin, /usr/sbin for known web servers."""
    candidates = []
    search_paths = [
        Path(rootfs_path) / "bin",
        Path(rootfs_path) / "sbin",
        Path(rootfs_path) / "usr" / "bin",
        Path(rootfs_path) / "usr" / "sbin"
    ]
    
    for sp in search_paths:
        if not sp.exists(): continue
        try:
            for f in sp.iterdir():
                if f.name in WEB_SERVERS:
                    if os.access(str(f), os.X_OK):
                        candidates.append(f.name)
        except: pass
    return candidates

def is_rootfs(path):
    """Heuristic to check if a directory looks like a rootfs."""
    p = Path(path)
    has_bin = (p / "bin").is_dir()
    has_lib = (p / "lib").is_dir()
    has_etc = (p / "etc").is_dir()
    return has_bin and (has_lib or has_etc)

def scan_all():
    targets = []
    
    # 1. Extraction Phase
    for root in SEARCH_ROOTS:
        for ext in ["*.zip", "*.bin", "*.img", "*.iso"]:
            for f in Path(root).rglob(ext):
                # Ignore items already in an extracted folder
                if ".extracted" in str(f): continue
                # Extract
                extract_firmware(f)

    # 2. Scanning Phase
    print("[*] Scanning for Rootfs candidates...")
    
    # We walk everything now
    potential_roots = []
    for root in SEARCH_ROOTS:
        for path in Path(root).rglob("*"):
            if path.is_dir() and is_rootfs(path):
                potential_roots.append(path)

    print(f"[*] Found {len(potential_roots)} directories looking like rootfs.")

    for r in potential_roots:
        rootfs = str(r)
        
        # Avoid fuzz_output garbage
        if "fuzz_output" in rootfs: continue
        
        # Avoid sub-directories of already found rootfs? 
        # (e.g. rootfs/usr/...) - is_rootfs check usually prevents this unless /usr has /bin and /lib
        
        # 1. Detect Architecture (via busybox/sh/ls)
        probe_bins = ["bin/busybox", "bin/sh", "bin/ls", "usr/bin/busybox"]
        arch = None
        for pb in probe_bins:
            full_pb = os.path.join(rootfs, pb)
            if os.path.exists(full_pb):
                arch = get_elf_arch(full_pb)
                if arch: break
        
        if arch:
            # 2. Detect Web Server
            servers = find_web_server(rootfs)
            if servers:
                # Add to targets
                # Check for duplicates (by name/path)
                t_name = r.name
                if t_name in ["rootfs", "squashfs-root"]:
                    # Use parent name to resolve ambiguity
                    t_name = f"{r.parent.name}_{t_name}"
                
                targets.append({
                    "name": t_name,
                    "rootfs": rootfs,
                    "arch": arch,
                    "web_server_candidate": servers[0],
                    "web_server_binary": servers[0]
                })

    return targets

def smoke_test(target_config):
    """Try to run the target for 5 seconds."""
    name = target_config['name']
    rootfs = target_config['rootfs']
    arch = target_config['arch']
    binary = target_config['web_server_binary']
    
    print(f"[*] Smoke Testing: {name} ({arch}) -> {binary}")
    
    binary_full = subprocess.getoutput(f"find {rootfs} -name {binary} -type f | head -n 1")
    if not binary_full: return False, "Binary not found"

    qemu_bin = os.path.join(QEMU_BUILD_ROOT, f"qemu-{arch}")
    if not os.path.exists(qemu_bin): return False, f"QEMU {arch} missing"

    env = os.environ.copy()
    env["QEMU_LD_PREFIX"] = rootfs
    # Library path guessing
    lib_paths = [str(Path(rootfs)/"lib"), str(Path(rootfs)/"usr"/"lib")]
    env["LD_LIBRARY_PATH"] = ":".join(lib_paths)

    cmd = [qemu_bin, binary_full]
    
    try:
        proc = subprocess.Popen(
            cmd, env=env, 
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        try:
            stdout, stderr = proc.communicate(timeout=5)
            ret = proc.returncode
            if ret == -11: return False, "Segfault"
            if ret == 127: return False, "Lib Missing"
            return True, f"Exited {ret}"
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), 9)
            return True, "Timeout (Running)"
    except Exception as e:
        return False, str(e)

if __name__ == "__main__":
    print("=== Universal Firmware Scanner ===")
    candidates = scan_all()
    print(f"Found {len(candidates)} candidates.")
    
    onboarded = []
    for cand in candidates:
        success, reason = smoke_test(cand)
        cand['smoke_status'] = success
        cand['smoke_reason'] = reason
        if success:
            onboarded.append(cand)
            print(f"   [+] {cand['name']}: Alive")
        else:
            print(f"   [-] {cand['name']}: Dead ({reason})")

    print(f"\nTotal Live Targets: {len(onboarded)}")
    with open(REPORT_FILE, "w") as f:
        json.dump(onboarded, f, indent=2)

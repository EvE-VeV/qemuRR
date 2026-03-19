#!/usr/bin/env python3
import json
import os
import stat
import subprocess

REPORT_FILE = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_onboard_report.json"
OUTPUT_DIR = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign"
QEMU_BUILD_ROOT = "/home/webfuzz/Documents/qemu/build"

# Template for individual fuzzing script
SCRIPT_TEMPLATE = """#!/bin/bash
# Auto-generated fuzzing script for {target_name}
# Arch: {arch}
# Binary: {binary}
# Config: {config_flag} {config_path}

export QEMU_LD_PREFIX="{rootfs}"
export RR_mmap_fixed_mapped_disallowed=1
# Mock wireless extensions and other ioctls using our preload
# export LD_PRELOAD="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/rr_mock_ioctls.so"
# Enable mock if needed (some need it, some don't. For mass scan, maybe safe to add?)

# Basic library path guess
export LD_LIBRARY_PATH="{rootfs}/lib:{rootfs}/usr/lib"

# Workdir for output
mkdir -p {output_dir}

# Copy config to tmp if needed (some servers need write access to config dir)
# For now we use in-place or assume read-only is fine

echo "[*] Starting fuzzing for {target_name}..."

while true; do
    {qemu_bin} \\
        {binary_path} \\
        {config_flag} {config_path} \\
        > {output_dir}/stdout.log 2> {output_dir}/stderr.log
    
    RET=$?
    # If it exits too fast (less than 1s), sleep a bit to avoid CPU spin
    # But for fuzzing we want fast restart. 
    # Logic: If it segfaults (>128), log it.
    
    if [ $RET -gt 128 ]; then
        echo "[!] CRASH DETECTED with signal $((RET-128))!"
        cp {output_dir}/stderr.log {output_dir}/crash_$(date +%s).log
    fi
    sleep 0.5
done
"""

def find_config(rootfs, binary_name):
    """Heuristic to find config file based on binary name."""
    candidates = []
    
    # Define search patterns
    patterns = []
    if "boa" in binary_name:
        patterns = ["boa.conf", "*.conf"]
    elif "httpd" in binary_name:
        patterns = ["httpd.conf", "lighttpd.conf", "*.conf"]
    elif "lighttpd" in binary_name:
        patterns = ["lighttpd.conf", "*.conf"]
    else:
        patterns = ["*.conf"]

    for pat in patterns:
        try:
            # Use find command to locate in rootfs
            cmd = f"find {rootfs} -name '{pat}' -type f | head -n 1"
            res = subprocess.getoutput(cmd).strip()
            if res:
                return res
        except:
            pass
    return None

def get_config_flag(binary_name):
    if "boa" in binary_name: return "-c" # boa usually takes directory or file?, usually -c /path/to/
    if "lighttpd" in binary_name: return "-f"
    if "httpd" in binary_name: return "-f" # generic guess, Tenda httpd might be different
    return ""

def generate_campaign():
    if not os.path.exists(REPORT_FILE):
        print("Report file not found. Run mass_onboard.py first.")
        return

    with open(REPORT_FILE, "r") as f:
        targets = json.load(f)

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    generated_scripts = []

    for t in targets:
        name = t['name']
        print(f"Generating script for {name}...")
        
        # 1. Resolve Binary Path
        binary_cmd = f"find {t['rootfs']} -name {t['web_server_binary']} -type f | head -n 1"
        bin_full = subprocess.getoutput(binary_cmd).strip()
        
        if not bin_full:
            print(f"  [!] Skipped: Binary {t['web_server_binary']} not found in {t['rootfs']}")
            continue

        # 2. Find Config
        conf_path = find_config(t['rootfs'], t['web_server_binary'])
        conf_flag = ""
        final_conf_path = ""
        
        if conf_path:
            conf_flag = get_config_flag(t['web_server_binary'])
            final_conf_path = conf_path
            
            # Special handling for boa: often wants a DIRECTORY not file for -c?
            # Boa usage: boa -c /etc/boa
            if "boa" in t['web_server_binary']:
                final_conf_path = os.path.dirname(conf_path)
            
            print(f"  [+] Found config: {conf_path} -> Flag: {conf_flag} {final_conf_path}")
        else:
            print(f"  [-] No config found, running without flags.")
        
        script_name = f"run_fuzz_{name}.sh"
        script_path = os.path.join(OUTPUT_DIR, script_name)
        
        content = SCRIPT_TEMPLATE.format(
            target_name=name,
            arch=t['arch'],
            binary=t['web_server_binary'],
            rootfs=t['rootfs'],
            output_dir=f"/tmp/mass_fuzz/{name}",
            qemu_bin=os.path.join(QEMU_BUILD_ROOT, f"qemu-{t['arch']}"),
            binary_path=bin_full,
            config_flag=conf_flag,
            config_path=final_conf_path
        )
        
        with open(script_path, "w") as f:
            f.write(content)
        
        os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IEXEC)
        generated_scripts.append(script_path)

    # Master launcher
    master_script = os.path.join(OUTPUT_DIR, "launch_all.sh")
    with open(master_script, "w") as f:
        f.write("#!/bin/bash\n")
        for s in generated_scripts:
            # Add a small stagger to avoid CPU spike
            f.write(f"sleep 0.5; {s} &\n")
        f.write("echo '[*] All targets launched.'\n")
        f.write("wait\n")
    os.chmod(master_script, os.stat(master_script).st_mode | stat.S_IEXEC)

    print(f"Generated {len(generated_scripts)} campaign scripts in {OUTPUT_DIR}")

if __name__ == "__main__":
    generate_campaign()

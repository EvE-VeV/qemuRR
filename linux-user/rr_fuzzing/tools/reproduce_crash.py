#!/usr/bin/env python3
"""
Crash Reproduction Tool for RR-Fuzz

This script reproduces crashes by replaying the saved trace file with the
exact mutations that triggered the crash.

Usage:
    python3 reproduce_crash.py <crash_meta_file> [--qemu=path] [--verbose]

Example:
    python3 reproduce_crash.py /tmp/fuzzing_output/crashes/crash_000000_7aab888f.meta
"""

import sys
import os
import json
import argparse
import subprocess
from pathlib import Path

def load_crash_metadata(meta_file):
    """Load crash metadata from JSON file"""
    with open(meta_file, 'r') as f:
        return json.load(f)

def parse_mutations(mutations):
    """Parse mutation data to understand the crash trigger"""
    print("\n" + "="*60)
    print("MUTATION ANALYSIS")
    print("="*60)
    
    for i, mut in enumerate(mutations):
        print(f"\nMutation #{i+1}:")
        print(f"  Syscall Index: {mut['syscall_index']}")
        print(f"  Command: {mut['cmd']}")
        print(f"  Arg Index: {mut['arg_index']}")
        print(f"  Data Size: {mut['size']} bytes")
        
        # Decode hex data
        data_hex = mut['data']
        data_bytes = bytes.fromhex(data_hex)
        
        # Show ASCII representation if printable
        try:
            ascii_repr = data_bytes.decode('ascii')
            if all(32 <= ord(c) <= 126 or c in '\n\t' for c in ascii_repr):
                print(f"  Data (ASCII): {repr(ascii_repr[:64])}")
            else:
                print(f"  Data (hex): {data_hex[:64]}...")
        except:
            print(f"  Data (hex): {data_hex[:64]}...")
        
        # Analyze mutation type
        if mut['cmd'] == 2:
            print(f"  Type: REPLACE_BUFFER (替换缓冲区)")
        elif mut['cmd'] == 4:
            print(f"  Type: BOUNDARY_VALUE (边界值)")
        elif mut['cmd'] == 6:
            print(f"  Type: LIGHT_MUTATION (轻度变异)")
        elif mut['cmd'] == 7:
            print(f"  Type: TRUNCATE (截断)")
        else:
            print(f"  Type: Unknown (cmd={mut['cmd']})")

def reproduce_with_qemu(crash_dir, metadata, qemu_path):
    """Reproduce the crash using QEMU with the saved trace"""
    print("\n" + "="*60)
    print("CRASH REPRODUCTION")
    print("="*60)
    
    # Find trace file
    trace_file = crash_dir / f"{metadata['crash_id']}.bin"
    if not trace_file.exists():
        print(f"❌ Error: Trace file not found: {trace_file}")
        return False
    
    print(f"\n✓ Found trace file: {trace_file}")
    print(f"  Size: {trace_file.stat().st_size} bytes")
    
    # We need to determine the target binary
    # For this demo, we'll use the vulnerable target
    target_binary = Path(__file__).parent / "tests/programs/vulnerable/fuzz_target_vulnerable"
    
    if not target_binary.exists():
        print(f"\n⚠️  Warning: Target binary not found at expected location")
        print(f"   Expected: {target_binary}")
        print(f"\n💡 To reproduce manually:")
        print(f"   1. Set environment: RR_MODE=fuzzing RR_TRACE_FILE={trace_file}")
        print(f"   2. Run: {qemu_path} <target_binary>")
        return False
    
    # Set up environment
    env = os.environ.copy()
    env.update({
        'RR_MODE': 'fuzzing',
        'RR_TRACE_FILE': str(trace_file),
        'RR_FUZZING_ENABLED': '1',
        'RR_DEBUG_LEVEL': '1'
    })
    
    print(f"\n▶ Running crash reproduction...")
    print(f"  QEMU: {qemu_path}")
    print(f"  Target: {target_binary}")
    print(f"  Trace: {trace_file}")
    
    try:
        result = subprocess.run(
            [qemu_path, str(target_binary)],
            env=env,
            capture_output=True,
            timeout=5
        )
        
        # Check if crash reproduced
        if result.returncode == 134:  # SIGABRT (128 + 6)
            print("\n✅ CRASH REPRODUCED!")
            print(f"   Exit code: {result.returncode} (SIGABRT)")
            if b"stack smashing detected" in result.stderr:
                print(f"   Type: Stack buffer overflow")
            return True
        elif result.returncode == 139:  # SIGSEGV (128 + 11)
            print("\n✅ CRASH REPRODUCED!")
            print(f"   Exit code: {result.returncode} (SIGSEGV)")
            return True
        else:
            print(f"\n⚠️  Process exited with code {result.returncode}")
            if result.stderr:
                print(f"\nStderr output:")
                print(result.stderr.decode('utf-8', errors='replace')[:500])
            return False
            
    except subprocess.TimeoutExpired:
        print("\n⚠️  Reproduction timed out (possible hang)")
        return False
    except Exception as e:
        print(f"\n❌ Error during reproduction: {e}")
        return False

def analyze_crash_completeness(metadata):
    """Analyze if crash metadata contains sufficient information"""
    print("\n" + "="*60)
    print("METADATA COMPLETENESS ANALYSIS")
    print("="*60)
    
    issues = []
    recommendations = []
    
    # Check for missing fields
    if metadata.get('exit_code') is None and metadata.get('signal') is None:
        issues.append("❌ Missing exit_code and signal information")
        recommendations.append("💡 Fork server should populate these fields from waitpid()")
    
    # Check mutations
    if not metadata.get('mutations'):
        issues.append("❌ No mutation information saved")
    else:
        # Check mutation details
        for mut in metadata['mutations']:
            if mut.get('mutation_type') == 'unknown':
                issues.append(f"⚠️  Mutation type unknown for syscall {mut['syscall_index']}")
        
        if len([m for m in metadata['mutations'] if m.get('mutation_type') == 'unknown']) == len(metadata['mutations']):
            recommendations.append("💡 Mutator should record mutation types in FuzzInstruction")
    
    # Check for syscall names
    has_syscall_info = any('syscall_name' in mut for mut in metadata.get('mutations', []))
    if not has_syscall_info:
        issues.append("⚠️  No syscall names saved (only indices)")
        recommendations.append("💡 Consider saving syscall names for better readability")
    
    # Check for stack trace
    if 'stack_trace' not in metadata:
        issues.append("⚠️  No stack trace information")
        recommendations.append("💡 Consider integrating GDB/LLDB for stack traces")
    
    # Print results
    print(f"\n✓ Crash ID: {metadata['crash_id']}")
    print(f"✓ Crash Hash: {metadata['crash_hash']}")
    print(f"✓ Timestamp: {metadata['timestamp']}")
    print(f"✓ Mutation Count: {len(metadata.get('mutations', []))}")
    print(f"✓ Trace File: Available (.bin)")
    
    if issues:
        print("\n📋 Issues Found:")
        for issue in issues:
            print(f"  {issue}")
    
    if recommendations:
        print("\n📝 Recommendations:")
        for rec in recommendations:
            print(f"  {rec}")
    
    # Overall assessment
    print("\n" + "-"*60)
    if len(issues) == 0:
        print("✅ Metadata is COMPLETE and sufficient for reproduction")
        return True
    elif len([i for i in issues if i.startswith('❌')]) == 0:
        print("⚠️  Metadata is SUFFICIENT but could be improved")
        return True
    else:
        print("❌ Metadata has CRITICAL gaps for reproduction")
        return False

def main():
    parser = argparse.ArgumentParser(description='Reproduce RR-Fuzz crashes')
    parser.add_argument('crash_meta', help='Path to crash metadata JSON file')
    parser.add_argument('--qemu', default='/home/webfuzz/Documents/qemu/build/qemu-x86_64',
                        help='Path to QEMU executable')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    # Load metadata
    meta_file = Path(args.crash_meta)
    if not meta_file.exists():
        print(f"❌ Error: Metadata file not found: {meta_file}")
        return 1
    
    crash_dir = meta_file.parent
    metadata = load_crash_metadata(meta_file)
    
    print("="*60)
    print("RR-FUZZ CRASH REPRODUCTION TOOL")
    print("="*60)
    print(f"\nCrash ID: {metadata['crash_id']}")
    print(f"Status: {metadata['status_name']} (code: {metadata['status']})")
    print(f"Trace ID: {metadata['trace_id']}")
    
    # Analyze mutations
    parse_mutations(metadata['mutations'])
    
    # Analyze metadata completeness
    is_complete = analyze_crash_completeness(metadata)
    
    # Attempt reproduction
    if Path(args.qemu).exists():
        success = reproduce_with_qemu(crash_dir, metadata, args.qemu)
        if success:
            print("\n" + "="*60)
            print("✅ CRASH SUCCESSFULLY REPRODUCED!")
            print("="*60)
            return 0
        else:
            print("\n" + "="*60)
            print("⚠️  CRASH REPRODUCTION INCOMPLETE")
            print("="*60)
            return 2
    else:
        print(f"\n⚠️  QEMU not found at: {args.qemu}")
        print("   Skipping reproduction attempt")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""
Syscall Tree Structure Verification Script

Validates that the syscall tree has correct structure:
1. No circular references
2. Each child is in parent's children_ids
3. Each parent_id points to valid node
4. Forms proper hierarchy (not flat list)
"""

import json
import sys
import re

def extract_json_from_html(filepath):
    """Extract embedded JSON data from HTML file"""
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    # Find start and end of JSON
    json_lines = []
    capturing = False
    for line in lines:
        if 'const treeData =' in line:
            # Start capturing, remove the JS assignment part
            json_lines.append(line.split('const treeData = ')[1])
            capturing = True
        elif capturing:
            # Stop at the standalone ";" after the closing "}"
            if line.strip() == ';':
                break
            json_lines.append(line)
    
    if not json_lines:
        raise ValueError(f"Could not find JSON data in {filepath}")
    
    json_str = ''.join(json_lines)
    return json.loads(json_str)


def validate_tree_structure(data):
    """Validate tree structure correctness"""
    errors = []
    warnings = []
    
    nodes = data.get('nodes', [])
    if not nodes:
        errors.append("No nodes found in tree")
        return errors, warnings
    
    print(f"✓ Found {len(nodes)} nodes")
    
    # Build node lookup map
    node_map = {node['id']: node for node in nodes}
    
    # Check 1: All parent_id references are valid
    print("\n[Check 1] Validating parent references...")
    for node in nodes:
        pid = node['parent_id']
        if pid != 4294967295 and pid not in node_map:  # -1 in uint32
            errors.append(f"Node {node['id']} has invalid parent_id {pid}")
    
    if not errors:
        print("  ✓ All parent references are valid")
    
    # Check 2: Parent-child relationship consistency
    print("\n[Check 2] Validating parent-child relationships...")
    for node in nodes:
        node_id = node['id']
        parent_id = node['parent_id']
        
        if parent_id != 4294967295:  # Not root
            parent = node_map.get(parent_id)
            if parent:
                if node_id not in parent.get('children_ids', []):
                    errors.append(
                        f"Node {node_id} claims parent {parent_id}, "
                        f"but parent doesn't list it as child"
                    )
    
    if not errors:
        print("  ✓ All parent-child relationships are consistent")
    
    # Check 3: No circular references
    print("\n[Check 3] Checking for circular references...")
    def has_cycle(node_id, visited, path):
        if node_id in path:
            return True
        if node_id in visited:
            return False
        
        visited.add(node_id)
        path.add(node_id)
        
        node = node_map.get(node_id)
        if node:
            for child_id in node.get('children_ids', []):
                if has_cycle(child_id, visited, path):
                    return True
        
        path.remove(node_id)
        return False
    
    visited = set()
    for node in nodes:
        if node['parent_id'] == 4294967295:  # Root node
            if has_cycle(node['id'], visited, set()):
                errors.append(f"Circular reference detected from root {node['id']}")
    
    if not errors:
        print("  ✓ No circular references found")
    
    # Check 4: Tree structure depth (not flat)
    print("\n[Check 4] Analyzing tree depth...")
    def get_depth(node_id):
        node = node_map.get(node_id)
        if not node:
            return 0
        parent_id = node['parent_id']
        if parent_id == 4294967295:
            return 0
        return 1 + get_depth(parent_id)
    
    depths = [get_depth(node['id']) for node in nodes]
    max_depth = max(depths) if depths else 0
    avg_depth = sum(depths) / len(depths) if depths else 0
    
    print(f"  Max depth: {max_depth}")
    print(f"  Avg depth: {avg_depth:.2f}")
    
    if max_depth <= 1:
        warnings.append("Tree is very shallow (max_depth <= 1), might be flat structure")
    else:
        print(f"  ✓ Tree has proper hierarchy (max_depth={max_depth})")
    
    # Check 5: Duplicate syscall_index
    print("\n[Check 5] Checking for duplicate syscall recordings...")
    index_counts = {}
    for node in nodes:
        idx = node['syscall_index']
        index_counts[idx] = index_counts.get(idx, 0) + 1
    
    duplicates = {idx: count for idx, count in index_counts.items() if count > 1}
    if duplicates:
        errors.append(f"Found duplicate syscall_index values: {duplicates}")
        print(f"  ✗ Found {len(duplicates)} duplicate indices")
    else:
        print("  ✓ No duplicate syscall recordings")
    
    return errors, warnings

def main():
    if len(sys.argv) < 2:
        print("Usage: verify_tree_structure.py <html_file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    print(f"Verifying tree structure in: {filepath}\n")
    
    try:
        data = extract_json_from_html(filepath)
        errors, warnings = validate_tree_structure(data)
        
        print("\n" + "="*60)
        if errors:
            print("VALIDATION FAILED ✗")
            print("\nErrors:")
            for err in errors:
                print(f"  • {err}")
        else:
            print("VALIDATION PASSED ✓")
        
        if warnings:
            print("\nWarnings:")
            for warn in warnings:
                print(f"  • {warn}")
        
        print("="*60)
        
        sys.exit(0 if not errors else 1)
        
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(2)

if __name__ == '__main__':
    main()

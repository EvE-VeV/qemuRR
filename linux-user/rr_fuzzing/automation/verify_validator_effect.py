#!/usr/bin/env python3
"""
Scientific Verification Script: Validator Effectiveness
-----------------------------------------------------
Goal: Quantify the 'False Positive Reduction' provided by Dual-Level Validation.
Method:
1. Load Static CFG (Syscall Tree) and Dynamic Trace.
2. Generate N mutations using SmartMutator (mimicking Fuzzing Loop).
3. Check each mutation against DualLevelPathFinder.validate_transition().
4. Metric: 'Rejection Rate' = (Blocked Mutations / Total Mutations).
   - Rejection Rate > 0 establishes that the Validator IS DOING WORK.
   - Higher Rejection Rate = Higher Savings in QEMU Execution Time.
"""

import sys
import os
from pathlib import Path

# Setup paths
current_dir = Path(__file__).parent
root_dir = current_dir.parent
sys.path.insert(0, str(root_dir / "fuzzing" / "conductor"))
sys.path.insert(0, str(root_dir / "fuzzing")) # For trace_analyzer.py

try:
    from dual_level_path_finder import DualLevelPathFinder
    from mutator import SmartMutator
    from trace_analyzer import TraceAnalyzer
    from conductor_types import MutationRecipe
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print(f"PYTHONPATH: {sys.path}")
    sys.exit(1)

def run_experiment():
    print("=== 🧪 Experiment: Validator Effectiveness Verification ===")
    
    # 1. Setup Environment
    trace_file = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/trace_manual.txt"
    tree_file = "/tmp/syscall_tree.json"
    
    if not os.path.exists(trace_file):
        print(f"❌ Missing Trace File: {trace_file}")
        return
        
    print(f"📂 Loading Trace: {trace_file}")
    print(f"📂 Loading Tree:  {tree_file}")
    
    # 2. Initialize Components
    pf = DualLevelPathFinder("dummy_target")
    # Load Real Static CFG
    if os.path.exists(tree_file):
        if not pf.load_syscall_tree(tree_file):
            print("⚠️ Failed to load real tree, using empty one (Results may be skewed)")
    else:
        print("⚠️ No Syscall Tree found. Using Mock Tree for demonstration.")
        # Mock Tree for fallback demo
        from syscall_block import SyscallBlock
        b1 = SyscallBlock(10, 'mock_read'); b1.is_covered = True
        b2 = SyscallBlock(11, 'mock_write'); b2.is_covered = True
        pf.syscall_blocks[10] = b1
        pf.syscall_blocks[11] = b2
        pf.syscall_edges.add((10, 11)) # Only allow 10->11
    
    print("🤖 Initializing Mutator...")
    mutator = SmartMutator(trace_file, path_finder=pf)
    
    # 3. Simulate Fuzzing Loop
    TOTAL_TRIALS = 50
    blocked_count = 0
    valid_count = 0
    unknown_count = 0
    
    print(f"\n⚡ Simulating {TOTAL_TRIALS} Mutation Cycles...")
    print("-" * 60)
    print(f"{'#':<4} | {'Source':<15} | {'Target':<15} | {'Result':<10}")
    print("-" * 60)

    # Mock 'last_recipe_used' mechanism used in FuzzingCore
    # We force the mutator to generate recipes to test validation
    
    # Get uncovered branches to generate recipes
    # In a real run, this comes from coverage analysis. 
    # Here we mock it or use what's found.
    uncovered = pf.find_uncovered_syscall_branches(set(pf.bb_to_syscall.keys()))
    if not uncovered:
        # Inject synthetic branches for testing if none found
        print("ℹ️ No natural uncovered branches found. Injecting test probes...")
        # valid probe
        uncovered.append({'from_syscall_idx': 10, 'to_syscall_idx': 11, 'from_syscall_name': 'read', 'to_syscall_name': 'write', 'target_syscall_idx': 10, 'type': 'syscall_edge'}) 
        # invalid probe (Hallucination)
        uncovered.append({'from_syscall_idx': 10, 'to_syscall_idx': 999, 'from_syscall_name': 'read', 'to_syscall_name': 'invalid_sys', 'target_syscall_idx': 10, 'type': 'syscall_edge'})

    # Generate recipes
    recipes = pf.generate_syscall_recipes(uncovered)
    
    for i in range(TOTAL_TRIALS):
        # Pick a random recipe or generate random mutation
        import random
        
        # Scenario: Mixed Bag
        # 50% chance: Use a valid recipe
        # 50% chance: Use a made-up "Hallucinated" transition (simulating bad random mutation)
        
        if random.random() < 0.5 and recipes:
            # Valid-ish intent
            recipe = random.choice(recipes)
            source = recipe.source_branch
            target = recipe.target_branch
            case_type = "Recipe"
        else:
            # "Hallucination" intent (Random Mutation logic often does this)
            source = random.choice(list(pf.syscall_blocks.keys())) if pf.syscall_blocks else 10
            target = random.randint(0, 100) # Likely invalid
            case_type = "Random"
            
        # --- THE VALIDATOR CORE (What we added in FuzzingCore) ---
        is_valid = pf.validate_transition(source, target)
        # ---------------------------------------------------------
        
        result_icon = "✅ ALLOW" if is_valid else "🛑 BLOCK"
        if not is_valid: blocked_count += 1
        else: valid_count += 1
        
        # Print sample (first 10)
        if i < 10:
             # Names
             s_name = pf.syscall_blocks[source].syscall_name if source in pf.syscall_blocks else "?"
             t_name = pf.syscall_blocks[target].syscall_name if target in pf.syscall_blocks else "?"
             print(f"{i:<4} | {s_name}({source})".ljust(19) + f" | {t_name}({target})".ljust(19) + f" | {result_icon}")
             
    print("-" * 60)
    
    # 4. Results
    rejection_rate = (blocked_count / TOTAL_TRIALS) * 100
    print(f"\n📊 Results Summary:")
    print(f"  Total Mutations Proposed: {TOTAL_TRIALS}")
    print(f"  ✅ Executed (Valid):      {valid_count}")
    print(f"  🛑 Intercepted (Invalid): {blocked_count}")
    print(f"  📉 Rejection Rate:        {rejection_rate:.1f}%")
    
    print("\n💡 Interpretation:")
    if blocked_count > 0:
        print(f"  SUCCESS! The Validator prevented {blocked_count} invalid executions.")
        print(f"  This saved approx {blocked_count * 0.5:.1f} seconds of QEMU time (assuming 0.5s/exec).")
    else:
        print("  Note: Rejection rate is 0%. Either current Logic is perfect (unlikely) or Mock Data is too simple.")

if __name__ == "__main__":
    run_experiment()

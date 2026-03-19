#!/usr/bin/env python3
"""
Verify Dictionary Mutation Logic
"""
import sys
import os
from pathlib import Path

# Add python path
sys.path.insert(0, "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/conductor")
# Add analysis path too just in case
sys.path.insert(0, "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/analysis")

from afl_enhanced_mutator import AFLEnhancedMutator, AFLStage
from instruction import FuzzInstruction

# Create a dummy candidate class
class MockCandidate:
    def __init__(self, index, name):
        self.index = index
        self.name = name

def test_manual_extraction():
    print(">>> Testing Manual Extraction Logic...")
    target_bin = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/test_dict_proof"
    
    if not os.path.exists(target_bin):
        print(f"❌ Error: Target binary {target_bin} not found. Did you compile it?")
        return

    # Instantiate logic wrapper
    class TestMutator(AFLEnhancedMutator):
        def __init__(self, target_bin):
            self.dictionary = []
            self.current_seed_data = b"AAAAAAAA"
            self.current_target_index = 0
            self._extract_dictionary_tokens(target_bin)
            
    mutator = TestMutator(target_bin)
    
    print(f"Dictionary Size: {len(mutator.dictionary)}")
    
    # Check for our specific magic token
    target_magic = b"FUZZMAGIC_TOKEN"
    found_magic = target_magic in mutator.dictionary
    print(f"Found Target Magic ({target_magic}): {found_magic}")
    
    if not found_magic:
        # Debugging: show what was found
        print(f"❌ FAILED: Magic token not found. First 20 tokens: {mutator.dictionary[:20]}")
        return

    # Test Generation
    print("\n>>> Testing Mutation Generation (Scanning for Magic Token)...")
    candidate = MockCandidate(1, "read")
    
    found_replacement = False
    # Try multiple times to overcome randomness
    for i in range(100):
        instrs = mutator._generate_extras_ao_instructions(candidate)
        for instr in instrs:
            if instr.data == target_magic or target_magic in instr.data:
                 print(f"✅ [Attempt {i+1}] Generated Mutation with Magic Token: {instr.data}")
                 found_replacement = True
                 break
        if found_replacement:
            break

    if found_replacement:
        print("✅ SUCCESS: Dictionary mutations generated with correct token.")
    else:
        print("❌ FAILURE: Magic token still not selected after 100 attempts.")

if __name__ == "__main__":
    test_manual_extraction()

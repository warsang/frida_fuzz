"""
manual_biodiff_test.py

A simple script to verify the functionality of the three biodiff algorithms in fridafuzzer_core:
- Wavefront Alignment (WFA2/pywfa)
- Needleman-Wunsch
- Smith-Waterman

This script creates two sample binary inputs with known differences, runs all three algorithms, and prints the results.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fridafuzzer_core.biodiff_algorithms import (
    needleman_wunsch,
    smith_waterman,
    wavefront_alignment
)

def print_alignment_result(name, result):
    print(f"\n=== {name} ===")
    print(f"Score: {result['score']}")
    print(f"Gap Analysis: {result['gap_analysis']}")
    print("Aligned Indices (first 20 shown):")
    for idx_pair in result['aligned_indices'][:20]:
        print(idx_pair)
    if len(result['aligned_indices']) > 20:
        print("... (truncated) ...")

def main():
    # Create two binary sequences with known differences
    seq1 = b"ABCDEFGH1234"
    seq2 = b"ABXDEFGY12345"

    print("Input 1:", seq1)
    print("Input 2:", seq2)

    # Needleman-Wunsch (global alignment)
    nw_result = needleman_wunsch(seq1, seq2)
    print_alignment_result("Needleman-Wunsch", nw_result)

    # Smith-Waterman (local alignment)
    sw_result = smith_waterman(seq1, seq2)
    print_alignment_result("Smith-Waterman", sw_result)

    # Wavefront Alignment (pywfa)
    try:
        wfa_result = wavefront_alignment(seq1, seq2)
        print_alignment_result("Wavefront Alignment (pywfa)", wfa_result)
    except ImportError as e:
        print("\n=== Wavefront Alignment (pywfa) ===")
        print("Skipped: pywfa package is not installed.")

if __name__ == "__main__":
    main()
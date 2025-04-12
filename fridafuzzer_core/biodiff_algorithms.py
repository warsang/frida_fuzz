"""
biodiff_algorithms.py

Implements binary diff alignment algorithms for fridafuzzer:
- Wavefront Alignment (WFA2)
- Needleman-Wunsch
- Smith-Waterman

All algorithms accept bytes or bytearray objects and return alignment results
suitable for HexdumpWidget highlighting.

Helper functions for visualization, gap analysis, and performance optimizations
using NumPy are included.

Dependencies: numpy, biopython, wfa2
"""

from typing import List, Tuple, Dict, Any, Optional, Union
import numpy as np

# Try to import wfa2, if available
try:
    import pywfa
    _HAS_PYWFA = True
except ImportError:
    _HAS_PYWFA = False

# Scoring matrix for binary data
def binary_score(a: int, b: int) -> int:
    """
    Custom scoring for binary alignment:
    - Exact byte match: +3
    - Both ASCII control chars (0x00-0x1F): +2
    - Both printable ASCII (0x20-0x7E): +1
    - Mismatch: -2
    """
    if a == b:
        return 3
    if 0x00 <= a <= 0x1F and 0x00 <= b <= 0x1F:
        return 2
    if 0x20 <= a <= 0x7E and 0x20 <= b <= 0x7E:
        return 1
    return -2

def _make_score_matrix(seq1: Union[bytes, bytearray], seq2: Union[bytes, bytearray]) -> np.ndarray:
    """
    Precompute the score matrix for all pairs.
    """
    s1 = np.frombuffer(seq1, dtype=np.uint8)
    s2 = np.frombuffer(seq2, dtype=np.uint8)
    mat = np.zeros((len(s1), len(s2)), dtype=np.int32)
    for i in range(len(s1)):
        for j in range(len(s2)):
            mat[i, j] = binary_score(s1[i], s2[j])
    return mat

def _alignment_to_highlight(aligned1: List[Optional[int]], aligned2: List[Optional[int]]) -> List[Tuple[Optional[int], Optional[int]]]:
    """
    Convert alignment index lists to a list of (i, j) pairs for highlighting.
    None means a gap.
    """
    return list(zip(aligned1, aligned2))

def _gap_analysis(aligned1: List[Optional[int]], aligned2: List[Optional[int]]) -> Dict[str, int]:
    """
    Analyze gaps in the alignment.
    Returns a dict with counts of insertions, deletions, and matches.
    """
    ins = del_ = match = 0
    for i, j in zip(aligned1, aligned2):
        if i is None:
            ins += 1
        elif j is None:
            del_ += 1
        else:
            match += 1
    return {"insertions": ins, "deletions": del_, "matches": match}

def visualize_alignment(seq1: Union[bytes, bytearray], seq2: Union[bytes, bytearray], aligned1: List[Optional[int]], aligned2: List[Optional[int]]) -> str:
    """
    Returns a string visualization of the alignment.
    """
    s1 = [f"{seq1[i]:02X}" if i is not None else "--" for i in aligned1]
    s2 = [f"{seq2[j]:02X}" if j is not None else "--" for j in aligned2]
    match_line = []
    for i, j in zip(aligned1, aligned2):
        if i is None or j is None:
            match_line.append(" ")
        elif seq1[i] == seq2[j]:
            match_line.append("|")
        else:
            match_line.append(".")
    return " ".join(s1) + "\n" + " ".join(match_line) + "\n" + " ".join(s2)

# Needleman-Wunsch Algorithm (global alignment)
def needleman_wunsch(
    seq1: Union[bytes, bytearray],
    seq2: Union[bytes, bytearray],
    gap_penalty: int = -2
) -> Dict[str, Any]:
    """
    Needleman-Wunsch global alignment for binary data.

    Returns:
        {
            "aligned_indices": List[Tuple[Optional[int], Optional[int]]],
            "score": int,
            "gap_analysis": Dict[str, int]
        }
    """
    n, m = len(seq1), len(seq2)
    score_mat = np.zeros((n+1, m+1), dtype=np.int32)
    pointer = np.zeros((n+1, m+1), dtype=np.int8)  # 0: diag, 1: up, 2: left

    # Initialize
    for i in range(1, n+1):
        score_mat[i, 0] = i * gap_penalty
        pointer[i, 0] = 1
    for j in range(1, m+1):
        score_mat[0, j] = j * gap_penalty
        pointer[0, j] = 2

    # Fill
    for i in range(1, n+1):
        for j in range(1, m+1):
            match = score_mat[i-1, j-1] + binary_score(seq1[i-1], seq2[j-1])
            delete = score_mat[i-1, j] + gap_penalty
            insert = score_mat[i, j-1] + gap_penalty
            best = max(match, delete, insert)
            score_mat[i, j] = best
            if best == match:
                pointer[i, j] = 0
            elif best == delete:
                pointer[i, j] = 1
            else:
                pointer[i, j] = 2

    # Traceback
    aligned1, aligned2 = [], []
    i, j = n, m
    while i > 0 or j > 0:
        if i > 0 and j > 0 and pointer[i, j] == 0:
            aligned1.append(i-1)
            aligned2.append(j-1)
            i -= 1
            j -= 1
        elif i > 0 and (j == 0 or pointer[i, j] == 1):
            aligned1.append(i-1)
            aligned2.append(None)
            i -= 1
        else:
            aligned1.append(None)
            aligned2.append(j-1)
            j -= 1
    aligned1.reverse()
    aligned2.reverse()
    return {
        "aligned_indices": _alignment_to_highlight(aligned1, aligned2),
        "score": int(score_mat[n, m]),
        "gap_analysis": _gap_analysis(aligned1, aligned2)
    }

# Smith-Waterman Algorithm (local alignment)
def smith_waterman(
    seq1: Union[bytes, bytearray],
    seq2: Union[bytes, bytearray],
    gap_penalty: int = -2
) -> Dict[str, Any]:
    """
    Smith-Waterman local alignment for binary data.

    Returns:
        {
            "aligned_indices": List[Tuple[Optional[int], Optional[int]]],
            "score": int,
            "gap_analysis": Dict[str, int]
        }
    """
    n, m = len(seq1), len(seq2)
    score_mat = np.zeros((n+1, m+1), dtype=np.int32)
    pointer = np.zeros((n+1, m+1), dtype=np.int8)  # 0: diag, 1: up, 2: left, 3: zero

    max_score = 0
    max_pos = (0, 0)

    # Fill
    for i in range(1, n+1):
        for j in range(1, m+1):
            match = score_mat[i-1, j-1] + binary_score(seq1[i-1], seq2[j-1])
            delete = score_mat[i-1, j] + gap_penalty
            insert = score_mat[i, j-1] + gap_penalty
            best = max(0, match, delete, insert)
            score_mat[i, j] = best
            if best == 0:
                pointer[i, j] = 3
            elif best == match:
                pointer[i, j] = 0
            elif best == delete:
                pointer[i, j] = 1
            else:
                pointer[i, j] = 2
            if best > max_score:
                max_score = best
                max_pos = (i, j)

    # Traceback
    aligned1, aligned2 = [], []
    i, j = max_pos
    while i > 0 and j > 0 and score_mat[i, j] > 0:
        if pointer[i, j] == 0:
            aligned1.append(i-1)
            aligned2.append(j-1)
            i -= 1
            j -= 1
        elif pointer[i, j] == 1:
            aligned1.append(i-1)
            aligned2.append(None)
            i -= 1
        elif pointer[i, j] == 2:
            aligned1.append(None)
            aligned2.append(j-1)
            j -= 1
        else:
            break
    aligned1.reverse()
    aligned2.reverse()
    return {
        "aligned_indices": _alignment_to_highlight(aligned1, aligned2),
        "score": int(max_score),
        "gap_analysis": _gap_analysis(aligned1, aligned2)
    }

# Wavefront Alignment Algorithm (pywfa)
def wavefront_alignment(
    seq1: Union[bytes, bytearray],
    seq2: Union[bytes, bytearray],
    match_score: int = 3,
    mismatch_penalty: int = -2,
    gap_opening: int = -2,
    gap_extension: int = -2
) -> Dict[str, Any]:
    """
    Wavefront Alignment (WFA2) for binary data.
    Requires the wfa2 package.

    Returns:
        {
            "aligned_indices": List[Tuple[Optional[int], Optional[int]]],
            "score": int,
            "gap_analysis": Dict[str, int]
        }
    """
    if not _HAS_PYWFA:
        raise ImportError("pywfa package is not installed.")

    # WFA2 expects strings, but we can encode bytes as latin1
    s1 = seq1.decode('latin1') if isinstance(seq1, bytes) else bytes(seq1).decode('latin1')
    s2 = seq2.decode('latin1') if isinstance(seq2, bytes) else bytes(seq2).decode('latin1')

    # Use the wfa2 Python API
    aligner = pywfa.WavefrontAligner(
        match=match_score,
        mismatch=mismatch_penalty,
        gap_open=gap_opening,
        gap_extend=gap_extension,
        alignment_scope="score+alignment",
        alignment_mode="global"
    )
    result = aligner.align(s1, s2)
    # Parse the CIGAR string to get aligned indices
    aligned1, aligned2 = [], []
    i, j = 0, 0
    for op in result.cigar:
        if op == 'M':  # match/mismatch
            aligned1.append(i)
            aligned2.append(j)
            i += 1
            j += 1
        elif op == 'I':  # insertion in seq1 (gap in seq2)
            aligned1.append(None)
            aligned2.append(j)
            j += 1
        elif op == 'D':  # deletion in seq1 (gap in seq1)
            aligned1.append(i)
            aligned2.append(None)
            i += 1
    return {
        "aligned_indices": _alignment_to_highlight(aligned1, aligned2),
        "score": int(result.score),
        "gap_analysis": _gap_analysis(aligned1, aligned2)
    }

# Helper: select algorithm
def align(
    seq1: Union[bytes, bytearray],
    seq2: Union[bytes, bytearray],
    method: str = "needleman-wunsch",
    **kwargs
) -> Dict[str, Any]:
    """
    Align two binary sequences using the specified method.
    method: "needleman-wunsch", "smith-waterman", or "wfa2"
    """
    if method == "needleman-wunsch":
        return needleman_wunsch(seq1, seq2, **kwargs)
    elif method == "smith-waterman":
        return smith_waterman(seq1, seq2, **kwargs)
    elif method == "wfa2":
        return wavefront_alignment(seq1, seq2, **kwargs)
    else:
        raise ValueError(f"Unknown alignment method: {method}")
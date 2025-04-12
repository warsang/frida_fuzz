import pytest
import sys

from fridafuzzer_core import biodiff_algorithms as bio

# Fixtures for common test data
@pytest.fixture
def identical_bytes():
    return b"\x01\x02\x03\x04\x05"

@pytest.fixture
def completely_different_bytes():
    return b"\x01\x02\x03\x04\x05", b"\xAA\xBB\xCC\xDD\xEE"

@pytest.fixture
def empty_bytes():
    return b"", b""

@pytest.fixture
def small_packet():
    return b"\x10\x20\x30\x40", b"\x10\x21\x30\x41"

@pytest.fixture
def sparse_diff_large():
    # 1KB mostly identical, with a few differences
    a = bytearray([0x55] * 1024)
    b = bytearray([0x55] * 1024)
    b[100] = 0xAA
    b[900] = 0xBB
    return bytes(a), bytes(b)

@pytest.fixture
def common_region_bytes():
    # Two sequences with a common region in the middle
    return b"\x00\x01\x02\x03\x04\x05\x06", b"\xAA\xBB\x02\x03\x04\xCC\xDD"

# Parameterized test cases for algorithms
@pytest.mark.parametrize("seq1,seq2,expected_score", [
    (b"\x01\x02\x03", b"\x01\x02\x03", 3),  # identical, expect max score
    (b"\x01\x02\x03", b"\x04\x05\x06", 0),  # completely different, expect low score
    (b"", b"", 0),                          # empty input
])
def test_needleman_wunsch_basic(seq1, seq2, expected_score):
    result = bio.needleman_wunsch(seq1, seq2)
    assert isinstance(result, dict)
    assert "aligned_indices" in result
    assert "score" in result
    assert "gap_analysis" in result
    # For identical, score should be len(seq1)
    if seq1 == seq2:
        assert result["score"] == len(seq1)
    # For empty, score should be 0
    if not seq1 and not seq2:
        assert result["score"] == 0
    # Output format
    for pair in result["aligned_indices"]:
        assert isinstance(pair, tuple)
        assert len(pair) == 2

@pytest.mark.parametrize("seq1,seq2,expected_score", [
    (b"\x01\x02\x03", b"\x01\x02\x03", 3),
    (b"\x01\x02\x03", b"\x04\x05\x06", 0),
    (b"", b"", 0),
])
def test_smith_waterman_basic(seq1, seq2, expected_score):
    result = bio.smith_waterman(seq1, seq2)
    assert isinstance(result, dict)
    assert "aligned_indices" in result
    assert "score" in result
    assert "gap_analysis" in result
    # For identical, score should be len(seq1)
    if seq1 == seq2:
        assert result["score"] == len(seq1)
    # For empty, score should be 0
    if not seq1 and not seq2:
        assert result["score"] == 0
    # Output format
    for pair in result["aligned_indices"]:
        assert isinstance(pair, tuple)
        assert len(pair) == 2

def test_needleman_wunsch_small_packet(small_packet):
    seq1, seq2 = small_packet
    result = bio.needleman_wunsch(seq1, seq2)
    assert result["score"] >= 2  # At least two matches
    assert isinstance(result["gap_analysis"], dict)

def test_smith_waterman_common_region(common_region_bytes):
    seq1, seq2 = common_region_bytes
    result = bio.smith_waterman(seq1, seq2)
    # Should find the common region (2,3,4)
    assert result["score"] >= 3
    assert result["gap_analysis"]["matches"] >= 3

def test_wavefront_alignment_sparse_diff(sparse_diff_large):
    try:
        seq1, seq2 = sparse_diff_large
        result = bio.wavefront_alignment(seq1, seq2)
        assert isinstance(result, dict)
        assert "aligned_indices" in result
        assert "score" in result
        assert "gap_analysis" in result
        # Should have mostly matches, a few mismatches
        assert result["gap_analysis"]["matches"] >= 1022
    except ImportError:
        pytest.skip("wfa2 package not installed")

def test_wavefront_alignment_empty(empty_bytes):
    try:
        seq1, seq2 = empty_bytes
        result = bio.wavefront_alignment(seq1, seq2)
        assert result["score"] == 0
        assert result["gap_analysis"]["matches"] == 0
    except ImportError:
        pytest.skip("wfa2 package not installed")

def test_align_dispatcher(identical_bytes):
    seq = identical_bytes
    for method in ["needleman-wunsch", "smith-waterman"]:
        result = bio.align(seq, seq, method=method)
        assert result["score"] == len(seq)
    try:
        result = bio.align(seq, seq, method="wfa2")
        assert result["score"] == len(seq)
    except ImportError:
        pass

# Helper function tests
def test_alignment_to_highlight_and_gap_analysis():
    aligned1 = [0, 1, None, 2]
    aligned2 = [0, None, 1, 2]
    highlight = bio._alignment_to_highlight(aligned1, aligned2)
    assert highlight == [(0, 0), (1, None), (None, 1), (2, 2)]
    gap = bio._gap_analysis(aligned1, aligned2)
    assert gap == {"insertions": 1, "deletions": 1, "matches": 2}

def test_visualize_alignment():
    seq1 = b"\x01\x02\x03"
    seq2 = b"\x01\xFF\x03"
    aligned1 = [0, 1, 2]
    aligned2 = [0, 1, 2]
    vis = bio.visualize_alignment(seq1, seq2, aligned1, aligned2)
    assert isinstance(vis, str)
    assert "01" in vis and "03" in vis
    assert "|" in vis or "." in vis

# Performance test (marked slow)
@pytest.mark.slow
def test_wavefront_alignment_performance(sparse_diff_large):
    try:
        seq1, seq2 = sparse_diff_large
        result = bio.wavefront_alignment(seq1, seq2)
        assert result["gap_analysis"]["matches"] >= 1022
    except ImportError:
        pytest.skip("wfa2 package not installed")
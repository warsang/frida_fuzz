import unittest
import math
from fridafuzzer_core.entropy_analyzer import EntropyAnalyzer

class TestEntropyAnalyzer(unittest.TestCase):

    def test_calculate_entropy_empty(self):
        """Test entropy calculation for empty data."""
        self.assertEqual(EntropyAnalyzer.calculate_entropy(b''), 0.0)

    def test_calculate_entropy_zero(self):
        """Test entropy calculation for data with zero entropy."""
        self.assertEqual(EntropyAnalyzer.calculate_entropy(b'\x00\x00\x00\x00'), 0.0)
        self.assertEqual(EntropyAnalyzer.calculate_entropy(b'AAAA'), 0.0)

    def test_calculate_entropy_known_values(self):
        """Test entropy calculation for data with known entropy values."""
        # Data: b'\x01\x02\x03\x04' - 4 unique bytes out of 4
        # Freq: [1/4, 1/4, 1/4, 1/4]
        # Entropy: -4 * (1/4 * log2(1/4)) = -4 * (1/4 * -2) = 2.0
        self.assertAlmostEqual(EntropyAnalyzer.calculate_entropy(b'\x01\x02\x03\x04'), 2.0)

        # Data: b'\x01\x01\x02\x02' - 2 unique bytes out of 4
        # Freq: [2/4, 2/4]
        # Entropy: -2 * (1/2 * log2(1/2)) = -2 * (1/2 * -1) = 1.0
        self.assertAlmostEqual(EntropyAnalyzer.calculate_entropy(b'\x01\x01\x02\x02'), 1.0)

        # Data: b'\x01\x01\x01\x02' - 2 unique bytes out of 4
        # Freq: [3/4, 1/4]
        # Entropy: -( (3/4 * log2(3/4)) + (1/4 * log2(1/4)) )
        # Entropy: -( (0.75 * -0.415) + (0.25 * -2.0) )
        # Entropy: -( -0.31125 - 0.5 ) = 0.81125
        expected_entropy = -((0.75 * math.log2(0.75)) + (0.25 * math.log2(0.25)))
        self.assertAlmostEqual(EntropyAnalyzer.calculate_entropy(b'\x01\x01\x01\x02'), expected_entropy)

    def test_sliding_window_empty(self):
        """Test sliding window entropy for empty data."""
        values, offsets = EntropyAnalyzer.sliding_window_entropy(b'', 10)
        self.assertEqual(values, [])
        self.assertEqual(offsets, [])

    def test_sliding_window_invalid_size(self):
        """Test sliding window entropy with invalid window size."""
        values, offsets = EntropyAnalyzer.sliding_window_entropy(b'\x01\x02\x03', 0)
        self.assertEqual(values, [])
        self.assertEqual(offsets, [])
        values, offsets = EntropyAnalyzer.sliding_window_entropy(b'\x01\x02\x03', -5)
        self.assertEqual(values, [])
        self.assertEqual(offsets, [])

    def test_sliding_window_size_larger_than_data(self):
        """Test sliding window entropy when window size exceeds data length."""
        data = b'\x01\x02\x03\x04'
        # Window size 10 > len(data) 4. Effective window size becomes 4.
        # Only one window: b'\x01\x02\x03\x04', entropy = 2.0, offset = 0
        expected_values = [2.0]
        expected_offsets = [0]
        values, offsets = EntropyAnalyzer.sliding_window_entropy(data, 10)
        self.assertAlmostEqual(values[0], expected_values[0])
        self.assertEqual(offsets, expected_offsets)
        self.assertEqual(len(values), len(expected_values))


    def test_sliding_window_simple(self):
        """Test sliding window entropy with a simple case."""
        data = b'\x01\x02\x03\x04'
        window_size = 2
        # Window 1: b'\x01\x02' -> Entropy = 1.0, Offset = 0
        # Window 2: b'\x02\x03' -> Entropy = 1.0, Offset = 1
        # Window 3: b'\x03\x04' -> Entropy = 1.0, Offset = 2
        expected_values = [1.0, 1.0, 1.0]
        expected_offsets = [0, 1, 2]
        values, offsets = EntropyAnalyzer.sliding_window_entropy(data, window_size)
        for v, ev in zip(values, expected_values):
            self.assertAlmostEqual(v, ev)
        self.assertEqual(offsets, expected_offsets)

    def test_sliding_window_zero_entropy(self):
        """Test sliding window entropy for data with zero entropy."""
        data = b'\x00\x00\x00\x00'
        window_size = 2
        # Window 1: b'\x00\x00' -> Entropy = 0.0, Offset = 0
        # Window 2: b'\x00\x00' -> Entropy = 0.0, Offset = 1
        # Window 3: b'\x00\x00' -> Entropy = 0.0, Offset = 2
        expected_values = [0.0, 0.0, 0.0]
        expected_offsets = [0, 1, 2]
        values, offsets = EntropyAnalyzer.sliding_window_entropy(data, window_size)
        for v, ev in zip(values, expected_values):
            self.assertAlmostEqual(v, ev)
        self.assertEqual(offsets, expected_offsets)

if __name__ == '__main__':
    unittest.main()
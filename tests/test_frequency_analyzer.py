import unittest
from fridafuzzer_core.frequency_analyzer import FrequencyAnalyzer

class TestFrequencyAnalyzer(unittest.TestCase):

    def test_calculate_frequencies_empty(self):
        """Test frequency calculation for empty data."""
        self.assertEqual(FrequencyAnalyzer.calculate_frequencies(b''), [])

    def test_calculate_frequencies_single_byte(self):
        """Test frequency calculation for data with a single unique byte."""
        expected = [(0xAA, 100.0)]
        result = FrequencyAnalyzer.calculate_frequencies(b'\xAA\xAA\xAA\xAA')
        self.assertEqual(len(result), len(expected))
        self.assertEqual(result[0][0], expected[0][0])
        self.assertAlmostEqual(result[0][1], expected[0][1])

    def test_calculate_frequencies_equal_counts(self):
        """Test frequency calculation for data with equal byte counts."""
        data = b'\x01\x01\x02\x02'
        expected_set = {(0x01, 50.0), (0x02, 50.0)}
        result = FrequencyAnalyzer.calculate_frequencies(data)
        # Convert result to set of tuples for order-independent comparison
        result_set = set((r[0], round(r[1], 5)) for r in result) # Round for float comparison
        expected_rounded_set = set((e[0], round(e[1], 5)) for e in expected_set)
        self.assertEqual(result_set, expected_rounded_set)
        self.assertEqual(len(result), 2) # Ensure correct number of entries

    def test_calculate_frequencies_mixed_counts(self):
        """Test frequency calculation for data with mixed byte counts."""
        data = b'\x01\x01\x01\x02\x02\x03' # 0x01: 3, 0x02: 2, 0x03: 1
        # Expected frequencies: 0x01: 3/6=50%, 0x02: 2/6=33.33%, 0x03: 1/6=16.66%
        expected = [
            (0x01, 50.0),
            (0x02, 100.0 / 3.0),
            (0x03, 50.0 / 3.0)
        ]
        result = FrequencyAnalyzer.calculate_frequencies(data)

        self.assertEqual(len(result), len(expected))
        for i in range(len(expected)):
            self.assertEqual(result[i][0], expected[i][0]) # Check byte value
            self.assertAlmostEqual(result[i][1], expected[i][1]) # Check frequency

    def test_calculate_frequencies_all_bytes(self):
        """Test frequency calculation with all 256 byte values present once."""
        data = bytes(range(256))
        expected_freq = (1 / 256) * 100
        result = FrequencyAnalyzer.calculate_frequencies(data)
        self.assertEqual(len(result), 256)
        # All frequencies should be equal
        for byte_val, freq in result:
            self.assertAlmostEqual(freq, expected_freq)
        # Check if all byte values are present (order might vary due to equal freqs)
        result_bytes = set(item[0] for item in result)
        expected_bytes = set(range(256))
        self.assertEqual(result_bytes, expected_bytes)


if __name__ == '__main__':
    unittest.main()
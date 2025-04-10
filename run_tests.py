import unittest
import sys

def run_tests():
    # Check if specific test file and test case are specified
    if len(sys.argv) > 2 and sys.argv[1] == "tests/test_hexdump_widget_ksy.py":
        # Load specific test file
        loader = unittest.TestLoader()
        test_module = __import__("tests.test_hexdump_widget_ksy", fromlist=['TestHexdumpWidgetKsy'])
        test_class = getattr(test_module, 'TestHexdumpWidgetKsy')
        
        # If specific test case is specified with -k flag
        if "-k" in sys.argv:
            test_name_idx = sys.argv.index("-k") + 1
            if test_name_idx < len(sys.argv):
                test_name = sys.argv[test_name_idx]
                suite = unittest.TestSuite()
                suite.addTest(test_class(test_name))
            else:
                suite = loader.loadTestsFromTestCase(test_class)
        else:
            suite = loader.loadTestsFromTestCase(test_class)
    else:
        # Default behavior for other test files
        suite = loader.discover('tests')
    
    # Run tests using TextTestRunner
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    # Exit with appropriate status code (0 for success, 1 for failure)
    exit(0 if success else 1)
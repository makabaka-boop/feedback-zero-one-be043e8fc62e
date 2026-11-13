#!/usr/bin/env python3
"""Test runner: prepends the workspace root to sys.path so the suite works
under ``python3 -I`` (isolated mode ignores cwd and PYTHONPATH)."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

if __name__ == "__main__":
    pattern = sys.argv[1] if len(sys.argv) > 1 else "test_*.py"
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(ROOT, "tests"), pattern=pattern)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

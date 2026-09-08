"""Run the Python suite from a clean source checkout.

This keeps local and CI behavior aligned without requiring an editable install
or relying on an ambient PYTHONPATH.
"""

from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

suite = unittest.defaultTestLoader.discover(str(ROOT / "python" / "tests"), pattern="test_*.py")
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)

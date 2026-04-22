from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sleeper_experiment import _variance  # noqa: E402


class TestVariance(unittest.TestCase):
    def test_variance_basic(self) -> None:
        self.assertEqual(_variance([3, 3, 3]), 0.0)
        v = _variance([1, 2, 3, 4, 5])
        assert v is not None
        self.assertGreater(v, 0)


if __name__ == "__main__":
    unittest.main()

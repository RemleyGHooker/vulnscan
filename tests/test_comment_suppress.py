"""Tests for comment-suppression aggregation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from comment_suppress import summarize_suppression  # noqa: E402


class TestSummarizeSuppression(unittest.TestCase):
    def test_basic_suppression(self) -> None:
        samples = [
            {"baseline_detected": True, "treatment_detected": False},
            {"baseline_detected": True, "treatment_detected": True},
            {"baseline_detected": False, "treatment_detected": False},
        ]
        s = summarize_suppression(samples)
        self.assertEqual(s["samples_evaluated"], 3)
        self.assertEqual(s["baseline_detection_count"], 2)
        self.assertEqual(s["treatment_detection_count"], 1)
        self.assertEqual(s["suppression_events"], 1)
        self.assertEqual(s["suppression_rate_given_baseline_detected"], 0.5)


if __name__ == "__main__":
    unittest.main()

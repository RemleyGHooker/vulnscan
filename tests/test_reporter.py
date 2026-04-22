"""Unit tests for reporter helpers (no API calls)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Repo root (parent of tests/)
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from reporter import normalize_finding, severity_meets_filter  # noqa: E402


class TestSeverityMeetsFilter(unittest.TestCase):
    def test_equal_threshold_included(self) -> None:
        self.assertTrue(severity_meets_filter("high", "high"))

    def test_above_threshold_included(self) -> None:
        self.assertTrue(severity_meets_filter("critical", "high"))
        self.assertTrue(severity_meets_filter("high", "medium"))

    def test_below_threshold_excluded(self) -> None:
        self.assertFalse(severity_meets_filter("low", "high"))
        self.assertFalse(severity_meets_filter("medium", "high"))

    def test_case_insensitive(self) -> None:
        self.assertTrue(severity_meets_filter("HIGH", "medium"))


class TestNormalizeFinding(unittest.TestCase):
    def test_full_valid_dict(self) -> None:
        raw = {
            "file_path": "src/app.py",
            "line_number": 42,
            "vulnerability_type": "sql_injection",
            "severity": "high",
            "description": "Unsafe query",
            "suggested_fix": "Use parameters",
        }
        out = normalize_finding(raw, "default.py")
        assert out is not None
        self.assertEqual(out["file_path"], "src/app.py")
        self.assertEqual(out["line_number"], 42)
        self.assertEqual(out["vulnerability_type"], "sql_injection")
        self.assertEqual(out["severity"], "high")
        self.assertEqual(out["description"], "Unsafe query")
        self.assertEqual(out["suggested_fix"], "Use parameters")

    def test_missing_file_path_uses_default(self) -> None:
        raw = {
            "line_number": 1,
            "vulnerability_type": "other",
            "severity": "low",
            "description": "x",
            "suggested_fix": "y",
        }
        out = normalize_finding(raw, "pkg/module.py")
        assert out is not None
        self.assertEqual(out["file_path"], "pkg/module.py")

    def test_invalid_severity_normalized_to_low(self) -> None:
        raw = {
            "file_path": "a.py",
            "line_number": 1,
            "vulnerability_type": "other",
            "severity": "nonsense",
            "description": "",
            "suggested_fix": "",
        }
        out = normalize_finding(raw, "a.py")
        assert out is not None
        self.assertEqual(out["severity"], "low")

    def test_invalid_line_number_returns_none(self) -> None:
        raw = {
            "file_path": "a.py",
            "line_number": "not-an-int",
            "vulnerability_type": "other",
            "severity": "low",
            "description": "",
            "suggested_fix": "",
        }
        self.assertIsNone(normalize_finding(raw, "a.py"))


if __name__ == "__main__":
    unittest.main()

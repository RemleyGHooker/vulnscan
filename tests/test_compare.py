"""Tests for compare finding diff logic."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from compare import diff_findings, findings_equivalent  # noqa: E402


class TestFindingsEquivalent(unittest.TestCase):
    def test_same_line_and_type(self) -> None:
        a = {"line_number": 10, "vulnerability_type": "sql_injection"}
        b = {"line_number": 12, "vulnerability_type": "sql_injection"}
        self.assertTrue(findings_equivalent(a, b, line_slack=5))

    def test_line_outside_slack(self) -> None:
        a = {"line_number": 10, "vulnerability_type": "sql_injection"}
        b = {"line_number": 20, "vulnerability_type": "sql_injection"}
        self.assertFalse(findings_equivalent(a, b, line_slack=5))

    def test_type_mismatch(self) -> None:
        a = {"line_number": 10, "vulnerability_type": "sql_injection"}
        b = {"line_number": 10, "vulnerability_type": "command_injection"}
        self.assertFalse(findings_equivalent(a, b))


class TestDiffFindings(unittest.TestCase):
    def test_partition(self) -> None:
        c = [
            {"line_number": 1, "vulnerability_type": "sql_injection"},
            {"line_number": 50, "vulnerability_type": "other"},
        ]
        g = [
            {"line_number": 2, "vulnerability_type": "sql_injection"},
            {"line_number": 99, "vulnerability_type": "hardcoded_secret"},
        ]
        c_only, g_only, pairs = diff_findings(c, g)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(len(c_only), 1)
        self.assertEqual(len(g_only), 1)


if __name__ == "__main__":
    unittest.main()

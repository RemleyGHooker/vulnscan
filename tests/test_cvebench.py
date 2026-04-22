"""Tests for CVE bench matching helper."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cvebench import finding_matches_expected  # noqa: E402


class TestFindingMatchesExpected(unittest.TestCase):
    def test_direct_type_match(self) -> None:
        findings = [{"vulnerability_type": "sql_injection", "description": ""}]
        self.assertTrue(finding_matches_expected(findings, ["sql_injection"]))

    def test_no_match(self) -> None:
        findings = [{"vulnerability_type": "memory_leak", "description": ""}]
        self.assertFalse(finding_matches_expected(findings, ["sql_injection"]))

    def test_description_heuristic(self) -> None:
        findings = [
            {"vulnerability_type": "other", "description": "SQL injection via string concat"}
        ]
        self.assertTrue(finding_matches_expected(findings, ["sql_injection"]))


if __name__ == "__main__":
    unittest.main()

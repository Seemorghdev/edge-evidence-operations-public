from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edge_evidence_operations.inventory_readiness import FUTURE_ACTION_AUTHORITY
from edge_evidence_operations.portfolio_demo import run_demo


class ProjectionBehaviorTest(unittest.TestCase):
    def test_recruiter_demo_matches_committed_example(self) -> None:
        expected = json.loads((ROOT / "examples/portfolio-demo.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_demo(Path(tmp) / "demo", ROOT / "runbooks")
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["portfolio"], expected)
        self.assertEqual(
            summary["portfolio"]["command"]["second_execution_attempts"], 0
        )
        self.assertEqual(summary["portfolio"]["execution"]["outcome"], "success")
        self.assertTrue(summary["portfolio"]["evidence"]["readback_verified"])

    def test_offline_validator_has_no_future_action_authority(self) -> None:
        self.assertTrue(FUTURE_ACTION_AUTHORITY)
        self.assertFalse(any(FUTURE_ACTION_AUTHORITY.values()))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Run the recruiter-facing offline demo from a clean checkout."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from edge_evidence_operations.portfolio_demo import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())

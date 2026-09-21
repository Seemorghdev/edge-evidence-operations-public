#!/usr/bin/env python3
"""Fail closed on publication-sensitive material or authority-bearing CI."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".portfolio-demo", "__pycache__"}

patterns = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----", re.I),
    "service account coordinate": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com\b", re.I
    ),
    "WIF coordinate": re.compile(
        r"\bprojects/\d+/locations/global/workloadIdentityPools/[A-Za-z0-9._-]+/"
        r"providers/[A-Za-z0-9._-]+\b"
    ),
    "private registry coordinate": re.compile(
        r"\b[a-z0-9-]+-docker\.pkg\.dev/[a-z0-9-]+/[A-Za-z0-9._/-]+\b", re.I
    ),
    "GitHub PAT": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "JWT": re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    ),
    "private-source commit/tree shaped identifier": re.compile(
        r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I
    ),
}

# The projection has no repository-coordinate links at all. Keeping this generic
# avoids embedding a private source repository name in the guard itself.
owner_slash = "Seemorghdev" + "/"

for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or any(part in SKIP for part in path.parts):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit(f"binary/non-UTF8 file refused: {path.relative_to(ROOT)}") from error
    if owner_slash in text:
        raise SystemExit(f"repository coordinate found in {path.relative_to(ROOT)}")
    for label, pattern in patterns.items():
        if pattern.search(text):
            raise SystemExit(f"{label} found in {path.relative_to(ROOT)}")

workflow = (ROOT / ".github/workflows/required.yml").read_text(encoding="utf-8")
for forbidden in (
    "id-token: write",
    "contents: write",
    "issues: write",
    "pull-requests: write",
    "packages: write",
    "deployments: write",
):
    if forbidden in workflow:
        raise SystemExit(f"authority-bearing workflow permission found: {forbidden}")
if "contents: read" not in workflow:
    raise SystemExit("read-only contents permission missing")

for forbidden_path in ("ops/", "transplant", "source-manifest", "disposition"):
    for path in ROOT.rglob("*"):
        if any(part in SKIP for part in path.parts):
            continue
        if forbidden_path.lower() in path.as_posix().lower():
            raise SystemExit(f"publication-sensitive path found: {path.relative_to(ROOT)}")

print("Public projection validation PASSED.")

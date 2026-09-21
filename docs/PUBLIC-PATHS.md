# Public path allowlist

Only the files listed below belong to this projection. The export is allowlist-first; anything not listed is out of scope for publication.

```text
.devcontainer/devcontainer.json
.github/workflows/required.yml
.gitignore
LICENSE
NOTICE
README.md
docs/ARCHITECTURE.md
docs/CONTROL-MODEL.md
docs/PROJECTION-PROVENANCE.md
docs/PROJECTION-VALIDATION.md
docs/PUBLIC-PATHS.md
examples/portfolio-demo.json
pyproject.toml
runbooks/inspect-v1.sh
scripts/check_public_projection.py
scripts/portfolio_demo.py
src/edge_evidence_operations/__init__.py
src/edge_evidence_operations/control.py
src/edge_evidence_operations/evidence_bundle.py
src/edge_evidence_operations/github_transport.py
src/edge_evidence_operations/history.py
src/edge_evidence_operations/inventory_readiness.py
src/edge_evidence_operations/model.py
src/edge_evidence_operations/portfolio_demo.py
src/edge_evidence_operations/receipt.py
src/edge_evidence_operations/registry.py
src/edge_evidence_operations/sanitize.py
tests/test_projection.py
```

The list contains recruiter navigation, public-safe control/architecture documentation, offline product code, one synthetic read-only runbook, one deterministic example, focused tests, license/NOTICE, minimal development metadata, read-only CI, and the projection privacy guard.

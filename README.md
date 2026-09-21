# Edge Evidence Operations

A history-free recruiter-facing projection of a reviewed Operations control-plane product.

The product story is deliberately narrow:

```text
intent
→ canonical command identity
→ complete-history / duplicate check
→ policy decision
→ exact runbook binding
→ one authorized attempt
→ receipt
→ verification
→ retained evidence
```

This repository is an **offline projection**. It demonstrates the control and evidence semantics without carrying live cloud authority, credentials, provider adapters, repository mutation, publication authority, or infrastructure mutation.

## 60-second review

Requirements: Python 3.12+ and Bash.

```bash
python scripts/check_public_projection.py
python -m unittest discover -s tests -v
python scripts/portfolio_demo.py --output .portfolio-demo
diff -u examples/portfolio-demo.json .portfolio-demo/portfolio.json
```

The demo proves, with deterministic local inputs:

- stable semantic command identity;
- complete-history duplicate rejection before a second execution attempt;
- policy and exact runbook binding;
- exactly one consumed authorization attempt;
- structured execution receipt and verification result;
- create-only retained evidence with read-back verification;
- a sanitized offline readiness validator whose future-action authority is entirely false.

## Recruiter navigation

- `docs/ARCHITECTURE.md` — system boundary and component map.
- `docs/CONTROL-MODEL.md` — the control sequence and fail-closed invariants.
- `docs/PROJECTION-PROVENANCE.md` — public-safe projection provenance.
- `src/edge_evidence_operations/` — reviewed offline product code.
- `runbooks/inspect-v1.sh` — synthetic read-only runbook used by the demo.
- `examples/portfolio-demo.json` — deterministic expected recruiter output.
- `tests/` — focused projection behavior tests.
- `.github/workflows/required.yml` — bounded read-only validation.

## Authority boundary

The code consumes caller-supplied local data and local synthetic runbooks. It does not authenticate to a provider, query cloud state, acquire credentials, deploy workloads, mutate infrastructure, publish releases, or perform an authority cutover.

A future production adapter would be a separate authority-bearing surface and is intentionally absent here.

## Provenance

Generated from a reviewed private canonical source. The projection uses an allowlist-first export and starts from fresh Git history. Private source identity, private source object identifiers, extraction manifests, source-path mappings, canonical issues/PRs/comments, and live authority adapters are not included.

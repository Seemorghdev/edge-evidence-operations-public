# Architecture

## Boundary

This projection contains the offline Operations product layer only. External systems are represented by caller-supplied, bounded data. There is no network client and no live provider adapter.

```text
caller-supplied intent / history
            |
            v
  canonical command model
            |
            v
 complete-history duplicate gate
            |
            v
       review policy
            |
            v
 exact local runbook snapshot
            |
            v
   one-attempt local ledger
            |
            v
 execution receipt + verification
            |
            v
 create-only evidence manifest
```

A separate offline readiness evaluator accepts sanitized fingerprints, a public-safe region token, reviewed service names, and an inventory count. Its result object explicitly carries an all-false future-action authority map.

## Components

`model.py` defines bounded command/review contracts and stable identities. `history.py` proves complete history or fails closed. `github_transport.py` adapts caller-supplied GitHub-like envelopes without network access. `registry.py` binds exact runbook bytes. `control.py` consumes one authorization attempt before preflight or execution and emits structured receipts. `evidence_bundle.py` builds deterministic create-only evidence manifests and verifies persisted bytes. `inventory_readiness.py` evaluates sanitized offline readiness observations.

## Non-goals

This projection does not include authentication, cloud/API clients, credential acquisition, IAM changes, Terraform execution, Kubernetes mutation, deployment, upload, publication, retries, rollback authority, or authority cutover.

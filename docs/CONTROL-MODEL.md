# Control model

The accepted control sequence is:

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

## Fail-closed invariants

A command is rejected if its schema is malformed, its review context is not permitted, its complete history cannot be proven, or a semantically identical consumed command already exists. Authorization binds the exact runbook digest. The one-shot ledger claims the authorization before preflight or execution, so failure does not create retry authority.

Execution evidence retains hashes and bounded metadata rather than raw command output. Verification failure is represented explicitly in the receipt. Evidence manifests are path-sorted, content-addressed, create-only, and re-read after write for canonical-byte verification.

The recruiter demo is local and deterministic. Its mutation capability is disabled; the synthetic runbook used by the public path is read-only.

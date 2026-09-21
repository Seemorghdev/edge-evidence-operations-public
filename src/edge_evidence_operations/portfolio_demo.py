"""One-command, credential-free portfolio demonstration of Operations."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .control import AttemptLedger, ControlPlane, Executor
from .evidence_bundle import ArtifactDescriptor, BundleStore, EvidenceBundle
from .github_transport import (
    CommentEnvelope,
    OfflineCommentHistoryProvider,
    TransportHistoryPage,
    TransportPolicy,
    authorize_comment,
)
from .history import DuplicateCommandError
from .inventory_readiness import (
    FUTURE_ACTION_AUTHORITY,
    REQUIRED_SERVICES,
    ExpectedInventoryContract,
    InventoryObservation,
    evaluate_inventory_readiness,
)
from .model import ActionPolicy, ReviewPolicy, digest_json
from .registry import RunbookRegistry


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _command_payload() -> dict[str, object]:
    return {
        "version": "v1",
        "action": "inspect",
        "runbook": "inspect-v1",
        "arguments": {"scope": "portfolio-synthetic"},
        "mutation": False,
    }


def _command_body() -> str:
    return "ops-review " + json.dumps(
        _command_payload(), sort_keys=True, separators=(",", ":")
    )


def _empty_history(policy: TransportPolicy) -> OfflineCommentHistoryProvider:
    return OfflineCommentHistoryProvider(
        {
            None: TransportHistoryPage(
                comments=(), next_cursor=None, complete=True
            )
        },
        policy,
    )


def _prior_history(
    policy: TransportPolicy, prior_comment: dict[str, object]
) -> OfflineCommentHistoryProvider:
    return OfflineCommentHistoryProvider(
        {
            None: TransportHistoryPage(
                comments=(prior_comment,), next_cursor=None, complete=True
            )
        },
        policy,
    )


def _fingerprint(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def run_demo(
    output: Path, runbook_root: Path = Path("runbooks")
) -> dict[str, object]:
    """Run one deterministic offline control -> evidence -> validator story."""
    if output.exists():
        raise SystemExit(f"refusing to reuse portfolio demo output directory: {output}")
    output.mkdir(parents=True)

    transport_policy = TransportPolicy(
        expected_repository="demo-org/operations",
        allowed_issues=frozenset({7}),
        allowed_actors=frozenset({"reviewer-a", "reviewer-b"}),
    )
    review_policy = ReviewPolicy(
        allowed_reviewers=frozenset({"reviewer-a", "reviewer-b"}),
        actions={"inspect": ActionPolicy(runbook="inspect-v1", mutation=False)},
    )
    registry = RunbookRegistry(runbook_root, {"inspect-v1": "inspect-v1.sh"})
    control = ControlPlane(review_policy, registry)

    first_comment = {
        "repository": "demo-org/operations",
        "issue": 7,
        "comment_id": 100,
        "actor": "reviewer-a",
        "body": _command_body(),
    }
    first_envelope = CommentEnvelope.from_mapping(first_comment)
    authorization, intent = authorize_comment(
        control,
        first_envelope,
        transport_policy,
        _empty_history(transport_policy),
    )

    ledger = AttemptLedger(output / "ledger")
    executor = Executor(registry, ledger, output / "work")
    receipt = executor.execute(authorization, verify=lambda _auth, _work: True)
    if receipt.outcome != "success" or receipt.exit_code != 0:
        raise AssertionError("synthetic portfolio execution did not succeed")

    claims_before_duplicate = len(list((output / "ledger").iterdir()))
    second_envelope = CommentEnvelope.from_mapping(
        {
            "repository": "demo-org/operations",
            "issue": 7,
            "comment_id": 101,
            "actor": "reviewer-b",
            "body": _command_body(),
        }
    )
    try:
        authorize_comment(
            control,
            second_envelope,
            transport_policy,
            _prior_history(transport_policy, first_comment),
        )
    except DuplicateCommandError:
        duplicate_rejected = True
    else:
        raise AssertionError("semantic duplicate was unexpectedly authorized")
    if len(list((output / "ledger").iterdir())) != claims_before_duplicate:
        raise AssertionError("duplicate rejection changed the execution ledger")

    project_fingerprint = _fingerprint("portfolio-project")
    principal_fingerprint = _fingerprint("portfolio-principal")
    expected = ExpectedInventoryContract.from_mapping(
        {
            "version": "gke-inventory-readiness-v1",
            "project_fingerprint": project_fingerprint,
            "region": "region-demo",
            "principal_fingerprint": principal_fingerprint,
        }
    )
    observed = InventoryObservation.from_mapping(
        {
            "version": "gke-inventory-readiness-observation-v1",
            "project_fingerprint": project_fingerprint,
            "region": "region-demo",
            "declared_principal_fingerprint": principal_fingerprint,
            "active_principal_fingerprint": principal_fingerprint,
            "enabled_services": list(REQUIRED_SERVICES),
            "inventory_observed": True,
            "cluster_count": 0,
        }
    )
    validator = evaluate_inventory_readiness(expected, observed)
    if validator.status != "ready" or any(FUTURE_ACTION_AUTHORITY.values()):
        raise AssertionError("offline validator authority contract drifted")

    artifacts_root = output / "artifacts"
    _write_json(artifacts_root / "dispatch-intent.json", intent.as_dict())
    _write_json(
        artifacts_root / "execution-receipt.json",
        {**receipt.as_dict(), "receipt_digest": receipt.receipt_digest},
    )
    _write_json(
        artifacts_root / "duplicate-decision.json",
        {
            "command_id": intent.command_id,
            "duplicate_rejected": duplicate_rejected,
            "execution_attempts_created": 0,
            "retry_authorized": False,
        },
    )
    _write_json(artifacts_root / "validator-result.json", validator.as_mapping())

    artifacts = [
        ArtifactDescriptor.from_local(
            artifacts_root, "dispatch-intent.json", "application/json"
        ),
        ArtifactDescriptor.from_local(
            artifacts_root, "duplicate-decision.json", "application/json"
        ),
        ArtifactDescriptor.from_local(
            artifacts_root, "execution-receipt.json", "application/json"
        ),
        ArtifactDescriptor.from_local(
            artifacts_root, "validator-result.json", "application/json"
        ),
    ]
    bundle = EvidenceBundle.create(
        intent,
        retention_days=14,
        artifacts=artifacts,
        receipt=receipt,
        metadata={
            "classification": "portfolio-evidence",
            "producer": "edge-evidence-operations",
        },
    )
    proof = BundleStore(output / "bundle-store").write_new(bundle)

    portfolio = {
        "command": {
            "canonical_identity": "sha256",
            "first_decision": "authorized",
            "second_decision": "duplicate_rejected",
            "second_execution_attempts": 0,
        },
        "evidence": {
            "artifact_count": len(bundle.artifacts),
            "readback_verified": True,
            "retention_days": int(bundle.retention),
        },
        "execution": {
            "outcome": receipt.outcome,
            "retry_authorized": receipt.retry_authorized,
            "rollback_performed": receipt.rollback_performed,
        },
        "status": "pass",
        "validator": {
            "classification": validator.classification,
            "future_action_authority": "all_false",
            "status": validator.status,
        },
    }
    core = {
        "authorization_id": intent.authorization_id,
        "bundle_digest": bundle.bundle_digest,
        "command_id": intent.command_id,
        "dispatch_id": bundle.dispatch.dispatch_id,
        "duplicate_rejected": duplicate_rejected,
        "execution_id": receipt.execution_id,
        "manifest_sha256": proof.manifest_sha256,
        "portfolio": portfolio,
        "receipt_id": receipt.receipt_digest,
        "review_id": intent.review_id,
        "validator_result_id": validator.result_id,
    }
    summary = {
        **core,
        "summary_fingerprint": digest_json(core),
        "status": "pass",
    }
    _write_json(output / "portfolio.json", portfolio)
    _write_json(output / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=Path(".portfolio-demo")
    )
    parser.add_argument(
        "--runbook-root",
        type=Path,
        default=Path("runbooks"),
        help="directory containing the synthetic read-only runbook",
    )
    args = parser.parse_args()
    summary = run_demo(args.output, args.runbook_root)
    print(json.dumps(summary["portfolio"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

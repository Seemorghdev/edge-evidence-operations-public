"""Pure offline GKE inventory-readiness evaluator.

This module is a sanitized copy-first extraction of the reviewed source
validator semantics. It accepts caller-supplied observations only; it never
authenticates, reads provider evidence, queries a provider, executes Terraform,
or grants future action.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .model import canonical_json, digest_json

EXPECTED_VERSION = "gke-inventory-readiness-v1"
OBSERVED_VERSION = "gke-inventory-readiness-observation-v1"
RESULT_VERSION = "gke-inventory-readiness-result-v1"

REQUIRED_SERVICES = (
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
)

CLASSIFICATION_DRIFT = "gke_inventory_preflight_drift"
CLASSIFICATION_REQUIRED_SERVICES_MISSING = (
    "gke_inventory_not_ready_required_services_missing"
)
CLASSIFICATION_NOT_OBSERVED = "gke_inventory_not_observed"
CLASSIFICATION_REVIEW_EXISTING = "gke_inventory_review_existing_clusters"
CLASSIFICATION_READY_NO_CLUSTER = "gke_inventory_ready_no_cluster"

MAX_MODEL_BYTES = 32 * 1024
MAX_TOKEN_LENGTH = 128
MAX_SERVICE_ITEMS = len(REQUIRED_SERVICES)
MAX_CLUSTER_COUNT = 100_000

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_PROJECT = re.compile(
    r"^project-[0-9a-f]{8}(?:-[0-9a-f]{3,12}){2,5}$",
    re.I,
)

EXPECTED_FIELDS = {
    "version",
    "project_fingerprint",
    "region",
    "principal_fingerprint",
}
OBSERVED_FIELDS = {
    "version",
    "project_fingerprint",
    "region",
    "declared_principal_fingerprint",
    "active_principal_fingerprint",
    "enabled_services",
    "inventory_observed",
    "cluster_count",
}

FUTURE_ACTION_AUTHORITY = {
    "authenticate": False,
    "collect_provider_state": False,
    "cluster_create": False,
    "cluster_delete": False,
    "credentials_acquisition": False,
    "helm": False,
    "kubectl": False,
    "network_mutation": False,
    "iam_mutation": False,
    "workload_deploy": False,
    "terraform_plan": False,
    "terraform_apply": False,
    "terraform_import": False,
    "terraform_destroy": False,
    "dispatch": False,
    "execute": False,
    "retry": False,
    "rollback": False,
    "publication": False,
    "upload": False,
    "authority_cutover": False,
}


class InventoryReadinessError(ValueError):
    """Sanitized inventory-readiness input is malformed or outside v1."""


def _bounded_mapping(raw: Mapping[str, Any], expected: set[str], label: str) -> None:
    if not isinstance(raw, Mapping):
        raise InventoryReadinessError(f"{label} must be an object")
    if set(raw) != expected:
        missing = sorted(expected - set(raw))
        unknown = sorted(set(raw) - expected)
        raise InventoryReadinessError(
            f"{label} fields mismatch: missing={missing}, unknown={unknown}"
        )
    if len(canonical_json(raw)) > MAX_MODEL_BYTES:
        raise InventoryReadinessError(f"{label} exceeds size limit")


def _fingerprint(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise InventoryReadinessError(f"{field} must be lowercase SHA-256 hex")
    return value


def _token(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TOKEN_LENGTH:
        raise InventoryReadinessError(f"{field} must be a non-empty bounded token")
    if not _TOKEN.fullmatch(value):
        raise InventoryReadinessError(f"{field} contains non-public-safe token syntax")
    if _PRIVATE_PROJECT.fullmatch(value):
        raise InventoryReadinessError(f"{field} resembles a private project coordinate")
    lowered = value.lower()
    if "gserviceaccount" in lowered or "workloadidentity" in lowered:
        raise InventoryReadinessError(f"{field} resembles a private identity coordinate")
    return value


def _bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise InventoryReadinessError(f"{field} must be boolean")
    return value


def _count(value: Any, field: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_CLUSTER_COUNT:
        raise InventoryReadinessError(f"{field} must be a bounded non-negative integer")
    return value


def _normalized_services(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise InventoryReadinessError(f"{field} must be a list")
    if len(value) > MAX_SERVICE_ITEMS:
        raise InventoryReadinessError(f"{field} exceeds item limit")
    services: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in REQUIRED_SERVICES:
            raise InventoryReadinessError(
                f"{field} may contain only the reviewed required-service projection"
            )
        services.append(item)
    if len(set(services)) != len(services):
        raise InventoryReadinessError(f"{field} contains duplicate values")
    return tuple(sorted(services))


@dataclass(frozen=True, slots=True)
class ExpectedInventoryContract:
    version: str
    project_fingerprint: str
    region: str
    principal_fingerprint: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ExpectedInventoryContract":
        _bounded_mapping(raw, EXPECTED_FIELDS, "expected inventory contract")
        if raw["version"] != EXPECTED_VERSION:
            raise InventoryReadinessError("unsupported expected inventory version")
        return cls(
            version=EXPECTED_VERSION,
            project_fingerprint=_fingerprint(
                raw["project_fingerprint"], "project_fingerprint"
            ),
            region=_token(raw["region"], "region"),
            principal_fingerprint=_fingerprint(
                raw["principal_fingerprint"], "principal_fingerprint"
            ),
        )

    def as_mapping(self) -> dict[str, object]:
        return {
            "principal_fingerprint": self.principal_fingerprint,
            "project_fingerprint": self.project_fingerprint,
            "region": self.region,
            "version": self.version,
        }

    @property
    def identity(self) -> str:
        return digest_json(self.as_mapping())


@dataclass(frozen=True, slots=True)
class InventoryObservation:
    version: str
    project_fingerprint: str
    region: str
    declared_principal_fingerprint: str
    active_principal_fingerprint: str
    enabled_services: tuple[str, ...]
    inventory_observed: bool
    cluster_count: int

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "InventoryObservation":
        _bounded_mapping(raw, OBSERVED_FIELDS, "inventory observation")
        if raw["version"] != OBSERVED_VERSION:
            raise InventoryReadinessError("unsupported inventory observation version")
        return cls(
            version=OBSERVED_VERSION,
            project_fingerprint=_fingerprint(
                raw["project_fingerprint"], "project_fingerprint"
            ),
            region=_token(raw["region"], "region"),
            declared_principal_fingerprint=_fingerprint(
                raw["declared_principal_fingerprint"],
                "declared_principal_fingerprint",
            ),
            active_principal_fingerprint=_fingerprint(
                raw["active_principal_fingerprint"], "active_principal_fingerprint"
            ),
            enabled_services=_normalized_services(
                raw["enabled_services"], "enabled_services"
            ),
            inventory_observed=_bool(raw["inventory_observed"], "inventory_observed"),
            cluster_count=_count(raw["cluster_count"], "cluster_count"),
        )

    def as_mapping(self) -> dict[str, object]:
        return {
            "active_principal_fingerprint": self.active_principal_fingerprint,
            "cluster_count": self.cluster_count,
            "declared_principal_fingerprint": self.declared_principal_fingerprint,
            "enabled_services": list(self.enabled_services),
            "inventory_observed": self.inventory_observed,
            "project_fingerprint": self.project_fingerprint,
            "region": self.region,
            "version": self.version,
        }

    @property
    def identity(self) -> str:
        return digest_json(self.as_mapping())


@dataclass(frozen=True, slots=True)
class InventoryReadinessResult:
    classification: str
    status: str
    exit_code: int
    expected_contract_digest: str
    observed_snapshot_digest: str
    drift_count: int
    missing_required_service_count: int
    inventory_observed: bool
    cluster_count: int | None
    ready: bool
    review_required: bool

    def identity_payload(self) -> dict[str, object]:
        return {
            "classification": self.classification,
            "cluster_count": self.cluster_count,
            "drift_count": self.drift_count,
            "exit_code": self.exit_code,
            "expected_contract_digest": self.expected_contract_digest,
            "future_action_authority": dict(FUTURE_ACTION_AUTHORITY),
            "inventory_observed": self.inventory_observed,
            "missing_required_service_count": self.missing_required_service_count,
            "observed_snapshot_digest": self.observed_snapshot_digest,
            "ready": self.ready,
            "review_required": self.review_required,
            "status": self.status,
            "version": RESULT_VERSION,
        }

    @property
    def result_id(self) -> str:
        return digest_json(self.identity_payload())

    def as_mapping(self) -> dict[str, object]:
        result = self.identity_payload()
        result["result_id"] = self.result_id
        return result

    def render(self) -> str:
        return json.dumps(
            self.as_mapping(),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n"


def evaluate_inventory_readiness(
    expected: ExpectedInventoryContract,
    observed: InventoryObservation,
) -> InventoryReadinessResult:
    drift_count = sum(
        (
            observed.project_fingerprint != expected.project_fingerprint,
            observed.region != expected.region,
            observed.declared_principal_fingerprint != expected.principal_fingerprint,
            observed.active_principal_fingerprint != expected.principal_fingerprint,
        )
    )
    missing_services = set(REQUIRED_SERVICES) - set(observed.enabled_services)

    if drift_count:
        classification = CLASSIFICATION_DRIFT
        status = "refused"
        exit_code = 2
    elif missing_services:
        classification = CLASSIFICATION_REQUIRED_SERVICES_MISSING
        status = "refused"
        exit_code = 2
    elif not observed.inventory_observed:
        classification = CLASSIFICATION_NOT_OBSERVED
        status = "refused"
        exit_code = 2
    elif observed.cluster_count:
        classification = CLASSIFICATION_REVIEW_EXISTING
        status = "review"
        exit_code = 0
    else:
        classification = CLASSIFICATION_READY_NO_CLUSTER
        status = "ready"
        exit_code = 0

    return InventoryReadinessResult(
        classification=classification,
        status=status,
        exit_code=exit_code,
        expected_contract_digest=expected.identity,
        observed_snapshot_digest=observed.identity,
        drift_count=drift_count,
        missing_required_service_count=len(missing_services),
        inventory_observed=observed.inventory_observed,
        cluster_count=observed.cluster_count if observed.inventory_observed else None,
        ready=classification == CLASSIFICATION_READY_NO_CLUSTER,
        review_required=classification == CLASSIFICATION_REVIEW_EXISTING,
    )

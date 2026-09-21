"""Deterministic offline evidence bundle and retention contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .github_transport import DispatchIntent
from .model import canonical_json, digest_json
from .receipt import Receipt

MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
MAX_PATH_BYTES = 512
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+_-]{0,31}/[a-z0-9][a-z0-9.+_-]{0,63}$")
_METADATA_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SENSITIVE_TOKEN = re.compile(
    r"token|secret|password|credential|private[_-]?key|authorization|bearer", re.I
)
_ALLOWED_METADATA_FIELDS = {"classification", "producer"}


class EvidenceBundleError(ValueError):
    """Evidence input cannot be proven bounded, safe, and deterministic."""


class BundleCollisionError(EvidenceBundleError):
    """A bundle destination already exists and is never overwritten."""


class ManifestVerificationError(EvidenceBundleError):
    """Persisted manifest bytes do not match the expected bundle proof."""


def _require_digest(name: str, value: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise EvidenceBundleError(f"{name} must be lowercase SHA-256 hex")
    return value


def _safe_metadata_token(name: str, value: object) -> str:
    if not isinstance(value, str) or not _METADATA_TOKEN.fullmatch(value):
        raise EvidenceBundleError(
            f"metadata {name} must be a bounded public-safe token"
        )
    if _SENSITIVE_TOKEN.search(value):
        raise EvidenceBundleError(f"metadata {name} contains a sensitive token")
    return value


class RetentionClass(IntEnum):
    DAYS_7 = 7
    DAYS_14 = 14
    DAYS_30 = 30

    @classmethod
    def from_days(cls, days: int) -> "RetentionClass":
        if type(days) is not int:
            raise EvidenceBundleError("retention days must be an integer class")
        try:
            return cls(days)
        except ValueError as error:
            raise EvidenceBundleError(
                "retention days must be exactly 7, 14, or 30"
            ) from error

    @property
    def label(self) -> str:
        return f"days-{int(self)}"


@dataclass(frozen=True, slots=True)
class BundleMetadata:
    classification: str
    producer: str

    def __post_init__(self) -> None:
        _safe_metadata_token("classification", self.classification)
        _safe_metadata_token("producer", self.producer)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "BundleMetadata":
        source: Mapping[str, Any] = raw or {
            "classification": "offline-evidence",
            "producer": "edge-evidence-operations",
        }
        if not isinstance(source, Mapping):
            raise EvidenceBundleError("bundle metadata must be an object")
        unknown = set(source) - _ALLOWED_METADATA_FIELDS
        missing = _ALLOWED_METADATA_FIELDS - set(source)
        if unknown or missing:
            raise EvidenceBundleError(
                "bundle metadata fields mismatch: "
                f"missing={sorted(missing)}, unknown={sorted(unknown)}"
            )
        return cls(
            classification=_safe_metadata_token(
                "classification", source["classification"]
            ),
            producer=_safe_metadata_token("producer", source["producer"]),
        )

    def as_dict(self) -> dict[str, str]:
        return {"classification": self.classification, "producer": self.producer}


def _normalize_relative_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_PATH_BYTES
    ):
        raise EvidenceBundleError(
            "artifact path must be a non-empty bounded UTF-8 string"
        )
    if "\\" in value:
        raise EvidenceBundleError(
            "artifact paths must use normalized POSIX separators"
        )
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or not parsed.parts or any(
        part in {"", ".", ".."} for part in parsed.parts
    ):
        raise EvidenceBundleError("artifact path must be normalized and relative")
    normalized = parsed.as_posix()
    if normalized != value:
        raise EvidenceBundleError("artifact path is not normalized")
    for segment in parsed.parts:
        if not _PATH_SEGMENT.fullmatch(segment):
            raise EvidenceBundleError(
                "artifact path contains a non-public-safe segment"
            )
        if _SENSITIVE_TOKEN.search(segment):
            raise EvidenceBundleError("artifact path contains a sensitive token")
    return normalized


def _validate_media_type(value: str) -> str:
    if not isinstance(value, str) or not _MEDIA_TYPE.fullmatch(value):
        raise EvidenceBundleError(
            "artifact media type must be a bounded lowercase type/subtype"
        )
    return value


@dataclass(frozen=True, slots=True)
class ArtifactDescriptor:
    path: str
    sha256: str
    size_bytes: int
    media_type: str

    def __post_init__(self) -> None:
        _normalize_relative_path(self.path)
        _require_digest("artifact sha256", self.sha256)
        if (
            type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= MAX_ARTIFACT_BYTES
        ):
            raise EvidenceBundleError(
                "artifact size must be a bounded non-negative integer"
            )
        _validate_media_type(self.media_type)

    @classmethod
    def from_local(
        cls, root: Path, relative_path: str, media_type: str
    ) -> "ArtifactDescriptor":
        relative = _normalize_relative_path(relative_path)
        media = _validate_media_type(media_type)
        root_path = Path(root)
        if root_path.is_symlink():
            raise EvidenceBundleError("artifact root symlinks are forbidden")
        try:
            root_resolved = root_path.resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError) as error:
            raise EvidenceBundleError("artifact root is missing or unsafe") from error
        if not root_resolved.is_dir():
            raise EvidenceBundleError("artifact root must be a directory")

        candidate = root_resolved / PurePosixPath(relative)
        current = root_resolved
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.is_symlink():
                raise EvidenceBundleError("artifact symlinks are forbidden")
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root_resolved)
        except (FileNotFoundError, ValueError, OSError, RuntimeError) as error:
            raise EvidenceBundleError(
                "artifact is missing or outside the selected root"
            ) from error
        if not resolved.is_file():
            raise EvidenceBundleError("artifact must be one regular file")

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(resolved, flags)
        except OSError as error:
            raise EvidenceBundleError("artifact could not be opened safely") from error
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise EvidenceBundleError(
                "artifact exceeds synthetic local size limit"
            )
        return cls(
            path=relative,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            media_type=media,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "media_type": self.media_type,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class DispatchBinding:
    command_id: str
    review_id: str
    authorization_id: str
    dispatch_id: str
    dispatch_evidence_id: str
    runbook_digest: str

    def __post_init__(self) -> None:
        for name, value in (
            ("command_id", self.command_id),
            ("review_id", self.review_id),
            ("authorization_id", self.authorization_id),
            ("dispatch_id", self.dispatch_id),
            ("dispatch_evidence_id", self.dispatch_evidence_id),
            ("runbook_digest", self.runbook_digest),
        ):
            _require_digest(name, value)

    @classmethod
    def from_intent(cls, intent: DispatchIntent) -> "DispatchBinding":
        if not isinstance(intent, DispatchIntent):
            raise EvidenceBundleError(
                "dispatch binding requires an existing DispatchIntent"
            )
        if intent.retry_authorized:
            raise EvidenceBundleError(
                "dispatch intent unexpectedly authorizes retry"
            )
        return cls(
            command_id=_require_digest("command_id", intent.command_id),
            review_id=_require_digest("review_id", intent.review_id),
            authorization_id=_require_digest(
                "authorization_id", intent.authorization_id
            ),
            dispatch_id=_require_digest(
                "dispatch_id", digest_json(intent.as_dict())
            ),
            dispatch_evidence_id=_require_digest(
                "dispatch evidence identity", intent.evidence_digest
            ),
            runbook_digest=_require_digest(
                "runbook_digest", intent.runbook_digest
            ),
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "authorization_id": self.authorization_id,
            "command_id": self.command_id,
            "dispatch_evidence_id": self.dispatch_evidence_id,
            "dispatch_id": self.dispatch_id,
            "review_id": self.review_id,
            "runbook_digest": self.runbook_digest,
        }


@dataclass(frozen=True, slots=True)
class ReceiptBinding:
    receipt_id: str
    execution_id: str | None
    execution_evidence_id: str

    def __post_init__(self) -> None:
        _require_digest("receipt_id", self.receipt_id)
        if self.execution_id is not None:
            _require_digest("execution_id", self.execution_id)
        _require_digest("execution_evidence_id", self.execution_evidence_id)

    @classmethod
    def from_receipt(
        cls, intent: DispatchIntent, receipt: Receipt
    ) -> "ReceiptBinding":
        if not isinstance(receipt, Receipt):
            raise EvidenceBundleError(
                "receipt binding requires an existing Receipt"
            )
        matched = (
            receipt.command_id == intent.command_id
            and receipt.review_id == intent.review_id
            and receipt.authorization_id == intent.authorization_id
            and receipt.runbook == intent.runbook
            and receipt.runbook_digest == intent.runbook_digest
            and receipt.mutation == intent.mutation
            and receipt.retry_authorized == intent.retry_authorized
        )
        if not matched:
            raise EvidenceBundleError(
                "receipt does not exactly bind the supplied dispatch intent"
            )
        execution_id = receipt.execution_id
        if execution_id is not None:
            execution_id = _require_digest("execution_id", execution_id)
        return cls(
            receipt_id=_require_digest("receipt_id", receipt.receipt_digest),
            execution_id=execution_id,
            execution_evidence_id=_require_digest(
                "execution evidence identity", receipt.evidence_digest
            ),
        )

    def as_dict(self) -> dict[str, str | None]:
        return {
            "execution_evidence_id": self.execution_evidence_id,
            "execution_id": self.execution_id,
            "receipt_id": self.receipt_id,
        }


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    version: str
    retention: RetentionClass
    dispatch: DispatchBinding
    receipt: ReceiptBinding | None
    artifacts: tuple[ArtifactDescriptor, ...]
    metadata: BundleMetadata

    def __post_init__(self) -> None:
        if self.version != "v1":
            raise EvidenceBundleError("unsupported evidence bundle version")
        if not isinstance(self.retention, RetentionClass):
            raise EvidenceBundleError(
                "retention must be an accepted RetentionClass"
            )
        if not isinstance(self.dispatch, DispatchBinding):
            raise EvidenceBundleError("dispatch binding is invalid")
        if self.receipt is not None and not isinstance(
            self.receipt, ReceiptBinding
        ):
            raise EvidenceBundleError("receipt binding is invalid")
        if not isinstance(self.metadata, BundleMetadata):
            raise EvidenceBundleError("bundle metadata is invalid")
        if not 1 <= len(self.artifacts) <= MAX_ARTIFACTS:
            raise EvidenceBundleError(
                f"artifact inventory must contain 1..{MAX_ARTIFACTS} descriptors"
            )
        if any(
            not isinstance(item, ArtifactDescriptor) for item in self.artifacts
        ):
            raise EvidenceBundleError(
                "artifact inventory contains an invalid descriptor"
            )
        paths = [item.path for item in self.artifacts]
        if paths != sorted(paths):
            raise EvidenceBundleError(
                "artifact inventory must be path-sorted"
            )
        if len(paths) != len(set(paths)):
            raise EvidenceBundleError(
                "artifact inventory contains duplicate paths"
            )

    @classmethod
    def create(
        cls,
        intent: DispatchIntent,
        *,
        retention_days: int,
        artifacts: Sequence[ArtifactDescriptor],
        receipt: Receipt | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "EvidenceBundle":
        if not isinstance(artifacts, Sequence) or isinstance(
            artifacts, (str, bytes, bytearray)
        ):
            raise EvidenceBundleError(
                "artifact inventory must be a bounded sequence"
            )
        if not 1 <= len(artifacts) <= MAX_ARTIFACTS:
            raise EvidenceBundleError(
                f"artifact inventory must contain 1..{MAX_ARTIFACTS} descriptors"
            )
        if any(
            not isinstance(item, ArtifactDescriptor) for item in artifacts
        ):
            raise EvidenceBundleError(
                "artifact inventory contains an invalid descriptor"
            )
        ordered = tuple(sorted(artifacts, key=lambda item: item.path))
        paths = [item.path for item in ordered]
        if len(paths) != len(set(paths)):
            raise EvidenceBundleError(
                "artifact inventory contains duplicate paths"
            )

        dispatch = DispatchBinding.from_intent(intent)
        receipt_binding = (
            ReceiptBinding.from_receipt(intent, receipt)
            if receipt is not None
            else None
        )
        return cls(
            version="v1",
            retention=RetentionClass.from_days(retention_days),
            dispatch=dispatch,
            receipt=receipt_binding,
            artifacts=ordered,
            metadata=BundleMetadata.from_mapping(metadata),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "artifacts": [item.as_dict() for item in self.artifacts],
            "dispatch": self.dispatch.as_dict(),
            "metadata": self.metadata.as_dict(),
            "receipt": (
                self.receipt.as_dict() if self.receipt is not None else None
            ),
            "retention": {
                "class": self.retention.label,
                "days": int(self.retention),
            },
            "version": self.version,
        }

    @property
    def bundle_digest(self) -> str:
        return digest_json(self.as_dict())

    def manifest_dict(self) -> dict[str, object]:
        return {**self.as_dict(), "bundle_digest": self.bundle_digest}

    def manifest_bytes(self) -> bytes:
        payload = canonical_json(self.manifest_dict()) + b"\n"
        if len(payload) > MAX_MANIFEST_BYTES:
            raise EvidenceBundleError("manifest exceeds bounded size limit")
        return payload


@dataclass(frozen=True, slots=True)
class ManifestProof:
    bundle_digest: str
    manifest_sha256: str
    manifest_bytes: int
    relative_path: str

    def as_dict(self) -> dict[str, object]:
        return {
            "bundle_digest": self.bundle_digest,
            "manifest_bytes": self.manifest_bytes,
            "manifest_sha256": self.manifest_sha256,
            "relative_path": self.relative_path,
        }


class BundleStore:
    """Create-only local manifest store; it has no overwrite operation."""

    def __init__(self, root: Path) -> None:
        root_path = Path(root)
        if root_path.is_symlink():
            raise EvidenceBundleError(
                "bundle store root symlinks are forbidden"
            )
        try:
            root_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as error:
            raise EvidenceBundleError(
                "bundle store root could not be created safely"
            ) from error
        self.root = root_path.resolve()
        if not self.root.is_dir():
            raise EvidenceBundleError(
                "bundle store root must be a directory"
            )

    def write_new(self, bundle: EvidenceBundle) -> ManifestProof:
        if not isinstance(bundle, EvidenceBundle):
            raise EvidenceBundleError(
                "write_new requires an EvidenceBundle"
            )
        directory = self.root / bundle.bundle_digest
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError as error:
            raise BundleCollisionError(
                "bundle destination already exists; overwrite refused"
            ) from error

        manifest = directory / "manifest.json"
        intended = bundle.manifest_bytes()
        intended_sha = hashlib.sha256(intended).hexdigest()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(manifest, flags, 0o600)
        except FileExistsError as error:
            raise BundleCollisionError(
                "manifest already exists; overwrite refused"
            ) from error
        with os.fdopen(fd, "wb") as handle:
            handle.write(intended)
            handle.flush()
            os.fsync(handle.fileno())

        return self.verify_manifest(
            manifest,
            expected_bundle_digest=bundle.bundle_digest,
            expected_manifest_sha256=intended_sha,
        )

    def verify_manifest(
        self,
        manifest: Path,
        *,
        expected_bundle_digest: str,
        expected_manifest_sha256: str | None = None,
    ) -> ManifestProof:
        expected_bundle_digest = _require_digest(
            "expected bundle digest", expected_bundle_digest
        )
        if expected_manifest_sha256 is not None:
            expected_manifest_sha256 = _require_digest(
                "expected manifest SHA-256", expected_manifest_sha256
            )
        path = Path(manifest)
        if path.is_symlink():
            raise ManifestVerificationError(
                "manifest symlinks are forbidden"
            )
        try:
            resolved = path.resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError) as error:
            raise ManifestVerificationError(
                "manifest is missing or unsafe"
            ) from error
        try:
            relative = resolved.relative_to(self.root)
        except ValueError as error:
            raise ManifestVerificationError(
                "manifest is outside bundle store root"
            ) from error
        if (
            len(relative.parts) != 2
            or relative.parts[0] != expected_bundle_digest
            or relative.name != "manifest.json"
        ):
            raise ManifestVerificationError(
                "manifest path does not match the expected bundle identity"
            )

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(resolved, flags)
        except OSError as error:
            raise ManifestVerificationError(
                "manifest could not be opened safely"
            ) from error
        with os.fdopen(fd, "rb") as handle:
            observed = handle.read(MAX_MANIFEST_BYTES + 1)
        if len(observed) > MAX_MANIFEST_BYTES:
            raise ManifestVerificationError(
                "manifest exceeds bounded size limit"
            )
        observed_sha = hashlib.sha256(observed).hexdigest()
        if (
            expected_manifest_sha256 is not None
            and observed_sha != expected_manifest_sha256
        ):
            raise ManifestVerificationError(
                "manifest byte hash does not match write proof"
            )
        try:
            parsed = json.loads(observed)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ManifestVerificationError(
                "manifest is not valid UTF-8 JSON"
            ) from error
        if not isinstance(parsed, dict) or set(parsed) != {
            "artifacts",
            "bundle_digest",
            "dispatch",
            "metadata",
            "receipt",
            "retention",
            "version",
        }:
            raise ManifestVerificationError(
                "manifest top-level schema mismatch"
            )
        embedded = parsed.get("bundle_digest")
        if embedded != expected_bundle_digest:
            raise ManifestVerificationError(
                "manifest bundle identity does not match expected identity"
            )
        payload = dict(parsed)
        payload.pop("bundle_digest")
        if digest_json(payload) != expected_bundle_digest:
            raise ManifestVerificationError(
                "manifest content digest does not match bundle identity"
            )
        canonical = canonical_json(parsed) + b"\n"
        if observed != canonical:
            raise ManifestVerificationError(
                "manifest bytes are not canonical"
            )

        return ManifestProof(
            bundle_digest=expected_bundle_digest,
            manifest_sha256=observed_sha,
            manifest_bytes=len(observed),
            relative_path=relative.as_posix(),
        )

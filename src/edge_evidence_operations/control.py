"""Authorization and one-attempt local execution semantics."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .history import HistoryProvider, assert_not_consumed
from .model import Command, ReviewContext, ReviewPolicy, canonical_json, digest_json
from .receipt import Receipt
from .registry import RunbookRegistry, RunbookSnapshot
from .sanitize import EvidenceSanitizer


class AuthorizationConsumedError(RuntimeError):
    """The exact authorization token has already been consumed."""


@dataclass(frozen=True, slots=True)
class Authorization:
    command: Command
    review_context: ReviewContext
    command_id: str
    review_id: str
    authorization_id: str
    runbook: RunbookSnapshot


class ControlPlane:
    def __init__(self, policy: ReviewPolicy, registry: RunbookRegistry) -> None:
        self.policy = policy
        self.registry = registry

    def authorize(
        self,
        command: Command,
        review_context: ReviewContext,
        history: HistoryProvider,
    ) -> Authorization:
        policy_id = self.policy.validate(command, review_context)
        assert_not_consumed(command, history)
        snapshot = self.registry.snapshot(command.runbook)
        review_id = digest_json(
            {
                "command_id": command.identity,
                "context_id": review_context.context_id,
                "policy_id": policy_id,
                "reviewer": review_context.reviewer,
            }
        )
        authorization_id = digest_json(
            {
                "command_id": command.identity,
                "review_id": review_id,
                "runbook": command.runbook,
                "runbook_digest": snapshot.digest,
            }
        )
        return Authorization(
            command=command,
            review_context=review_context,
            command_id=command.identity,
            review_id=review_id,
            authorization_id=authorization_id,
            runbook=snapshot,
        )


class AttemptLedger:
    """Filesystem one-shot ledger; claim happens before preflight or execution."""

    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = root.resolve()

    def claim(self, authorization_id: str) -> None:
        if len(authorization_id) != 64 or any(ch not in "0123456789abcdef" for ch in authorization_id):
            raise ValueError("authorization ID must be lowercase SHA-256 hex")
        marker = self.root / authorization_id
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(marker, flags, 0o600)
        except FileExistsError as error:
            raise AuthorizationConsumedError("authorization already consumed; no retry authority") from error
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(authorization_id + "\n")


Preflight = Callable[[Authorization, Path], None]
Verification = Callable[[Authorization, Path], bool]


class Executor:
    def __init__(
        self,
        registry: RunbookRegistry,
        ledger: AttemptLedger,
        work_root: Path,
    ) -> None:
        work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.registry = registry
        self.ledger = ledger
        self.work_root = work_root.resolve()
        self.sanitizer = EvidenceSanitizer(
            frozenset(
                {
                    "phase",
                    "error_type",
                    "stdout_sha256",
                    "stderr_sha256",
                    "stdout_bytes",
                    "stderr_bytes",
                    "verification_passed",
                }
            )
        )

    def _evidence_digest(self, **raw: object) -> str:
        return digest_json(self.sanitizer.sanitize(raw))

    def _receipt(
        self,
        auth: Authorization,
        *,
        outcome: str,
        exit_code: int | None,
        execution_id: str | None,
        partial_state: bool,
        evidence_digest: str,
    ) -> Receipt:
        return Receipt(
            command_id=auth.command_id,
            review_id=auth.review_id,
            authorization_id=auth.authorization_id,
            execution_id=execution_id,
            runbook=auth.runbook.name,
            runbook_digest=auth.runbook.digest,
            outcome=outcome,
            exit_code=exit_code,
            mutation=auth.command.mutation,
            partial_state=partial_state,
            evidence_digest=evidence_digest,
            retry_authorized=False,
            rollback_performed=False,
        )

    def execute(
        self,
        auth: Authorization,
        *,
        preflight: Preflight | None = None,
        verify: Verification | None = None,
        timeout_seconds: int = 10,
    ) -> Receipt:
        self.ledger.claim(auth.authorization_id)
        work_dir = self.work_root / auth.authorization_id

        try:
            work_dir.mkdir(mode=0o700)
            self.registry.assert_unchanged(auth.runbook)
            if preflight is not None:
                preflight(auth, work_dir)
            self.registry.assert_unchanged(auth.runbook)
        except Exception as error:
            return self._receipt(
                auth,
                outcome="preflight_failed",
                exit_code=None,
                execution_id=None,
                partial_state=False,
                evidence_digest=self._evidence_digest(
                    phase="preflight",
                    error_type=type(error).__name__,
                ),
            )

        execution_id = digest_json(
            {
                "authorization_id": auth.authorization_id,
                "runbook_digest": auth.runbook.digest,
            }
        )
        env = {
            "PATH": os.environ.get("PATH", ""),
            "OPS_ARGUMENTS_JSON": canonical_json(dict(auth.command.arguments)).decode("utf-8"),
            "OPS_WORK_DIR": str(work_dir),
        }
        try:
            result = subprocess.run(
                ["bash", str(auth.runbook.path)],
                cwd=work_dir,
                env=env,
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
            )
        except Exception as error:
            return self._receipt(
                auth,
                outcome="execution_failed",
                exit_code=None,
                execution_id=execution_id,
                partial_state=auth.command.mutation,
                evidence_digest=self._evidence_digest(
                    phase="execution",
                    error_type=type(error).__name__,
                ),
            )

        execution_evidence = {
            "phase": "execution",
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
            "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr),
        }
        if result.returncode != 0:
            return self._receipt(
                auth,
                outcome="execution_failed",
                exit_code=result.returncode,
                execution_id=execution_id,
                partial_state=auth.command.mutation,
                evidence_digest=self._evidence_digest(**execution_evidence),
            )

        if verify is not None:
            try:
                verified = bool(verify(auth, work_dir))
            except Exception:
                verified = False
            if not verified:
                return self._receipt(
                    auth,
                    outcome="verification_failed",
                    exit_code=result.returncode,
                    execution_id=execution_id,
                    partial_state=auth.command.mutation,
                    evidence_digest=self._evidence_digest(
                        **execution_evidence,
                        verification_passed=False,
                    ),
                )

        return self._receipt(
            auth,
            outcome="success",
            exit_code=result.returncode,
            execution_id=execution_id,
            partial_state=False,
            evidence_digest=self._evidence_digest(
                **execution_evidence,
                verification_passed=True,
            ),
        )

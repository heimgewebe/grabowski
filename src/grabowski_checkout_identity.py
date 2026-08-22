from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any


SCHEMA_VERSION = 1
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ACTIVE_GENERATION_STATES = ("reserved", "active", "blocking")


class CheckoutIdentityError(RuntimeError):
    pass


class CheckoutIdentityConflict(CheckoutIdentityError):
    pass


def _checkouts() -> Any:
    # Keep the identity contract import-safe for minimal runtime and RepoGround probes.
    import grabowski_checkouts

    return grabowski_checkouts


def _now() -> int:
    return int(time.time())


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required_text(value: Any, name: str, *, maximum: int = 1000) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a non-empty trimmed string")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} is too long")
    if "\x00" in value:
        raise ValueError(f"{name} contains NUL")
    return value


def _optional_branch(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, name, maximum=500)


def _optional_identifier(value: Any, name: str) -> str | None:
    if value is None:
        return None
    text = _required_text(value, name, maximum=200)
    if not re.fullmatch(r"[0-9A-Za-z_.:-]+", text):
        raise ValueError(f"{name} contains unsupported characters")
    return text


def normalize_supersession(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("identity_supersession must be an object")
    expected_fields = {
        "schema_version",
        "expected_checkout_key",
        "expected_generation_id",
        "expected_archive_id",
        "expected_owner_id",
        "expected_head",
        "expected_branch",
        "authorized_by_owner_id",
        "handoff_receipt_sha256",
        "new_owner_id",
        "reason",
    }
    if set(value) != expected_fields or value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("identity_supersession shape or schema is invalid")
    checkout_key = _required_text(
        value.get("expected_checkout_key"), "identity_supersession.expected_checkout_key", maximum=64
    ).lower()
    if SHA256_RE.fullmatch(checkout_key) is None:
        raise ValueError("identity_supersession.expected_checkout_key is invalid")
    expected_head = _required_text(
        value.get("expected_head"), "identity_supersession.expected_head", maximum=40
    ).lower()
    if SHA40_RE.fullmatch(expected_head) is None:
        raise ValueError("identity_supersession.expected_head is invalid")
    receipt_sha256 = _required_text(
        value.get("handoff_receipt_sha256"),
        "identity_supersession.handoff_receipt_sha256",
        maximum=64,
    ).lower()
    if SHA256_RE.fullmatch(receipt_sha256) is None:
        raise ValueError("identity_supersession.handoff_receipt_sha256 is invalid")
    expected_owner = _required_text(
        value.get("expected_owner_id"), "identity_supersession.expected_owner_id", maximum=300
    )
    authorized_owner = _required_text(
        value.get("authorized_by_owner_id"),
        "identity_supersession.authorized_by_owner_id",
        maximum=300,
    )
    if authorized_owner != expected_owner:
        raise ValueError("identity supersession authorization is not bound to the prior owner")
    return {
        "schema_version": SCHEMA_VERSION,
        "expected_checkout_key": checkout_key,
        "expected_generation_id": _optional_identifier(
            value.get("expected_generation_id"),
            "identity_supersession.expected_generation_id",
        ),
        "expected_archive_id": _optional_identifier(
            value.get("expected_archive_id"),
            "identity_supersession.expected_archive_id",
        ),
        "expected_owner_id": expected_owner,
        "expected_head": expected_head,
        "expected_branch": _optional_branch(
            value.get("expected_branch"), "identity_supersession.expected_branch"
        ),
        "authorized_by_owner_id": authorized_owner,
        "handoff_receipt_sha256": receipt_sha256,
        "new_owner_id": _required_text(
            value.get("new_owner_id"), "identity_supersession.new_owner_id", maximum=300
        ),
        "reason": _required_text(value.get("reason"), "identity_supersession.reason"),
    }


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS checkout_identity_generations (
            generation_id TEXT PRIMARY KEY,
            checkout_key TEXT NOT NULL,
            repo_common_dir TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            checkout_path TEXT NOT NULL,
            identity_json TEXT NOT NULL,
            identity_sha256 TEXT NOT NULL,
            state TEXT NOT NULL,
            predecessor_generation_id TEXT,
            superseded_by_generation_id TEXT,
            archive_id TEXT,
            recovery_refs_json TEXT,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            finalized_at_unix INTEGER,
            superseded_at_unix INTEGER,
            aborted_at_unix INTEGER
        )
        """
    )
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS checkout_identity_current_idx
        ON checkout_identity_generations(checkout_key)
        WHERE state IN ('reserved', 'active', 'blocking')
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS checkout_identity_reservations (
            intent_key TEXT PRIMARY KEY,
            checkout_key TEXT NOT NULL,
            generation_id TEXT NOT NULL,
            prior_generation_id TEXT,
            action TEXT NOT NULL,
            state TEXT NOT NULL,
            requested_identity_json TEXT NOT NULL,
            requested_identity_sha256 TEXT NOT NULL,
            prior_lifecycle_json TEXT,
            prior_retention_json TEXT,
            archive_id TEXT,
            supersession_json TEXT,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            finalized_at_unix INTEGER,
            error TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS checkout_identity_archive_supersessions (
            archive_id TEXT PRIMARY KEY,
            checkout_key TEXT NOT NULL,
            prior_generation_id TEXT NOT NULL,
            superseded_by_generation_id TEXT NOT NULL,
            handoff_receipt_sha256 TEXT,
            reason TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL
        )
        """
    )


def _row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return None if row is None else dict(row)


def _requested_identity(inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "owner_id": str(inputs["lease_owner_id"]),
        "purpose": str(inputs["purpose"]),
        "source_kind": str(inputs["source_kind"]),
        "source_id": str(inputs["source_id"]),
        "artifact_class": str(inputs["artifact_class"]),
        "expected_head": str(inputs["base_head"]),
        "expected_branch": str(inputs["branch"]),
    }


def _prior_identity(
    lifecycle: dict[str, Any] | None,
    retention: dict[str, Any] | None,
    archive: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "owner_id": (
            lifecycle.get("owner_id") if lifecycle else None
        ) or (retention.get("owner_id") if retention else None) or (
            archive.get("owner_id") if archive else None
        ),
        "purpose": (
            lifecycle.get("purpose") if lifecycle else None
        ) or (retention.get("purpose") if retention else None) or (
            archive.get("purpose") if archive else None
        ),
        "source_kind": lifecycle.get("source_kind") if lifecycle else None,
        "source_id": lifecycle.get("source_id") if lifecycle else None,
        "artifact_class": lifecycle.get("artifact_class") if lifecycle else None,
        "expected_head": (
            lifecycle.get("expected_head") if lifecycle else None
        ) or (retention.get("expected_head") if retention else None) or (
            archive.get("head") if archive else None
        ),
        "expected_branch": (
            lifecycle.get("expected_branch")
            if lifecycle and "expected_branch" in lifecycle
            else retention.get("expected_branch")
            if retention and "expected_branch" in retention
            else archive.get("branch") if archive else None
        ),
    }


def _identity_complete(identity: dict[str, Any]) -> bool:
    return all(
        identity.get(field) is not None
        for field in (
            "owner_id",
            "purpose",
            "source_kind",
            "source_id",
            "artifact_class",
            "expected_head",
        )
    ) and "expected_branch" in identity


def _identity_matches(prior: dict[str, Any], requested: dict[str, Any]) -> bool:
    return _identity_complete(prior) and prior == requested


def _load_evidence(
    connection: sqlite3.Connection, checkout_key: str, now: int
) -> dict[str, Any]:
    lifecycle = _row_dict(
        connection.execute(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?", (checkout_key,)
        ).fetchone()
    )
    retention = _row_dict(
        connection.execute(
            "SELECT * FROM retention WHERE checkout_key=?", (checkout_key,)
        ).fetchone()
    )
    archive = _row_dict(
        connection.execute(
            """
            SELECT a.* FROM archives a
            LEFT JOIN checkout_identity_archive_supersessions s
              ON s.archive_id=a.archive_id
            WHERE a.checkout_key=? AND a.cleaned_at_unix IS NULL
              AND s.archive_id IS NULL
            ORDER BY a.created_at_unix DESC, a.archive_id DESC
            LIMIT 1
            """,
            (checkout_key,),
        ).fetchone()
    )
    reasons: list[str] = []
    if retention and int(retention["retention_until_unix"]) > now:
        reasons.append("active_retention")
    if archive is not None:
        reasons.append("open_archive")
    if (
        lifecycle
        and lifecycle.get("phase") in {"active", "completed_retained", "archived"}
        and int(lifecycle.get("retention_until_unix") or 0) > now
    ):
        reasons.append("live_lifecycle_binding")
    return {
        "lifecycle": lifecycle,
        "retention": retention,
        "archive": archive,
        "protected": bool(reasons),
        "protected_reasons": sorted(set(reasons)),
        "prior_identity": _prior_identity(lifecycle, retention, archive),
    }


def _current_generation(
    connection: sqlite3.Connection, checkout_key: str
) -> dict[str, Any] | None:
    return _row_dict(
        connection.execute(
            """
            SELECT * FROM checkout_identity_generations
            WHERE checkout_key=? AND state IN ('reserved', 'active', 'blocking')
            ORDER BY created_at_unix DESC, generation_id DESC
            LIMIT 1
            """,
            (checkout_key,),
        ).fetchone()
    )


def _generation_id(checkout_key: str, material: dict[str, Any]) -> str:
    return f"generation-{_sha256_json({'checkout_key': checkout_key, **material})[:32]}"


def _intent_key(inputs: dict[str, Any], identity: dict[str, Any]) -> str:
    return _sha256_json(
        {
            "checkout_key": inputs["checkout_key"],
            "idempotency_key": inputs["idempotency_key"],
            "identity": identity,
            "supersession": inputs.get("identity_supersession"),
        }
    )


def _insert_generation(
    connection: sqlite3.Connection,
    *,
    generation_id: str,
    inputs: dict[str, Any],
    identity: dict[str, Any],
    state: str,
    predecessor_generation_id: str | None,
    archive: dict[str, Any] | None,
    now: int,
) -> None:
    connection.execute(
        """
        INSERT INTO checkout_identity_generations(
            generation_id, checkout_key, repo_common_dir, repo_path,
            checkout_path, identity_json, identity_sha256, state,
            predecessor_generation_id, superseded_by_generation_id,
            archive_id, recovery_refs_json, created_at_unix, updated_at_unix,
            finalized_at_unix, superseded_at_unix, aborted_at_unix
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, NULL, NULL, NULL)
        """,
        (
            generation_id,
            inputs["checkout_key"],
            inputs["repo_common_dir"],
            inputs["repo"],
            inputs["target_path"],
            _canonical_json(identity),
            _sha256_json(identity),
            state,
            predecessor_generation_id,
            archive.get("archive_id") if archive else None,
            archive.get("recovery_refs_json") if archive else None,
            now,
            now,
        ),
    )


def _insert_baseline_generation(
    connection: sqlite3.Connection,
    *,
    inputs: dict[str, Any],
    evidence: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    identity = evidence["prior_identity"]
    generation_id = _generation_id(
        inputs["checkout_key"],
        {
            "kind": "baseline",
            "identity": identity,
            "archive_id": (evidence["archive"] or {}).get("archive_id"),
        },
    )
    existing = _row_dict(
        connection.execute(
            "SELECT * FROM checkout_identity_generations WHERE generation_id=?",
            (generation_id,),
        ).fetchone()
    )
    if existing is None:
        _insert_generation(
            connection,
            generation_id=generation_id,
            inputs=inputs,
            identity=identity,
            state="active",
            predecessor_generation_id=None,
            archive=evidence["archive"],
            now=now,
        )
        existing = _row_dict(
            connection.execute(
                "SELECT * FROM checkout_identity_generations WHERE generation_id=?",
                (generation_id,),
            ).fetchone()
        )
    assert existing is not None
    return existing


def _reconcile_archived_evidence_generation(
    connection: sqlite3.Connection,
    *,
    inputs: dict[str, Any],
    evidence: dict[str, Any],
    current: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    """Converge an immutable active generation to exact archived evidence.

    Archive and safe identity-rebind paths may advance a checkout's head or
    branch after its original identity generation was finalized.  The ledger
    must preserve that historical generation while making the protected
    lifecycle/archive identity current before any later reactivation or
    owner-bound supersession is evaluated.
    """
    prior = evidence["prior_identity"]
    current_identity = json.loads(current["identity_json"])
    lifecycle = evidence.get("lifecycle")
    retention = evidence.get("retention")
    archive = evidence.get("archive")
    immutable_fields = (
        "owner_id",
        "purpose",
        "source_kind",
        "source_id",
        "artifact_class",
    )
    valid = bool(
        current.get("state") == "active"
        and evidence.get("protected") is True
        and isinstance(lifecycle, dict)
        and lifecycle.get("phase") == "archived"
        and type(lifecycle.get("terminal_at_unix")) is int
        and type(lifecycle.get("archived_at_unix")) is int
        and isinstance(retention, dict)
        and isinstance(archive, dict)
        and archive.get("cleaned_at_unix") is None
        and _identity_complete(current_identity)
        and _identity_complete(prior)
        and all(current_identity.get(field) == prior.get(field) for field in immutable_fields)
        and archive.get("owner_id") == prior.get("owner_id")
        and archive.get("head") == prior.get("expected_head")
        and archive.get("branch") == prior.get("expected_branch")
        and retention.get("owner_id") == prior.get("owner_id")
        and retention.get("expected_head") == prior.get("expected_head")
        and retention.get("expected_branch") == prior.get("expected_branch")
        and type(archive.get("created_at_unix")) is int
        and type(current.get("created_at_unix")) is int
        and archive["created_at_unix"] >= current["created_at_unix"]
    )
    if not valid:
        raise CheckoutIdentityConflict(
            "identity ledger and protected checkout evidence disagree"
        )

    generation_id = _generation_id(
        inputs["checkout_key"],
        {
            "kind": "archived-evidence-baseline",
            "identity": prior,
            "archive_id": archive["archive_id"],
            "predecessor_generation_id": current["generation_id"],
        },
    )
    if connection.execute(
        "SELECT 1 FROM checkout_identity_generations WHERE generation_id=?",
        (generation_id,),
    ).fetchone() is not None:
        raise CheckoutIdentityConflict(
            "archived evidence baseline generation already exists in a conflicting state"
        )
    changed = connection.execute(
        """
        UPDATE checkout_identity_generations
        SET state='superseded', superseded_by_generation_id=?,
            superseded_at_unix=?, updated_at_unix=?
        WHERE generation_id=? AND state='active'
        """,
        (generation_id, now, now, current["generation_id"]),
    )
    if changed.rowcount != 1:
        raise CheckoutIdentityConflict(
            "active checkout identity generation changed during evidence reconciliation"
        )
    _insert_generation(
        connection,
        generation_id=generation_id,
        inputs=inputs,
        identity=prior,
        state="active",
        predecessor_generation_id=current["generation_id"],
        archive=archive,
        now=now,
    )
    reconciled = _row_dict(
        connection.execute(
            "SELECT * FROM checkout_identity_generations WHERE generation_id=?",
            (generation_id,),
        ).fetchone()
    )
    if reconciled is None:
        raise CheckoutIdentityConflict(
            "archived evidence baseline generation was not persisted"
        )
    return reconciled


def _validate_supersession(
    supersession: dict[str, Any],
    *,
    inputs: dict[str, Any],
    evidence: dict[str, Any],
    prior_generation: dict[str, Any] | None,
) -> None:
    prior = evidence["prior_identity"]
    archive_id = (evidence["archive"] or {}).get("archive_id")
    if supersession["expected_checkout_key"] != inputs["checkout_key"]:
        raise CheckoutIdentityConflict("supersession checkout key does not match the exact target path")
    if supersession["new_owner_id"] != inputs["lease_owner_id"]:
        raise CheckoutIdentityConflict("supersession new owner does not match the live lease owner")
    if supersession["expected_owner_id"] != prior.get("owner_id"):
        raise CheckoutIdentityConflict("supersession prior owner does not match current evidence")
    if supersession["expected_head"] != prior.get("expected_head"):
        raise CheckoutIdentityConflict("supersession prior head does not match current evidence")
    if supersession["expected_branch"] != prior.get("expected_branch"):
        raise CheckoutIdentityConflict("supersession prior branch does not match current evidence")
    if archive_id is not None and supersession["expected_archive_id"] != archive_id:
        raise CheckoutIdentityConflict("supersession archive id does not match the open archive")
    if archive_id is None and supersession["expected_archive_id"] is not None:
        raise CheckoutIdentityConflict("supersession names an archive that is not open")
    expected_generation = supersession["expected_generation_id"]
    if expected_generation is not None:
        observed_generation = prior_generation.get("generation_id") if prior_generation else None
        if expected_generation != observed_generation:
            raise CheckoutIdentityConflict("supersession generation does not match current evidence")


def _active_slot_available(
    connection: sqlite3.Connection,
    *,
    inputs: dict[str, Any],
    lifecycle: dict[str, Any] | None,
    now: int,
) -> None:
    was_active = bool(
        lifecycle
        and lifecycle.get("phase") == "active"
        and int(lifecycle.get("retention_until_unix") or 0) > now
    )
    if was_active:
        return
    row = connection.execute(
        """
        SELECT count(*) AS total FROM lifecycle_bindings
        WHERE repo_common_dir=? AND checkout_key<>?
          AND phase='active' AND retention_until_unix>?
        """,
        (inputs["repo_common_dir"], inputs["checkout_key"], now),
    ).fetchone()
    count = int(row["total"] if row is not None else 0)
    limit = _checkouts()._phase_limit("active")
    if count >= limit:
        raise CheckoutIdentityConflict(
            f"identity supersession would exceed active checkout capacity: active={count} limit={limit}"
        )


def _replace_current_rows(
    connection: sqlite3.Connection,
    *,
    inputs: dict[str, Any],
    identity: dict[str, Any],
    now: int,
) -> None:
    connection.execute(
        """
        INSERT INTO lifecycle_bindings(
            checkout_key, repo_common_dir, repo_path, checkout_path,
            owner_id, purpose, source_kind, source_id, artifact_class,
            phase, retention_until_unix, expected_head, expected_branch,
            created_at_unix, updated_at_unix, terminal_at_unix, archived_at_unix
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, NULL, NULL)
        ON CONFLICT(checkout_key) DO UPDATE SET
            repo_common_dir=excluded.repo_common_dir,
            repo_path=excluded.repo_path,
            checkout_path=excluded.checkout_path,
            owner_id=excluded.owner_id,
            purpose=excluded.purpose,
            source_kind=excluded.source_kind,
            source_id=excluded.source_id,
            artifact_class=excluded.artifact_class,
            phase='active',
            retention_until_unix=excluded.retention_until_unix,
            expected_head=excluded.expected_head,
            expected_branch=excluded.expected_branch,
            created_at_unix=excluded.created_at_unix,
            updated_at_unix=excluded.updated_at_unix,
            terminal_at_unix=NULL,
            archived_at_unix=NULL
        """,
        (
            inputs["checkout_key"],
            inputs["repo_common_dir"],
            inputs["repo"],
            inputs["target_path"],
            identity["owner_id"],
            identity["purpose"],
            identity["source_kind"],
            identity["source_id"],
            identity["artifact_class"],
            inputs["retention_until_unix"],
            identity["expected_head"],
            identity["expected_branch"],
            now,
            now,
        ),
    )
    connection.execute(
        """
        INSERT INTO retention(
            checkout_key, repo_common_dir, repo_path, checkout_path,
            owner_id, purpose, retention_until_unix, expected_head,
            expected_branch, created_at_unix, updated_at_unix
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(checkout_key) DO UPDATE SET
            repo_common_dir=excluded.repo_common_dir,
            repo_path=excluded.repo_path,
            checkout_path=excluded.checkout_path,
            owner_id=excluded.owner_id,
            purpose=excluded.purpose,
            retention_until_unix=excluded.retention_until_unix,
            expected_head=excluded.expected_head,
            expected_branch=excluded.expected_branch,
            created_at_unix=excluded.created_at_unix,
            updated_at_unix=excluded.updated_at_unix
        """,
        (
            inputs["checkout_key"],
            inputs["repo_common_dir"],
            inputs["repo"],
            inputs["target_path"],
            identity["owner_id"],
            identity["purpose"],
            inputs["retention_until_unix"],
            identity["expected_head"],
            identity["expected_branch"],
            now,
            now,
        ),
    )


def _reservation_public(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "intent_key": row["intent_key"],
        "checkout_key": row["checkout_key"],
        "generation_id": row["generation_id"],
        "prior_generation_id": row.get("prior_generation_id"),
        "action": row["action"],
        "state": row["state"],
        "requested_identity_sha256": row["requested_identity_sha256"],
        "archive_id": row.get("archive_id"),
        "supersession_sha256": (
            hashlib.sha256(row["supersession_json"].encode("utf-8")).hexdigest()
            if row.get("supersession_json")
            else None
        ),
        "created_at_unix": row["created_at_unix"],
        "updated_at_unix": row["updated_at_unix"],
        "finalized_at_unix": row.get("finalized_at_unix"),
        "error": row.get("error"),
        "does_not_establish": [
            "permission_to_delete_archive_or_recovery_refs",
            "terminal_external_task_truth",
            "permission_to_override_live_foreign_leases",
        ],
    }


def _insert_reservation(
    connection: sqlite3.Connection,
    *,
    intent_key: str,
    inputs: dict[str, Any],
    generation_id: str,
    prior_generation_id: str | None,
    action: str,
    state: str,
    identity: dict[str, Any],
    evidence: dict[str, Any],
    supersession: dict[str, Any] | None,
    now: int,
) -> dict[str, Any]:
    connection.execute(
        """
        INSERT INTO checkout_identity_reservations(
            intent_key, checkout_key, generation_id, prior_generation_id,
            action, state, requested_identity_json, requested_identity_sha256,
            prior_lifecycle_json, prior_retention_json, archive_id,
            supersession_json, created_at_unix, updated_at_unix,
            finalized_at_unix, error
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        """,
        (
            intent_key,
            inputs["checkout_key"],
            generation_id,
            prior_generation_id,
            action,
            state,
            _canonical_json(identity),
            _sha256_json(identity),
            _canonical_json(evidence["lifecycle"]) if evidence["lifecycle"] else None,
            _canonical_json(evidence["retention"]) if evidence["retention"] else None,
            (evidence["archive"] or {}).get("archive_id"),
            _canonical_json(supersession) if supersession else None,
            now,
            now,
            now if state == "active" else None,
        ),
    )
    row = _row_dict(
        connection.execute(
            "SELECT * FROM checkout_identity_reservations WHERE intent_key=?",
            (intent_key,),
        ).fetchone()
    )
    assert row is not None
    return row


def prepare(inputs: dict[str, Any]) -> dict[str, Any]:
    identity = _requested_identity(inputs)
    supersession = inputs.get("identity_supersession")
    if supersession is not None:
        supersession = normalize_supersession(supersession)
    common_dir = _checkouts()._git_common_dir(Path(inputs["repo"]))
    checkout_path = Path(inputs["target_path"]).expanduser().resolve(strict=False)
    checkout_key = _checkouts()._checkout_key(common_dir, checkout_path)
    prepared_inputs = {
        **inputs,
        "repo_common_dir": str(common_dir),
        "checkout_key": checkout_key,
        "target_path": str(checkout_path),
    }
    intent_key = _intent_key(prepared_inputs, identity)
    now = _now()
    with _checkouts()._database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _ensure_schema(connection)
        existing_reservation = _row_dict(
            connection.execute(
                "SELECT * FROM checkout_identity_reservations WHERE intent_key=?",
                (intent_key,),
            ).fetchone()
        )
        if existing_reservation is not None:
            connection.commit()
            if existing_reservation["state"] == "aborted":
                raise CheckoutIdentityConflict("identity reservation was previously aborted")
            return _reservation_public(existing_reservation)

        evidence = _load_evidence(connection, checkout_key, now)
        current = _current_generation(connection, checkout_key)
        if current is not None and current["state"] in {"reserved", "blocking"}:
            raise CheckoutIdentityConflict(
                "checkout path has an unfinished identity transition that requires reconciliation"
            )
        if current is not None:
            current_identity = json.loads(current["identity_json"])
            if evidence["protected"] and current_identity != evidence["prior_identity"]:
                current = _reconcile_archived_evidence_generation(
                    connection,
                    inputs=prepared_inputs,
                    evidence=evidence,
                    current=current,
                    now=now,
                )

        exact_replay = _identity_matches(evidence["prior_identity"], identity)
        needs_reactivation = bool(
            exact_replay
            and (
                evidence["archive"] is not None
                or evidence["lifecycle"] is None
                or evidence["lifecycle"].get("phase") != "active"
            )
        )
        if evidence["protected"] and not exact_replay and supersession is None:
            raise CheckoutIdentityConflict(
                "checkout path is protected by "
                + ", ".join(evidence["protected_reasons"])
                + "; explicit owner-bound supersession is required"
            )
        if supersession is not None and not evidence["protected"]:
            raise CheckoutIdentityConflict("supersession is stale because the prior identity is no longer protected")

        if evidence["protected"] and exact_replay and not needs_reactivation:
            generation = current or _insert_baseline_generation(
                connection, inputs=prepared_inputs, evidence=evidence, now=now
            )
            row = _insert_reservation(
                connection,
                intent_key=intent_key,
                inputs=prepared_inputs,
                generation_id=generation["generation_id"],
                prior_generation_id=generation.get("predecessor_generation_id"),
                action="replay",
                state="active",
                identity=identity,
                evidence=evidence,
                supersession=None,
                now=now,
            )
            connection.commit()
            return _reservation_public(row)

        if evidence["protected"]:
            prior_generation = current or _insert_baseline_generation(
                connection, inputs=prepared_inputs, evidence=evidence, now=now
            )
            action = "reactivation" if exact_replay else "supersession"
            if action == "supersession":
                assert supersession is not None
                _validate_supersession(
                    supersession,
                    inputs=prepared_inputs,
                    evidence=evidence,
                    prior_generation=prior_generation,
                )
            _active_slot_available(
                connection,
                inputs=prepared_inputs,
                lifecycle=evidence["lifecycle"],
                now=now,
            )
            generation_id = _generation_id(
                checkout_key,
                {"kind": action, "intent_key": intent_key, "identity": identity},
            )
            connection.execute(
                """
                UPDATE checkout_identity_generations
                SET state='superseded', superseded_by_generation_id=?,
                    superseded_at_unix=?, updated_at_unix=?
                WHERE generation_id=? AND state='active'
                """,
                (generation_id, now, now, prior_generation["generation_id"]),
            )
            _insert_generation(
                connection,
                generation_id=generation_id,
                inputs=prepared_inputs,
                identity=identity,
                state="reserved",
                predecessor_generation_id=prior_generation["generation_id"],
                archive=evidence["archive"],
                now=now,
            )
            archive = evidence["archive"]
            if archive is not None:
                connection.execute(
                    """
                    INSERT INTO checkout_identity_archive_supersessions(
                        archive_id, checkout_key, prior_generation_id,
                        superseded_by_generation_id, handoff_receipt_sha256,
                        reason, created_at_unix
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        archive["archive_id"],
                        checkout_key,
                        prior_generation["generation_id"],
                        generation_id,
                        supersession["handoff_receipt_sha256"] if supersession else None,
                        supersession["reason"] if supersession else "same-identity reactivation",
                        now,
                    ),
                )
            _replace_current_rows(
                connection, inputs=prepared_inputs, identity=identity, now=now
            )
            row = _insert_reservation(
                connection,
                intent_key=intent_key,
                inputs=prepared_inputs,
                generation_id=generation_id,
                prior_generation_id=prior_generation["generation_id"],
                action=action,
                state="reserved",
                identity=identity,
                evidence=evidence,
                supersession=supersession,
                now=now,
            )
            connection.commit()
            return _reservation_public(row)

        if supersession is not None:
            raise CheckoutIdentityConflict("supersession has no protected predecessor")

        prior_present = any(
            evidence[name] is not None for name in ("lifecycle", "retention", "archive")
        )
        if current is None and prior_present and _identity_complete(evidence["prior_identity"]):
            current = _insert_baseline_generation(
                connection, inputs=prepared_inputs, evidence=evidence, now=now
            )
        if current is not None:
            current_identity = json.loads(current["identity_json"])
            lifecycle_is_reusable = bool(
                evidence["lifecycle"] is None
                or evidence["lifecycle"].get("phase") == "active"
            )
            if current_identity == identity and lifecycle_is_reusable:
                row = _insert_reservation(
                    connection,
                    intent_key=intent_key,
                    inputs=prepared_inputs,
                    generation_id=current["generation_id"],
                    prior_generation_id=current.get("predecessor_generation_id"),
                    action="replay",
                    state="active",
                    identity=identity,
                    evidence=evidence,
                    supersession=None,
                    now=now,
                )
                connection.commit()
                return _reservation_public(row)
            connection.execute(
                """
                UPDATE checkout_identity_generations
                SET state='superseded', superseded_at_unix=?, updated_at_unix=?
                WHERE generation_id=? AND state='active'
                """,
                (now, now, current["generation_id"]),
            )
        action = "terminal_reuse" if prior_present else "new"
        generation_id = _generation_id(
            checkout_key, {"kind": action, "intent_key": intent_key, "identity": identity}
        )
        _insert_generation(
            connection,
            generation_id=generation_id,
            inputs=prepared_inputs,
            identity=identity,
            state="reserved",
            predecessor_generation_id=current["generation_id"] if current else None,
            archive=None,
            now=now,
        )
        if prior_present:
            _active_slot_available(
                connection,
                inputs=prepared_inputs,
                lifecycle=evidence["lifecycle"],
                now=now,
            )
            _replace_current_rows(
                connection, inputs=prepared_inputs, identity=identity, now=now
            )
        row = _insert_reservation(
            connection,
            intent_key=intent_key,
            inputs=prepared_inputs,
            generation_id=generation_id,
            prior_generation_id=current["generation_id"] if current else None,
            action=action,
            state="reserved",
            identity=identity,
            evidence=evidence,
            supersession=None,
            now=now,
        )
        connection.commit()
        return _reservation_public(row)



def finalize(reservation: dict[str, Any]) -> dict[str, Any]:
    intent_key = _required_text(reservation.get("intent_key"), "identity reservation intent")
    now = _now()
    with _checkouts()._database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _ensure_schema(connection)
        row = _row_dict(
            connection.execute(
                "SELECT * FROM checkout_identity_reservations WHERE intent_key=?",
                (intent_key,),
            ).fetchone()
        )
        if row is None:
            raise CheckoutIdentityConflict("identity reservation is missing")
        if row["state"] == "aborted":
            raise CheckoutIdentityConflict("identity reservation is aborted")
        if row["state"] != "active":
            connection.execute(
                """
                UPDATE checkout_identity_generations
                SET state='active', finalized_at_unix=?, updated_at_unix=?
                WHERE generation_id=? AND state IN ('reserved', 'blocking')
                """,
                (now, now, row["generation_id"]),
            )
            connection.execute(
                """
                UPDATE checkout_identity_reservations
                SET state='active', finalized_at_unix=?, updated_at_unix=?, error=NULL
                WHERE intent_key=?
                """,
                (now, now, intent_key),
            )
        connection.commit()
        current = _row_dict(
            connection.execute(
                "SELECT * FROM checkout_identity_reservations WHERE intent_key=?",
                (intent_key,),
            ).fetchone()
        )
    assert current is not None
    return _reservation_public(current)


def mark_blocking(reservation: dict[str, Any], *, reason: str) -> dict[str, Any]:
    intent_key = _required_text(reservation.get("intent_key"), "identity reservation intent")
    error = _required_text(reason, "identity blocking reason", maximum=2000)
    now = _now()
    with _checkouts()._database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _ensure_schema(connection)
        row = _row_dict(
            connection.execute(
                "SELECT * FROM checkout_identity_reservations WHERE intent_key=?",
                (intent_key,),
            ).fetchone()
        )
        if row is None:
            raise CheckoutIdentityConflict("identity reservation is missing")
        if row["state"] == "active":
            connection.commit()
            return _reservation_public(row)
        connection.execute(
            "UPDATE checkout_identity_generations SET state='blocking', updated_at_unix=? WHERE generation_id=? AND state='reserved'",
            (now, row["generation_id"]),
        )
        connection.execute(
            "UPDATE checkout_identity_reservations SET state='blocking', error=?, updated_at_unix=? WHERE intent_key=?",
            (error, now, intent_key),
        )
        connection.commit()
        current = _row_dict(
            connection.execute(
                "SELECT * FROM checkout_identity_reservations WHERE intent_key=?",
                (intent_key,),
            ).fetchone()
        )
    assert current is not None
    return _reservation_public(current)


def _restore_row(
    connection: sqlite3.Connection,
    table: str,
    checkout_key: str,
    encoded: str | None,
) -> None:
    if table not in {"lifecycle_bindings", "retention"}:
        raise ValueError("unsupported identity rollback table")
    if encoded is None:
        connection.execute(f"DELETE FROM {table} WHERE checkout_key=?", (checkout_key,))
        return
    value = json.loads(encoded)
    if not isinstance(value, dict) or value.get("checkout_key") != checkout_key:
        raise CheckoutIdentityConflict("identity rollback preimage is invalid")
    columns = list(value)
    placeholders = ",".join("?" for _ in columns)
    connection.execute(
        f"INSERT OR REPLACE INTO {table}({','.join(columns)}) VALUES({placeholders})",
        tuple(value[column] for column in columns),
    )


def abort(reservation: dict[str, Any], *, reason: str) -> dict[str, Any]:
    intent_key = _required_text(reservation.get("intent_key"), "identity reservation intent")
    error = _required_text(reason, "identity abort reason", maximum=2000)
    now = _now()
    with _checkouts()._database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _ensure_schema(connection)
        row = _row_dict(
            connection.execute(
                "SELECT * FROM checkout_identity_reservations WHERE intent_key=?",
                (intent_key,),
            ).fetchone()
        )
        if row is None:
            raise CheckoutIdentityConflict("identity reservation is missing")
        if row["state"] == "active":
            connection.commit()
            return _reservation_public(row)
        if row["state"] == "aborted":
            connection.commit()
            return _reservation_public(row)
        if row["action"] in {"supersession", "reactivation", "terminal_reuse"}:
            requested = json.loads(row["requested_identity_json"])
            lifecycle = _row_dict(
                connection.execute(
                    "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
                    (row["checkout_key"],),
                ).fetchone()
            )
            if lifecycle is not None:
                observed = {
                    "owner_id": lifecycle["owner_id"],
                    "purpose": lifecycle["purpose"],
                    "source_kind": lifecycle["source_kind"],
                    "source_id": lifecycle["source_id"],
                    "artifact_class": lifecycle["artifact_class"],
                    "expected_head": lifecycle["expected_head"],
                    "expected_branch": lifecycle["expected_branch"],
                }
                if observed != requested:
                    connection.execute(
                        "UPDATE checkout_identity_generations SET state='blocking', updated_at_unix=? WHERE generation_id=?",
                        (now, row["generation_id"]),
                    )
                    connection.execute(
                        "UPDATE checkout_identity_reservations SET state='blocking', error=?, updated_at_unix=? WHERE intent_key=?",
                        ("rollback blocked by lifecycle drift: " + error, now, intent_key),
                    )
                    connection.commit()
                    blocked = _row_dict(
                        connection.execute(
                            "SELECT * FROM checkout_identity_reservations WHERE intent_key=?",
                            (intent_key,),
                        ).fetchone()
                    )
                    assert blocked is not None
                    return _reservation_public(blocked)
            connection.execute(
                """
                UPDATE checkout_identity_generations
                SET state='aborted', aborted_at_unix=?, updated_at_unix=?
                WHERE generation_id=? AND state IN ('reserved', 'blocking')
                """,
                (now, now, row["generation_id"]),
            )
            _restore_row(
                connection,
                "lifecycle_bindings",
                row["checkout_key"],
                row["prior_lifecycle_json"],
            )
            _restore_row(
                connection,
                "retention",
                row["checkout_key"],
                row["prior_retention_json"],
            )
            connection.execute(
                "DELETE FROM checkout_identity_archive_supersessions WHERE superseded_by_generation_id=?",
                (row["generation_id"],),
            )
            if row["prior_generation_id"]:
                connection.execute(
                    """
                    UPDATE checkout_identity_generations
                    SET state='active', superseded_by_generation_id=NULL,
                        superseded_at_unix=NULL, updated_at_unix=?
                    WHERE generation_id=? AND state='superseded'
                    """,
                    (now, row["prior_generation_id"]),
                )
        connection.execute(
            """
            UPDATE checkout_identity_generations
            SET state='aborted', aborted_at_unix=?, updated_at_unix=?
            WHERE generation_id=? AND state IN ('reserved', 'blocking')
            """,
            (now, now, row["generation_id"]),
        )
        connection.execute(
            """
            UPDATE checkout_identity_reservations
            SET state='aborted', error=?, updated_at_unix=?
            WHERE intent_key=?
            """,
            (error, now, intent_key),
        )
        connection.commit()
        current = _row_dict(
            connection.execute(
                "SELECT * FROM checkout_identity_reservations WHERE intent_key=?",
                (intent_key,),
            ).fetchone()
        )
    assert current is not None
    return _reservation_public(current)

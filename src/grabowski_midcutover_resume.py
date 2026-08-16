"""Classify whether a broken runtime may *continue* a proven blue-green cutover.

A productive cutover that reaches ``outcome_unknown`` after a successful
selector switch leaves the system in a state neither existing lane can serve:

* the ordinary deployment recovery lane insists on a canonical blue selector,
  because starting a new cutover from a green selector would mean cutting over
  on top of an unfinished cutover, and
* rolling back to blue is forbidden by contract -- green is live and serving.

This module supplies the missing classification, and *only* the classification.
It performs no effect, opens no service, writes nothing.  Its single output is a
verdict over durable evidence:

``scheduled_deploy_recovery``
    The selector is canonical and no unresolved post-switch cutover exists.
    The existing scheduled deployment recovery is the right lane.

``mid_cutover_resume``
    The selector is green and *exactly one* authentic, unresolved receipt proves
    that this exact selector generation is the switched half of that cutover.
    The resume lane may continue it.

``fail_closed``
    Anything else.  An indeterminate cutover state is not a warrant.

The verdict is deliberately not derived from a caller-supplied flag.  Every
input is durable evidence: the routing selector the ingress actually serves and
the hash-bound receipts the cutover itself persisted.  A caller may name the
commit it expects, which can only narrow the verdict, never widen it.

Deliberate limits:

* The lane resumes; it never starts.  A green selector without a receipt that
  *proves* the switch already happened is fail-closed, not an invitation.
* Exactly one unresolved post-switch cutover may exist.  Two competing ambiguous
  cutovers are not resolvable by machine.
* A receipt that already reached a terminal outcome (``completed``,
  ``rolled_back``, ``failed_pre_cutover``) is never resumable.
* Resolution is durable: a terminal resume receipt naming the original cutover
  retires it, so the same ambiguity cannot authorise a second resume.
* Nothing here proves that the green process is healthy.  The caller supplies a
  green observation, and the effect side re-proves it authoritatively before it
  touches anything.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = 1
KIND = "grabowski_midcutover_recovery_classification"

LANE_SCHEDULED_DEPLOY = "scheduled_deploy_recovery"
LANE_MID_CUTOVER_RESUME = "mid_cutover_resume"
LANE_FAIL_CLOSED = "fail_closed"

CUTOVER_RECEIPT_KIND = "grabowski_blue_green_deployment_receipt"
RESUME_RECEIPT_KIND = "grabowski_blue_green_resume_receipt"

#: Outcomes that leave a cutover open.  Everything else is terminal and must
#: never be resumed, however broken the runtime happens to look.
RESUMABLE_OUTCOME = "outcome_unknown"
TERMINAL_OUTCOMES = frozenset({"completed", "rolled_back", "failed_pre_cutover"})

CANONICAL_SLOT = "canonical"
GREEN_SLOT = "green"
CANONICAL_UPSTREAM_PORT = 18181
GREEN_UPSTREAM_PORT = 18182

BLUE_GREEN_RECEIPT_ROOT = (
    Path.home() / ".local/state/grabowski/blue-green-deployment-receipts"
)
MAX_RECEIPT_BYTES = 256 * 1024
MAX_RECEIPT_ENTRIES = 4096

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
#: The same object-id contract the recovery tool input and the resume
#: command builder use.  Accepting only 40 here would make every otherwise
#: valid recovery fail closed on a SHA-256 repository, for a reason that has
#: nothing to do with the cutover being recovered.
HEAD_RE = re.compile(r"[0-9a-f]{40,64}\Z")
CUTOVER_ID_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")


class MidCutoverEvidenceError(ValueError):
    """A persisted receipt does not validate as authentic cutover evidence."""


def canonical_json_sha256(value: Any) -> str:
    """Hash exactly as the cutover receipts are hashed by the deploy tool."""
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _require_receipt_hash(value: dict[str, Any], *, label: str) -> dict[str, Any]:
    declared = value.get("receipt_sha256")
    if not isinstance(declared, str) or SHA256_RE.fullmatch(declared) is None:
        raise MidCutoverEvidenceError(f"{label} hash is invalid")
    material = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if canonical_json_sha256(material) != declared:
        raise MidCutoverEvidenceError(f"{label} hash mismatch")
    return dict(value)


def validate_cutover_receipt(value: Any) -> dict[str, Any]:
    """Accept a persisted blue-green receipt only if it re-hashes to itself."""
    if not isinstance(value, dict):
        raise MidCutoverEvidenceError("blue-green receipt is not an object")
    if value.get("kind") != CUTOVER_RECEIPT_KIND:
        raise MidCutoverEvidenceError("blue-green receipt kind is invalid")
    if value.get("schema_version") != 1:
        raise MidCutoverEvidenceError("blue-green receipt schema version is invalid")
    cutover_id = value.get("cutover_id")
    if not isinstance(cutover_id, str) or CUTOVER_ID_RE.fullmatch(cutover_id) is None:
        raise MidCutoverEvidenceError("blue-green receipt cutover id is invalid")
    return _require_receipt_hash(value, label="blue-green receipt")


def validate_resume_receipt(value: Any) -> dict[str, Any]:
    """Accept a persisted resume receipt only if it re-hashes to itself.

    A resume that was *denied* is durable evidence too, and it legitimately
    names no lineage -- nothing was continued.  Requiring a lineage on every
    resume receipt made the first denial unreadable, and an unreadable receipt
    fails the whole classification closed: one refused attempt would have
    permanently blocked the recovery it refused.  Lineage is therefore required
    exactly where it means something, on a completed resume.
    """
    if not isinstance(value, dict):
        raise MidCutoverEvidenceError("resume receipt is not an object")
    if value.get("kind") != RESUME_RECEIPT_KIND:
        raise MidCutoverEvidenceError("resume receipt kind is invalid")
    if value.get("schema_version") != 1:
        raise MidCutoverEvidenceError("resume receipt schema version is invalid")
    resume_id = value.get("resume_id")
    if not isinstance(resume_id, str) or CUTOVER_ID_RE.fullmatch(resume_id) is None:
        raise MidCutoverEvidenceError("resume receipt id is invalid")
    resumed = value.get("resumed_cutover_id")
    if value.get("outcome") == "completed":
        if not isinstance(resumed, str) or CUTOVER_ID_RE.fullmatch(resumed) is None:
            raise MidCutoverEvidenceError("completed resume receipt names no lineage")
    elif resumed is not None and (
        not isinstance(resumed, str) or CUTOVER_ID_RE.fullmatch(resumed) is None
    ):
        raise MidCutoverEvidenceError("resume receipt lineage is invalid")
    return _require_receipt_hash(value, label="resume receipt")


def validate_any_receipt(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and value.get("kind") == RESUME_RECEIPT_KIND:
        return validate_resume_receipt(value)
    return validate_cutover_receipt(value)


def _require_private_receipt_root(root: Path) -> None:
    """A receipt root anyone else can write to is not evidence.

    ``receipt_sha256`` is an unkeyed self-hash, so it proves internal
    consistency and nothing about authorship: another local user who can write
    the file can recompute it and forge resumable -- or already-resolved --
    lineage. The privacy of the directory and of each file is therefore part of
    the authenticity check, exactly as it already is for the routing selector
    and for the writer that produced these files.
    """
    metadata = root.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise MidCutoverEvidenceError(
            f"receipt directory must be private and owner-controlled: {root}"
        )


def _read_private_json(path: Path) -> Any:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > MAX_RECEIPT_BYTES
        ):
            raise MidCutoverEvidenceError(f"receipt file is not private evidence: {path}")
        raw = os.read(descriptor, MAX_RECEIPT_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MidCutoverEvidenceError(f"receipt file is not valid JSON: {path}") from exc


def load_receipts(root: Path = BLUE_GREEN_RECEIPT_ROOT) -> dict[str, Any]:
    """Load every persisted receipt, separating authentic evidence from noise.

    An unreadable or non-authentic file is never silently skipped: it is
    reported, and the caller treats a non-empty ``unreadable`` list as a reason
    to fail closed.  A resume that ignored evidence it could not parse would be
    deciding on a partial view of the very ambiguity it exists to resolve.
    """
    receipts: list[dict[str, Any]] = []
    unreadable: list[dict[str, str]] = []
    try:
        _require_private_receipt_root(root)
        entries = sorted(root.iterdir())
    except FileNotFoundError:
        return {"receipts": [], "unreadable": [], "root": str(root), "present": False}
    except (MidCutoverEvidenceError, OSError) as exc:
        # Reported as unreadable rather than empty: an insecure or unusable
        # receipt root must fail the classification closed, not silently look
        # like a system with no history.
        return {
            "receipts": [],
            "unreadable": [{"path": str(root), "error": str(exc)}],
            "root": str(root),
            "present": True,
        }
    if len(entries) > MAX_RECEIPT_ENTRIES:
        return {
            "receipts": [],
            "unreadable": [{"path": str(root), "error": "receipt directory is oversized"}],
            "root": str(root),
            "present": True,
        }
    for entry in entries:
        if entry.suffix != ".json" or entry.is_symlink() or not entry.is_file():
            continue
        try:
            receipts.append(validate_any_receipt(_read_private_json(entry)))
        except (MidCutoverEvidenceError, OSError) as exc:
            unreadable.append({"path": str(entry), "error": str(exc)})
    return {
        "receipts": receipts,
        "unreadable": unreadable,
        "root": str(root),
        "present": True,
    }


DEFAULT_SELECTOR_FILE = (
    Path.home()
    / ".local/state/grabowski/transport-connectors/operator-routing-selector.json"
)
MAX_SELECTOR_BYTES = 16 * 1024
ROUTING_SELECTOR_KIND = "grabowski_transport_ingress_routing_selector"
ROUTING_SLOTS = {CANONICAL_SLOT: CANONICAL_UPSTREAM_PORT, GREEN_SLOT: GREEN_UPSTREAM_PORT}


def read_routing_selector_document(
    path: Path = DEFAULT_SELECTOR_FILE,
) -> dict[str, Any]:
    """Read the routing selector as *classification evidence*, not as authority.

    The ingress owns the selector; this reader never writes it and never decides
    routing.  It exists because the deployed runtime does not ship the ingress
    module, and a classification that could not see the selector would have to
    guess the one fact the whole verdict turns on.  The document is accepted only
    if it is a private single-link owner-owned regular file whose declared hash
    covers its own content, so a tampered selector is unreadable rather than
    misread.
    """
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_SELECTOR_BYTES
        ):
            raise MidCutoverEvidenceError(
                "routing selector must be one private owner-controlled regular file"
            )
        raw = os.read(descriptor, MAX_SELECTOR_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_SELECTOR_BYTES:
        raise MidCutoverEvidenceError("routing selector exceeds size bound")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MidCutoverEvidenceError("routing selector is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("kind") != ROUTING_SELECTOR_KIND:
        raise MidCutoverEvidenceError("routing selector contract is invalid")
    slot = value.get("selected_slot")
    if slot not in ROUTING_SLOTS or value.get("upstream_port") != ROUTING_SLOTS[slot]:
        raise MidCutoverEvidenceError("routing selector target is not allowed")
    declared = value.get("selector_sha256")
    if not isinstance(declared, str) or SHA256_RE.fullmatch(declared) is None:
        raise MidCutoverEvidenceError("routing selector hash is invalid")
    unsigned = {key: item for key, item in value.items() if key != "selector_sha256"}
    if canonical_json_sha256(unsigned) != declared:
        raise MidCutoverEvidenceError("routing selector hash mismatch")
    if not _selector_shape_valid(value):
        raise MidCutoverEvidenceError("routing selector shape is invalid")
    return dict(value)


DEFAULT_RELEASES_ROOT = Path.home() / ".local/share/grabowski-mcp-releases"
MANIFEST_NAME = "deployment-manifest.json"
MAX_MANIFEST_BYTES = 1024 * 1024


def observe_green_release(
    release_id: str,
    *,
    releases_root: Path = DEFAULT_RELEASES_ROOT,
    port: int = GREEN_UPSTREAM_PORT,
    connect_timeout_seconds: float = 1.0,
) -> dict[str, Any]:
    """Cheap, effect-free evidence about the release the green slot points at.

    This is not a readiness proof and is not treated as one: it reads the
    release's own manifest and checks that *something* listens on the green
    port.  The effect side re-proves green authoritatively over MCP before it
    touches anything, so this stays a gate input rather than a claim.
    """
    import socket  # local: classification must not cost the import at module load

    observation: dict[str, Any] = {
        "release_id": None,
        "repo_head": None,
        "completion_status": None,
        "listener_present": False,
        "port": port,
        "error": None,
        "does_not_establish": ["that the green process serves the release"],
    }
    try:
        with socket.create_connection(
            ("127.0.0.1", port), timeout=connect_timeout_seconds
        ):
            observation["listener_present"] = True
    except OSError:
        observation["listener_present"] = False
    if not isinstance(release_id, str) or not release_id or "/" in release_id:
        observation["error"] = "release id is invalid"
        return observation
    manifest_path = releases_root / release_id / MANIFEST_NAME
    try:
        descriptor = os.open(
            manifest_path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
    except OSError as exc:
        observation["error"] = type(exc).__name__
        return observation
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_size > MAX_MANIFEST_BYTES
        ):
            observation["error"] = "release manifest is not private evidence"
            return observation
        raw = os.read(descriptor, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        observation["error"] = "release manifest is invalid JSON"
        return observation
    if not isinstance(manifest, dict):
        observation["error"] = "release manifest is not an object"
        return observation
    observation["release_id"] = manifest.get("release_id")
    observation["repo_head"] = manifest.get("repo_head")
    observation["completion_status"] = manifest.get("completion_status")
    return observation


def collect_classification_inputs(
    *,
    selector_path: Path = DEFAULT_SELECTOR_FILE,
    receipt_root: Path = BLUE_GREEN_RECEIPT_ROOT,
    releases_root: Path = DEFAULT_RELEASES_ROOT,
) -> dict[str, Any]:
    """Gather every durable input the lane verdict is derived from."""
    selector: dict[str, Any] | None = None
    selector_error: str | None = None
    selector_present = True
    try:
        selector = read_routing_selector_document(selector_path)
    except FileNotFoundError:
        # No selector at all means no blue-green topology, which is a different
        # world -- not a broken one.  The ordinary lane still applies.
        selector_present = False
    except (MidCutoverEvidenceError, OSError) as exc:
        selector_error = str(exc)
    loaded = load_receipts(receipt_root)
    green_observation = None
    if isinstance(selector, dict):
        green_observation = observe_green_release(
            str(selector.get("runtime_binding", {}).get("release_id") or ""),
            releases_root=releases_root,
        )
    return {
        "selector": selector,
        "selector_present": selector_present,
        "selector_error": selector_error,
        "receipts": loaded["receipts"],
        "unreadable_receipts": loaded["unreadable"],
        "green_observation": green_observation,
    }


def classify_from_durable_state(
    *,
    expected_head: str,
    selector_path: Path = DEFAULT_SELECTOR_FILE,
    receipt_root: Path = BLUE_GREEN_RECEIPT_ROOT,
    releases_root: Path = DEFAULT_RELEASES_ROOT,
) -> dict[str, Any]:
    inputs = collect_classification_inputs(
        selector_path=selector_path,
        receipt_root=receipt_root,
        releases_root=releases_root,
    )
    return classify_recovery_lane(expected_head=expected_head, **inputs)


def _switch_evidence(receipt: dict[str, Any]) -> dict[str, Any] | None:
    """Return the selector-switch record only if it proves the switch happened."""
    switch = receipt.get("selector_switch")
    if not isinstance(switch, dict) or switch.get("switched") is not True:
        return None
    generation = switch.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        return None
    if switch.get("selected_slot") != GREEN_SLOT:
        return None
    if switch.get("upstream_port") != GREEN_UPSTREAM_PORT:
        return None
    for key in ("selector_sha256", "runtime_binding_sha256"):
        value = switch.get(key)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            return None
    return switch


def is_post_switch_outcome_unknown(receipt: dict[str, Any]) -> bool:
    """True only for a cutover proven to have switched and then lost its outcome."""
    if receipt.get("kind") != CUTOVER_RECEIPT_KIND:
        return False
    if receipt.get("outcome") != RESUMABLE_OUTCOME:
        return False
    if receipt.get("phase") != RESUMABLE_OUTCOME:
        return False
    if _switch_evidence(receipt) is None:
        return False
    recovery = receipt.get("recovery")
    if (
        not isinstance(recovery, dict)
        or recovery.get("automatic_rollback_forbidden") is not True
    ):
        # Only the post-switch classification sets this marker.  A rollback that
        # itself failed pre-switch is ambiguous, but it is *not* a switched
        # cutover and must not be continued forward onto green.
        return False
    # A promoted cutover is finished even if its receipt says outcome_unknown for
    # a later reason; continuing it would re-run promotion on an already
    # canonical runtime.
    return receipt.get("retirement") is None and receipt.get("final_routing") is None


def resolution_for_cutover(
    receipts: Iterable[dict[str, Any]], cutover_id: str
) -> dict[str, Any] | None:
    """Find the terminal resume receipt that retired one cutover, if any.

    Resolution must be discoverable *from the original cutover*, not only by
    scanning: an operator holding ``bgc-...`` has to be able to ask what became
    of it and get a hash-bound answer rather than an inference.
    """
    for receipt in receipts:
        if receipt.get("kind") != RESUME_RECEIPT_KIND:
            continue
        if receipt.get("outcome") != "completed":
            continue
        if receipt.get("resumed_cutover_id") != cutover_id:
            continue
        return {
            "resume_id": receipt.get("resume_id"),
            "resume_receipt_sha256": receipt.get("receipt_sha256"),
            "resumed_cutover_id": cutover_id,
            "resumed_receipt_sha256": receipt.get("resumed_receipt_sha256"),
            "expected_head": receipt.get("expected_head"),
            "final_routing": receipt.get("final_routing"),
        }
    return None


def resolved_cutover_ids(receipts: Iterable[dict[str, Any]]) -> set[str]:
    """Cutovers a terminal resume receipt has already retired."""
    resolved: set[str] = set()
    for receipt in receipts:
        if receipt.get("kind") != RESUME_RECEIPT_KIND:
            continue
        if receipt.get("outcome") != "completed":
            continue
        resumed = receipt.get("resumed_cutover_id")
        if isinstance(resumed, str):
            resolved.add(resumed)
    return resolved


def unresolved_post_switch_receipts(
    receipts: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    materialised = list(receipts)
    resolved = resolved_cutover_ids(materialised)
    return [
        receipt
        for receipt in materialised
        if is_post_switch_outcome_unknown(receipt)
        and receipt.get("cutover_id") not in resolved
    ]


def _highest_switch_generation(receipts: Iterable[dict[str, Any]]) -> int:
    highest = 0
    for receipt in receipts:
        switch = _switch_evidence(receipt) if isinstance(receipt, dict) else None
        if switch is not None:
            highest = max(highest, int(switch["generation"]))
    return highest


def _selector_shape_valid(selector: Any) -> bool:
    if not isinstance(selector, dict):
        return False
    generation = selector.get("generation")
    binding = selector.get("runtime_binding")
    return (
        not isinstance(generation, bool)
        and isinstance(generation, int)
        and generation >= 1
        and isinstance(binding, dict)
        and isinstance(selector.get("selector_sha256"), str)
        and SHA256_RE.fullmatch(str(selector.get("selector_sha256"))) is not None
        and isinstance(selector.get("runtime_binding_sha256"), str)
        and SHA256_RE.fullmatch(str(selector.get("runtime_binding_sha256"))) is not None
        and isinstance(selector.get("cutover_id"), str)
    )


def _verdict(
    *,
    lane: str,
    checks: dict[str, bool],
    reasons: Sequence[str],
    selector_summary: dict[str, Any] | None,
    receipt_summary: dict[str, Any] | None,
    resume_binding: dict[str, Any] | None,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "lane": lane,
        "checks": dict(sorted(checks.items())),
        "reasons": sorted(reasons),
        "selector": selector_summary,
        "receipt": receipt_summary,
        "resume_binding": resume_binding,
        "evidence": evidence,
        "does_not_establish": [
            "that the green process is healthy",
            "that the resume will succeed",
            "authority to start a new blue-green cutover",
            "authority for any mutation other than the classified operation",
        ],
    }
    return {**material, "classification_sha256": canonical_json_sha256(material)}


def classify_recovery_lane(
    *,
    expected_head: str,
    selector: dict[str, Any] | None,
    receipts: Sequence[dict[str, Any]],
    selector_error: str | None = None,
    selector_present: bool = True,
    unreadable_receipts: Sequence[dict[str, str]] = (),
    green_observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Decide which recovery lane -- if any -- this durable state admits."""
    checks: dict[str, bool] = {}
    evidence: dict[str, Any] = {
        "selector_error": selector_error,
        "selector_present": selector_present,
        "unreadable_receipts": list(unreadable_receipts),
        "green_observation": green_observation,
    }

    checks["expected_head_named"] = bool(
        isinstance(expected_head, str) and HEAD_RE.fullmatch(expected_head)
    )
    # An unparseable receipt is unresolved ambiguity, not absent evidence.
    checks["all_receipt_evidence_readable"] = not list(unreadable_receipts)

    if not selector_present and selector_error is None:
        # A host without an ingress routing selector has no blue-green state to
        # continue.  That is the ordinary lane's world, and stopping it here
        # would break deployment recovery on every non-ingress topology.
        checks["no_unresolved_post_switch_cutover"] = not unresolved_post_switch_receipts(
            receipts
        )
        reasons = sorted(name for name, ok in checks.items() if not ok)
        return _verdict(
            lane=LANE_SCHEDULED_DEPLOY if not reasons else LANE_FAIL_CLOSED,
            checks=checks,
            reasons=reasons,
            selector_summary=None,
            receipt_summary=None,
            resume_binding=None,
            evidence=evidence,
        )

    checks["selector_readable"] = selector_error is None and _selector_shape_valid(
        selector
    )

    if not checks["expected_head_named"] or not checks["selector_readable"]:
        reasons = sorted(name for name, ok in checks.items() if not ok)
        return _verdict(
            lane=LANE_FAIL_CLOSED,
            checks=checks,
            reasons=reasons,
            selector_summary=None,
            receipt_summary=None,
            resume_binding=None,
            evidence=evidence,
        )

    assert selector is not None
    binding = selector["runtime_binding"]
    selector_summary = {
        "selector_sha256": selector.get("selector_sha256"),
        "generation": selector.get("generation"),
        "selected_slot": selector.get("selected_slot"),
        "upstream_port": selector.get("upstream_port"),
        "runtime_binding_sha256": selector.get("runtime_binding_sha256"),
        "cutover_id": selector.get("cutover_id"),
        "release_id": binding.get("release_id"),
        "repo_head": binding.get("repo_head"),
    }

    open_cutovers = unresolved_post_switch_receipts(receipts)
    evidence["unresolved_post_switch_cutover_ids"] = sorted(
        str(receipt.get("cutover_id")) for receipt in open_cutovers
    )
    # If this selector's cutover was already continued, say so with the receipt
    # that did it.  "Refused" and "already done" are different answers, and an
    # operator who cannot tell them apart will retry the one that is finished.
    evidence["resolution"] = resolution_for_cutover(
        receipts, str(selector.get("cutover_id"))
    )

    slot = selector.get("selected_slot")
    if slot == CANONICAL_SLOT:
        checks["selector_slot_is_canonical"] = True
        # The ordinary lane starts a *new* cutover.  Doing that while a switched
        # cutover is still unresolved would stack an unfinished promotion under
        # a fresh one, which is exactly the state this module exists to prevent.
        checks["no_unresolved_post_switch_cutover"] = not open_cutovers
        reasons = sorted(name for name, ok in checks.items() if not ok)
        return _verdict(
            lane=LANE_SCHEDULED_DEPLOY if not reasons else LANE_FAIL_CLOSED,
            checks=checks,
            reasons=reasons,
            selector_summary=selector_summary,
            receipt_summary=None,
            resume_binding=None,
            evidence=evidence,
        )

    checks["selector_slot_is_green"] = slot == GREEN_SLOT
    checks["selector_upstream_is_green_port"] = (
        selector.get("upstream_port") == GREEN_UPSTREAM_PORT
    )
    if not checks["selector_slot_is_green"]:
        reasons = sorted(name for name, ok in checks.items() if not ok)
        return _verdict(
            lane=LANE_FAIL_CLOSED,
            checks=checks,
            reasons=reasons,
            selector_summary=selector_summary,
            receipt_summary=None,
            resume_binding=None,
            evidence=evidence,
        )

    checks["exactly_one_unresolved_post_switch_cutover"] = len(open_cutovers) == 1
    candidate = open_cutovers[0] if len(open_cutovers) == 1 else None
    checks["receipt_binds_current_selector_cutover"] = bool(
        candidate is not None
        and candidate.get("cutover_id") == selector.get("cutover_id")
    )

    receipt_summary: dict[str, Any] | None = None
    resume_binding: dict[str, Any] | None = None
    if candidate is not None:
        switch = _switch_evidence(candidate)
        assert switch is not None
        receipt_summary = {
            "cutover_id": candidate.get("cutover_id"),
            "receipt_sha256": candidate.get("receipt_sha256"),
            "outcome": candidate.get("outcome"),
            "phase": candidate.get("phase"),
            "expected_head": candidate.get("expected_head"),
            "blue_release_id": candidate.get("blue_release_id"),
            "green_release_id": candidate.get("green_release_id"),
            "source_identity_sha256": candidate.get("source_identity_sha256"),
            "switch_generation": switch.get("generation"),
            "switch_selector_sha256": switch.get("selector_sha256"),
            "switch_runtime_binding_sha256": switch.get("runtime_binding_sha256"),
        }
        checks["receipt_expected_head_matches_request"] = (
            candidate.get("expected_head") == expected_head
        )
        checks["selector_generation_matches_receipt"] = selector.get(
            "generation"
        ) == switch.get("generation")
        checks["selector_sha256_matches_receipt"] = selector.get(
            "selector_sha256"
        ) == switch.get("selector_sha256")
        checks["selector_binding_digest_matches_receipt"] = selector.get(
            "runtime_binding_sha256"
        ) == switch.get("runtime_binding_sha256")
        checks["selector_release_matches_receipt_green"] = (
            binding.get("release_id") == candidate.get("green_release_id")
        )
        checks["selector_repo_head_matches_expected_head"] = (
            binding.get("repo_head") == expected_head
        )
        # Nothing may have switched the selector since this receipt was written.
        checks["no_newer_switch_generation_recorded"] = _highest_switch_generation(
            receipts
        ) <= int(switch["generation"])
        checks["resume_not_already_terminal"] = candidate.get(
            "cutover_id"
        ) not in resolved_cutover_ids(receipts)
        green_release = candidate.get("green_release_id")
        checks["green_serves_expected_release"] = bool(
            isinstance(green_observation, dict)
            and green_observation.get("release_id") == green_release
            and green_observation.get("repo_head") == expected_head
            and green_observation.get("listener_present") is True
        )
        if all(checks.values()):
            resume_binding = {
                "cutover_id": str(candidate["cutover_id"]),
                "resumed_receipt_sha256": str(candidate["receipt_sha256"]),
                "expected_head": expected_head,
                "expected_selector_sha256": str(switch["selector_sha256"]),
                "expected_generation": int(switch["generation"]),
                "expected_slot": GREEN_SLOT,
                "expected_release_id": str(green_release),
                "expected_runtime_binding_sha256": str(
                    switch["runtime_binding_sha256"]
                ),
                "expected_upstream_port": GREEN_UPSTREAM_PORT,
                "source_identity_sha256": candidate.get("source_identity_sha256"),
            }
            resume_binding["binding_sha256"] = canonical_json_sha256(resume_binding)

    reasons = sorted(name for name, ok in checks.items() if not ok)
    return _verdict(
        lane=LANE_MID_CUTOVER_RESUME if not reasons else LANE_FAIL_CLOSED,
        checks=checks,
        reasons=reasons,
        selector_summary=selector_summary,
        receipt_summary=receipt_summary,
        resume_binding=resume_binding,
        evidence=evidence,
    )

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
import subprocess
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

#: The resume is a staged effect, so a resume that itself fails leaves the
#: system somewhere in the middle of it.  Naming those places is what keeps the
#: lane restartable: without them, a resume that promoted the pointer and then
#: died would leave the original cutover permanently unresumable -- the very
#: failure mode this whole lane exists to remove, reintroduced one level up.
PHASE_REBIND_SNAPSHOT = "S0_rebind_snapshot"
PHASE_PROMOTE_POINTER = "S1_promote_pointer"
PHASE_SELECT_CANONICAL = "S2_select_canonical"
PHASE_RETIRE_GREEN = "S3_retire_green"
PHASE_CLOSEOUT = "S4_closeout"
RESUME_PHASES = (
    PHASE_REBIND_SNAPSHOT,
    PHASE_PROMOTE_POINTER,
    PHASE_SELECT_CANONICAL,
    PHASE_RETIRE_GREEN,
    PHASE_CLOSEOUT,
)

DEFAULT_CLIENT_SNAPSHOT_PATH = (
    Path.home() / ".local/state/grabowski/client-snapshot/current.json"
)
SNAPSHOT_BINDING_PENDING = "bound_to_predecessor"
SNAPSHOT_BINDING_DONE = "rebound_by_this_lineage"
SNAPSHOT_BINDING_FOREIGN = "foreign"
SNAPSHOT_BINDING_UNREADABLE = "unreadable"


def observe_client_snapshot_binding(
    *,
    cutover_id: str,
    cutover_generation: int,
    blue_release_id: str,
    blue_repo_head: str,
    green_release_id: str,
    target_head: str,
    source_evidence_time: int,
    publication_request_id: str,
    registered_tool_count: int,
    registered_names_sha256: str,
    agent_instructions_sha256: str,
    green_readiness: dict[str, Any],
    snapshot_inspector: Any,
    path: Path = DEFAULT_CLIENT_SNAPSHOT_PATH,
) -> dict[str, Any]:
    """Project canonical snapshot inspection into the recovery vocabulary.

    The snapshot authority is injected by the recovery composition root.  This
    module owns recovery classification, not the client-snapshot parser, and
    therefore must not import the latter back into the recovery layer.
    """
    if not callable(snapshot_inspector):
        raise MidCutoverEvidenceError(
            "canonical client snapshot inspector is unavailable"
        )
    observed = snapshot_inspector(
        cutover_id=cutover_id,
        cutover_generation=cutover_generation,
        source_release_id=blue_release_id,
        source_repo_head=blue_repo_head,
        target_release_id=green_release_id,
        target_repo_head=target_head,
        source_evidence_time=source_evidence_time,
        publication_request_id=publication_request_id,
        registered_tool_count=registered_tool_count,
        registered_names_sha256=registered_names_sha256,
        agent_instructions_sha256=agent_instructions_sha256,
        green_readiness=green_readiness,
        path=path,
    )
    if not isinstance(observed, dict):
        raise MidCutoverEvidenceError(
            "canonical client snapshot inspector returned invalid evidence"
        )
    state = observed.get("state")
    if state not in {
        SNAPSHOT_BINDING_PENDING,
        SNAPSHOT_BINDING_DONE,
        SNAPSHOT_BINDING_FOREIGN,
        SNAPSHOT_BINDING_UNREADABLE,
    }:
        state = SNAPSHOT_BINDING_UNREADABLE
    return {
        **observed,
        "state": state,
        "transition_sha256": observed.get("publication_transition_sha256"),
    }

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
#: The canonical release identifier grammar produced by the build:
#: <head12>-srcset<12>-lock<12>-contract<12>, optionally -attempt<n>.
#: One definition, used by every layer that has to judge a release id. Two
#: grammars would eventually disagree about a legitimate retry release, and the
#: disagreement would surface as a refused recovery rather than as a bug.
RELEASE_ID_RE = re.compile(
    r"(?P<head>[0-9a-f]{12})-srcset(?P<srcset>[0-9a-f]{12})"
    r"-lock(?P<lock>[0-9a-f]{12})-contract(?P<contract>[0-9a-f]{12})"
    r"(?:-attempt(?P<attempt>[0-9]{1,3}))?\Z"
)


def parse_release_id(release_id: Any) -> dict[str, Any] | None:
    """Decompose a release id into the identities it commits to.

    The identifier is not opaque: the build encodes the repository head and the
    contract digest into it, so a release id is itself a binding that can be
    checked against a receipt rather than trusted because a directory of that
    name exists.
    """
    if not isinstance(release_id, str):
        return None
    match = RELEASE_ID_RE.fullmatch(release_id)
    if match is None:
        return None
    return {
        "release_id": release_id,
        "head12": match.group("head"),
        "srcset12": match.group("srcset"),
        "lock12": match.group("lock"),
        "contract12": match.group("contract"),
        "attempt": int(match.group("attempt")) if match.group("attempt") else None,
    }


def release_id_binds_head(release_id: Any, repo_head: Any) -> bool:
    """Whether one release identifier commits to the supplied repository head."""
    identity = parse_release_id(release_id)
    return bool(
        identity is not None
        and isinstance(repo_head, str)
        and HEAD_RE.fullmatch(repo_head)
        and repo_head.startswith(identity["head12"])
    )


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
    generation = value.get("cutover_generation")
    resumable = (
        value.get("outcome") == RESUMABLE_OUTCOME
        and value.get("phase") == RESUMABLE_OUTCOME
    )
    if (
        (generation is not None or resumable)
        and (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 1
        )
    ):
        raise MidCutoverEvidenceError("blue-green receipt cutover generation is invalid")
    return _require_receipt_hash(value, label="blue-green receipt")


def activation_observation(receipt: dict[str, Any]) -> dict[str, Any]:
    """Return the unique hash-bound Publication-v2 activation observation."""
    validated = validate_cutover_receipt(receipt)
    observations = validated.get("observations")
    if not isinstance(observations, list):
        raise MidCutoverEvidenceError("blue-green receipt observations are missing")
    matches: list[dict[str, Any]] = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise MidCutoverEvidenceError(
                f"blue-green observation {index} is not an object"
            )
        declared = observation.get("observation_sha256")
        material = {
            key: item
            for key, item in observation.items()
            if key != "observation_sha256"
        }
        if (
            not isinstance(declared, str)
            or SHA256_RE.fullmatch(declared) is None
            or canonical_json_sha256(material) != declared
        ):
            raise MidCutoverEvidenceError(
                f"blue-green observation {index} hash mismatch"
            )
        if observation.get("phase") == "platform_publication_activation":
            matches.append(dict(observation))
    if len(matches) != 1:
        raise MidCutoverEvidenceError(
            "blue-green receipt requires exactly one publication activation observation"
        )
    activation = matches[0]
    observed_at = activation.get("observed_at_unix")
    details = activation.get("details")
    if (
        isinstance(observed_at, bool)
        or not isinstance(observed_at, int)
        or observed_at < 0
        or not isinstance(details, dict)
        or details.get("state") != "publication_pending"
        or not isinstance(details.get("request_id"), str)
        or CUTOVER_ID_RE.fullmatch(details["request_id"]) is None
    ):
        raise MidCutoverEvidenceError(
            "blue-green publication activation observation is invalid"
        )
    return {
        "source_evidence_time": observed_at,
        "publication_request_id": details["request_id"],
        "observation_sha256": activation["observation_sha256"],
        "state": details["state"],
    }


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
    if RELEASE_ID_RE.fullmatch(release_id or "") is None:
        # Validate before any I/O: an unusable identifier is not a reason to
        # open a socket.
        observation["error"] = "release id is invalid"
        return observation
    try:
        with socket.create_connection(
            ("127.0.0.1", port), timeout=connect_timeout_seconds
        ):
            observation["listener_present"] = True
    except OSError:
        observation["listener_present"] = False
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


DEFAULT_STABLE_RUNTIME = Path.home() / ".local/share/grabowski-mcp"


def _pointer_binding(
    runtime_path: Path, releases_root: Path | None = None
) -> dict[str, Any]:
    """What the stable runtime path actually *is*, before reading any manifest.

    A manifest found under the path proves what that directory says about
    itself; it does not prove the pointer binds it. The release directory the
    symlink resolves to is the binding, and a pointer that is missing, is not a
    symlink into the releases root, or resolves somewhere else entirely is not a
    weaker phase -- it is an unclassifiable one.
    """
    binding: dict[str, Any] = {
        "kind": None,
        "target_release_id": None,
        "error": None,
    }
    try:
        linked = runtime_path.lstat()
    except OSError as exc:
        binding["error"] = type(exc).__name__
        return binding
    if not stat.S_ISLNK(linked.st_mode):
        binding["kind"] = "directory" if stat.S_ISDIR(linked.st_mode) else "unexpected"
        return binding
    binding["kind"] = "symlink"
    try:
        resolved = runtime_path.resolve(strict=True)
    except OSError as exc:
        binding["error"] = type(exc).__name__
        return binding
    binding["resolved_path"] = str(resolved)
    if releases_root is not None:
        try:
            resolved_root = releases_root.resolve(strict=True)
        except OSError as exc:
            binding["error"] = f"releases root is unavailable: {type(exc).__name__}"
            return binding
        if resolved.parent != resolved_root:
            # A same-named release outside the managed root would otherwise let
            # an unmanaged directory impersonate the promotion target.
            binding["kind"] = "outside_releases_root"
            binding["error"] = "stable pointer resolves outside the releases root"
            return binding
        binding["releases_root"] = str(resolved_root)
    if RELEASE_ID_RE.fullmatch(resolved.name) is None:
        binding["error"] = "stable pointer target is not a canonical release id"
        return binding
    binding["target_release_id"] = resolved.name
    return binding


def observe_stable_pointer(
    runtime_path: Path = DEFAULT_STABLE_RUNTIME,
    releases_root: Path | None = None,
) -> dict[str, Any]:
    """Which release the stable runtime pointer currently names.

    This is the fact that separates "the resume has not started" from "the
    resume already promoted the pointer and then failed". Without it a partially
    applied resume is indistinguishable from an untouched one, and the lane
    would either redo an applied effect or refuse forever.
    """
    binding = _pointer_binding(runtime_path, releases_root)
    observation: dict[str, Any] = {
        "runtime_path": str(runtime_path),
        "release_id": None,
        "repo_head": None,
        "completion_status": None,
        "pointer_kind": binding["kind"],
        "pointer_target_release_id": binding["target_release_id"],
        "error": binding["error"],
    }
    if binding["error"] is not None or binding["kind"] != "symlink":
        observation["error"] = observation["error"] or (
            f"stable runtime pointer is {binding['kind']}, not a managed symlink"
        )
        return observation
    manifest_path = runtime_path / MANIFEST_NAME
    try:
        descriptor = os.open(manifest_path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        observation["error"] = type(exc).__name__
        return observation
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MANIFEST_BYTES:
            observation["error"] = "stable runtime manifest is not usable evidence"
            return observation
        raw = os.read(descriptor, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        observation["error"] = "stable runtime manifest is invalid JSON"
        return observation
    if not isinstance(manifest, dict):
        observation["error"] = "stable runtime manifest is not an object"
        return observation
    if manifest.get("release_id") != binding["target_release_id"]:
        observation["error"] = "stable runtime manifest disagrees with the pointer"
        return observation
    observation["release_id"] = manifest.get("release_id")
    observation["repo_head"] = manifest.get("repo_head")
    observation["completion_status"] = manifest.get("completion_status")
    return observation


GREEN_OPERATOR_UNIT_PREFIX = "grabowski-green-operator-"


def green_operator_unit(cutover_id: str) -> str:
    """The transient unit name of one cutover -- derived, never supplied.

    Mirrors the deploy tool's own derivation so classification asks about
    exactly the unit that cutover created, and a caller cannot point the
    observation at some other service.
    """
    digest = hashlib.sha256(cutover_id.encode("utf-8")).hexdigest()[:12]
    return f"{GREEN_OPERATOR_UNIT_PREFIX}{digest}.service"


def observe_green_operator_unit(unit: str) -> dict[str, Any]:
    """Read the transient unit state without importing the deployment runner."""
    if not unit.startswith(GREEN_OPERATOR_UNIT_PREFIX) or not unit.endswith(
        ".service"
    ):
        return {"unit": unit, "active": None, "error": "green unit is invalid"}
    try:
        result = subprocess.run(
            [
                "systemctl",
                "--user",
                "show",
                unit,
                "--property=LoadState,ActiveState,SubState",
                "--no-pager",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"unit": unit, "active": None, "error": type(exc).__name__}
    fields = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value
    load = fields.get("LoadState")
    active_state = fields.get("ActiveState")
    sub_state = fields.get("SubState")
    if active_state == "active":
        active: bool | None = True
    elif load == "not-found" or (
        active_state == "inactive" and sub_state in {"dead", "exited"}
    ):
        active = False
    else:
        active = None
    return {
        "unit": unit,
        "active": active,
        "load_state": load,
        "active_state": active_state,
        "sub_state": sub_state,
        "returncode": result.returncode,
        "error": None if active is not None else "green unit state is ambiguous",
    }


def collect_classification_inputs(
    *,
    selector_path: Path = DEFAULT_SELECTOR_FILE,
    receipt_root: Path = BLUE_GREEN_RECEIPT_ROOT,
    releases_root: Path = DEFAULT_RELEASES_ROOT,
    runtime_path: Path = DEFAULT_STABLE_RUNTIME,
    pointer_releases_root: Path | None = None,
    client_snapshot_path: Path = DEFAULT_CLIENT_SNAPSHOT_PATH,
    green_unit_observer: Any = None,
    snapshot_inspector: Any = None,
) -> dict[str, Any]:
    """Gather every durable input the lane verdict is derived from."""
    if pointer_releases_root is None:
        pointer_releases_root = releases_root
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
    open_cutovers = unresolved_post_switch_receipts(loaded["receipts"])
    open_cutover_id = (
        str(open_cutovers[0]["cutover_id"]) if len(open_cutovers) == 1 else None
    )
    green_observation = None
    if isinstance(selector, dict):
        green_observation = observe_green_release(
            str(selector.get("runtime_binding", {}).get("release_id") or ""),
            releases_root=releases_root,
        )
    snapshot_observation = None
    activation_error = None
    activation = None
    blue_observation = None
    if open_cutover_id is not None:
        cutover = open_cutovers[0]
        blue_observation = observe_green_release(
            str(cutover.get("blue_release_id") or ""),
            releases_root=releases_root,
            port=0,
            connect_timeout_seconds=0.01,
        )
        try:
            activation = activation_observation(cutover)
            readiness = cutover.get("green_readiness")
            if not isinstance(readiness, dict):
                raise MidCutoverEvidenceError(
                    "blue-green receipt carries no green readiness evidence"
                )
            snapshot_observation = observe_client_snapshot_binding(
                cutover_id=open_cutover_id,
                cutover_generation=int(cutover["cutover_generation"]),
                blue_release_id=str(cutover.get("blue_release_id") or ""),
                blue_repo_head=str((blue_observation or {}).get("repo_head") or ""),
                green_release_id=str(cutover.get("green_release_id") or ""),
                target_head=str(cutover.get("expected_head") or ""),
                source_evidence_time=activation["source_evidence_time"],
                publication_request_id=activation["publication_request_id"],
                registered_tool_count=int(
                    readiness.get("complete_schema_count") or 0
                ),
                registered_names_sha256=str(cutover.get("names_sha256") or ""),
                agent_instructions_sha256=str(
                    cutover.get("agent_instructions_sha256") or ""
                ),
                green_readiness=readiness,
                snapshot_inspector=snapshot_inspector,
                path=client_snapshot_path,
            )
        except (MidCutoverEvidenceError, KeyError, TypeError, ValueError) as exc:
            activation_error = str(exc)
    return {
        "selector": selector,
        "selector_present": selector_present,
        "selector_error": selector_error,
        "receipts": loaded["receipts"],
        "unreadable_receipts": loaded["unreadable"],
        "green_observation": green_observation,
        "blue_observation": blue_observation,
        "activation_observation": activation,
        "activation_error": activation_error,
        "pointer_observation": observe_stable_pointer(
            runtime_path, pointer_releases_root
        ),
        "green_unit_observation": (
            (green_unit_observer or observe_green_operator_unit)(
                green_operator_unit(open_cutover_id)
            )
            if open_cutover_id is not None
            else None
        ),
        "snapshot_observation": snapshot_observation,
    }


def classify_from_durable_state(
    *,
    expected_head: str,
    selector_path: Path = DEFAULT_SELECTOR_FILE,
    receipt_root: Path = BLUE_GREEN_RECEIPT_ROOT,
    releases_root: Path = DEFAULT_RELEASES_ROOT,
    runtime_path: Path = DEFAULT_STABLE_RUNTIME,
    pointer_releases_root: Path | None = None,
    client_snapshot_path: Path = DEFAULT_CLIENT_SNAPSHOT_PATH,
    green_unit_observer: Any = None,
    snapshot_inspector: Any = None,
) -> dict[str, Any]:
    inputs = collect_classification_inputs(
        selector_path=selector_path,
        receipt_root=receipt_root,
        releases_root=releases_root,
        runtime_path=runtime_path,
        pointer_releases_root=pointer_releases_root,
        client_snapshot_path=client_snapshot_path,
        green_unit_observer=green_unit_observer,
        snapshot_inspector=snapshot_inspector,
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


def _pointer_state(
    observation: Any,
    *,
    blue_release_id: Any,
    blue_repo_head: Any,
    target_release_id: Any,
    target_head: str,
) -> str:
    """Classify the stable pointer as exactly blue, exactly target, or neither.

    "Not the target" is not the same as "still blue".  A pointer that is
    missing, unreadable, malformed or naming some third release describes a
    system this lane has no model of, and guessing S0 there would promote on top
    of an unknown runtime.
    """
    if not isinstance(observation, dict) or observation.get("error") is not None:
        return "unreadable"
    if observation.get("pointer_kind") != "symlink":
        return "unbound"
    release_id = observation.get("release_id")
    if release_id == target_release_id and observation.get("repo_head") == target_head:
        return "target"
    if (
        release_id == blue_release_id
        and observation.get("repo_head") == blue_repo_head
        and observation.get("completion_status") == "complete"
    ):
        return "blue"
    return "foreign"


def _resume_phase(
    *,
    slot: str,
    pointer_promoted: bool,
    green_retired: bool,
    snapshot_rebound: bool,
) -> str | None:
    """Where in the staged resume this durable state already is.

    Derived, never chosen. The three observable facts -- which slot the ingress
    serves, whether the stable pointer already names the target release, and
    whether the transient green unit is still up -- pin the phase exactly, and a
    combination that cannot occur in a forward-only resume returns ``None`` so
    the caller fails closed rather than guessing which half is true.
    """
    if slot == GREEN_SLOT:
        if snapshot_rebound is not True:
            # The step the original cutover died on. Nothing downstream may run
            # until the cutover's own contract is fulfilled.
            return PHASE_REBIND_SNAPSHOT if not pointer_promoted else None
        return PHASE_PROMOTE_POINTER if not pointer_promoted else PHASE_SELECT_CANONICAL
    if slot == CANONICAL_SLOT:
        if not pointer_promoted:
            # Canonical routing to a release the stable pointer does not name is
            # not a phase of this resume; it is a contradiction.
            return None
        return PHASE_CLOSEOUT if green_retired else PHASE_RETIRE_GREEN
    return None


_RESUME_BINDING_V2_KEYS = frozenset(
    {
        "resume_binding_schema_version",
        "cutover_id",
        "resumed_receipt_sha256",
        "resume_phase",
        "cutover_generation",
        "snapshot_binding_state",
        "blue_release_id",
        "blue_repo_head",
        "target_head",
        "expected_head",
        "expected_selector_sha256",
        "switch_selector_sha256",
        "expected_generation",
        "switch_generation",
        "expected_slot",
        "pointer_state",
        "green_retired",
        "expected_release_id",
        "expected_runtime_binding_sha256",
        "expected_upstream_port",
        "source_identity_sha256",
        "source_evidence_time",
        "activation_observation_sha256",
        "publication_request_id",
        "registered_tool_count",
        "registered_names_sha256",
        "agent_instructions_sha256",
        "green_readiness",
        "source_snapshot_receipt_sha256",
        "source_client_declaration_sha256",
        "classified_snapshot_receipt_sha256",
        "binding_sha256",
    }
)
_LEGACY_TERMINAL_BINDING_KEYS = frozenset(
    _RESUME_BINDING_V2_KEYS
    - {
        "resume_binding_schema_version",
        "source_snapshot_receipt_sha256",
        "source_client_declaration_sha256",
        "classified_snapshot_receipt_sha256",
    }
)
_BINDING_SHA256_KEYS = frozenset(
    {
        "resumed_receipt_sha256",
        "expected_selector_sha256",
        "switch_selector_sha256",
        "expected_runtime_binding_sha256",
        "source_identity_sha256",
        "activation_observation_sha256",
        "registered_names_sha256",
        "agent_instructions_sha256",
        "source_snapshot_receipt_sha256",
        "source_client_declaration_sha256",
        "classified_snapshot_receipt_sha256",
        "binding_sha256",
    }
)


def _green_readiness_matches_resume_binding(
    readiness: Any, binding: dict[str, Any]
) -> bool:
    """Bind readiness metadata to the exact release surface being resumed."""
    if not isinstance(readiness, dict) or readiness.get("ready") is not True:
        return False
    count = binding["registered_tool_count"]
    if (
        readiness.get("release_id") != binding["expected_release_id"]
        or readiness.get("repo_head") != binding["target_head"]
        or readiness.get("complete_schema_count") != count
        or readiness.get("names_sha256") != binding["registered_names_sha256"]
        or readiness.get("agent_instructions_sha256")
        != binding["agent_instructions_sha256"]
    ):
        return False
    for optional_count in ("observed_tool_count",):
        if optional_count in readiness and readiness.get(optional_count) != count:
            return False
    for key in (
        "complete_schema_sha256",
        "schema_identity_sha256",
        "names_sha256",
        "agent_instructions_sha256",
        "expected_agent_instructions_sha256",
        "observed_agent_instructions_sha256",
        "observed_tools_artifact_sha256",
    ):
        if key in readiness and SHA256_RE.fullmatch(str(readiness.get(key))) is None:
            return False
    schema_hashes = readiness.get("schema_sha256_by_tool")
    if schema_hashes is not None:
        if (
            not isinstance(schema_hashes, dict)
            or not schema_hashes
            or any(
                not isinstance(name, str)
                or not name
                or SHA256_RE.fullmatch(str(digest)) is None
                for name, digest in schema_hashes.items()
            )
            or readiness.get("schema_identity_sha256")
            != canonical_json_sha256(schema_hashes)
        ):
            return False
    return True


def _validated_resume_binding(
    value: Any, *, allow_legacy_terminal: bool = False
) -> dict[str, Any] | None:
    """Validate the one authoritative resume-binding schema.

    The legacy branch exists only to keep already-written completed receipts as
    terminal tombstones.  It is never emitted by new code and never authorises
    an effect; v2 is the sole binding accepted for a new resume.
    """
    if not isinstance(value, dict):
        return None
    binding = dict(value)
    keys = frozenset(binding)
    is_v2 = binding.get("resume_binding_schema_version") == 2
    if is_v2:
        if keys != _RESUME_BINDING_V2_KEYS:
            return None
    elif not allow_legacy_terminal or keys != _LEGACY_TERMINAL_BINDING_KEYS:
        return None

    material = dict(binding)
    binding_sha256 = material.pop("binding_sha256", None)
    if canonical_json_sha256(material) != binding_sha256:
        return None
    for key in _BINDING_SHA256_KEYS & keys:
        if SHA256_RE.fullmatch(str(binding.get(key))) is None:
            return None
    for key in ("blue_repo_head", "target_head", "expected_head"):
        if HEAD_RE.fullmatch(str(binding.get(key) or "")) is None:
            return None
    for key in (
        "cutover_generation",
        "expected_generation",
        "switch_generation",
        "expected_upstream_port",
        "source_evidence_time",
        "registered_tool_count",
    ):
        item = binding.get(key)
        minimum = 0 if key == "source_evidence_time" else 1
        if isinstance(item, bool) or not isinstance(item, int) or item < minimum:
            return None
    if (
        CUTOVER_ID_RE.fullmatch(str(binding.get("cutover_id") or "")) is None
        or CUTOVER_ID_RE.fullmatch(
            str(binding.get("publication_request_id") or "")
        )
        is None
        or binding.get("expected_head") != binding.get("target_head")
        or not release_id_binds_head(
            binding.get("blue_release_id"), binding.get("blue_repo_head")
        )
        or not release_id_binds_head(
            binding.get("expected_release_id"), binding.get("target_head")
        )
        or type(binding.get("green_retired")) is not bool
        or binding.get("expected_slot") not in ROUTING_SLOTS
        or binding.get("expected_upstream_port")
        != ROUTING_SLOTS[binding["expected_slot"]]
        or not _green_readiness_matches_resume_binding(
            binding.get("green_readiness"), binding
        )
    ):
        return None

    phase_state = {
        PHASE_REBIND_SNAPSHOT: (
            GREEN_SLOT,
            SNAPSHOT_BINDING_PENDING,
            "blue",
            False,
        ),
        PHASE_PROMOTE_POINTER: (
            GREEN_SLOT,
            SNAPSHOT_BINDING_DONE,
            "blue",
            False,
        ),
        PHASE_SELECT_CANONICAL: (
            GREEN_SLOT,
            SNAPSHOT_BINDING_DONE,
            "target",
            False,
        ),
        PHASE_RETIRE_GREEN: (
            CANONICAL_SLOT,
            SNAPSHOT_BINDING_DONE,
            "target",
            False,
        ),
        PHASE_CLOSEOUT: (
            CANONICAL_SLOT,
            SNAPSHOT_BINDING_DONE,
            "target",
            True,
        ),
    }
    expected_state = phase_state.get(binding.get("resume_phase"))
    observed_state = (
        binding.get("expected_slot"),
        binding.get("snapshot_binding_state"),
        binding.get("pointer_state"),
        binding.get("green_retired"),
    )
    if expected_state is None or observed_state != expected_state:
        return None
    if binding["expected_slot"] == GREEN_SLOT:
        if (
            binding.get("expected_selector_sha256")
            != binding.get("switch_selector_sha256")
            or binding.get("expected_generation")
            != binding.get("switch_generation")
        ):
            return None
    elif (
        binding.get("expected_generation") != binding.get("switch_generation") + 1
        or binding.get("expected_selector_sha256")
        == binding.get("switch_selector_sha256")
    ):
        return None
    if is_v2:
        if binding["resume_phase"] == PHASE_REBIND_SNAPSHOT:
            if (
                binding["classified_snapshot_receipt_sha256"]
                != binding["source_snapshot_receipt_sha256"]
            ):
                return None
        elif (
            binding["classified_snapshot_receipt_sha256"]
            == binding["source_snapshot_receipt_sha256"]
        ):
            return None
    return binding


def _completed_lineage_binding(receipt: dict[str, Any]) -> dict[str, Any] | None:
    """The full identity a completed resume must carry to resolve a cutover.

    ``resumed_cutover_id`` alone is a name, and a name is not a proof: a receipt
    naming the right cutover but a different original receipt, release or head
    would otherwise retire a lineage it never continued.
    """
    try:
        receipt = validate_resume_receipt(receipt)
    except MidCutoverEvidenceError:
        return None
    if receipt.get("kind") != RESUME_RECEIPT_KIND:
        return None
    if (
        receipt.get("outcome") != "completed"
        or receipt.get("phase") != "completed"
        or receipt.get("recovery") is not None
    ):
        return None
    binding = _validated_resume_binding(
        receipt.get("resume_binding"), allow_legacy_terminal=True
    )
    if binding is None:
        return None
    binding_sha256 = binding["binding_sha256"]
    if receipt.get("resume_binding_sha256") != binding_sha256:
        return None
    legacy_terminal = "resume_binding_schema_version" not in binding
    if (
        receipt.get("resumed_cutover_id") != binding.get("cutover_id")
        or receipt.get("resumed_receipt_sha256")
        != binding.get("resumed_receipt_sha256")
        or receipt.get("expected_head") != binding.get("expected_head")
        or receipt.get("green_release_id") != binding.get("expected_release_id")
        or receipt.get("resume_phase") != binding.get("resume_phase")
        or receipt.get("source_identity_sha256")
        != binding.get("source_identity_sha256")
        or receipt.get("resumed_selector_sha256")
        != binding.get("expected_selector_sha256")
        or receipt.get("resumed_generation") != binding.get("expected_generation")
    ):
        return None
    # ``execution_expected_head`` was an incorrectly named duplicate in v1:
    # it carried the target head, not the revision executing the recovery.  A
    # new v2 receipt must not revive that false authority; a legacy tombstone
    # must at least agree with the target it historically represented.
    if (
        (not legacy_terminal and "execution_expected_head" in receipt)
        or (
            legacy_terminal
            and receipt.get("execution_expected_head") != binding["target_head"]
        )
    ):
        return None
    contract = receipt.get("target_contract")
    contract_identity = (
        parse_release_id(binding["expected_release_id"])
        if isinstance(contract, dict)
        else None
    )
    if (
        not isinstance(contract, dict)
        or contract.get("release_id") != binding["expected_release_id"]
        or contract.get("repo_head") != binding["target_head"]
        or contract.get("expected_tool_count") != binding["registered_tool_count"]
        or SHA256_RE.fullmatch(str(contract.get("entrypoint_contract_sha256")))
        is None
        or SHA256_RE.fullmatch(str(contract.get("decoded_contract_sha256"))) is None
        or str(contract.get("entrypoint_contract_sha256"))[:12]
        != contract_identity["contract12"]
        or contract.get("release_identity") != contract_identity
        or isinstance(contract.get("schema_version"), bool)
        or contract.get("schema_version") not in {1, 2, 3, 4}
        or contract.get("mode") not in {"module", "source"}
        or not isinstance(contract.get(contract.get("mode")), str)
        or not contract.get(contract.get("mode"))
        or contract.get("historical_validator_executed") is not True
        or contract.get("executed_release_code") is not False
        or contract.get("judged_by_checkout") is not False
    ):
        return None
    routing = receipt.get("final_routing")
    if (
        not isinstance(routing, dict)
        or routing.get("selected_slot") != CANONICAL_SLOT
        or routing.get("release_id") != binding.get("expected_release_id")
        or routing.get("repo_head") != binding.get("target_head")
        or routing.get("cutover_id") != binding.get("cutover_id")
        or routing.get("previous_selector_sha256")
        != binding.get("switch_selector_sha256")
        or routing.get("generation") != int(binding.get("switch_generation", 0)) + 1
        or routing.get("runtime_binding_sha256")
        != binding.get("expected_runtime_binding_sha256")
    ):
        return None
    starting_slot = binding.get("expected_slot")
    if starting_slot == GREEN_SLOT:
        if (
            binding.get("expected_selector_sha256")
            != binding.get("switch_selector_sha256")
            or binding.get("expected_generation")
            != binding.get("switch_generation")
        ):
            return None
    elif starting_slot == CANONICAL_SLOT:
        if (
            binding.get("expected_selector_sha256")
            != routing.get("selector_sha256")
            or binding.get("expected_generation") != routing.get("generation")
        ):
            return None
    else:
        return None
    # The cutover contract includes the snapshot rebind. A resume that finished
    # canonical promotion without it has not completed the cutover, and its
    # receipt must not retire the lineage -- a malformed or partial "completed"
    # is not terminal, it is fail-closed.
    rebind = receipt.get("snapshot_rebind")
    if not isinstance(rebind, dict) or rebind.get("rebound") is not True:
        return None
    if SHA256_RE.fullmatch(str(rebind.get("receipt_sha256"))) is None:
        return None
    if not legacy_terminal:
        if (
            rebind.get("source_snapshot_receipt_sha256")
            != binding["source_snapshot_receipt_sha256"]
            or rebind.get("source_client_declaration_sha256")
            != binding["source_client_declaration_sha256"]
            or rebind.get("source_release_id") != binding["blue_release_id"]
            or rebind.get("source_repo_head") != binding["blue_repo_head"]
            or rebind.get("target_release_id") != binding["expected_release_id"]
            or rebind.get("target_repo_head") != binding["target_head"]
            or rebind.get("classified_snapshot_receipt_sha256")
            != binding["classified_snapshot_receipt_sha256"]
            or (
                binding["resume_phase"] != PHASE_REBIND_SNAPSHOT
                and rebind.get("receipt_sha256")
                != binding["classified_snapshot_receipt_sha256"]
            )
        ):
            return None
    retirement = receipt.get("retirement")
    admission = receipt.get("admission_state")
    final = receipt.get("final_state")
    expected_green_unit = green_operator_unit(str(binding.get("cutover_id")))
    if (
        not isinstance(retirement, dict)
        or retirement.get("retired") is not True
        or retirement.get("unit") != expected_green_unit
        or not isinstance(admission, dict)
        or admission.get("state") not in {"absent", "released"}
        or (
            admission.get("state") == "released"
            and admission.get("verified_absent") is not True
        )
        or not isinstance(final, dict)
        or final.get("release_id") != binding.get("expected_release_id")
        or final.get("repo_head") != binding.get("target_head")
        or final.get("completion_status") != "complete"
        or final.get("runtime_binding_sha256")
        != binding.get("expected_runtime_binding_sha256")
        or final.get("admission_marker_state") != "absent"
    ):
        return None
    final_pointer = final.get("pointer")
    final_snapshot = final.get("snapshot")
    final_selector = final.get("selector")
    final_green = final.get("green_unit")
    if (
        not isinstance(final_pointer, dict)
        or final_pointer.get("error") is not None
        or final_pointer.get("pointer_kind") != "symlink"
        or final_pointer.get("pointer_target_release_id")
        != binding.get("expected_release_id")
        or final_pointer.get("release_id") != binding.get("expected_release_id")
        or final_pointer.get("repo_head") != binding.get("target_head")
        or final_pointer.get("completion_status") != "complete"
        or not isinstance(final_snapshot, dict)
        or final_snapshot.get("state") != SNAPSHOT_BINDING_DONE
        or final_snapshot.get("snapshot_receipt_sha256")
        != rebind.get("receipt_sha256")
        or not isinstance(final_selector, dict)
        or final_selector != routing
        or not isinstance(final_green, dict)
        or final_green.get("active") is not False
        or final_green.get("unit") != expected_green_unit
        or final_green.get("error") is not None
    ):
        return None
    if not legacy_terminal and (
        final_snapshot.get("source_snapshot_receipt_sha256")
        != binding["source_snapshot_receipt_sha256"]
        or final_snapshot.get("source_client_declaration_sha256")
        != binding["source_client_declaration_sha256"]
        or final_snapshot.get("classified_snapshot_receipt_sha256")
        != rebind.get("receipt_sha256")
    ):
        return None
    schema_changed = final_snapshot.get("schema_changed")
    transition_sha256 = final_snapshot.get("transition_sha256")
    if schema_changed is True:
        if (
            SHA256_RE.fullmatch(str(transition_sha256 or "")) is None
            or rebind.get("publication_schema_transition_sha256")
            != transition_sha256
        ):
            return None
    elif schema_changed is False:
        if (
            transition_sha256 is not None
            or rebind.get("publication_schema_transition_sha256") is not None
        ):
            return None
    else:
        return None
    readback = receipt.get("authoritative_readback")
    if (
        not isinstance(readback, dict)
        or readback.get("authoritative") is not True
        or set(readback) != {"authoritative", "selector", "ingress", "readback_sha256"}
    ):
        return None
    readback_material = dict(readback)
    readback_sha256 = readback_material.pop("readback_sha256", None)
    readback_selector = readback.get("selector")
    ingress = readback.get("ingress")
    if (
        canonical_json_sha256(readback_material) != readback_sha256
        or readback_selector != routing
        or not isinstance(ingress, dict)
        or ingress.get("selector_sha256") != routing.get("selector_sha256")
        or ingress.get("selector_generation") != routing.get("generation")
        or ingress.get("selected_slot") != CANONICAL_SLOT
        or ingress.get("upstream_port") != routing.get("upstream_port")
        or ingress.get("runtime_binding_sha256")
        != binding.get("expected_runtime_binding_sha256")
        or ingress.get("release_id") != binding.get("expected_release_id")
        or ingress.get("repo_head") != binding.get("target_head")
    ):
        return None
    return binding


def _lineage_resolved(
    receipts: Iterable[dict[str, Any]], cutover: dict[str, Any]
) -> bool:
    """True only for a completed resume bound to *this exact* cutover receipt."""
    try:
        cutover = validate_cutover_receipt(cutover)
        activation = activation_observation(cutover)
    except MidCutoverEvidenceError:
        return False
    switch = _switch_evidence(cutover)
    if switch is None:
        return False
    expected = (
        cutover.get("cutover_id"),
        cutover.get("receipt_sha256"),
        cutover.get("expected_head"),
        cutover.get("green_release_id"),
    )
    for receipt in receipts:
        binding = _completed_lineage_binding(receipt)
        if binding is None:
            continue
        identity_matches = (
            binding.get("cutover_id"),
            binding.get("resumed_receipt_sha256"),
            binding.get("target_head"),
            binding.get("expected_release_id"),
        ) == expected
        if not identity_matches:
            continue
        if (
            binding.get("cutover_generation") != cutover.get("cutover_generation")
            or binding.get("blue_release_id") != cutover.get("blue_release_id")
            or binding.get("source_identity_sha256")
            != cutover.get("source_identity_sha256")
            or binding.get("switch_generation") != switch.get("generation")
            or binding.get("switch_selector_sha256")
            != switch.get("selector_sha256")
            or binding.get("expected_runtime_binding_sha256")
            != switch.get("runtime_binding_sha256")
            or binding.get("source_evidence_time")
            != activation.get("source_evidence_time")
            or binding.get("activation_observation_sha256")
            != activation.get("observation_sha256")
            or binding.get("publication_request_id")
            != activation.get("publication_request_id")
            or binding.get("registered_names_sha256")
            != cutover.get("names_sha256")
            or binding.get("registered_tool_count")
            != cutover.get("green_readiness", {}).get("complete_schema_count")
            or binding.get("agent_instructions_sha256")
            != cutover.get("agent_instructions_sha256")
            or binding.get("green_readiness") != cutover.get("green_readiness")
        ):
            continue
        return True
    return False


def _continues_this_lineage(
    selector: dict[str, Any], open_cutovers: Sequence[dict[str, Any]]
) -> bool:
    """Does a canonical selector belong to an unresolved cutover of ours?

    A canonical selector is normally the ordinary lane's world. It is *not*
    when a resume of a still-open cutover already wrote it: refusing there
    would strand the lineage one step before the finish line.
    """
    if selector.get("selected_slot") != CANONICAL_SLOT:
        return False
    return any(
        cutover.get("cutover_id") == selector.get("cutover_id")
        for cutover in open_cutovers
    )


def resolution_for_cutover(
    receipts: Iterable[dict[str, Any]], cutover: dict[str, Any]
) -> dict[str, Any] | None:
    """Find the terminal resume receipt that retired one cutover, if any.

    Resolution must be discoverable *from the original cutover*, not only by
    scanning: an operator holding ``bgc-...`` has to be able to ask what became
    of it and get a hash-bound answer rather than an inference.
    """
    materialised = list(receipts)
    if not _lineage_resolved(materialised, cutover):
        # Exactly one notion of "resolved" exists.  A weaker, name-only lookup
        # beside the strict one would eventually disagree with it, and the
        # disagreement would be invisible until it mattered.
        return None
    for receipt in materialised:
        if _completed_lineage_binding(receipt) is None:
            continue
        if receipt.get("resumed_cutover_id") != cutover.get("cutover_id"):
            continue
        if receipt.get("resumed_receipt_sha256") != cutover.get("receipt_sha256"):
            continue
        return {
            "resume_id": receipt.get("resume_id"),
            "resume_receipt_sha256": receipt.get("receipt_sha256"),
            "resumed_cutover_id": cutover.get("cutover_id"),
            "resumed_receipt_sha256": receipt.get("resumed_receipt_sha256"),
            "expected_head": receipt.get("expected_head"),
            "final_routing": receipt.get("final_routing"),
        }
    return None


def claimed_resolution_cutover_ids(receipts: Iterable[dict[str, Any]]) -> set[str]:
    """Cutover ids that some completed resume receipt *claims* to have retired.

    A claim, not a verdict: whether the claim holds for a specific cutover is
    ``_lineage_resolved``'s answer, and only that one is used for decisions.
    """
    resolved: set[str] = set()
    for receipt in receipts:
        binding = _completed_lineage_binding(receipt)
        if binding is not None and isinstance(binding.get("cutover_id"), str):
            resolved.add(binding["cutover_id"])
    return resolved


def unresolved_post_switch_receipts(
    receipts: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    materialised = list(receipts)
    return [
        receipt
        for receipt in materialised
        if is_post_switch_outcome_unknown(receipt)
        and not _lineage_resolved(materialised, receipt)
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
    blue_observation: dict[str, Any] | None = None,
    activation_observation: dict[str, Any] | None = None,
    activation_error: str | None = None,
    pointer_observation: dict[str, Any] | None = None,
    green_unit_observation: dict[str, Any] | None = None,
    snapshot_observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Decide which recovery lane -- if any -- this durable state admits."""
    checks: dict[str, bool] = {}
    evidence: dict[str, Any] = {
        "selector_error": selector_error,
        "selector_present": selector_present,
        "unreadable_receipts": list(unreadable_receipts),
        "green_observation": green_observation,
        "blue_observation": blue_observation,
        "activation_observation": activation_observation,
        "activation_error": activation_error,
        "pointer_observation": pointer_observation,
        "green_unit_observation": green_unit_observation,
        "snapshot_observation": snapshot_observation,
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
        "previous_selector_sha256": selector.get("previous_selector_sha256"),
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
    evidence["resolution"] = next(
        (
            resolution
            for cutover in receipts
            if cutover.get("cutover_id") == selector.get("cutover_id")
            and (resolution := resolution_for_cutover(receipts, cutover)) is not None
        ),
        None,
    )

    slot = selector.get("selected_slot")
    if slot == CANONICAL_SLOT and not _continues_this_lineage(selector, open_cutovers):
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

    checks["selector_slot_is_resumable"] = slot in {GREEN_SLOT, CANONICAL_SLOT}
    checks["selector_upstream_matches_slot"] = selector.get("upstream_port") == (
        GREEN_UPSTREAM_PORT if slot == GREEN_SLOT else CANONICAL_UPSTREAM_PORT
    )
    if not checks["selector_slot_is_resumable"]:
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
            "cutover_generation": candidate.get("cutover_generation"),
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
        generation = candidate.get("cutover_generation")
        activation = activation_observation
        blue_head = (
            blue_observation.get("repo_head")
            if isinstance(blue_observation, dict)
            else None
        )
        checks["cutover_generation_valid"] = bool(
            not isinstance(generation, bool)
            and isinstance(generation, int)
            and generation >= 1
        )
        checks["activation_observation_valid"] = bool(
            activation_error is None
            and isinstance(activation, dict)
            and isinstance(activation.get("source_evidence_time"), int)
            and activation.get("state") == "publication_pending"
            and isinstance(activation.get("publication_request_id"), str)
            and SHA256_RE.fullmatch(
                str(activation.get("observation_sha256") or "")
            )
            is not None
        )
        checks["blue_release_artifact_matches_predecessor"] = bool(
            isinstance(blue_head, str)
            and HEAD_RE.fullmatch(blue_head)
            and release_id_binds_head(candidate.get("blue_release_id"), blue_head)
            and isinstance(blue_observation, dict)
            and blue_observation.get("error") is None
            and blue_observation.get("release_id")
            == candidate.get("blue_release_id")
            and blue_observation.get("completion_status") == "complete"
        )
        green_release = candidate.get("green_release_id")
        target_head = str(candidate.get("expected_head") or "")
        pointer_state = _pointer_state(
            pointer_observation,
            blue_release_id=candidate.get("blue_release_id"),
            blue_repo_head=blue_head,
            target_release_id=green_release,
            target_head=target_head,
        )
        pointer_promoted = pointer_state == "target"
        # Only a *confirmed* inactive green unit retires green.  Unknown is not
        # a quieter kind of inactive.
        green_active = (
            green_unit_observation.get("active")
            if isinstance(green_unit_observation, dict)
            else None
        )
        green_retired = green_active is False
        snapshot_state = (
            snapshot_observation.get("state")
            if isinstance(snapshot_observation, dict)
            else None
        )
        snapshot_rebound = snapshot_state == SNAPSHOT_BINDING_DONE
        phase = (
            _resume_phase(
                slot=str(slot),
                pointer_promoted=pointer_promoted,
                green_retired=green_retired,
                snapshot_rebound=snapshot_rebound,
            )
            if pointer_state in {"blue", "target"}
            and snapshot_state
            in {SNAPSHOT_BINDING_PENDING, SNAPSHOT_BINDING_DONE}
            else None
        )
        evidence["snapshot_binding_state"] = snapshot_state
        evidence["snapshot_rebound"] = snapshot_rebound
        evidence["pointer_state"] = pointer_state
        evidence["pointer_promoted"] = pointer_promoted
        evidence["green_retired"] = green_retired
        receipt_summary["resume_phase"] = phase

        checks["stable_pointer_classifiable"] = pointer_state in {"blue", "target"}
        checks["client_snapshot_classifiable"] = snapshot_state in {
            SNAPSHOT_BINDING_PENDING,
            SNAPSHOT_BINDING_DONE,
        }
        source_snapshot_receipt_sha256 = (
            snapshot_observation.get("source_snapshot_receipt_sha256")
            if isinstance(snapshot_observation, dict)
            else None
        )
        source_client_declaration_sha256 = (
            snapshot_observation.get("source_client_declaration_sha256")
            if isinstance(snapshot_observation, dict)
            else None
        )
        classified_snapshot_receipt_sha256 = (
            snapshot_observation.get("classified_snapshot_receipt_sha256")
            if isinstance(snapshot_observation, dict)
            else None
        )
        checks["snapshot_identity_digests_authentic"] = all(
            SHA256_RE.fullmatch(str(value or "")) is not None
            for value in (
                source_snapshot_receipt_sha256,
                source_client_declaration_sha256,
                classified_snapshot_receipt_sha256,
            )
        )
        checks["classified_snapshot_is_observed_snapshot"] = (
            classified_snapshot_receipt_sha256
            == snapshot_observation.get("snapshot_receipt_sha256")
            if isinstance(snapshot_observation, dict)
            else False
        )
        checks["predecessor_snapshot_identity_is_exact"] = (
            snapshot_state != SNAPSHOT_BINDING_PENDING
            or classified_snapshot_receipt_sha256
            == source_snapshot_receipt_sha256
        )
        # A cutover whose snapshot rebind never happened is not finishable by
        # promoting canonical: the contract it broke is still broken.
        checks["snapshot_rebind_precedes_promotion"] = (
            snapshot_rebound or phase == PHASE_REBIND_SNAPSHOT
        )
        checks["green_unit_state_known"] = (
            green_active is not None if slot == CANONICAL_SLOT else True
        )
        checks["resume_phase_derivable"] = phase is not None
        # The requested head names the *cutover* being continued, never the
        # revision this recovery code happens to come from.  Those are two
        # different things whenever recovery outlives the commit it repairs.
        checks["receipt_expected_head_matches_request"] = (
            candidate.get("expected_head") == expected_head
        )
        checks["selector_release_matches_receipt_green"] = (
            binding.get("release_id") == green_release
        )
        checks["selector_repo_head_matches_target_head"] = (
            binding.get("repo_head") == target_head
        )
        checks["selector_binding_digest_matches_receipt"] = selector.get(
            "runtime_binding_sha256"
        ) == switch.get("runtime_binding_sha256")
        checks["resume_not_already_terminal"] = not _lineage_resolved(
            receipts, candidate
        )

        if slot == GREEN_SLOT:
            # Untouched half of the cutover: the selector must still be exactly
            # the one the receipt recorded, generation included.
            checks["selector_generation_matches_receipt"] = selector.get(
                "generation"
            ) == switch.get("generation")
            checks["selector_sha256_matches_receipt"] = selector.get(
                "selector_sha256"
            ) == switch.get("selector_sha256")
            checks["no_newer_switch_generation_recorded"] = (
                _highest_switch_generation(receipts) <= int(switch["generation"])
            )
        else:
            # A previous resume already promoted this lineage.  The selector has
            # moved forward by exactly one generation and must still name this
            # cutover; anything else is a foreign writer, not our own progress.
            checks["canonical_selector_continues_this_cutover"] = selector.get(
                "cutover_id"
            ) == candidate.get("cutover_id")
            checks["canonical_generation_follows_receipt"] = (
                selector.get("generation") == int(switch["generation"]) + 1
            )
            checks["canonical_selector_directly_follows_switch"] = (
                selector.get("previous_selector_sha256")
                == switch.get("selector_sha256")
            )
            checks["pointer_promoted_before_canonical_selector"] = pointer_promoted

        # Green must still be serving until it is retired; once retired, the
        # remaining work is readback and lineage closeout, which needs no green.
        if phase in {PHASE_PROMOTE_POINTER, PHASE_SELECT_CANONICAL, PHASE_RETIRE_GREEN}:
            checks["green_serves_expected_release"] = bool(
                isinstance(green_observation, dict)
                and green_observation.get("release_id") == green_release
                and green_observation.get("repo_head") == target_head
                and green_observation.get("listener_present") is True
            )
        else:
            checks["green_release_artifact_matches_target"] = bool(
                isinstance(green_observation, dict)
                and green_observation.get("release_id") == green_release
                and green_observation.get("repo_head") == target_head
            )

        if all(checks.values()) and phase is not None:
            resume_binding = {
                "resume_binding_schema_version": 2,
                "cutover_id": str(candidate["cutover_id"]),
                "resumed_receipt_sha256": str(candidate["receipt_sha256"]),
                "resume_phase": phase,
                "cutover_generation": int(generation),
                "snapshot_binding_state": snapshot_state,
                "blue_release_id": candidate.get("blue_release_id"),
                "blue_repo_head": blue_head,
                "target_head": target_head,
                "expected_head": expected_head,
                "expected_selector_sha256": str(selector["selector_sha256"]),
                "switch_selector_sha256": str(switch["selector_sha256"]),
                "expected_generation": int(selector["generation"]),
                "switch_generation": int(switch["generation"]),
                "expected_slot": str(slot),
                "pointer_state": pointer_state,
                "green_retired": green_retired,
                "expected_release_id": str(green_release),
                "expected_runtime_binding_sha256": str(
                    switch["runtime_binding_sha256"]
                ),
                "expected_upstream_port": selector.get("upstream_port"),
                "source_identity_sha256": candidate.get("source_identity_sha256"),
                "source_evidence_time": activation.get("source_evidence_time"),
                "activation_observation_sha256": activation.get(
                    "observation_sha256"
                ),
                "publication_request_id": activation.get(
                    "publication_request_id"
                ),
                "registered_tool_count": candidate.get("green_readiness", {}).get(
                    "complete_schema_count"
                ),
                "registered_names_sha256": candidate.get("names_sha256"),
                "agent_instructions_sha256": candidate.get(
                    "agent_instructions_sha256"
                ),
                "green_readiness": candidate.get("green_readiness"),
                "source_snapshot_receipt_sha256": (
                    source_snapshot_receipt_sha256
                ),
                "source_client_declaration_sha256": (
                    source_client_declaration_sha256
                ),
                "classified_snapshot_receipt_sha256": (
                    classified_snapshot_receipt_sha256
                ),
            }
            resume_binding["binding_sha256"] = canonical_json_sha256(resume_binding)
            checks["resume_binding_schema_valid"] = (
                _validated_resume_binding(resume_binding) is not None
            )
            if not checks["resume_binding_schema_valid"]:
                resume_binding = None

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

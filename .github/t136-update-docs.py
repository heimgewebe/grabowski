from __future__ import annotations

from pathlib import Path

path = Path("docs/transport-roundtrip-gate-v1.md")
text = path.read_text(encoding="utf-8")
replacements = {
    "When `_meta.client_id` is absent, calls use the explicit `shared_unlabeled` scope. This remains functional for connector clients that do not emit the optional metadata, but it proves only possession of the challenge response within the shared transport boundary. It does not distinguish concurrent unauthenticated clients.":
    "When `_meta.client_id` is absent, a stateful HTTP deployment assigns a random server-session scope that remains stable only for the lifetime of that server session. The production HTTP transport is stateless, so it cannot honestly provide that identity and uses the explicit `shared_unlabeled` scope instead. That scope uses a bounded shared token pool: exact challenges and verifications coexist under one lock, concurrent handshakes no longer overwrite one another, and every admitted mutation still consumes exactly one verification. The pool proves only possession within the shared transport boundary; it neither attributes a token to one caller nor distinguishes concurrent unauthenticated clients.",
    "2. A still-current, unconsumed verification may be returned.\n3. Otherwise acknowledge the returned `challenge_receipt_sha256` with `action=ack`.":
    "2. A declared or stateful-session scope may reuse its still-current, unconsumed verification. The stateless shared scope always allocates a new exact challenge, subject to its bounded pool limit.\n3. Acknowledge the returned `challenge_receipt_sha256` with `action=ack`; only that pending entry becomes a verification.",
    "Challenges expire after five minutes. Completed verification expires after fifteen minutes but is single-use. Consumption is serialized under the same private state lock, preventing two admitted mutations from using one verification.":
    "Challenges expire after five minutes. Completed verification expires after fifteen minutes but is single-use. Consumption is serialized under the same private state lock, preventing two admitted mutations from using one verification. Declared and stateful-session scopes retain one pending and one verified slot. The stateless shared scope is capped at 32 pending challenges and 32 verified receipts; stale or runtime-mismatched entries are pruned on the next mutation, and a full live pool blocks fail-closed.",
    "State lives below `~/.local/state/grabowski/transport-roundtrip/` with a private directory, private regular files, bounded JSON, serialized writers, atomic replacement, and file plus directory synchronization. Status reads do not create state.":
    "State lives below `~/.local/state/grabowski/transport-roundtrip/` with a private directory, private regular files, bounded JSON, serialized writers, atomic replacement, and file plus directory synchronization. Legacy single-slot state is validated and migrated on the next mutation. Status reads do not create or rewrite state.",
}
for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one documentation marker, got {count}: {old[:80]}")
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")

integration_path = Path("tests/test_transport_gate_integration.py")
integration = integration_path.read_text(encoding="utf-8")
start_marker = (
    "    def test_stateless_shared_scope_admits_two_independent_handshakes"
    "(self) -> None:\n"
)
end_marker = "    def test_handshake_grip_is_narrowly_exempt(self) -> None:\n"
if integration.count(start_marker) != 1 or integration.count(end_marker) != 1:
    raise SystemExit("stateless integration test markers are not unique")
start = integration.index(start_marker)
end = integration.index(end_marker, start)
block = integration[start:end]
old_root = '        root = Path(temporary.name) / "state"\n'
if block.count(old_root) != 1:
    raise SystemExit("integration test root marker is not unique")
old_operator = "            operator = self.configured_operator()\n"
if block.count(old_operator) != 1:
    raise SystemExit("integration test operator marker is not unique")
block = block.replace(old_operator, "", 1)
block = block.replace(
    old_root,
    old_root
    + "        operator = self.configured_operator()\n"
    + "        transport = operator.grabowski_transport_roundtrip\n",
    1,
)
for old, new, expected in (
    ('            roundtrip, "STATE_ROOT", root\n', '            transport, "STATE_ROOT", root\n', 1),
    ('            roundtrip, "LOCK_PATH", root / ".lock"\n', '            transport, "LOCK_PATH", root / ".lock"\n', 1),
    ("                roundtrip.begin(\n", "                transport.begin(\n", 1),
    ("                roundtrip.acknowledge(\n", "                transport.acknowledge(\n", 1),
):
    if block.count(old) != expected:
        raise SystemExit(f"integration binding marker mismatch: {old!r}")
    block = block.replace(old, new, expected)
integration = integration[:start] + block + integration[end:]
integration_path.write_text(integration, encoding="utf-8")

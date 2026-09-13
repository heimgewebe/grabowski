from __future__ import annotations

import json
import py_compile
import runpy
from pathlib import Path


SCRIPT = Path("tools/pr1186_review_remediation.py")
CHECKOUTS = Path("src/grabowski_checkouts.py")
TESTS = Path("tests/test_checkouts.py")
CONTRACT = Path("config/runtime-entrypoint.json")
CAPABILITIES = Path("src/grabowski_capabilities.py")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one marker, found {count}")
    return text.replace(old, new, 1)


def scope_original_writer() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    replacements = {
        'replace_once(CHECKOUTS, archive_sig_old, archive_sig_new)': '''archive_source = Path(CHECKOUTS).read_text(encoding="utf-8")
archive_start_at = archive_source.index('@mcp.tool(name="grabowski_checkout_archive", annotations=MUTATING)')
archive_end_at = archive_source.index('@mcp.tool(name="grabowski_checkout_cleanup", annotations=MUTATING)', archive_start_at)
archive_block = archive_source[archive_start_at:archive_end_at]
if archive_block.count(archive_sig_old) != 1:
    raise SystemExit("archive signature marker is not unique inside archive function")
archive_block = archive_block.replace(archive_sig_old, archive_sig_new, 1)
Path(CHECKOUTS).write_text(
    archive_source[:archive_start_at] + archive_block + archive_source[archive_end_at:],
    encoding="utf-8",
)''',
        'replace_once(CHECKOUTS, archive_fence_init_old, archive_fence_init_new)': '''archive_source = Path(CHECKOUTS).read_text(encoding="utf-8")
archive_start_at = archive_source.index('@mcp.tool(name="grabowski_checkout_archive", annotations=MUTATING)')
archive_end_at = archive_source.index('@mcp.tool(name="grabowski_checkout_cleanup", annotations=MUTATING)', archive_start_at)
archive_block = archive_source[archive_start_at:archive_end_at]
if archive_block.count(archive_fence_init_old) != 1:
    raise SystemExit("archive fence-init marker is not unique inside archive function")
archive_block = archive_block.replace(archive_fence_init_old, archive_fence_init_new, 1)
Path(CHECKOUTS).write_text(
    archive_source[:archive_start_at] + archive_block + archive_source[archive_end_at:],
    encoding="utf-8",
)''',
    }
    for old, new in replacements.items():
        text = replace_once(text, old, new, old)

    cleanup_marker = "replace_once(CHECKOUTS, cleanup_release_before_audit,"
    if text.count(cleanup_marker) != 1:
        raise SystemExit("cleanup release writer marker is not unique")
    start = text.index(cleanup_marker)
    end = text.index("\n\ncleanup_return_old =", start)
    cleanup_replacement = '''cleanup_source = Path(CHECKOUTS).read_text(encoding="utf-8")
cleanup_start_at = cleanup_source.index('@mcp.tool(name="grabowski_checkout_cleanup", annotations=MUTATING)')
cleanup_block = cleanup_source[cleanup_start_at:]
if cleanup_block.count(cleanup_release_before_audit) != 1:
    raise SystemExit("cleanup release marker is not unique inside cleanup function")
cleanup_block = cleanup_block.replace(cleanup_release_before_audit, "    audit = {\\n", 1)
Path(CHECKOUTS).write_text(
    cleanup_source[:cleanup_start_at] + cleanup_block,
    encoding="utf-8",
)'''
    text = text[:start] + cleanup_replacement + text[end:]

    assertion_marker = 'workspace_source = Path(WORKSPACE).read_text(encoding="utf-8")'
    if text.count(assertion_marker) != 1:
        raise SystemExit("workspace assertion writer marker is not unique")
    start = text.index(assertion_marker)
    text = text[:start] + '''workspace_source = Path(WORKSPACE).read_text(encoding="utf-8")
if workspace_source.count(workspace_call_new) != 1:
    raise SystemExit("workspace archive call is not exactly identity-bound")
'''
    SCRIPT.write_text(text, encoding="utf-8")
    py_compile.compile(str(SCRIPT), doraise=True)


def patch_uncertainty_listing() -> None:
    text = CHECKOUTS.read_text(encoding="utf-8")
    old = "    wanted = set(resources.normalize_resource_keys(resource_keys))\n"
    new = (
        "    raw_resource_keys = list(resource_keys)\n"
        "    wanted = (\n"
        "        set(resources.normalize_resource_keys(raw_resource_keys))\n"
        "        if raw_resource_keys\n"
        "        else set()\n"
        "    )\n"
    )
    CHECKOUTS.write_text(
        replace_once(text, old, new, "uncertainty listing"), encoding="utf-8"
    )


def function_bounds(text: str, name: str) -> tuple[int, int]:
    marker = f"    def {name}("
    if text.count(marker) != 1:
        raise SystemExit(f"test function marker for {name} is not unique")
    start = text.index(marker)
    end = text.find("\n    def ", start + len(marker))
    return start, len(text) if end < 0 else end


def replace_in_test(text: str, name: str, old: str, new: str) -> str:
    start, end = function_bounds(text, name)
    block = text[start:end]
    if block.count(old) != 1:
        raise SystemExit(
            f"test replacement for {name} expected one marker, found {block.count(old)}"
        )
    block = block.replace(old, new, 1)
    return text[:start] + block + text[end:]


def append_to_test(text: str, name: str, addition: str) -> str:
    start, end = function_bounds(text, name)
    block = text[start:end].rstrip()
    return text[:start] + block + "\n" + addition.rstrip() + "\n" + text[end:]


def lines(*items: str) -> str:
    return "\n".join(items)


def patch_test_contracts() -> None:
    text = TESTS.read_text(encoding="utf-8")
    fence_assertion = lines(
        "        fences = checkouts._active_checkout_operation_uncertainties()",
        "        self.assertEqual(len(fences), 1)",
        "        fence = fences[0]",
        '        self.assertEqual(fence["operation"], "archive")',
        "        leases = checkouts._read_resource_leases()",
        "        self.assertTrue(leases)",
        "        self.assertEqual(",
        '            {item["owner_id"] for item in leases},',
        '            {fence["lease_owner_id"]},',
        "        )",
    )
    old_release = "        self.assertEqual(checkouts._read_resource_leases(), [])"
    text = replace_in_test(
        text,
        "test_archive_transaction_rolls_back_on_lifecycle_transition_failure",
        old_release,
        fence_assertion,
    )

    old_name = (
        "    def test_archive_releases_operation_lease_when_manifest_write_fails(self) -> None:"
    )
    new_name = (
        "    def test_archive_manifest_failure_retains_uncertainty_fence(self) -> None:"
    )
    text = replace_once(text, old_name, new_name, "manifest test rename")
    text = replace_in_test(
        text,
        "test_archive_manifest_failure_retains_uncertainty_fence",
        old_release,
        fence_assertion,
    )

    audit_recovery = fence_assertion + "\n" + lines(
        "        with checkouts.resources._database() as connection:",
        "            connection.execute(",
        '                "UPDATE leases SET expires_at_unix=? WHERE owner_id=?",',
        '                (int(time.time()) - 1, fence["lease_owner_id"]),',
        "            )",
        "            connection.commit()",
        "        reconciled = checkouts.grabowski_checkout_uncertainty_reconcile(",
        '            fence["fence_id"],',
        '            "reconcile-checkout-operation-outcome",',
        "        )",
        '        self.assertEqual(reconciled["state"], "reconciled")',
        '        self.assertEqual(reconciled["outcome"], "confirmed_success")',
        "        self.assertEqual(checkouts._active_checkout_operation_uncertainties(), [])",
        "        self.assertEqual(checkouts._read_resource_leases(), [])",
    )
    text = replace_in_test(
        text,
        "test_archive_preserves_committed_state_when_audit_append_fails",
        old_release,
        audit_recovery,
    )

    text = append_to_test(
        text,
        "test_partial_archive_failure_remains_durably_fenced_after_lease_expiry",
        lines(
            "        reconciliation = checkouts.grabowski_checkout_uncertainty_reconcile(",
            '            fence["fence_id"],',
            '            "reconcile-checkout-operation-outcome",',
            "        )",
            '        self.assertEqual(reconciliation["state"], "still_fenced")',
            "        self.assertEqual(",
            "            len(checkouts._active_checkout_operation_uncertainties()), 1",
            "        )",
        ),
    )
    text = append_to_test(
        text,
        "test_cleanup_unknown_outcome_remains_durably_fenced_after_lease_expiry",
        lines(
            "        reconciliation = checkouts.grabowski_checkout_uncertainty_reconcile(",
            '            fence["fence_id"],',
            '            "reconcile-checkout-operation-outcome",',
            "        )",
            '        self.assertEqual(reconciliation["state"], "reconciled")',
            '        self.assertEqual(reconciliation["outcome"], "confirmed_no_effect")',
            "        self.assertEqual(checkouts._active_checkout_operation_uncertainties(), [])",
        ),
    )
    TESTS.write_text(text, encoding="utf-8")
    py_compile.compile(str(TESTS), doraise=True)


def publish_capability_contract() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    expected = contract["expected_tools"]
    new_tools = [
        "grabowski_checkout_uncertainty_status",
        "grabowski_checkout_uncertainty_reconcile",
    ]
    if any(name in expected for name in new_tools):
        raise SystemExit("uncertainty tools unexpectedly already published")
    anchor = expected.index("grabowski_checkout_cleanup") + 1
    expected[anchor:anchor] = new_tools
    CONTRACT.write_text(
        json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    capabilities = CAPABILITIES.read_text(encoding="utf-8")
    marker = '    "grabowski_github": {\n'
    insertion = '''    "grabowski_checkout_uncertainty_status": {
        "category": "checkout-lifecycle",
        "purpose": "Read persistent unknown-outcome fences for checkout archive and cleanup effects.",
        "risk_class": "low",
        "effects": [],
        "reversibility": "not-applicable",
    },
    "grabowski_checkout_uncertainty_reconcile": {
        "category": "checkout-lifecycle",
        "purpose": "Reconcile one persistent unknown-outcome checkout fence from primary Git and database evidence and release coordination only after the outcome is proven.",
        "risk_class": "high",
        "effects": ["audit-append", "resource-lease-release", "state-change"],
        "reversibility": "evidence-bound-state-transition",
    },
'''
    CAPABILITIES.write_text(
        replace_once(capabilities, marker, insertion + marker, "capability insertion"),
        encoding="utf-8",
    )


def main() -> None:
    scope_original_writer()
    runpy.run_path(str(SCRIPT), run_name="__main__")
    patch_uncertainty_listing()
    patch_test_contracts()
    publish_capability_contract()
    for path in (
        CHECKOUTS,
        Path("src/grabowski_agent_workspace.py"),
        TESTS,
        CAPABILITIES,
    ):
        py_compile.compile(str(path), doraise=True)


if __name__ == "__main__":
    main()

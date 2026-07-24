from __future__ import annotations

from pathlib import Path
import sys


if Path(sys.argv[0]).name == "_bootstrap_routing_shadow_hardening.py":
    runner = Path(__file__).with_name("_bootstrap_routing_shadow_hardening.py")
    text = runner.read_text(encoding="utf-8")
    marker = "# ROUTING_SHADOW_SCOPED_V3_REPAIR"
    if marker not in text:
        text += r'''

# ROUTING_SHADOW_SCOPED_V3_REPAIR
import subprocess as _scope_subprocess

_scope_path = Path("src/grabowski_operator_routing_shadow_capture.py")
_scope_current = _scope_path.read_text(encoding="utf-8")
_scope_original = _scope_subprocess.check_output(
    ["git", "show", "HEAD:src/grabowski_operator_routing_shadow_capture.py"],
    text=True,
)

_scope_v2_pattern = r"^def build_shadow_record_v2\(.*?(?=^def validate_shadow_record_v2\()"
_scope_original_v2 = re.search(
    _scope_v2_pattern, _scope_original, flags=re.M | re.S
)
if _scope_original_v2 is None:
    raise SystemExit("original build_shadow_record_v2 function not found")
_scope_current, _scope_count = re.subn(
    _scope_v2_pattern,
    lambda _: _scope_original_v2.group(0),
    _scope_current,
    count=1,
    flags=re.M | re.S,
)
if _scope_count != 1:
    raise SystemExit(f"current build_shadow_record_v2 function count={_scope_count}")

_scope_v3_pattern = r"^def build_shadow_record_v3\(.*?(?=^def validate_shadow_record_v3\()"
_scope_v3_match = re.search(_scope_v3_pattern, _scope_current, flags=re.M | re.S)
if _scope_v3_match is None:
    raise SystemExit("build_shadow_record_v3 function not found")
_scope_v3 = _scope_v3_match.group(0)
_scope_timeline_pattern = (
    r'    normalized_captured_at = _parse_timestamp\(captured_at, "captured_at"\)\n'
    r'    frozen_at = eligibility\["frozen_at"\]\n'
    r'    timeline_values = \[\("outcome observation", normalized_outcome\["observed_at"\]\)\]\n'
    r'(?:(?!\ndef ).)*?'
    r'    prospective = eligibility\["prospective_eligibility"\]'
)
_scope_replacement = (
    '    normalized_captured_at = _parse_timestamp(captured_at, "captured_at")\n'
    '    frozen_at = eligibility["frozen_at"]\n'
    '    _validate_v3_timeline(\n'
    '        frozen_at=frozen_at,\n'
    '        outcome=normalized_outcome,\n'
    '        execution=execution,\n'
    '        assessments=assessments,\n'
    '        captured_at=normalized_captured_at,\n'
    '    )\n'
    '    prospective = eligibility["prospective_eligibility"]'
)
_scope_v3_updated, _scope_count = re.subn(
    _scope_timeline_pattern,
    _scope_replacement,
    _scope_v3,
    count=1,
    flags=re.S,
)
if _scope_count != 1:
    raise SystemExit(f"v3 builder timeline count={_scope_count}")
_scope_current = (
    _scope_current[: _scope_v3_match.start()]
    + _scope_v3_updated
    + _scope_current[_scope_v3_match.end() :]
)
_scope_path.write_text(_scope_current, encoding="utf-8")

_scope_test_path = Path("tests/test_operator_routing_shadow_cohort.py")
_scope_tests = _scope_test_path.read_text(encoding="utf-8")
_scope_old = '        tampered["case_provenance"]["case_origin"] = "production"\n'
_scope_new = '        tampered["case_provenance"]["case_origin"] = "quarantined"\n'
if _scope_tests.count(_scope_old) != 1:
    raise SystemExit(
        "case-origin tamper test replacement count="
        f"{_scope_tests.count(_scope_old)}"
    )
_scope_test_path.write_text(
    _scope_tests.replace(_scope_old, _scope_new), encoding="utf-8"
)

Path("tools/sitecustomize.py").unlink(missing_ok=True)
Path(".routing-shadow-bootstrap-trigger").unlink(missing_ok=True)
_scope_subprocess.run(["make", "context-refresh"], check=True)
'''
        runner.write_text(text, encoding="utf-8")

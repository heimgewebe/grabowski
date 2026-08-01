from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests" / "test_reposkop_context.py"

text = TESTS.read_text(encoding="utf-8")
text = text.replace(
    '        self.assertNotIn("report_sha256", receipt)\n',
    '        self.assertEqual(receipt["report_sha256"], first["report"]["report_sha256"])\n'
    '        self.assertEqual(\n'
    '            receipt["observation_sha256"],\n'
    '            first["report"]["observation"]["observation_sha256"],\n'
    '        )\n'
    '        self.assertEqual(\n'
    '            receipt["repository_identity_sha256"],\n'
    '            first["report"]["observation"]["identities"][\n'
    '                "repository_identity_sha256"\n'
    '            ],\n'
    '        )\n'
    '        self.assertEqual(\n'
    '            receipt["checkout_identity_sha256"],\n'
    '            first["report"]["observation"]["identities"][\n'
    '                "checkout_identity_sha256"\n'
    '            ],\n'
    '        )\n'
)
text = text.replace(
    '                self.report(observation_schema_version=2),\n',
    '                self.report(observation_schema_version=3),\n',
)
TESTS.write_text(text, encoding="utf-8")

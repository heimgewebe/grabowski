#!/usr/bin/env python3
from pathlib import Path

path = Path("tools/pr514_review_fix.py")
text = path.read_text(encoding="utf-8")
start = text.index("    create_call = (\n")
end = text.index("    clean_call = (\n", start)
replacement = '''    create_function_at = source.index(
        "_create_quarantine_locked(",
        source.index("quarantine_receipt = _build_quarantine_receipt("),
    )
    inventory_line = source.index("inventory=inventory,", create_function_at)
    inventory_line_end = source.index("\\n", inventory_line) + 1
    inventory_indent = source[source.rfind("\\n", 0, inventory_line) + 1 : inventory_line]
    source = (
        source[:inventory_line_end]
        + inventory_indent
        + "receipt=quarantine_receipt,\\n"
        + source[inventory_line_end:]
    )

'''
path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")

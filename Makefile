.RECIPEPREFIX := >

PYTHON ?= python3

.PHONY: validate syntax test policy secrets

validate: syntax test policy secrets

syntax:
>$(PYTHON) -m py_compile src/grabowski_mcp.py

test:
>$(PYTHON) -m unittest discover -s tests -v

policy:
>$(PYTHON) tools/validate_access_policy.py

secrets:
>$(PYTHON) tools/check_no_secrets.py

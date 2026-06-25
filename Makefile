.RECIPEPREFIX := >

PYTHON ?= python3

.PHONY: validate syntax test policy runtime-lock secrets deploy-check deploy

validate: syntax test policy runtime-lock secrets

syntax:
>$(PYTHON) -m py_compile src/grabowski_mcp.py
>$(PYTHON) -m py_compile tools/deploy_runtime.py
>$(PYTHON) -m py_compile tools/validate_runtime_lock.py

test:
>$(PYTHON) -m unittest discover -s tests -v

policy:
>$(PYTHON) tools/validate_access_policy.py

runtime-lock:
>$(PYTHON) tools/validate_runtime_lock.py

secrets:
>$(PYTHON) tools/check_no_secrets.py

deploy-check:
>$(PYTHON) tools/deploy_runtime.py --check

deploy:
>$(PYTHON) tools/deploy_runtime.py --apply

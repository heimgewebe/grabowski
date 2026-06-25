.RECIPEPREFIX := >

PYTHON ?= python3
UV ?= uv
UV_RUNTIME_LOCK_VERSION := 0.9.18

.PHONY: validate syntax test policy runtime-lock runtime-lock-refresh secrets deploy-check deploy

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

runtime-lock-refresh:
>test "$$($(UV) --version)" = "uv $(UV_RUNTIME_LOCK_VERSION)"
>$(UV) pip compile requirements/runtime.in --python-version 3.10 --python-platform x86_64-unknown-linux-gnu --generate-hashes --output-file requirements/runtime.lock.txt

secrets:
>$(PYTHON) tools/check_no_secrets.py

deploy-check:
>$(PYTHON) tools/deploy_runtime.py --check

deploy:
>$(PYTHON) tools/deploy_runtime.py --apply

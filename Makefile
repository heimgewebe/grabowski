.RECIPEPREFIX := >

PYTHON ?= python3
UV ?= uv
UV_RUNTIME_LOCK_VERSION := 0.9.18
DEPLOY_TOOLING_VENV ?= build/deploy-tooling/.venv
DEPLOY_TOOL_PYTHON := $(DEPLOY_TOOLING_VENV)/bin/python

.PHONY: validate syntax test policy runtime-lock runtime-lock-refresh secrets deploy-tooling deploy-tooling-check deploy-tooling-lock-refresh deploy-check deploy

validate: syntax test policy runtime-lock deploy-tooling-check secrets

syntax:
>$(PYTHON) -m py_compile src/grabowski_mcp.py
>$(PYTHON) -m py_compile src/grabowski_operator.py
>$(PYTHON) -m py_compile tools/deploy_runtime.py
>$(PYTHON) -m py_compile tools/watchdog_runtime.py
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

deploy-tooling:
>$(PYTHON) -m venv --clear $(DEPLOY_TOOLING_VENV)
>PIP_CONFIG_FILE=/dev/null PIP_NO_INPUT=1 PYTHONNOUSERSITE=1 $(DEPLOY_TOOL_PYTHON) -m pip install --isolated --disable-pip-version-check --no-input --require-hashes --no-deps --only-binary=:all: --index-url https://pypi.org/simple -r requirements/deploy-tooling.lock.txt

deploy-tooling-check: deploy-tooling
>$(DEPLOY_TOOL_PYTHON) -c 'import yaml; raise SystemExit(0 if yaml.__version__ == "6.0.3" else 1)'
>PIP_CONFIG_FILE=/dev/null PYTHONNOUSERSITE=1 $(DEPLOY_TOOL_PYTHON) tools/verify_tooling_venv.py

deploy-tooling-lock-refresh:
>test "$$($(UV) --version)" = "uv $(UV_RUNTIME_LOCK_VERSION)"
>$(UV) pip compile requirements/deploy-tooling.in --python-version 3.10 --python-platform x86_64-unknown-linux-gnu --generate-hashes --output-file requirements/deploy-tooling.lock.txt

secrets:
>$(PYTHON) tools/check_no_secrets.py

deploy-check: deploy-tooling
>$(DEPLOY_TOOL_PYTHON) tools/deploy_runtime.py --check

deploy: deploy-tooling
>$(DEPLOY_TOOL_PYTHON) tools/deploy_runtime.py --apply
.RECIPEPREFIX := >

PYTHON ?= python3
UV ?= uv
UV_RUNTIME_LOCK_VERSION := 0.9.18
DEPLOY_TOOLING_VENV ?= build/deploy-tooling/.venv
DEPLOY_TOOL_PYTHON := $(DEPLOY_TOOLING_VENV)/bin/python

.PHONY: validate syntax test policy context-refresh context-check profiles-refresh profiles-check runtime-lock runtime-lock-refresh secrets deploy-tooling deploy-tooling-check deploy-tooling-lock-refresh deploy-check deploy-preflight deploy

validate: syntax test policy context-check profiles-check runtime-lock deploy-tooling-check secrets

syntax:
>$(PYTHON) -m py_compile src/grabowski_mcp.py
>$(PYTHON) -m py_compile src/grabowski_operator.py
>$(PYTHON) -m py_compile src/grabowski_capabilities.py
>$(PYTHON) -m py_compile src/grabowski_runtime_extensions.py
>$(PYTHON) -m py_compile src/grabowski_read_surface.py
>$(PYTHON) -m py_compile src/grabowski_self_deploy.py
>$(PYTHON) -m py_compile src/grabowski_runtime.py
>$(PYTHON) -m py_compile src/grabowski_fleet.py
>$(PYTHON) -m py_compile src/grabowski_artifacts.py
>$(PYTHON) -m py_compile src/grabowski_operations.py
>$(PYTHON) -m py_compile src/grabowski_privileged.py
>$(PYTHON) -m py_compile src/grabowski_privileged_status_core.py
>$(PYTHON) -m py_compile src/grabowski_privileged_broker.py
>$(PYTHON) -m py_compile src/grabowski_recovery.py
>$(PYTHON) -m py_compile src/grabowski_tasks.py
>$(PYTHON) -m py_compile src/grabowski_resources.py
>$(PYTHON) -m py_compile src/grabowski_checkouts.py
>$(PYTHON) -m py_compile src/grabowski_task_reconcile.py
>$(PYTHON) -m py_compile src/grabowski_workers.py
>$(PYTHON) -m py_compile src/grabowski_worker_process.py
>$(PYTHON) -m py_compile tools/build_operator_context.py
>$(PYTHON) -m py_compile tools/build_publication_profiles.py
>$(PYTHON) -m py_compile tools/run_scheduled_deploy.py
>$(PYTHON) -m py_compile tools/deploy_runtime.py
>$(PYTHON) -m py_compile tools/deploy_runtime_dual.py
>$(PYTHON) -m py_compile tools/watchdog_runtime.py
>$(PYTHON) -m py_compile tools/validate_runtime_lock.py
>$(PYTHON) -m py_compile tools/build_local_evidence.py
>$(PYTHON) -m py_compile tools/connector_probe.py
>$(PYTHON) -m py_compile tools/grabowski_fleet_cli.py
>$(PYTHON) -m py_compile tools/grabowski_recipe_cli.py
>$(PYTHON) -m py_compile tools/grabowski_privileged_status.py
>$(PYTHON) -m py_compile tools/grabowski_privileged_broker.py
>$(PYTHON) -m py_compile tools/grabowski_privileged_request.py

test:
>set -eu; test_home="$(CURDIR)/build/test-home"; rm -rf "$$test_home"; trap 'rm -rf "$$test_home"' EXIT; install -d -m 700 "$$test_home/.config/grabowski"; install -m 600 config/access.home-wide-operator.example.json "$$test_home/.config/grabowski/access.json"; HOME="$$test_home" $(PYTHON) -m unittest discover -s tests -v

policy:
>$(PYTHON) tools/validate_access_policy.py

context-refresh:
>$(PYTHON) tools/build_operator_context.py --write
>$(PYTHON) tools/build_publication_profiles.py --write

context-check:
>$(PYTHON) tools/build_operator_context.py --check

profiles-refresh:
>$(PYTHON) tools/build_publication_profiles.py --write

profiles-check:
>$(PYTHON) tools/build_publication_profiles.py --check

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

deploy-check: context-check deploy-tooling
>$(DEPLOY_TOOL_PYTHON) tools/deploy_runtime_dual.py --check

deploy-preflight: context-check deploy-tooling
>$(DEPLOY_TOOL_PYTHON) tools/deploy_runtime_dual.py --preflight

deploy: context-check deploy-tooling
>$(DEPLOY_TOOL_PYTHON) tools/deploy_runtime_dual.py --apply

.RECIPEPREFIX := >

PYTHON ?= python3
UV ?= uv
UV_RUNTIME_LOCK_VERSION := 0.9.18
DEPLOY_TOOLING_VENV ?= build/deploy-tooling/.venv
DEPLOY_TOOL_PYTHON := $(DEPLOY_TOOLING_VENV)/bin/python
GRABOWSKI_RUNTIME_PYTHON ?= $(HOME)/.local/share/grabowski-mcp/.venv/bin/python
RETENTION_MIN_AGE_SECONDS ?= 86400
RETENTION_MAX_ARCHIVE_JOBS ?= 128

.PHONY: validate syntax test policy context-refresh context-check profiles-refresh profiles-check runtime-lock runtime-lock-refresh secrets deploy-tooling deploy-tooling-check deploy-tooling-lock-refresh deploy-check deploy-preflight deploy-apply deploy-direct deploy runtime-retention-check runtime-retention-apply runtime-legacy-status

validate: syntax test policy context-check profiles-check runtime-lock deploy-tooling-check secrets

syntax:
>$(PYTHON) -m py_compile tools/operator_patch_relay.py
>$(PYTHON) -m py_compile $(wildcard src/*.py) $(wildcard tools/*.py)

test:
>set -eu; install -d -m 700 "$(CURDIR)/build"; test_home="$$(mktemp -d "$(CURDIR)/build/test-home.XXXXXX")"; trap 'rm -rf "$$test_home"' EXIT; install -d -m 700 "$$test_home/.config/grabowski"; install -m 600 config/access.home-wide-operator.example.json "$$test_home/.config/grabowski/access.json"; HOME="$$test_home" $(PYTHON) -m unittest discover -s tests -v

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

deploy-apply: context-check deploy-tooling
>$(DEPLOY_TOOL_PYTHON) tools/deploy_runtime_dual.py --apply

deploy-direct: deploy-apply

deploy: context-check
>test -x "$(GRABOWSKI_RUNTIME_PYTHON)"
>set -eu; expected_head="$$(git rev-parse --verify HEAD)"; "$(GRABOWSKI_RUNTIME_PYTHON)" tools/schedule_runtime_deploy.py --expected-head "$$expected_head" --delay-seconds 8

runtime-retention-check: context-check
>test -x "$(GRABOWSKI_RUNTIME_PYTHON)"
>"$(GRABOWSKI_RUNTIME_PYTHON)" tools/maintain_runtime_state.py --minimum-job-age-seconds "$(RETENTION_MIN_AGE_SECONDS)" --max-archive-jobs "$(RETENTION_MAX_ARCHIVE_JOBS)"

runtime-retention-apply: context-check
>test -x "$(GRABOWSKI_RUNTIME_PYTHON)"
>test -n "$(RETENTION_PLAN_SHA256)"
>"$(GRABOWSKI_RUNTIME_PYTHON)" tools/maintain_runtime_state.py --minimum-job-age-seconds "$(RETENTION_MIN_AGE_SECONDS)" --max-archive-jobs "$(RETENTION_MAX_ARCHIVE_JOBS)" --apply --expected-plan-sha256 "$(RETENTION_PLAN_SHA256)"

runtime-legacy-status: context-check
>test -x "$(GRABOWSKI_RUNTIME_PYTHON)"
>"$(GRABOWSKI_RUNTIME_PYTHON)" tools/maintain_runtime_state.py --legacy-archive-status

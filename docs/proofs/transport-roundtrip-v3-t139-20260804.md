# T139 caller-session transport verification proof

## Binding

- Bureau task: `GRABOWSKI-OPERATOR-SURFACE-V1-T139`
- Baseline deployed Grabowski revision: `ae8c8a97209cb3d4e5a62bc47b8b57c23d85ee48`
- Baseline observation date: 2026-08-04
- Candidate revision: the Git commit containing this proof
- Focused verification task: `cbe83eaa40aa4ee0b796f2e2`
- Focused lifecycle receipt: `29f87244e179a4fab11f9dd5efcc4a46922a4be3425defa95cc745d7fb1caf1a`

## Baseline

The deployed runtime reported `client_scope_kind=shared_unlabeled` and
`pool_mode=bounded-shared-token-pool`. Under that model, two logically distinct
callers without a transport-provided identity shared one authorization scope.
An exact mutation verification created by one logical caller could therefore be
consumed by another logical caller that presented the same tool and arguments.

## Candidate

The candidate derives a private `caller_session` scope from:

- the server-process instance nonce;
- the FastMCP client identifier when available;
- the FastMCP session identity;
- an opaque weak-reference-bound random token when FastMCP exposes only the
  session object.

Every verification is additionally bound to the integrity-valid runtime
contract, exact tool name, canonical argument hash, expiry and single use.
Legacy state that may contain global or unbound authority is discarded rather
than migrated as authority.

## Measured regression comparison

Method: deterministic state-engine regression test
`test_regression_shared_scope_baseline_vs_caller_session_isolation`.

| Metric | Baseline shared scope | Candidate caller-session scope |
| --- | ---: | ---: |
| Foreign logical caller admitted | 1 / 1 | 0 / 1 |
| Owning caller admitted | not separately isolated | 1 / 1 |

The candidate removes the reproduced cross-caller authorization while
preserving the intended owner's exact single-use mutation.

## Verification coverage

The focused suite ran 51 tests and passed 51 tests in 0.163 seconds using the
Python environment of the installed Grabowski release. Coverage includes:

- caller/session/server-instance binding;
- actual FastMCP `Context` compatibility (`session` exists, `session_id` does
  not in the installed version);
- Python object-ID reuse resistance through identity-checked weak references;
- exact tool and canonical argument binding;
- concurrent distinct exact mutations inside one session;
- atomic acknowledge and consume under the existing file lock;
- read-only tools bypassing the mutation gate;
- replay, expiry, runtime drift, foreign scope and server restart;
- fail-closed behavior when the effect fails after admission;
- fail-closed state-schema migration.

## Limits

This proof is deterministic and revision-bound. It establishes the admission
semantics and concurrent state behavior, not a production network load test
with two external MCP clients. Full repository validation and CI remain the
publication gates for the candidate revision.

# ntfy Out-of-Band Alerting v1

## Scope

The dispatcher exposes one canonical, redacted notification rendering contract for:

- `blocked_operation`
- `recovery`
- `service_failure`
- `long_run_completed`
- `owner_decision`

Every outbound request carries `X-Grabowski-Event-Class` and `X-Grabowski-Correlation-Id`. Delivery remains fail-closed: the durable outbox receipt is acknowledged only after a 2xx ntfy response.

## Boundary

This change establishes dispatch-format parity for all five event classes. It does not by itself prove that every producing subsystem emits those classes, nor does a mocked HTTP test prove reception on an owner device. A live delivery probe and producer bindings remain required for complete end-to-end attestation.

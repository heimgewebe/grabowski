# ntfy alert outbox v1

## Purpose and boundary

The general ntfy alert outbox carries a small, bounded set of operator-facing
events:

- `blocked_operation`
- `recovery`
- `service_failure`
- `long_run_completed`
- `owner_decision`

It is separate from the terminal job-notification outbox. A
`grabowski_job_notification` and its acknowledgement keep their existing
meaning and storage. An alert receipt never reinterprets, replaces, or
acknowledges a terminal job receipt.

The default alert root is
`~/.local/state/grabowski/alert-outbox`; tests may set the absolute
`GRABOWSKI_ALERT_OUTBOX_ROOT`.

## Receipt identity and publication

`correlation_id` is the first 32 hexadecimal characters of a SHA-256 over the
versioned producer, subject, and caller-supplied correlation identity.
`alert_id` is the first 32 hexadecimal characters of a separate SHA-256 over
the versioned event class, producer, correlation ID, and deduplication
identity. The source identity values are bounded before hashing and are not
stored.

One `<alert_id>.json` file is the queued alert receipt. One
`<alert_id>.ack.json` file is its delivery acknowledgement. Both are private
mode-0600 regular files under an owner-controlled mode-0700 directory. They
are published create-only through the repository private-I/O primitive, which
uses `O_EXCL` temporary creation, an atomic create-only link, fsync, and
post-publication inode validation. Existing receipts are never replaced,
moved, or deleted.

Repeating the same event identity and material reads back the winner and is an
idempotent replay. Reusing an identity with different alert material is a
conflict. Receipt self-hashes bind the canonical JSON material; acknowledgement
hashes additionally bind the alert receipt and file SHA-256.

## Data minimization

The receipt stores only:

- versioned kind and schema;
- deterministic alert and correlation IDs;
- one supported event class;
- bounded lowercase producer and subject codes;
- at most eight sorted fields, each at most 160 UTF-8 bytes;
- fixed ntfy delivery metadata, timestamp, hashes, and non-claims.

Identity source strings are never stored. Field values accept a deliberately
narrow character set, collapse whitespace, reject controls and unsafe
punctuation, and redact common password, secret, token, API-key,
authorization, and bearer forms before publication. Producers pass only
transition type, state, attempt, or exception-class metadata; objectives,
commands, evidence text, blockers, paths, credentials, and secret material are
not copied into alerts.

Every queued receipt explicitly does **not** establish:

- external push delivery;
- that the user has seen the alert;
- success of the primary operation;
- authorization to retry or mutate;
- root cause.

An HTTP acknowledgement still does not establish user visibility, primary
operation success, or mutation authority.

## Delivery

After create-only publication, `enqueue_and_schedule` starts a transient
user-systemd unit named from the deterministic alert ID. It executes the
existing installed entrypoint:

```text
python -I -m grabowski_ntfy_dispatch
```

Scheduling success means only that `systemd-run` returned zero; it does not
claim the dispatcher started or that ntfy accepted a request.

The dispatcher holds its existing private process lock, loads the existing
private topic, and processes terminal job notifications and general alerts as
independent queues. Alert presentation is derived from the fixed event class
and bounded receipt fields. No caller-supplied URL, title, header, tag, topic,
or arbitrary message is accepted.

The dispatcher writes an alert acknowledgement only after the publisher
returns HTTP 2xx. Transport exceptions and non-2xx responses leave the alert
queued. Invalid alert receipts block alert dispatch fail-closed. This does not
change the existing terminal notification acknowledgement contract.

The runtime-entrypoint manifest is intentionally outside this change. The
integration therefore loads the packaged alert module through an optional
boundary. If an older deployed source set does not contain the module,
terminal-job dispatch continues and reports `alert_outbox_unavailable` with an
explicit `alert_outbox_empty` non-claim; producer transitions remain primary
and do not fail during a staggered package rollout.

## Producer adapters

The v1 adapters are intentionally narrow:

- `grabowski_task_attention.record_decision` emits `owner_decision` only after
  the create-only decision winner has been validated.
- `grabowski_operator_obligation.close_obligation` emits
  `blocked_operation` for a validated blocked close and
  `long_run_completed` for a validated completed close. Delegation and open
  records do not emit.
- `grabowski_recovery.grabowski_recovery_server_probe` emits `recovery` after
  a successful server probe or eligible test-kill-switch recovery, and
  `service_failure` when either primary recovery operation raises.

The immutable primary receipt digest is the alert deduplication identity where
one exists. Recovery failures use the exception class and operation/target
correlation, so repeated observation of the same failure class deduplicates.

Each adapter catches alert publication and scheduling exceptions. Therefore an
alert-path failure cannot turn a successful primary transition into failure,
hide a primary exception, or change the primary return value. The alert path
itself remains fail-closed: it records no scheduling or delivery claim without
the corresponding observed result, and no acknowledgement before HTTP 2xx.

## Recovery and rollback

Queued alerts are retried by invoking the same dispatcher entrypoint. Because
receipts and acknowledgements are append-only, recovery is inspection and
retry rather than receipt rewriting. Invalid state must be repaired through an
operator-reviewed recovery path; the dispatcher does not skip an invalid
receipt and claim complete alert-outbox success.

Rollback of this feature removes the producer adapters and alert dispatcher
pass, then removes the module from packaging. Existing alert files may remain
as inert append-only evidence. They must not be relabelled as terminal job
notifications or deleted as part of code rollback.

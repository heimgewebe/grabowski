# Plain-LLM external review

Status: active, advisory only

## Purpose

`tools/external_review_plain.py` asks an account-backed Gemini or Grok
command-line client for one independent review without giving the model a
repository checkout or an implementation role. It consumes the immutable
external-review packet produced by `tools/pr_review_gate.py`, transmits the
packet prompt plus the exact hash-bound diff, and writes schema-valid optional
`external_review` evidence.

This path is deliberately distinct from coding-agent review:

- one turn only and no conversation continuation;
- an empty temporary working directory instead of the target repository;
- the prompt forbids tool use, browsing, repository inspection, and mutation;
- Gemini runs in sandboxed plan mode with slash expansion disabled; this
  constrains tools but does not prove that the provider exposed no tool surface;
- Grok receives an empty tool set in plan mode and disables web search, memory,
  and subagents through explicit CLI flags;
- a fixed environment allowlist passes only account-client configuration,
  locale, network, certificate, and temporary-directory settings; API keys,
  Git context, DBus, display, runtime-directory, and SSH-agent variables never
  reach the provider process; inherited variable names and passed values must
  be free of surrogate-escaped non-UTF-8 text before artifact creation;
  inherited `HOME` and explicit XDG account roots must be absolute,
  owner-controlled, non-symlink directories with trusted full ancestry and
  stable inode identity rechecked immediately before launch;
- stdin is `/dev/null`, each provider has a new process group, and stdout and
  stderr are byte-bounded while they are read and decoded as strict UTF-8;
  malformed output is rejected, while timeout or overflow terminates the whole
  process group;
- the packet manifest, diff, and packet prompt are opened nonblocking and
  without following a final symlink, must remain the same single-link regular
  inode throughout a bounded read, and retain their manifest-directory
  containment; a raced FIFO, replacement, mutation, or oversized input fails
  before provider launch;
- the executable resolves to an owner-controlled, executable regular file that
  is not group- or world-writable; every resolved ancestor must be owned by the
  current user or root and may be group- or world-writable only with sticky-bit
  replacement protection; Grok additionally requires the canonical native
  binary under the private `~/.grok/bin` directory rather than an npm or Node
  trampoline;
- the selected temporary base is validated before workspace creation; the
  private workspace has mode `0700`, a trusted full ancestry, and a stable inode
  identity checked immediately before and after the provider turn; readback
  also opens Grok's prompt file nonblocking, inode-matches and bounds it to the
  expected prompt size before comparing its contents and mode; cleanup holds
  the original directory descriptor so a renamed workspace cannot strand the
  prompt-bearing original inode;
- the exact transmitted prompt, raw stdout, argv digest, and evidence are
  create-only artifacts; missing artifact directories are created with mode
  `0700`, their full ancestry is validated against replacement by another local
  user, and every newly created directory entry is synced through its verified
  containing directory before local text artifacts are durably created with
  mode `0600`; directories created by an attempt are removed again if that
  attempt fails before a valid review is retained.

The external result remains diagnostic. It never replaces, satisfies, or
shortens the head/diff-bound Grabowski self-review loop.

## Inputs

Generate an external-review packet for the current pull-request head with
`tools/pr_review_gate.py`. The packet manifest must bind:

- repository and pull-request number;
- exact 40-character head SHA;
- exact diff and packet-prompt SHA-256 values;
- diff and prompt files contained inside the packet directory.

The adapter adds a random 128-bit execution nonce and hashes the full transmitted
prompt. When the evidence is later supplied through `--external-review-evidence`,
the central review gate reconstructs the packet prompt and full nonce-bound
prompt independently from the current PR identity and diff. A copied or stale
prompt hash therefore cannot become valid merely because the adapter asserts it.
The gate also binds the reconstructed prompt's exact UTF-8 byte count, provider,
requested model label, source identifier, transport, tool policy, verdict,
finding count, and response hashes. It also recomputes a canonical digest over
`verdict`, `finding_count`, and `findings`, so retained structured review data
cannot be edited independently of the digest checked by the gate. The gate also
opens the retained raw response beneath the evidence artifact directory without
following symlinks, bounds and identity-checks the private file while reading
it, verifies its stdout hash, parses it with the adapter's strict parser, and
requires the parsed raw response to equal those structured evidence fields. The
adapter requires custom raw-review and transmitted-prompt outputs to stay below
that same directory before it invokes the provider.

Any path escape, stale digest, malformed identity, oversized prompt or provider
output, colliding or existing output artifact, provider failure, empty response,
workspace mutation, or malformed review JSON fails before evidence publication.
Before a structurally valid provider response exists, the adapter removes only
artifacts that this invocation created with `O_EXCL`; pre-existing paths are
never replaced or deleted. If final evidence publication fails after a valid
response, the create-only transmitted prompt and raw response are preserved as
forensic artifacts and a retry must use fresh output paths.

## Gemini

```bash
python3 tools/external_review_plain.py \
  --manifest .review-packets/pr-123/manifest.json \
  --output .review-audits/pr-123-gemini-external.json \
  --provider gemini \
  --model "Gemini 3.1 Pro (Low)"
```

The default executable is `agy`. `--executable gemini` remains available for
the compatibility alias installed on the Heim-PC.

## Grok

```bash
python3 tools/external_review_plain.py \
  --manifest .review-packets/pr-123/manifest.json \
  --output .review-audits/pr-123-grok-external.json \
  --provider grok \
  --model grok-4.5
```

The default executable name is `grok`, but it must resolve to the canonical
owner-controlled native binary behind `~/.grok/bin/grok`. Wrappers elsewhere on
`PATH`, including npm or Node trampolines, fail closed.

The adapter does not attest the signed-in account tier, remaining subscription
quota, absence of provider-side overage, or the provider's resolved model
identity. The evidence records the requested model label conservatively as
`requested_not_provider_attested`. Automatic callers must obtain cost and quota
truth from Grabowski's verified route and quota-pool preflight; direct callers
must stop when the account route is not already known to be free or included in
the subscription. The fixed environment allowlist prevents an accidental API-key
fallback but is not a subscription entitlement or no-overage proof.

Grok receives the full prompt through a short-lived `0600` file inside the empty
temporary working directory and uses `--verbatim --prompt-file`; the file is
removed with that directory after the client exits. Its evidence therefore records
`transport: prompt_file`, `ephemeral_prompt_file: true`, and
`prompt_argument_exposure: false`. Gemini has no documented prompt-file option in
the installed account CLI and still receives the prompt through `--print`; its
evidence records `transport: argv`, `ephemeral_prompt_file: false`, and
`prompt_argument_exposure: true`. Gemini prompts are capped at 120,000 UTF-8
bytes so the single prompt argument remains below Linux's per-argument exec
limit, even when the generic prompt budget is larger. Another process running as
the same local user may be able to observe Gemini command arguments while the
client is active. A future Gemini stdin, file, or browser transport should be
preferred only if it preserves the same independent prompt and response binding.

No model request is performed by repository tests. Tests replace the provider
process and validate argv, environment isolation, prompt reconstruction,
evidence shape, executable identity, bounded process output, workspace readback,
immutable output behavior, and failure handling.

## Evidence and triage

A clean `PASS` with zero findings is recorded as already triaged. Any
`NEEDS_CHANGE` or `BLOCK` result remains untriaged. Raw provider findings stay
inside the individual review object and acquire no authority until Grabowski
checks each finding against the current head and records the disposition.

The evidence records:

- provider, requested model label, transport, and tool policy;
- packet prompt, transmitted prompt, and nonce;
- exact diff hash and pull-request head;
- transmitted prompt and raw response paths;
- argv, stdout, stderr, raw-review, and canonical parsed-review hashes;
- removed billable API-key and inherited Git-context variable names;
- the exact passed environment-key names (never values), removed session-variable
  names, Null-stdin, process-group and output-limit policy, and workspace
  readback;
- whether the working directory was isolated and whether local repository
  context, web search, or memory was supplied;
- the explicit absence of adapter-level quota and provider-model attestation.

The evidence declares `review_gate_authority: none_advisory_only`. Even valid
Plain-LLM evidence is an optional diagnostic input: it never satisfies, replaces,
or shortens the required head/diff-bound self-review and merge checks. The gate
revalidates that non-authority declaration and ignores malformed optional
evidence with a warning.

The legacy `tools/external_review_antigravity.py` command remains as a
Gemini-only compatibility wrapper and now emits the same strict evidence.

## Browser path

Normal web-chat automation is not part of this implementation. It requires a
separate browser contract for navigation, model selection, prompt submission,
complete-response readback, transcript hashing, and session/provider
attestation. Browser chat should be added only when it provides a model or
subscription surface that the account CLI cannot reach, or when it materially
improves prompt confidentiality without weakening auditability.

The account CLI necessarily reads its own local authentication material. The
adapter does not copy browser profiles or secrets into the prompt, evidence, or
logs, and it withholds GUI/session-bus variables so the client cannot silently
open an interactive browser through the inherited session. This boundary does
not defend against a compromised provider executable or other hostile code
already running as the same local user; executable ownership/mode checks and the
documented account-client trust boundary remain required.

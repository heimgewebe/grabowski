# Merge Delivery v1

Status: implementation contract
Date: 2026-07-24

## Purpose

A nontrivial pull request must not be merged merely because its diff artifact exists. Before merge dispatch, Grabowski requires a durable receipt that the exact downloadable `git-diff.v1` artifact was exposed through a user-visible channel.

The receipt binds one repository, pull request, base commit, head commit and complete diff SHA-256. The same values must also be bound by review evidence, CI evidence, the Captain execution intent and the atomic merge guard.

## Required sequence

1. Read the current pull-request head, base and complete GitHub diff.
2. Publish the complete diff through `grabowski_text_artifact_publish` with profile `git-diff.v1`.
3. Transfer the real UTF-8 `.txt` file into the user-visible download surface.
4. Expose the concrete download link to the user.
5. Only after that visible delivery, call `grabowski_merge_delivery_record` with the exact link and the artifact receipt.
6. Build review evidence and Captain execution intent against the same repository, PR, base, head, diff and delivery-receipt SHA-256.
7. Revalidate the durable delivery receipt in `captain-run`, in the atomic merge guard after acquisition, and again immediately before `gh pr merge` dispatch.

Creating or transferring the artifact without the user-visible delivery step is insufficient. A later delivery after an external merge is recorded as post-merge exposure and never converted into retrospective compliance.

## Receipt contract

The private create-only receipt records:

- repository and pull-request number;
- full base and head commit SHAs;
- complete diff SHA-256;
- artifact id, artifact SHA-256, artifact-receipt SHA-256, canonical owner/repository identity (with read-only legacy-name compatibility), local repository-path SHA-256, filename and byte size;
- artifact creation time and delivery-confirmation time;
- delivery channel and a private delivery reference plus its SHA-256;
- one-hour expiry, Unix realtime clock domain and explicit GitHub timestamp uncertainty;
- a deterministic binding SHA-256.

The receipt and the underlying artifact are owner-controlled regular files. Symlinks, hard links, permissive modes, changed files, malformed canonical JSON, hash drift and stale receipts fail closed.

The one-hour validity window deliberately forces delivery to happen after the final CI and review cycle, close to merge dispatch. A changed PR head or diff invalidates the delivery. An expired receipt for an unchanged PR requires a newly published artifact with a new artifact id and a new visible delivery; the create-only store retains the old receipt instead of replacing it.

## Parallel merge serialization

The existing atomic merge guard is the cooperating-actor merge-intent gate. It holds exact repository, PR, branch, changed-path and merge-effect resources through dispatch and post-merge readback.

Delivery evidence is checked before guard entry, after resource acquisition and immediately before dispatch. A cooperating parallel actor therefore cannot use an older delivery receipt after head, diff, artifact or receipt drift.

This does not lock arbitrary non-cooperating GitHub users or external automation. If an external merge is observed, Grabowski sends no duplicate merge command and compares the recorded delivery time with GitHub's merge time. Ordering inside the stated clock uncertainty remains `ordering_uncertain`, not compliant.

## Non-claims

A valid delivery receipt does not prove that the user opened or downloaded the file. It proves only that the exact downloadable artifact was exposed through the recorded user-visible reference before the receipt was created.

It also does not establish:

- code or review correctness;
- green CI;
- merge authority;
- branch-protection compliance;
- deployment or production safety.

Those remain independent Captain gates and post-action checks.

# Optional Diff Delivery v1

Status: optional artifact contract
Date: 2026-07-30

## Purpose

`grabowski_merge_delivery_record` remains available when a user explicitly requests a downloadable diff or when an operator chooses to provide one as additional evidence. It is not a prerequisite for review, Captain preflight, Captain execution or merge dispatch.

The optional receipt can bind one repository, pull request, base commit, head commit and complete diff SHA-256 to a concrete user-visible artifact reference. It proves only that this artifact reference was recorded. It grants no review, CI, merge or deployment authority.

## Optional sequence

1. Read the current pull-request base, head and complete GitHub diff.
2. Publish the exact raw diff bytes through the `git-diff.v1` artifact profile.
3. Transfer the UTF-8 `.txt` file into a user-visible download surface.
4. Expose the concrete download link.
5. Record the optional delivery receipt with `grabowski_merge_delivery_record`.

This sequence is used only when the artifact itself is wanted. Normal merges continue to require exact live base/head/diff binding, diff-bound review, green required CI, current GitHub state, resource leases and post-merge readback, but no user-visible diff file.

## Receipt contract

The create-only private receipt records repository and PR identity, full base and head SHAs, complete diff SHA-256, artifact identity and size, delivery channel and reference, timestamps, expiry and deterministic hashes. Owner-control, file integrity and freshness checks remain fail-closed for consumers that explicitly choose to verify such a receipt.

## Non-claims

A valid optional receipt does not prove that the user opened or downloaded the file. It also does not establish code correctness, review completeness, green CI, merge authority, branch-protection compliance, deployment safety or production correctness.

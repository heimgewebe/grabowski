# P0: Operator read-cost discrimination, 2026-09-23

Status: measured baseline; not a performance fix, deployment proof, or P1–P8 closeout.

## Question and result

Full audit snapshot materialization is a demonstrated CPU/RAM and coordination-lock bottleneck. At one million synthetic payload records the cold snapshot took 19.81 s and held the coordination lock for 19.73 s. A warm repeat still took 20.21 s. An exclusive contender against that real shared lock timed out after 5.016 s. With 100,000 records it acquired the lock after 2.116 s.

This does **not** show that every audit read has this cost. Warm audit-only health took 0.285 s at one million records; its maximum coordination-lock hold was 0.138 s. Cold health/audit verification took 13.44 s, so first-use historical verification remains materially different from a small liveness read.

One actual production audit projection took 84.177 s for 1,315,325 records. This is a client-observed wall time, including transport and any concurrent server work, not an isolated profiler sample. No production audit data was deleted, truncated, or copied into the synthetic fixture.

## Bindings

- Measured source: `70d2810830cf08814e9bcb61cc46c93af960ced2`, fetched previously and verified against GitHub main immediately before work acquisition.
- Isolated lane: `7d41a3b75189c8623a67398ecb034e61`.
- Worktree: `operator-read-cost-p0-20260923` (isolated worktree name).
- Initial probe SHA-256: `b06219a0794b9bcf928a4e5e15fbf1b519ea341d62157ca4717dd880e60d8ba8`.
- Strengthened warm/contender probe SHA-256: `520db81f00922079296797716edf5eb385252412fa1d5d35f18c8cd76ecfe207`.
- Interpreter for the recorded warm run: `/usr/bin/python3`, Python 3.10.12. Initial task explicitly used system Python as well; no runtime virtualenv was used.
- Cold task: `fcc72382e9ff410f8a3a6ce6`, completed; terminal outcome receipt `afeb73ec15b4b40ee499e5021eb0d94523ae663f2dcd93ea1d7dc785cc432a6d`.
- Warm/contender task: `88a2d623bb0c41979c06e677`, completed; terminal outcome receipt `c1208f51ec527367a4fb42332c1bc19680ebff2b2b06327f22276edc79f1bc6c`.
- Runtime during production observations: `d1e1d3dd8df3504b2e8913c49f00b9a020429840`, release `d1e1d3dd8df3-srcset86853ca07931-lock4760b9056ea3-contract03ebb6191f56`.
- The measured source and runtime have identical audit-query/read-surface algorithms and audit routines. Their MCP source difference is the compact minimal-status response, not the measured audit implementation.

Raw bounded JSON results remain in the existing Grabowski task-output contract. The task receipts establish process terminalization, not independent authenticity or functional correctness of all projection semantics.

## Method

[The probe](../../tools/operator_read_cost_probe.py) reuses the existing test loaders, audit record hashing, segment rotation, and verification. Every generated fixture is private and temporary; it contains only neutral synthetic records with 768-byte payloads. The real 16-MiB segment size is unchanged. Fixture creation and initial verification are outside the measured interval. Each case executes in a fresh system interpreter.

The strengthened runner requires system Python and an absent source deployment manifest before importing the test loader. It binds task, friction, deployment and kill-switch providers to synthetic data and fixes the projection observation time. It verifies `total_records == payload_records + archived_segment_count`. The initial runner lacked those explicit import guards and additional count assertions; its actual system-Python invocation and the valid observed counts are recorded above. Do not rerun that initial version under the runtime interpreter.

Fixture sizes:

| Payload records | Total records | Archived segments | Approximate fixture bytes |
| ---: | ---: | ---: | ---: |
| 100000 | 100006 | 6 | 108322003 |
| 1000000 | 1000065 | 65 | 1084258388 |

“Kalt” below means an empty Python verification cache. The OS page cache is neither cleared nor controlled. “Warm” means one prior invocation in the same measured interpreter, followed by collection.

Metrics:

- Wall time: `perf_counter_ns`; CPU: `process_time_ns`.
- RSS: own `/proc/self/status`, before/after call and after collection.
- Process lifetime peak: `ru_maxrss`; the strengthened runner also records its pre-call floor and `VmHWM`. `VmHWM` is the resident-memory high-water mark, exposed as `rss_hwm_before_kib` / `rss_hwm_after_kib`. The recorded historical runner used the misleading `address_space_hwm_*` labels for these same RSS values; only the field names were corrected after review. These are **not isolated call peaks**, and peaks are never subtracted to fabricate one.
- Logical audit bytes: values returned by `_read_audit_descriptor`, including repeated reads. These are not physical disk-I/O bytes.
- Coordination hold: body of the real `_audit_coordination_lock`; acquisition timings aggregate real flock calls, including file locks. Separate file-lock hold times are not measured.
- The contender uses the real exclusive coordination lock in a second thread. It writes no audit record. This proves lock acquisition contention, not whole-append latency, writer fairness, or rotation safety.
- The optional decoder counter counts actual V2 JSON decodes, including repeated decoding. It changes runtime and is reserved for separate instrumented trials.
- Deployment, task-store, registry, transport and UI cost are excluded from the synthetic audit-only measurements. Synthetic projection shape validity is not a full semantic regression suite.

## Cold Python-cache results

MiB means 1,048,576 bytes. RSS is a snapshot immediately after the operation; process peak includes imports and any inherited floor.

| Payload records | Operation | Wall ms | CPU ms | RSS after MiB | Process peak MiB | Max coordination hold ms | Logical read MiB |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | verify | 28.1 | 28.1 | 58.0 | 64.3 | 13.9 | 2.1 |
| 1,000 | snapshot | 18.3 | 18.3 | 57.0 | 64.3 | 18.2 | 1.0 |
| 1,000 | query_limit1 | 22.6 | 22.6 | 56.9 | 64.5 | 13.1 | 1.0 |
| 1,000 | projection | 54.3 | 54.3 | 58.0 | 64.8 | 19.4 | 3.1 |
| 1,000 | health_audit_only | 27.9 | 27.9 | 58.0 | 64.4 | 14.2 | 2.1 |
| 100,000 | verify | 1496.9 | 1496.5 | 66.6 | 92.9 | 119.9 | 112.1 |
| 100,000 | snapshot | 2003.6 | 2003.1 | 257.3 | 358.9 | 1996.5 | 103.3 |
| 100,000 | query_limit1 | 2280.4 | 2280.1 | 71.4 | 122.8 | 118.2 | 197.8 |
| 100,000 | projection | 4255.4 | 4254.3 | 150.0 | 358.4 | 1990.4 | 215.4 |
| 100,000 | health_audit_only | 1515.0 | 1514.7 | 64.0 | 92.6 | 123.9 | 112.1 |
| 1,000,000 | verify | 13745.8 | 13735.6 | 68.1 | 108.9 | 139.2 | 1044.3 |
| 1,000,000 | snapshot | 19810.7 | 19803.1 | 2183.0 | 3214.9 | 19734.0 | 1034.0 |
| 1,000,000 | query_limit1 | 14888.5 | 14460.1 | 73.1 | 124.1 | 137.5 | 1128.5 |
| 1,000,000 | projection | 41274.3 | 40851.1 | 875.8 | 3215.1 | 19781.4 | 2078.3 |
| 1,000,000 | health_audit_only | 13437.2 | 13433.3 | 67.2 | 107.8 | 139.0 | 1044.3 |

The general snapshot retains all verified segment bytes and then all record dictionaries. Snapshot processing deliberately bypasses the verification cache. The small query returns one item but scans up to 100,000 records; on a cold process its preceding chain verification still scales with history. Truncation is correctly exposed rather than presented as complete history.

## Warm Python-cache results with an exclusive contender

These runs include thread-start and contention instrumentation overhead. The contender is signalled after the first shared coordination lock is acquired.

| Payload records | Operation | Wall ms | RSS after MiB | Max coordination hold ms | Exclusive contender |
| ---: | --- | ---: | ---: | ---: | --- |
| 100,000 | health_audit_only | 236.6 | 66.9 | 119.7 | acquired / 241.8 ms |
| 100,000 | query_limit1 | 1067.3 | 68.2 | 120.8 | acquired / 141.4 ms |
| 100,000 | snapshot | 2103.5 | 360.7 | 2103.1 | acquired / 2116.5 ms |
| 100,000 | projection | 3013.7 | 238.9 | 1991.3 | acquired / 2023.0 ms |
| 1,000,000 | health_audit_only | 284.9 | 69.8 | 137.7 | acquired / 149.2 ms |
| 1,000,000 | query_limit1 | 1024.8 | 83.1 | 131.8 | acquired / 167.0 ms |
| 1,000,000 | snapshot | 20210.4 | 3217.3 | 20210.0 | timeout / 5015.6 ms |
| 1,000,000 | projection | 27218.9 | 1892.1 | 19190.3 | timeout / 5015.6 ms |

The warm full snapshot does not become cheap. Warm health and query costs are substantially smaller; their contender succeeds. At one million records both snapshot and public projection reproduce the configured five-second lock timeout.

## Fresh production observations

Primary calls were executed serially. Großer Adler sampled the actual system service before and after each call; samples are observation windows, not exclusive per-call CPU attribution.

| Operation | Client wall time | Observation |
| --- | ---: | --- |
| Runtime health | 2.424 s | healthy; 1,315,291 records; 78 archives |
| Audit query, limit=1 | 4.529 s | 100,000 scanned, one returned; incomplete scan explicitly reported |
| Current work, limit=5 | 14.917 s | partial checkout/attention/reconciliation sources; one checkout observation error |
| Workspace cleanup plan | 15.937 s | 68 workspaces; eligible=0; 11 cleaned, 34 absent, 23 blocked |
| Audit projection, minimal | 84.177 s | complete 1,315,325-record binding; source did not advance during projection |
| Earlier full status, evidence view | 32.049 s | successful; no isolated component timings captured for this sample |

Current-work projection reported 23 closed-not-cleaned and two cleanup-ready entries, but those two entries referred to task-output cleanup, not the same population as the workspace-cleanup plan. Comparing those counts as if they denoted identical deletion authority would be incorrect. No cleanup was applied.

The deployed Current Work implementation predates main's #1301 overlapping independent reads. Its source costs must not be confused with the pure bounded Current Work projection.

### Memory and service identity

At the first fresh observation the system service had restarted at 18:24:10 CEST, PID 1165. Its current group memory was about 35 GiB, but Python RSS was about 2.57 GiB. The group split was approximately 2.75 GB anonymous, 31.68 GB file cache and 3.11 GB kernel memory, mostly reclaimable slab. Swap-in/out counters for this boot were zero.

Later independent samples showed roughly 10.7 GiB Python RSS. Concurrent work was not excluded, so this growth is not attributed to one selected call. The measured production audit projection actually ended at a lower RSS snapshot than it began (about 9.0 versus 10.8 GiB). This does not disprove its transient allocations.

The system service was active. A user service with the same name existed but was inactive. The last observed audit-lock timeout in the initial log excerpt belonged to the **previous** process before restart; no current-boot production timeout is claimed from that excerpt. The reproduced timeout above is explicitly synthetic.

## Gegenprobe applied in the same thread

- **strongest_countercase:** Cold verification, import peaks, OS cache and artificial payloads could overstate normal-path cost; current cgroup memory is mostly cache; an existing PR may already solve the material problem.
- **fragile_assumption:** A synthetic full-history cost is a complete explanation of the historical 23-GiB RSS or every slow production read.
- **discriminating_evidence:** Warm-versus-cold runs, separate snapshot/query/health cases, actual RSS snapshots, actual exclusive-lock contention, and serial live observations. Warm verification improved dramatically while snapshot time/lock hold did not.
- **disposition:** CONTINUE with the measured snapshot/lock bottleneck; do not infer the historical memory cause or automatically redesign all readers.

## Existing fix and remaining P1/P1b gaps

Published [PR #1300](https://github.com/heimgewebe/grabowski/pull/1300), head `8f96816cbe9a20183c049c367023f47d5b68f815`, moves verification/materialization outside the coordination lock and bounds the public projection to a recent 100,000-record window with explicit incompleteness.

At inspection it was behind main with failing checks. The active foreign lane `5d855a9c2b89705bb9d25b847b4482ec` already contained unpublished retry/backoff and truncation-review corrections. No overlapping file or branch was changed.

That PR alone does not establish all required outcomes:

1. Generic full snapshots remain O(history) in memory; identify and narrow actual consumers instead of replacing necessary full-history diagnostics indiscriminately.
2. Health still calls full audit verification; separate small logical liveness from historical integrity diagnosis without weakening mutation integrity gates.
3. Full status still invokes task-list terminalization recovery. Detailed diagnosis should not silently perform repair.
4. Cold chain verification still scales with the full history even when projection output is bounded.
5. Serving manager scope and host identity need authoritative bindings, not inference from duplicate unit names.
6. The final published retry fix needs exact-head tests, review, CI, contention/rotation coverage and post-deployment measurements.

No new store, cache, service, timer, routing abstraction, or telemetry platform is introduced by this baseline. The next performance comparison must use the same fixture sizes and metric definitions against the actual accepted fix, followed by real runtime reads. None of P1–P8 is marked complete by this report.

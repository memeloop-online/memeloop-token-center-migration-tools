This source adds a target-only operator for a separately authorized runtime
window. Source, CI and peer review are not permission to execute it. The plan
stays suspended; no source PVC, copy, backup, import or volume deletion is added.

Reviewed source contract proposed for R2: startup 300s, execution 165s, total
480s, cleanup 30s, API read 2s, observation freshness 10s, polling 1s. The config
must explicitly supply these values and match the shipped plan. Startup 300s
is a finite allocation larger than the exhausted October 6 mount window,
not a measured attachment feasibility claim. Total 480s covers startup plus
full execution plus 15s observation/dispatch headroom. No budget changes or
deadline extensions are permitted during the attempt. Job and Pod each retain
a finite 480s activeDeadlineSeconds; termination grace is separately 5s.

Before unsuspension the operator verifies the exact fresh Job UID/RV, fixed
derivative PVC UID/RV and Bound volumeName, suspended unused Job, reviewed
target-only Pod specification, single completion/parallelism, no retries,
pinned image and deny-network policy. It rejects any pre-existing owned Pod.
It PATCHes suspend=false exactly once with JSON Patch tests for UID, RV and
suspend=true. There is no apply/create/retry path. After unsuspension it captures
the unique controller-owned Pod, verifies target-only spec and policy label,
and pins its UID. No Pod UID is required before a suspended Job creates a Pod.

Startup includes no Pod, missing container status, mount, image pull and init.
Execution starts only at the directio container's actual startedAt; that value
is pinned, never inferred from Ready or Job age, and cannot reset the clock.
Timestamp bounds, terminal Job/Pod/init states, all resource versions and
bounded collection duration are checked. Logs come only from that exact Pod's
directio container, followed by UID/RV revalidation; only successful terminated
write/read completion produces bytes. Unknown or failed startup uses null,
never 0B throughput. Stale/missing/invalid/replaced observations fail closed.
Total deadline has priority; terminalCause remains a separate diagnostic.

The operator stops itself on startup/exec/total expiry or observation failure.
Cleanup gets fresh exact identities, DELETEs only the original Job and pinned
Pod with DeleteOptions UID and current RV preconditions, and bounds absence
confirmation to 30s. Job deletion uses Orphan to prevent implicit cascading
deletion of unrecorded/replacement Pods. A previously pinned Pod may become
orphaned; its original UID and fresh RV still guard its explicit deletion.
An unrecorded late orphan or replacement is never deleted, and leaves cleanup
unconfirmed. No DELETE is retried. Controller-label listing is discovery and
confirmation only, never selector deletion. A cleanup conflict/failure is not
PASS; fallback Pod deadline also bounds orphan execution. It does not erase
unconfirmed orphan metadata or guarantee the original attempt's overall wall
time if the operator itself is killed. The Job deadline remains the ordinary
independent fallback. Both fallbacks are finite.

No PVC, source, exclusive directory or old partial is cleaned. The original
container trap still removes only its exclusively created probe.bin. SIGKILL
can leave that file; no broad removal or second mount is attempted to hide it.

The executable entry below starts a local Unix-socket kubectl proxy using the
operator's existing Kubernetes identity, without reading Secrets, exporting
credentials or listening on TCP. Bootstrap and preflight are each bounded by
10s and happen before execution. Total control window begins immediately
before PATCH (conservatively rounded down to a second for Kubernetes times).
Normal process wall limit is bootstrap 10s + preflight 10s + total 480s +
cleanup 30s + proxy termination 1s. SIGINT/TERM enters bounded cleanup.
SIGKILL cannot run cleanup. Target Pods remain network-denied and tokenless.

Only after independent source review and a separate runtime authorization,
provide a private config with jobName, jobUid, jobResourceVersion, pvcUid,
pvcResourceVersion and the explicit budgets below. The Job must already exist
under the reviewed target-only plan and have fresh unused identity. Node and
Longhorn attachment/locality must be checked separately before that window.

```json
{"startupMs":300000,"execMs":165000,"totalMs":480000,"cleanupMs":30000,"apiMs":2000,"freshnessMs":10000,"pollMs":1000}
```

```
node ops/inspection/cpa-work-probe-operator.ts --execute-authorized-target-only private-config.json
```

The optional `--api-socket PATH` uses an existing current-UID Unix socket (also
used by the GHA fake API integration). The CLI emits a structured receipt and
exits nonzero unless write/read completed AND exact cleanup was confirmed.
Historical receipts are evidence only; live decisions always come from fresh
API reads, not an observation file. GHA exercises operator decisions and the
real CLI against a local fake API, plus the existing real DirectIO command on
scratch disk. None of these establish cluster mount/copy/import acceptance.

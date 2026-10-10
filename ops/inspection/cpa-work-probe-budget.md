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

An unused Job must have generation 1, no start/completion time, no execution or
uncounted termination counters, and no existing owned Pod. Empty initial status
is accepted, as is exactly one controller-generated Suspended=True condition
with reason JobSuspended and message "Job suspended". Resumed/duplicate/unknown
or terminal conditions remain rejected before PATCH or DELETE. Re-suspension
can clear startTime in Kubernetes, so a Suspended condition alone never proves
that the Job is unused. Exact self-created UID/RV receipts remain required.
The condition values follow the upstream [Job controller](https://github.com/kubernetes/kubernetes/blob/v1.35.0/pkg/controller/job/job_controller.go);
generation behavior follows the upstream [Job strategy](https://github.com/kubernetes/kubernetes/blob/v1.35.0/pkg/registry/batch/job/strategy.go).

Startup includes no Pod, missing container status, mount, image pull and init.
Execution starts only at the directio container's actual startedAt; that value
is pinned, never inferred from Ready or Job age, and cannot reset the clock.
Timestamp bounds, terminal Job/Pod/init states, all resource versions and
bounded collection duration are checked. Logs come only from that exact Pod's
directio container, followed by UID, owner, spec and policy-label revalidation; only successful terminated
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

Across polls and around log reads, resourceVersion may change through normal
status updates. It remains required observation metadata and an exact fresh
PATCH/DELETE precondition, but is not immutable Pod identity. UID, namespace,
name, controller owner, reviewed spec, PVC binding and policy labels remain
fail-closed gates. The observation before the log GET is retained; a later
status update is evaluated on the next bounded poll, without resetting clocks.

Cleanup receipts now expose `cleanup.startedAt` and `cleanup.deadline`, captured
at the actual operator finally entry. The tracked `cpa-work-probe-lifecycle.ts`
module supervises an already launched operator using its explicit original
launch timestamp (delayed supervision never resets it): wait at most 480s, SIGTERM first,
allow operator finally cleanup for at most 30s plus 5s grace, and SIGKILL
within the fixed 515s outer cap. Early cancellation uses the same 30s plus 5s
from its TERM boundary, without renewing caller cleanup after a forced stop.
Caller cleanup also runs in finally. It uses the explicit operator cleanup entry
when present, otherwise the observed operator end (or actual cleanup entry if
no operator end is available), capped by the same outer deadline. Init/main
container termination times, decision times and API diagnostic times never
anchor cleanup. An exhausted window is not renewed. Cleanup callbacks receive
an absolute deadline and abort signal and must honor both for each API call;
2s API/three transient GET attempts/no mutation retry remain unchanged.
This module has no executable entrypoint and performs no operator launch,
resource creation, probe, import or volume operation. Temporary callers should
use `observeProbeProcess`/`superviseProbe` rather than copy timestamp heuristics.

`cpa-work-probe-supervised.ts` is the thinnest such executable caller. It is
invoked with the operator's exact argument contract, with `--api-socket`
mandatory because caller cleanup shares the caller-owned Unix socket:

```sh
node ops/inspection/cpa-work-probe-supervised.ts \
  --execute-authorized-target-only <private-config.json> --api-socket <path>
```

It records the original launch clock immediately before spawning the reviewed
operator once with unchanged arguments, forwards SIGTERM/SIGINT as an abort
signal, and delegates every deadline, signal-first, forced-stop and cleanup
boundary decision to `superviseProbe`. Both processes use the operator's full
`configValid` gate and shared `cleanupProbe`, including reviewed Job/Pod specs,
unique controller ownership, runtime name/namespace/UID/resourceVersion checks,
guarded Orphan Job deletion and bounded absence confirmation.

The supervisor creates a private attempt journal directory and passes its
file path through `CPA_PROBE_ATTEMPT_JOURNAL`; operator arguments stay unchanged.
The operator atomically records attempt acquisition before invoking PATCH,
clears acquisition on definitive PATCH 4xx rejection, and records each DELETE
before invoking the transport. Pod adoption and the original cleanup entry
and deadline are also journaled. Parent cleanup requires this journal to match
the fully validated config; missing/unacquired journals grant no API access.
An issued DELETE with unknown acknowledgement, failed cleanup or malformed
journal stays unconfirmed and cannot be replayed by the parent. Acknowledged
deletions may be observed for absence within the original window, never reissued.
Completed operator cleanup requires no additional parent API calls.

Each DELETE retains exact UID/resourceVersion preconditions and 5s grace.
Malformed capture identities stop cleanup before any DELETE. Identity mismatch,
transport failure, abort or deadline expiry fails closed without increasing
the original 2s API, three transient GET, 30s cleanup or 515s outer budgets.
Cleanup never touches the PVC, PV, deny policy, foreign or unrecorded resources,
and the entrypoint exits nonzero unless the operator passed and caller cleanup
completed without a forced stop. The private journal is removed on exit.

The target-only DirectIO plan stays suspended and retains its 175-second Job
deadline (plus five seconds termination grace), no retries, pinned image,
network deny, no service account token, fixed derivative claim and exclusive
probe-file cleanup. This change does not authorize a runtime attempt.

The operator startup observation budget is 60 seconds from Job status.startTime.
It includes scheduling, attachment, mounting, image pull and init execution.
The 165-second execution budget begins at the directio container's actual
state.running.startedAt (or state.terminated.startedAt). The in-container
timeout enforces that execution limit. The unchanged overall cap can truncate
execution; a late mount never grants extra wall time. Budget annotations are
contracts for the operator, not Kubernetes-enforced startup timers.

In an independently authorized window, the parent operator must observe the
exact Job, its exact owned Pod and the existing derivative PVC, recording their
fresh UIDs before unsuspension. Feed a fresh observation JSON to:

```
node ops/inspection/cpa-work-probe-budget.ts observation.json JOB_UID POD_UID PVC_UID
```

Fields are jobUid, podUid, ownerUid (Pod's controller Job UID), pvcUid,
claimName, jobStartedAt, initFailed, state (directio container state),
writeStarted and complete. Set initFailed from a nonzero init termination or a
terminal Pod before directio starts; set marker booleans only from that exact
Pod's WRITE_START and DIRECTIO_COMPLETE logs. Do not substitute Pod Ready for
execution or performance evidence. Missing/stale observations are failures,
never successful measurements. Polling and stopping belong to the parent
operator; this local receipt evaluator does not call Kubernetes.

STARTUP_DEADLINE/STARTUP_FAILED are separate from EXEC_DEADLINE/EXEC_FAILED and
TOTAL_DEADLINE. The operator must stop on stopRequired, using UID-preconditioned
deletion of only the recorded Job/Pod, after checking identity again. Never
delete by selector or name alone, remove a PVC, remove the exclusive directory,
or clean another partial. The Job total deadline remains the fallback when
operator observation is interrupted. The existing in-container trap removes
only its exclusively created probe.bin; force-kill leftovers require separate
review, never broad cleanup. Until COMPLETE, bytes is null, not 0B throughput.

No source mount, backup, data copy, import or performance PASS follows from
this source change or from the GHA scratch-disk contract test. The parent must
review startup-budget feasibility and intended node/attachment locality before
scheduling a new runtime window.

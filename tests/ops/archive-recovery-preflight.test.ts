import assert from "node:assert/strict";
import { test } from "node:test";
import { assessRecovery } from "../../ops/archive-recovery-preflight.ts";
import { archiveErrorDiagnostic } from "../../ops/lib/archive-error-diagnostic.ts";

function receipt() {
  return { seal: { source_records: 10, source_sessions: 2, source_blobs: 30, source_compressed_bytes: 400 },
    live_stats: { records: 10, sessions: 2, blobs: 30, compressed_bytes: 400 },
    export_job: { metadata: { uid: "job-uid" }, status: { conditions: [{ type: "Failed", status: "True", reason: "BackoffLimitExceeded" }] } },
    export_pods: { items: [] as unknown[] } };
}

test("equal counts and backoff exhaustion do not establish safety or root cause", () => {
  const result = assessRecovery(receipt());
  assert.equal(result.post_seal_delta, "unknown_missing_comparable_ingest_fences");
  assert.equal(result.failure_cause, "not_established");
  assert.equal(result.recovery_ready, false);
  assert.equal(result.deletion_ready, false);
});

test("equal counts cannot hide a newer mutation fence", () => {
  const input = receipt();
  assert.equal(assessRecovery({ ...input, seal: { ...input.seal, source_ingest_fence: "12" }, live_ingest_fence: "13" }).post_seal_delta, "post_seal_mutations_present");
});

test("only owned Pod failures identify the failing stage", () => {
  const input = receipt();
  const pod = { metadata: { ownerReferences: [{ uid: "other-job" }] }, status: {
    initContainerStatuses: [{ state: { terminated: { exitCode: 1, reason: "Error", message: "private payload" } } }] } };
  input.export_pods.items.push(pod);
  assert.deepEqual(assessRecovery(input).container_failures, []);
  pod.metadata.ownerReferences[0]!.uid = "job-uid";
  const result = assessRecovery(input);
  assert.deepEqual(result.container_failures, [{ stage: "init", exit_code: 1, reason: "Error" }]);
  assert.ok(!JSON.stringify(result).includes("private payload"));
});

test("invalid counts fail closed", () => {
  const input = receipt();
  input.live_stats.records = -1;
  assert.throws(() => assessRecovery(input), /invalid metadata count/);
});

test("diagnostics retain actionable codes without paths, SQL, payloads or stacks", () => {
  assert.equal(archiveErrorDiagnostic({ code: "EROFS", message: "private", path: "private", stack: "private" }), "delta export failed: code=EROFS");
  assert.equal(archiveErrorDiagnostic({ code: "ERR_SQLITE_ERROR", errcode: 14, message: "private SQL" }), "delta export failed: code=ERR_SQLITE_ERROR sqlite_errcode=14");
  assert.equal(archiveErrorDiagnostic({ code: "private", errcode: "private" }), "delta export failed: code=UNCLASSIFIED");
  assert.equal(archiveErrorDiagnostic(null), "delta export failed: code=UNCLASSIFIED");
});

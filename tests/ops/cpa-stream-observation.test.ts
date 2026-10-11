import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { confirmedSegmentedBytes, selectSegmentedPod, type ObservedPod } from "../../ops/lib/cpa-stream-observation.ts";

const ready: ObservedPod = {
  metadata: { uid: "pod-uid", ownerReferences: [{ uid: "job-uid" }] },
  spec: { nodeName: "versetensor-hv" },
  status: { phase: "Running", podIP: "10.42.8.133", initContainerStatuses: [{ name: "private-new-directories", state: { terminated: { exitCode: 0 } } }], containerStatuses: [{ name: "receiver", state: { running: {} } }] },
};

test("no Pod, Pending, no IP and incomplete init wait within the original deadline", () => {
  assert.deepEqual(selectSegmentedPod([], "job-uid", "receiver", 0), { state: "wait" });
  for (const status of [{ phase: "Pending" }, { ...ready.status, podIP: undefined }, { ...ready.status, initContainerStatuses: [] }, { ...ready.status, containerStatuses: [] }]) assert.deepEqual(selectSegmentedPod([{ ...ready, status }], "job-uid", "receiver", 119999), { state: "wait" });
  assert.throws(() => selectSegmentedPod([], "job-uid", "receiver", 120000), /BUSINESS_DEADLINE/);
  assert.deepEqual(selectSegmentedPod([ready], "job-uid", "receiver", 1000), { state: "ready", uid: "pod-uid", ip: "10.42.8.133" });
});

test("ownership, terminal state, wrong node or endpoint fail closed", () => {
  assert.throws(() => selectSegmentedPod([ready], "other-job", "receiver", 0), /POD_OWNER/);
  assert.throws(() => selectSegmentedPod([ready, ready], "job-uid", "receiver", 0), /POD_COUNT/);
  assert.throws(() => selectSegmentedPod([{ ...ready, status: { ...ready.status, phase: "Failed" } }], "job-uid", "receiver", 0), /POD_TERMINAL/);
  assert.throws(() => selectSegmentedPod([{ ...ready, spec: { nodeName: "westlake" } }], "job-uid", "receiver", 0), /NODE_PLACEMENT/);
  assert.throws(() => selectSegmentedPod([{ ...ready, status: { ...ready.status, podIP: "100.64.0.8" } }], "job-uid", "receiver", 0));
});

test("empty or pre-ACK observations preserve progress without claiming written bytes", () => {
  assert.equal(confirmedSegmentedBytes([], 0), 0);
  assert.equal(confirmedSegmentedBytes([{ phase: "frame-write", segment: 1 }], 0), 0);
  assert.equal(confirmedSegmentedBytes([{ phase: "ack-read", segment: 1 }], 0), 4194304);
  assert.equal(confirmedSegmentedBytes([], 4194304), 4194304);
  assert.equal(confirmedSegmentedBytes([{ confirmedBytes: 0 }], 4194304), 4194304);
  assert.equal(confirmedSegmentedBytes([{ phase: "ack-read", segment: 4 }], 0), 16777216);
  assert.throws(() => confirmedSegmentedBytes([{ phase: "ack-read", segment: 5 }], 0), /PROGRESS_SEGMENT/);
  assert.throws(() => confirmedSegmentedBytes([{ confirmedBytes: -1 }], 0), /PROGRESS_RANGE/);
});

test("actual observer CLI handles empty first log and Pending/no-IP without runtime resources", () => {
  for (const [request, expected] of [
    [{ operation: "progress", events: [], previous: 0 }, { confirmedBytes: 0 }],
    [{ operation: "pod", items: [], jobUid: "job-uid", role: "receiver", elapsedMs: 1000 }, { state: "wait" }],
    [{ operation: "pod", items: [{ ...ready, status: { phase: "Pending" } }], jobUid: "job-uid", role: "receiver", elapsedMs: 1000 }, { state: "wait" }],
    [{ operation: "pod", items: [ready], jobUid: "job-uid", role: "receiver", elapsedMs: 1000 }, { state: "ready", uid: "pod-uid", ip: "10.42.8.133" }],
  ]) {
    const result = spawnSync(process.execPath, ["ops/lib/cpa-stream-observation.ts"], { input: JSON.stringify(request), encoding: "utf8", timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), expected);
  }
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseAllDocuments } from "yaml";
import { PROBE_BUDGET } from "../../ops/inspection/cpa-work-probe-budget.ts";
import { ApiFailure, ApiTransportFailure, unixApi, runProbe, type ProbeApi, type ProbeClock, type ProbeConfig, type Resource } from "../../ops/inspection/cpa-work-probe-operator.ts";

const [policy, plan] = parseAllDocuments(readFileSync("ops/inspection/cpa-work-directio-20261006a.yaml", "utf8")).map((doc) => doc.toJSON() as Resource);
assert.ok(policy && plan);
const reviewedPolicy = policy!, reviewedPlan = plan!;
const epoch = Date.parse("2026-10-09T10:00:00Z");
const config: ProbeConfig = { jobName: "mtc-cpa-work-directio-contract", jobUid: "11111111-1111-4111-8111-111111111111", jobResourceVersion: "1", pvcUid: "a5045b54-0f10-4f60-b1f5-18167620ba31", pvcResourceVersion: "3", budgets: { ...PROBE_BUDGET } };
const ns = "/api/v1/namespaces/cliproxyapi";
const jobPath = `/apis/batch/v1/namespaces/cliproxyapi/jobs/${config.jobName}`;
const podPath = `${ns}/pods/probe-pod`;

function fixture(mode: "late" | "startup" | "exec" | "total" | "init" | "replacement" | "job-replacement" | "pvc-replacement" | "stale" | "cleanup-timeout" | "post-log-replacement" = "late") {
  let now = epoch, step = 0, enabled = false, jobGone = false, podGone = false, cleanupStarted = false, staleInjected = false;
  let job: Resource = { ...structuredClone(reviewedPlan), metadata: { name: config.jobName, namespace: "cliproxyapi", uid: config.jobUid, resourceVersion: "1", generation: 1 } };
  const pvc: Resource = { metadata: { name: "mtc-cpa-recovery-work-20261005", namespace: "cliproxyapi", uid: config.pvcUid, resourceVersion: "3" }, spec: { volumeName: `pvc-${config.pvcUid}` }, status: { phase: "Bound" } };
  let pod: Resource | null = null;
  const operations: { method: string; path: string; body?: unknown; timeout: number }[] = [];
  const times = mode === "startup" ? [300_000] : mode === "exec" ? [180_000, 345_000] : mode === "total" ? [480_000] : [180_000, 180_001, 344_000];
  const clock: ProbeClock = { now: () => now, cancelled: () => false, sleep: async (ms) => {
    assert.ok(ms >= 0 && ms <= PROBE_BUDGET.pollMs);
    if (cleanupStarted) now += ms; else { now = epoch + (times[step] ?? 344_000); step++; }
  } };
  const updatePod = () => {
    if (!enabled || podGone || mode === "startup" || mode === "total" || step === 0 && mode !== "init") return;
    if (!pod) pod = { metadata: { name: "probe-pod", namespace: "cliproxyapi", uid: "22222222-2222-4222-8222-222222222222", resourceVersion: "10", labels: { "memeloop.io/cpa-work-probe": "directio-20261006a" }, ownerReferences: [{ kind: "Job", controller: true, uid: config.jobUid }] }, spec: structuredClone((reviewedPlan.spec.template as { spec: Record<string, unknown> }).spec) };
    if (cleanupStarted) return;
    pod.metadata.resourceVersion = String(10 + step);
    const terminated = step >= 3;
    pod.status = mode === "init" ? { phase: "Failed", initContainerStatuses: [{ name: "exclusive-probe-directory", restartCount: 0, state: { terminated: { startedAt: new Date(now).toISOString(), finishedAt: new Date(now).toISOString(), exitCode: 1 } } }] } : {
      phase: terminated ? "Succeeded" : "Running", containerStatuses: [{ name: "directio", restartCount: 0, state: terminated ? { terminated: { startedAt: new Date(epoch + 180_000).toISOString(), finishedAt: new Date(epoch + 344_000).toISOString(), exitCode: 0 } } : { running: { startedAt: new Date(epoch + 180_000).toISOString() } } }],
    };
  };
  const api: ProbeApi = { call: async (method, path, timeout, body) => {
    operations.push({ method, path, body, timeout });
    assert.ok(timeout > 0 && timeout <= PROBE_BUDGET.apiMs);
    assert.ok(!path.includes("secrets") && !path.includes("persistentvolumes/"));
    if (method === "PATCH") {
      assert.equal(path, jobPath);
      assert.deepEqual(body, [{ op: "test", path: "/metadata/uid", value: config.jobUid }, { op: "test", path: "/metadata/resourceVersion", value: "1" }, { op: "test", path: "/spec/suspend", value: true }, { op: "replace", path: "/spec/suspend", value: false }]);
      enabled = true; job.spec.suspend = false; job.metadata.resourceVersion = "2";
      return structuredClone(job);
    }
    if (method === "DELETE") {
      cleanupStarted = true;
      const options = body as { propagationPolicy?: string; preconditions: { uid: string; resourceVersion: string }; gracePeriodSeconds: number };
      assert.equal(options.gracePeriodSeconds, 5);
      if (path === jobPath) {
        assert.equal(options.propagationPolicy, "Orphan");
        assert.deepEqual(options.preconditions, { uid: job.metadata.uid, resourceVersion: job.metadata.resourceVersion });
        jobGone = true; if (pod) { pod.metadata.ownerReferences = []; pod.metadata.resourceVersion = "50"; }
      } else {
        assert.equal(path, podPath); assert.ok(pod);
        assert.equal(options.preconditions.uid, "22222222-2222-4222-8222-222222222222");
        assert.equal(options.preconditions.resourceVersion, pod!.metadata.resourceVersion); podGone = true;
      }
      return {};
    }
    if (path === jobPath) {
      if (jobGone && mode !== "cleanup-timeout") throw new ApiFailure(404);
      if (enabled && mode === "job-replacement") job = { ...job, metadata: { ...job.metadata, uid: "33333333-3333-4333-8333-333333333333" } };
      if (enabled && mode === "stale" && !staleInjected) { staleInjected = true; now += PROBE_BUDGET.freshnessMs + 1; }
      return structuredClone(job);
    }
    if (path.includes("persistentvolumeclaims/")) return structuredClone(enabled && mode === "pvc-replacement" ? { ...pvc, metadata: { ...pvc.metadata, uid: "other-pvc" } } : pvc);
    if (path.includes("networkpolicies/")) return structuredClone(reviewedPolicy);
    if (path === `${ns}/pods`) { updatePod(); return { items: pod && !podGone ? [structuredClone(pod)] : [] }; }
    updatePod();
    if (path.includes("/log?")) {
      if (mode === "post-log-replacement" && pod) pod.metadata.uid = "33333333-3333-4333-8333-333333333333";
      return step >= 3 ? "WRITE_START 2026-10-09T10:03:00Z\nDIRECTIO_COMPLETE 2026-10-09T10:05:44Z\n" : "WRITE_START 2026-10-09T10:03:00Z\n";
    }
    if (cleanupStarted && mode === "replacement" && pod) pod.metadata.uid = "33333333-3333-4333-8333-333333333333";
    if (path.includes("/pods?")) return { items: pod && !podGone ? [structuredClone(pod)] : [] };
    assert.equal(path, podPath);
    if (!pod || podGone) throw new ApiFailure(404);
    return structuredClone(pod);
  } };
  return { api, clock, operations, now: () => now, setNow: (value: number) => { now = value; } };
}

test("operator starts once, adopts Pod after unsuspend and preserves full exec budget after 180s mount", async () => {
  const f = fixture(); const receipt = await runProbe(config, f.api, reviewedPlan, reviewedPolicy, f.clock);
  assert.equal(receipt.status, "COMPLETE"); assert.equal(receipt.passed, true);
  assert.equal(receipt.decision?.execDeadline, epoch + 345_000);
  assert.equal(receipt.decision?.execElapsedMs, 164_000);
  assert.equal(receipt.bytes, 1024 ** 3); assert.equal(receipt.cleanup.complete, true);
  assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1);
  assert.deepEqual(f.operations.filter((op) => op.method === "DELETE").map((op) => op.path), [jobPath, podPath]);
});

test("operator startup, exec and total deadlines terminate with null bytes and bounded cleanup", async () => {
  for (const [mode, expected] of [["startup", "STARTUP_DEADLINE"], ["exec", "EXEC_DEADLINE"], ["total", "TOTAL_DEADLINE"], ["init", "STARTUP_FAILED"]] as const) {
    const f = fixture(mode); const receipt = await runProbe(config, f.api, reviewedPlan, reviewedPolicy, f.clock);
    assert.equal(receipt.status, expected); assert.equal(receipt.bytes, null); assert.equal(receipt.passed, false);
    assert.equal(receipt.cleanup.complete, true); assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1);
  }
});

test("preflight RV mismatch never unsuspends or cleans any resource", async () => {
  const f = fixture();
  const receipt = await runProbe({ ...config, jobResourceVersion: "999" }, f.api, reviewedPlan, reviewedPolicy, f.clock);
  assert.equal(receipt.status, "IDENTITY_MISMATCH");
  assert.equal(receipt.bytes, null);
  assert.equal(f.operations.some((op) => op.method !== "GET"), false);
});

type PodSpec = Record<string, unknown>;
const initialSuspended = { type: "Suspended", status: "True", reason: "JobSuspended", message: "Job suspended", lastProbeTime: new Date(epoch).toISOString(), lastTransitionTime: new Date(epoch).toISOString() };

const serializedDenySpec = {
  podSelector: { matchLabels: { "memeloop.io/cpa-work-probe": "directio-20261006a" } },
  policyTypes: ["Ingress", "Egress"],
};

test("deny policy accepts actual API omitted and empty rule arrays with one PATCH and guarded cleanup", async () => {
  const vectors: [string, Record<string, unknown>][] = [
    ["actual 14:45 API spec", structuredClone(serializedDenySpec)],
    ["explicit empty rules", { ...structuredClone(serializedDenySpec), ingress: [], egress: [] }],
    ["omitted ingress", { ...structuredClone(serializedDenySpec), egress: [] }],
    ["omitted egress", { ...structuredClone(serializedDenySpec), ingress: [] }],
  ];
  for (const [name, spec] of vectors) {
    const f = fixture();
    const api: ProbeApi = { call: async (method, path, timeout, body) => {
      const data = await f.api.call(method, path, timeout, body);
      if (method === "GET" && path.includes("networkpolicies/")) (data as Resource).spec = structuredClone(spec);
      if (method === "GET" && path === jobPath && (data as Resource).spec.suspend === true) {
        (data as Resource).status = { ready: 0, terminating: 0, uncountedTerminatedPods: {}, conditions: [structuredClone(initialSuspended)] };
      }
      return data;
    } };
    const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, f.clock);
    assert.equal(receipt.status, "COMPLETE", name); assert.equal(receipt.passed, true, name);
    assert.equal(receipt.bytes, 1024 ** 3, name); assert.equal(receipt.cleanup.complete, true, name);
    assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1, name);
    assert.deepEqual(f.operations.filter((op) => op.method === "DELETE").map((op) => op.path), [jobPath, podPath], name);
    console.log(JSON.stringify({ fixture: "deny-normalization-accept", name, status: receipt.status, patches: 1, deletes: 2 }));
  }
});

test("deny policy rejects nonempty, malformed, extra and changed selector or type paths with zero PATCH/DELETE", async () => {
  const vectors: [string, (spec: Record<string, unknown>) => void][] = [
    ...["ingress", "egress"].flatMap((key): [string, (spec: Record<string, unknown>) => void][] => [
      [key + " allow all", (spec) => { spec[key] = [{}]; }],
      [key + " peer rule", (spec) => { spec[key] = [{ [key === "ingress" ? "from" : "to"]: [{ podSelector: {} }] }]; }],
      [key + " port rule", (spec) => { spec[key] = [{ ports: [{ port: 443 }] }]; }],
      [key + " null", (spec) => { spec[key] = null; }],
      [key + " object", (spec) => { spec[key] = {}; }],
      [key + " string", (spec) => { spec[key] = ""; }],
      [key + " undefined", (spec) => { spec[key] = undefined; }],
    ]),
    ["missing selector", (spec) => { delete spec.podSelector; }],
    ["all Pods selector", (spec) => { spec.podSelector = {}; }],
    ["different selector", (spec) => { spec.podSelector = { matchLabels: { app: "other" } }; }],
    ["extra selector expression", (spec) => { (spec.podSelector as Record<string, unknown>).matchExpressions = []; }],
    ["missing policy types", (spec) => { delete spec.policyTypes; }],
    ["ingress only", (spec) => { spec.policyTypes = ["Ingress"]; }],
    ["egress only", (spec) => { spec.policyTypes = ["Egress"]; }],
    ["reordered policy types", (spec) => { spec.policyTypes = ["Egress", "Ingress"]; }],
    ["extra policy type", (spec) => { spec.policyTypes = ["Ingress", "Egress", "Unknown"]; }],
    ["extra spec field", (spec) => { spec.unknown = []; }],
  ];
  for (const [name, mutate] of vectors) {
    const f = fixture();
    const api: ProbeApi = { call: async (method, path, timeout, body) => {
      const data = await f.api.call(method, path, timeout, body);
      if (method === "GET" && path.includes("networkpolicies/")) {
        const policy = data as Resource; policy.spec = structuredClone(serializedDenySpec); mutate(policy.spec);
      }
      return data;
    } };
    const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, f.clock);
    assert.equal(receipt.status, "NETWORK_DENY_MISMATCH", name);
    assert.equal(receipt.passed, false, name); assert.equal(receipt.bytes, null, name); assert.equal(receipt.attemptStartedAt, null, name);
    assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 0, name);
    assert.equal(f.operations.filter((op) => op.method === "DELETE").length, 0, name);
    console.log(JSON.stringify({ fixture: "deny-normalization-reject", name, status: receipt.status, patches: 0, deletes: 0 }));
  }
});

test("API omitted deny rules retain used Job and Pod ownership gates with zero PATCH/DELETE", async () => {
  for (const mode of ["used Job", "existing owned Pod", "foreign Pod"] as const) {
    const f = fixture();
    const api: ProbeApi = { call: async (method, path, timeout, body) => {
      const data = await f.api.call(method, path, timeout, body);
      if (method === "GET" && path.includes("networkpolicies/")) (data as Resource).spec = structuredClone(serializedDenySpec);
      if (method === "GET" && path === jobPath) {
        const job = data as Resource;
        job.status = { ready: 0, terminating: 0, uncountedTerminatedPods: {}, conditions: [structuredClone(initialSuspended)] };
        if (mode === "used Job") job.metadata.generation = 2;
      }
      if (method === "GET" && path.includes("/pods?") && mode !== "used Job") return { items: [{
        metadata: { name: "probe-pod", namespace: "cliproxyapi", uid: "22222222-2222-4222-8222-222222222222", resourceVersion: "10", labels: { "memeloop.io/cpa-work-probe": "directio-20261006a" }, ownerReferences: [{ kind: "Job", controller: true, uid: mode === "foreign Pod" ? "33333333-3333-4333-8333-333333333333" : config.jobUid }] },
        spec: structuredClone((reviewedPlan.spec.template as { spec: PodSpec }).spec),
      }] };
      return data;
    } };
    const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, f.clock);
    assert.equal(receipt.status, mode === "foreign Pod" ? "POD_OWNERSHIP_REJECTED" : "ATTEMPT_ALREADY_USED", mode);
    assert.equal(receipt.passed, false, mode); assert.equal(receipt.bytes, null, mode); assert.equal(receipt.attemptStartedAt, null, mode);
    assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 0, mode);
    assert.equal(f.operations.filter((op) => op.method === "DELETE").length, 0, mode);
    console.log(JSON.stringify({ fixture: "deny-normalization-gates", name: mode, status: receipt.status, patches: 0, deletes: 0 }));
  }
});

test("initial controller Suspended=True condition permits exactly one unsuspend and guarded cleanup", async () => {
  const f = fixture();
  const api: ProbeApi = { call: async (method, path, timeout, body) => {
    const data = await f.api.call(method, path, timeout, body);
    if (method === "GET" && path === jobPath && (data as Resource).spec.suspend === true) {
      (data as Resource).status = { active: 0, failed: 0, succeeded: 0, ready: 0, terminating: 0, uncountedTerminatedPods: { succeeded: [], failed: [] }, conditions: [structuredClone(initialSuspended)] };
    }
    return data;
  } };
  const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, f.clock);
  assert.equal(receipt.status, "COMPLETE"); assert.equal(receipt.passed, true);
  assert.equal(receipt.bytes, 1024 ** 3); assert.equal(receipt.cleanup.complete, true);
  assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1);
  assert.equal(f.operations.filter((op) => op.method === "DELETE").length, 2);
  console.log(JSON.stringify({ fixture: "initial-suspended", status: receipt.status, patches: 1, deletes: 2, cleanup: "confirmed" }));
});

test("suspension misuse, terminal and reused histories reject with zero PATCH/DELETE", async () => {
  const vectors: [string, (job: Resource) => void][] = [
    ["previously unsuspended generation", (job) => { job.metadata.generation = 2; }],
    ["resumed generation", (job) => { job.metadata.generation = 3; }],
    ["missing generation", (job) => { delete job.metadata.generation; }],
    ["not suspended", (job) => { job.spec.suspend = false; }],
    ["deleting Job", (job) => { job.metadata.deletionTimestamp = new Date(epoch).toISOString(); }],
    ["Suspended False", (job) => { job.status!.conditions![0]!.status = "False"; }],
    ["Suspended Unknown", (job) => { job.status!.conditions![0]!.status = "Unknown"; }],
    ["resumed reason", (job) => { job.status!.conditions![0]!.reason = "JobResumed"; }],
    ["missing suspension reason", (job) => { delete job.status!.conditions![0]!.reason; }],
    ["missing suspension message", (job) => { delete job.status!.conditions![0]!.message; }],
    ["contradictory message", (job) => { job.status!.conditions![0]!.message = "Job resumed"; }],
    ["duplicate Suspended", (job) => { job.status!.conditions!.push(structuredClone(initialSuspended)); }],
    ...["Complete", "Failed", "FailureTarget", "SuccessCriteriaMet", "UnknownHistory"].flatMap((type): [string, (job: Resource) => void][] => [
      [type + " True history", (job) => { job.status!.conditions!.push({ type, status: "True" }); }],
      [type + " False history", (job) => { job.status!.conditions!.push({ type, status: "False" }); }],
      [type + " sole condition", (job) => { job.status!.conditions = [{ type, status: "True" }]; }],
    ]),
    ["prior start", (job) => { job.status!.startTime = new Date(epoch).toISOString(); }],
    ["prior completion", (job) => { job.status!.completionTime = new Date(epoch).toISOString(); }],
    ["active Pod", (job) => { job.status!.active = 1; }],
    ["failed Pod", (job) => { job.status!.failed = 1; }],
    ["succeeded Pod", (job) => { job.status!.succeeded = 1; }],
    ["ready Pod", (job) => { job.status!.ready = 1; }],
    ["terminating Pod", (job) => { job.status!.terminating = 1; }],
    ["completed indexes", (job) => { job.status!.completedIndexes = "0"; }],
    ["failed indexes", (job) => { job.status!.failedIndexes = "0"; }],
    ["uncounted success", (job) => { job.status!.uncountedTerminatedPods = { succeeded: ["prior-pod"] }; }],
    ["uncounted failure", (job) => { job.status!.uncountedTerminatedPods = { failed: ["prior-pod"] }; }],
  ];
  for (const [name, mutate] of vectors) {
    const f = fixture();
    const api: ProbeApi = { call: async (method, path, timeout, body) => {
      const data = await f.api.call(method, path, timeout, body);
      if (method === "GET" && path === jobPath) {
        const job = data as Resource; job.status = { conditions: [structuredClone(initialSuspended)] }; mutate(job);
      }
      return data;
    } };
    const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, f.clock);
    assert.equal(receipt.status, "ATTEMPT_ALREADY_USED", name);
    assert.equal(receipt.passed, false, name); assert.equal(receipt.bytes, null, name); assert.equal(receipt.attemptStartedAt, null, name);
    assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 0, name);
    assert.equal(f.operations.filter((op) => op.method === "DELETE").length, 0, name);
    console.log(JSON.stringify({ fixture: "initial-suspended-reject", name, status: receipt.status, patches: 0, deletes: 0 }));
  }
});

test("initial Suspended condition never permits an existing owned Pod", async () => {
  const f = fixture();
  const api: ProbeApi = { call: async (method, path, timeout, body) => {
    const data = await f.api.call(method, path, timeout, body);
    if (method === "GET" && path === jobPath) (data as Resource).status = { conditions: [structuredClone(initialSuspended)] };
    if (method === "GET" && path.includes("/pods?")) return { items: [{ metadata: { name: "probe-pod", namespace: "cliproxyapi", uid: "22222222-2222-4222-8222-222222222222", resourceVersion: "10", labels: { "memeloop.io/cpa-work-probe": "directio-20261006a" }, ownerReferences: [{ kind: "Job", controller: true, uid: config.jobUid }] }, spec: structuredClone((reviewedPlan.spec.template as { spec: PodSpec }).spec) }] };
    return data;
  } };
  const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, f.clock);
  assert.equal(receipt.status, "ATTEMPT_ALREADY_USED");
  assert.equal(receipt.passed, false); assert.equal(receipt.bytes, null); assert.equal(receipt.attemptStartedAt, null);
  assert.equal(f.operations.some((op) => op.method !== "GET"), false);
});

function template(job: Resource): PodSpec { return (job.spec.template as { spec: PodSpec }).spec; }
function context(spec: PodSpec, role: "containers" | "initContainers"): Record<string, unknown> {
  return (spec[role] as Record<string, unknown>[])[0]!.securityContext as Record<string, unknown>;
}

test("N1 exact preflight fixtures reject nested privilege, seccomp and Job control expansion with zero PATCH/DELETE", async () => {
  const vectors: [string, (job: Resource) => void][] = [
    ["directio privileged true", (job) => { context(template(job), "containers").privileged = true; }],
    ["init privileged true", (job) => { context(template(job), "initContainers").privileged = true; }],
    ["directio add SYS_ADMIN retaining drop ALL", (job) => { (context(template(job), "containers").capabilities as Record<string, unknown>).add = ["SYS_ADMIN"]; }],
    ["init add SYS_ADMIN retaining CHOWN and drop ALL", (job) => { (context(template(job), "initContainers").capabilities as Record<string, unknown>).add = ["CHOWN", "SYS_ADMIN"]; }],
    ["pod seccomp Unconfined", (job) => { (template(job).securityContext as Record<string, unknown>).seccompProfile = { type: "Unconfined" }; }],
    ["pod seccomp unexpected nested profile", (job) => { (template(job).securityContext as Record<string, unknown>).seccompProfile = { type: "RuntimeDefault", localhostProfile: "unreviewed" }; }],
    ["directio seccomp Unconfined override", (job) => { context(template(job), "containers").seccompProfile = { type: "Unconfined" }; }],
    ["init seccomp Unconfined override", (job) => { context(template(job), "initContainers").seccompProfile = { type: "Unconfined" }; }],
    ["directio runAsUser root override", (job) => { context(template(job), "containers").runAsUser = 0; }],
    ["directio procMount Unmasked", (job) => { context(template(job), "containers").procMount = "Unmasked"; }],
    ["pod extra supplemental group", (job) => { (template(job).securityContext as Record<string, unknown>).supplementalGroups = [0]; }],
    ["pod hostPID true", (job) => { template(job).hostPID = true; }],
    ["pod unreviewed runtime class", (job) => { template(job).runtimeClassName = "unreviewed"; }],
    ["Job manual selector true", (job) => { job.spec.manualSelector = true; }],
    ["Job Indexed completion", (job) => { job.spec.completionMode = "Indexed"; }],
    ["Job per-index retry", (job) => { job.spec.backoffLimitPerIndex = 1; }],
    ["Job ignore failure policy", (job) => { job.spec.podFailurePolicy = { rules: [{ action: "Ignore", onExitCodes: { operator: "In", values: [1] } }] }; }],
    ["Job unreviewed success policy", (job) => { job.spec.successPolicy = { rules: [{ succeededCount: 1 }] }; }],
    ["Job foreign controller", (job) => { job.spec.managedBy = "unreviewed.example/controller"; }],
    ["Job foreign selector", (job) => { job.spec.selector = { matchLabels: { app: "other" } }; }],
    ["Job automatic TTL deletion", (job) => { job.spec.ttlSecondsAfterFinished = 0; }],
  ];
  for (const [name, mutate] of vectors) {
    const f = fixture();
    const api: ProbeApi = { call: async (method, path, timeout, body) => {
      const data = await f.api.call(method, path, timeout, body);
      if (method === "GET" && path === jobPath) mutate(data as Resource);
      return data;
    } };
    const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, f.clock);
    assert.match(receipt.status, /^UNSAFE_(CONTAINER_SPEC|SECURITY_CONTEXT|POD_SPEC|JOB_CONTROL)$/, name);
    assert.equal(receipt.passed, false, name); assert.equal(receipt.bytes, null, name);
    assert.equal(receipt.attemptStartedAt, null, name);
    assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 0, name);
    assert.equal(f.operations.filter((op) => op.method === "DELETE").length, 0, name);
    console.log(JSON.stringify({ fixture: "N1", name, status: receipt.status, patches: 0, deletes: 0 }));
  }
});

test("N1 normal Kubernetes defaults and inherited reviewed security remain accepted through operator cleanup", async () => {
  const f = fixture();
  const normalDefaults = (resource: Resource) => {
    const isJob = resource.spec.template !== undefined;
    const spec = isJob ? template(resource) : resource.spec;
    if (isJob) Object.assign(resource.spec, { parallelism: 1, completions: 1, manualSelector: false, completionMode: "NonIndexed", podReplacementPolicy: "TerminatingOrFailed", managedBy: "kubernetes.io/job-controller", selector: { matchLabels: { "batch.kubernetes.io/controller-uid": config.jobUid } } });
    Object.assign(spec, { hostNetwork: false, hostPID: false, hostIPC: false, shareProcessNamespace: false, hostUsers: true, imagePullSecrets: [], resourceClaims: [], hostAliases: [], ephemeralContainers: [], dnsPolicy: "ClusterFirst", schedulerName: "default-scheduler", serviceAccountName: "default" });
    Object.assign(spec.securityContext as Record<string, unknown>, { supplementalGroups: [], sysctls: [], fsGroupChangePolicy: "Always" });
    for (const role of ["containers", "initContainers"] as const) {
      const container = (spec[role] as Record<string, unknown>[])[0]!;
      Object.assign(container, { imagePullPolicy: "IfNotPresent", terminationMessagePath: "/dev/termination-log", terminationMessagePolicy: "File" });
      Object.assign(context(spec, role), { privileged: false, procMount: "Default", seccompProfile: { type: "RuntimeDefault" } });
    }
    Object.assign(context(spec, "containers"), { runAsUser: 10001, runAsGroup: 10001, runAsNonRoot: true });
    (context(spec, "containers").capabilities as Record<string, unknown>).add = [];
  };
  const api: ProbeApi = { call: async (method, path, timeout, body) => {
    const data = await f.api.call(method, path, timeout, body);
    if (method === "GET") {
      if (path === jobPath || path === podPath) {
        normalDefaults(data as Resource);
        if (path === jobPath && (data as Resource).spec.suspend === true) (data as Resource).status = { conditions: [structuredClone(initialSuspended)] };
      } else if (path.includes("/pods?")) for (const pod of (data as { items: Resource[] }).items) normalDefaults(pod);
    }
    return data;
  } };
  const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, f.clock);
  assert.equal(receipt.status, "COMPLETE"); assert.equal(receipt.passed, true);
  assert.equal(receipt.cleanup.complete, true); assert.equal(receipt.decision?.execDeadline, epoch + 345_000);
  assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1);
  assert.equal(f.operations.filter((op) => op.method === "DELETE").length, 2);
  console.log(JSON.stringify({ fixture: "N1-normal-defaults", status: receipt.status, patches: 1, deletes: 2, cleanup: "confirmed" }));
});

test("cleanup RV conflict never deletes a Pod while its original Job remains active", async () => {
  const f = fixture();
  const transport: ProbeApi = { call: async (method, path, timeout, body) => {
    if (method === "DELETE" && path === jobPath) throw new ApiFailure(409);
    return f.api.call(method, path, timeout, body);
  } };
  const receipt = await runProbe(config, transport, reviewedPlan, reviewedPolicy, f.clock);
  assert.equal(receipt.passed, false);
  assert.ok(receipt.cleanup.errors.includes("JOB_STOP_UNCONFIRMED"));
  assert.equal(f.operations.some((op) => op.method === "DELETE" && op.path === podPath), false);
});

test("definitive unsuspend conflict acquires no attempt and never cleans a concurrent actor's Job", async () => {
  const f = fixture(); let patches = 0;
  const transport: ProbeApi = { call: async (method, path, timeout, body) => {
    if (method === "PATCH") { patches++; throw new ApiFailure(409); }
    return f.api.call(method, path, timeout, body);
  } };
  const receipt = await runProbe(config, transport, reviewedPlan, reviewedPolicy, f.clock);
  assert.equal(patches, 1); assert.equal(receipt.status, "API_FAILED");
  assert.equal(receipt.attemptStartedAt, null); assert.equal(receipt.bytes, null);
  assert.equal(f.operations.some((op) => op.method === "DELETE"), false);
});

test("operator fails closed on UID replacements, slow observation and cleanup noncompletion without spillover", async () => {
  for (const mode of ["job-replacement", "pvc-replacement", "replacement", "post-log-replacement", "stale", "cleanup-timeout"] as const) {
    const f = fixture(mode); const receipt = await runProbe(config, f.api, reviewedPlan, reviewedPolicy, f.clock);
    assert.equal(receipt.passed, false, mode);
    if (mode === "job-replacement") assert.equal(f.operations.filter((op) => op.method === "DELETE").length, 0);
    if (mode === "replacement" || mode === "post-log-replacement") assert.equal(f.operations.some((op) => op.method === "DELETE" && op.path === podPath), false);
    if (mode === "cleanup-timeout") assert.ok(receipt.cleanup.errors.includes("CLEANUP_DEADLINE_OR_UNCONFIRMED"));
    assert.ok(f.operations.every((op) => op.method !== "DELETE" || op.path === jobPath || op.path === podPath));
    assert.ok(f.now() <= epoch + PROBE_BUDGET.totalMs + PROBE_BUDGET.cleanupMs);
  }
});

test("diagnostics retain observation GET and separate ambiguous cleanup DELETE without replay or private data", async () => {
  const f = fixture(); let patched = false, failedRead = false, deletes = 0;
  const api: ProbeApi = { call: async (method, path, timeout, body) => {
    if (method === "GET" && patched && !failedRead) {
      failedRead = true;
      throw new ApiTransportFailure("API_TRANSPORT_FAILED", "SOCKET_RESET", null);
    }
    if (method === "DELETE") {
      deletes++;
      throw new ApiTransportFailure("API_TRANSPORT_FAILED", "REQUEST_DEADLINE", null);
    }
    const value = await f.api.call(method, path, timeout, body);
    if (method === "PATCH") patched = true;
    return value;
  } };
  let firstSleep = true;
  const clock: ProbeClock = { ...f.clock, sleep: async (ms) => { if (firstSleep) { firstSleep = false; f.setNow(f.now() + ms); } else await f.clock.sleep(ms); } };
  const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, clock);
  assert.equal(receipt.status, "COMPLETE"); assert.equal(receipt.passed, false);
  const [read, cleanup] = receipt.apiDiagnostics.failures;
  assert.ok(read && cleanup);
  assert.equal(read.method, "GET"); assert.equal(read.stage, "OBSERVATION"); assert.equal(read.resource, "JOB");
  assert.equal(read.category, "SOCKET_RESET"); assert.equal(read.httpStatus, null);
  assert.equal(read.acknowledgement, "NOT_APPLICABLE");
  assert.equal(read.previousSuccessfulCall?.method, "PATCH");
  assert.equal(read.previousSuccessfulCall?.stage, "UNSUSPEND");
  assert.equal(read.previousSuccessfulCall?.acknowledgement, "RESPONSE_RECEIVED");
  assert.equal(cleanup.method, "DELETE"); assert.equal(cleanup.stage, "CLEANUP_JOB");
  assert.equal(cleanup.category, "REQUEST_DEADLINE"); assert.equal(cleanup.acknowledgement, "UNKNOWN");
  assert.equal(deletes, 1); assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1);
  assert.deepEqual(receipt.cleanup.errors, ["JOB_STOP_UNCONFIRMED", "POD_STOP_SKIPPED_JOB_UNCONFIRMED"]);
  assert.deepEqual(receipt.budgets, PROBE_BUDGET);
  const diagnosticText = JSON.stringify(receipt.apiDiagnostics);
  for (const privateValue of [config.jobName, config.jobUid, config.pvcUid, "/apis/", "/api/", "preconditions", "headers", "body"]) assert.ok(!diagnosticText.includes(privateValue), privateValue);
});

test("unsuspend diagnostics distinguish a lost acknowledgement from definitive HTTP rejection", async () => {
  for (const rejected of [false, true]) {
    const f = fixture(); let patches = 0;
    const api: ProbeApi = { call: async (method, path, timeout, body) => {
      if (method === "PATCH") {
        patches++;
        if (rejected) throw new ApiFailure(409);
        // Simulate server application followed by a lost reply.
        await f.api.call(method, path, timeout, body);
        throw new ApiTransportFailure("API_TRANSPORT_FAILED", "SOCKET_RESET", null);
      }
      return f.api.call(method, path, timeout, body);
    } };
    const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, f.clock);
    const failure = receipt.apiDiagnostics.failures[0]!;
    assert.equal(patches, 1); assert.equal(failure.stage, "UNSUSPEND"); assert.equal(failure.method, "PATCH");
    assert.equal(failure.acknowledgement, rejected ? "REJECTED_4XX" : "UNKNOWN");
    assert.equal(failure.httpStatus, rejected ? 409 : null);
    assert.equal(failure.category, rejected ? "HTTP_STATUS" : "SOCKET_RESET");
    assert.equal(receipt.cleanup.complete, !rejected);
    assert.equal(f.operations.filter((op) => op.method === "DELETE").length, rejected ? 0 : 1);
  }
});

test("Unix transport reports fixed deadline, reset, body limit, read abort and JSON categories without raw errors", { timeout: 10_000 }, async () => {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  const directory = mkdtempSync(join(tmpdir(), "cpa-transport-fixture-"));
  const socket = join(directory, "api.sock");
  const server = createServer((req, res) => {
    if (req.url === "/deadline") return;
    if (req.url === "/reset") { req.socket.destroy(); return; }
    if (req.url === "/abort") {
      res.writeHead(200, { "Content-Length": "100" }); res.flushHeaders();
      setTimeout(() => res.destroy(), 20); return;
    }
    if (req.url === "/limit") { res.end("x".repeat(1024 * 1024 + 1)); return; }
    if (req.url === "/json") { res.end("private-response-marker"); return; }
    if (req.url === "/status") { res.statusCode = 503; res.end("private-response-marker"); return; }
    res.end("{}");
  });
  try {
    await new Promise<void>((resolveListening, reject) => { server.once("error", reject); server.listen(socket, resolveListening); });
    const api = unixApi(socket);
    for (const [path, category, status] of [["/deadline", "REQUEST_DEADLINE", null], ["/reset", "SOCKET_RESET", null], ["/abort", "RESPONSE_ABORTED", 200], ["/limit", "RESPONSE_LIMIT", 200], ["/json", "JSON_INVALID", 200]] as const) {
      await assert.rejects(api.call("GET", path, path === "/deadline" ? 50 : 1000), (error: unknown) => {
        assert.ok(error instanceof ApiTransportFailure);
        assert.equal(error.category, category); assert.equal(error.statusCode, status);
        assert.ok(!error.message.includes("private-response-marker")); return true;
      });
    }
    await assert.rejects(api.call("GET", "/status", 1000), (error: unknown) => error instanceof ApiFailure && error.statusCode === 503);
    await api.call("GET", "/ok", 1000);
    assert.equal(api.lastResponseStatus?.(), 200);
    await assert.rejects(unixApi(join(directory, "missing.sock")).call("GET", "/", 1000), (error: unknown) => error instanceof ApiTransportFailure && error.category === "SOCKET_MISSING");
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolveClosed) => server.close(() => resolveClosed()));
    rmSync(directory, { recursive: true, force: true });
  }
});

test("real CLI decision entry uses Unix HTTP and guarded startup-failure cleanup, no cluster", { timeout: 30_000 }, async () => {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  const directory = mkdtempSync(join(tmpdir(), "cpa-operator-cli-"));
  const socket = join(directory, "api.sock"), input = join(directory, "config.json");
  writeFileSync(input, JSON.stringify(config), { mode: 0o600 });
  const f = fixture("init");
  const server = createServer(async (req, res) => {
    try {
      const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const text = Buffer.concat(chunks).toString("utf8");
      f.setNow(Date.now());
      const data = await f.api.call(req.method as "GET" | "PATCH" | "DELETE", req.url!, PROBE_BUDGET.apiMs, text ? JSON.parse(text) : undefined);
      res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(data));
    } catch (error) { res.statusCode = error instanceof ApiFailure ? error.statusCode : 500; res.end("{}"); }
  });
  try {
    await new Promise<void>((resolveListening, reject) => { server.once("error", reject); server.listen(socket, resolveListening); });
    const result = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolveExit, reject) => {
      const child = spawn(process.execPath, [resolve("ops/inspection/cpa-work-probe-operator.ts"), "--execute-authorized-target-only", input, "--api-socket", socket], { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "", stderr = "";
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("CLI_TEST_DEADLINE")); }, 20_000);
      child.stdout.on("data", (chunk) => { stdout += chunk; }); child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.on("error", reject); child.on("exit", (code) => { clearTimeout(timer); resolveExit({ code, stdout, stderr }); });
    });
    assert.equal(result.code, 1, result.stderr);
    const receipt = JSON.parse(result.stdout);
    assert.equal(receipt.status, "STARTUP_FAILED"); assert.equal(receipt.bytes, null); assert.equal(receipt.cleanup.complete, true);
    assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1);
    assert.equal(f.operations.filter((op) => op.method === "DELETE").length, 2);
  } finally {
    await new Promise<void>((resolveClosed) => server.close(() => resolveClosed())); rmSync(directory, { recursive: true, force: true });
  }
});

test("GET-only recovery keeps three-call cap, original phase deadline and permanent rejection", async () => {
  for (const mode of ["reset", "deadline", "502", "503", "504", "cap", "403", "json", "phase-deadline", "replacement", "spec-mismatch", "cleanup-deadline"] as const) {
    const f = fixture(); let patched = false, failed = 0, retrySleep = false, deletes = 0, cleanupStart = 0;
    const recoveryClock: ProbeClock = { ...f.clock, sleep: async (ms) => {
      if (retrySleep) { f.setNow(f.now() + ms); retrySleep = false; }
      else await f.clock.sleep(ms);
    } };
    const api: ProbeApi = { call: async (method, path, timeout, body) => {
      if (method === "PATCH") patched = true;
      if (method === "DELETE") { deletes++; if (!cleanupStart) cleanupStart = f.now(); }
      if (method === "GET" && patched && path === jobPath && deletes === 0 && (failed === 0 || mode === "cap" && failed < 3)) {
        failed++; retrySleep = true;
        if (mode === "phase-deadline") f.setNow(epoch + PROBE_BUDGET.startupMs - 500);
        if (mode === "403") throw new ApiFailure(403);
        if (mode === "json") throw new ApiTransportFailure("API_JSON_INVALID", "JSON_INVALID", 200);
        if (["502", "503", "504"].includes(mode)) throw new ApiFailure(Number(mode));
        throw new ApiTransportFailure("API_TRANSPORT_FAILED", mode === "deadline" ? "REQUEST_DEADLINE" : "SOCKET_RESET", null);
      }
      if (mode === "cleanup-deadline" && deletes && method === "GET" && path === jobPath) {
        f.setNow(cleanupStart + PROBE_BUDGET.cleanupMs - 500);
        throw new ApiFailure(503);
      }
      const value = await f.api.call(method, path, timeout, body);
      if (method === "GET" && path === jobPath && patched && deletes === 0 && failed && mode === "replacement") (value as Resource).metadata.uid = "replacement";
      if (method === "GET" && path === jobPath && patched && deletes === 0 && failed && mode === "spec-mismatch") ((value as Resource).spec.template as {spec: Record<string, unknown>}).spec.hostNetwork = true;
      return value;
    } };
    const receipt = await runProbe(config, api, reviewedPlan, reviewedPolicy, recoveryClock);
    const recovered = ["reset", "deadline", "502", "503", "504"].includes(mode);
    assert.equal(receipt.passed, recovered, mode);
    assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1, mode);
    assert.ok(deletes <= 2, mode);
    assert.equal(failed, mode === "cap" ? 3 : 1, mode);
    assert.equal(receipt.apiDiagnostics.failures[0]?.stage, "OBSERVATION", mode);
    assert.ok(receipt.apiDiagnostics.failures.every((entry) => entry.timeoutMs <= 2000), mode);
    if (mode === "phase-deadline") assert.ok(f.now() <= epoch + PROBE_BUDGET.startupMs + PROBE_BUDGET.cleanupMs);
    if (mode === "cleanup-deadline") { assert.equal(receipt.cleanup.complete,false); assert.ok(f.now() <= cleanupStart + PROBE_BUDGET.cleanupMs); }
  }
});

const claimName = "mtc-cpa-recovery-work-20261005";
function foreignConsumer(name: string, status?: Resource["status"]): Resource {
  return { metadata: { name, namespace: "cliproxyapi", uid: `historical-${name}`, resourceVersion: "1" }, spec: { volumes: [{ persistentVolumeClaim: { claimName } }] }, ...(status === undefined ? {} : { status }) };
}
function withConsumers(f: ReturnType<typeof fixture>, consumers: Resource[]): ProbeApi {
  return { call: async (method, path, timeout, body) => {
    const value = await f.api.call(method, path, timeout, body);
    return method === "GET" && path === `${ns}/pods` ? { items: [...(value as { items: Resource[] }).items, ...structuredClone(consumers)] } : value;
  } };
}

test("four supplied terminal PVC references coexist with one successful owned probe", async () => {
  // Exact sanitized status shape from the 05:20 terminal-consumer receipt.
  // No restartCount or other optional status fields are invented for this evidence.
  const historical = [
    {
      "metadata": {
        "name": "mtc-cpa-copy-destination-inspect-20261005",
        "namespace": "cliproxyapi",
        "uid": "13eec83e-c09c-4649-8792-6908df9d1cb6",
        "resourceVersion": "72426988"
      },
      "spec": {
        "volumes": [
          {
            "persistentVolumeClaim": {
              "claimName": "mtc-cpa-recovery-work-20261005"
            }
          }
        ]
      },
      "status": {
        "phase": "Succeeded",
        "containerStatuses": [
          {
            "name": "inspect",
            "state": {
              "terminated": {
                "exitCode": 0,
                "finishedAt": "2026-10-05T18:10:31Z",
                "reason": "Completed",
                "startedAt": "2026-10-05T18:10:30Z"
              }
            }
          }
        ],
        "initContainerStatuses": [],
        "ephemeralContainerStatuses": []
      }
    },
    {
      "metadata": {
        "name": "mtc-cpa-copy-destination-inspect-20261005b",
        "namespace": "cliproxyapi",
        "uid": "b94d92c1-29a4-474b-a559-5f77c1090408",
        "resourceVersion": "72429427"
      },
      "spec": {
        "volumes": [
          {
            "persistentVolumeClaim": {
              "claimName": "mtc-cpa-recovery-work-20261005"
            }
          }
        ]
      },
      "status": {
        "phase": "Succeeded",
        "containerStatuses": [
          {
            "name": "inspect",
            "state": {
              "terminated": {
                "exitCode": 0,
                "finishedAt": "2026-10-05T18:14:41Z",
                "reason": "Completed",
                "startedAt": "2026-10-05T18:14:41Z"
              }
            }
          }
        ],
        "initContainerStatuses": [],
        "ephemeralContainerStatuses": []
      }
    },
    {
      "metadata": {
        "name": "mtc-cpa-recovery-copy-20261005-4mz8q",
        "namespace": "cliproxyapi",
        "uid": "bdd35434-e245-4a56-94eb-06f4dd1cface",
        "resourceVersion": "72423323"
      },
      "spec": {
        "volumes": [
          {
            "persistentVolumeClaim": {
              "claimName": "mtc-cpa-recovery-work-20261005"
            }
          }
        ]
      },
      "status": {
        "phase": "Failed",
        "containerStatuses": [
          {
            "name": "verified-copy",
            "state": {
              "waiting": {
                "reason": "PodInitializing"
              }
            }
          }
        ],
        "initContainerStatuses": [
          {
            "name": "create-new-private-destination",
            "state": {
              "terminated": {
                "exitCode": 1,
                "finishedAt": "2026-10-05T18:04:22Z",
                "reason": "Error",
                "startedAt": "2026-10-05T18:04:21Z"
              }
            }
          }
        ],
        "ephemeralContainerStatuses": []
      }
    },
    {
      "metadata": {
        "name": "mtc-cpa-recovery-copy-20261005-r2-62tt6",
        "namespace": "cliproxyapi",
        "uid": "2532863b-36e5-4a20-b89f-9260b4c8a4a7",
        "resourceVersion": "72445061"
      },
      "spec": {
        "volumes": [
          {
            "persistentVolumeClaim": {
              "claimName": "mtc-cpa-recovery-work-20261005"
            }
          }
        ]
      },
      "status": {
        "phase": "Failed",
        "containerStatuses": [
          {
            "name": "verified-copy",
            "state": {
              "terminated": {
                "exitCode": 1,
                "finishedAt": "2026-10-05T18:41:48Z",
                "reason": "Error",
                "startedAt": "2026-10-05T18:21:33Z"
              }
            }
          }
        ],
        "initContainerStatuses": [
          {
            "name": "create-new-private-destination",
            "state": {
              "terminated": {
                "exitCode": 0,
                "finishedAt": "2026-10-05T18:21:32Z",
                "reason": "Completed",
                "startedAt": "2026-10-05T18:21:32Z"
              }
            }
          }
        ],
        "ephemeralContainerStatuses": []
      }
    }
  ] as unknown as Resource[];
  const original = structuredClone(historical);
  for (const deleting of [false, true]) {
    const references = structuredClone(historical);
    if (deleting) for (const pod of references) pod.metadata.deletionTimestamp = new Date(epoch).toISOString();
    const f = fixture();
    const receipt = await runProbe(config, withConsumers(f, references), reviewedPlan, reviewedPolicy, f.clock);
    assert.equal(receipt.status, "COMPLETE"); assert.equal(receipt.passed, true);
    assert.equal(receipt.bytes, 1024 ** 3); assert.equal(receipt.cleanup.complete, true);
    assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1);
    assert.deepEqual(f.operations.filter((op) => op.method === "DELETE").map((op) => op.path), [jobPath, podPath]);
    assert.ok(f.operations.every((op) => !references.some((pod) => op.path.includes(pod.metadata.name))));
    console.log(JSON.stringify({ fixture: "terminal-consumers-accept", historical: 4, deleting, status: receipt.status, patches: 1, deletes: 2 }));
  }
  assert.deepEqual(historical, original);
});

test("terminal waiting containers need no specific reason, name or optional status fields", async () => {
  for (const phase of ["Succeeded", "Failed"]) {
    for (const field of ["containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"] as const) {
      for (const waiting of [{}, { reason: "UnrelatedWaitingReason" }, { reason: "PodInitializing" }]) {
        for (const deleting of [false, true]) {
          const consumer = foreignConsumer("arbitrary-terminal-name", { phase, [field]: [{ state: { waiting } }] } as Resource["status"]);
          if (deleting) consumer.metadata.deletionTimestamp = new Date(epoch).toISOString();
          const f = fixture();
          const receipt = await runProbe(config, withConsumers(f, [consumer]), reviewedPlan, reviewedPolicy, f.clock);
          assert.equal(receipt.status, "COMPLETE"); assert.equal(receipt.passed, true);
          assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1);
          assert.deepEqual(f.operations.filter((op) => op.method === "DELETE").map((op) => op.path), [jobPath, podPath]);
          console.log(JSON.stringify({ fixture: "terminal-waiting-accept", phase, field, waiting, deleting, status: receipt.status, patches: 1, deletes: 2 }));
        }
      }
    }
  }
});

test("active, missing and ambiguous PVC consumers reject before any mutation", async () => {
  const vectors: [string, Resource["status"]][] = [
    ["missing status", undefined], ["missing phase", {}],
    ...["Pending", "Running", "Unknown", "", "Unrecognized"].map((phase): [string, Resource["status"]] => [phase || "empty phase", { phase }]),
  ];
  for (const phase of ["Succeeded", "Failed"]) {
    for (const field of ["containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"] as const) {
      for (const [name, state] of [
        ["running", { running: { startedAt: new Date(epoch).toISOString() } }],
        ["unknown", {}],
        ["contradictory", { running: { startedAt: new Date(epoch).toISOString() }, terminated: { finishedAt: new Date(epoch).toISOString(), exitCode: 0 } }],
      ] as const) vectors.push([`${phase}/${field}/${name}`, { phase, [field]: [{ name: "foreign", restartCount: 0, state }] }]);
      for (const malformed of [null, {}, [null], [{ name: "foreign" }], [{ state: { terminated: null } }], [{ state: { waiting: null } }], [{ state: { waiting: {}, terminated: {} } }]]) {
        vectors.push([`${phase}/${field}/malformed-${JSON.stringify(malformed)}`, { phase, [field]: malformed } as unknown as Resource["status"]]);
      }
    }
  }
  for (const [name, status] of vectors) {
    for (const deleting of [false, true]) {
      const consumer = foreignConsumer("foreign", status);
      if (deleting) consumer.metadata.deletionTimestamp = new Date(epoch).toISOString();
      const f = fixture();
      const receipt = await runProbe(config, withConsumers(f, [consumer]), reviewedPlan, reviewedPolicy, f.clock);
      assert.equal(receipt.status, "PVC_CONSUMER_CONFLICT", name); assert.equal(receipt.passed, false, name);
      assert.equal(receipt.attemptStartedAt, null, name); assert.equal(receipt.podUid, null, name); assert.equal(receipt.bytes, null, name);
      assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 0, name);
      assert.equal(f.operations.filter((op) => op.method === "DELETE").length, 0, name);
      console.log(JSON.stringify({ fixture: "terminal-consumers-reject", name, deleting, status: receipt.status, patches: 0, deletes: 0 }));
    }
  }
});

test("active cross-PVC consumers are ignored and deleting owned consumers remain conflicts", async () => {
  const foreign = foreignConsumer("other-claim", { phase: "Running" });
  foreign.spec.volumes = [{ persistentVolumeClaim: { claimName: "unrelated-pvc" } }];
  foreign.metadata.deletionTimestamp = new Date(epoch).toISOString();
  const f = fixture();
  const receipt = await runProbe(config, withConsumers(f, [foreign]), reviewedPlan, reviewedPolicy, f.clock);
  assert.equal(receipt.passed, true); assert.equal(receipt.cleanup.complete, true);
  assert.equal(f.operations.filter((op) => op.method === "PATCH").length, 1);
  assert.deepEqual(f.operations.filter((op) => op.method === "DELETE").map((op) => op.path), [jobPath, podPath]);
  const owned = foreignConsumer("deleting-owned", { phase: "Running" });
  owned.metadata.ownerReferences = [{ kind: "Job", controller: true, uid: config.jobUid }];
  owned.metadata.deletionTimestamp = new Date(epoch).toISOString();
  const g = fixture();
  const rejected = await runProbe(config, withConsumers(g, [owned]), reviewedPlan, reviewedPolicy, g.clock);
  assert.equal(rejected.status, "PVC_CONSUMER_CONFLICT");
  assert.equal(g.operations.filter((op) => op.method !== "GET").length, 0);
});

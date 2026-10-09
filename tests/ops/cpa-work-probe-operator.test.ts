import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseAllDocuments } from "yaml";
import { PROBE_BUDGET } from "../../ops/inspection/cpa-work-probe-budget.ts";
import { ApiFailure, runProbe, type ProbeApi, type ProbeClock, type ProbeConfig, type Resource } from "../../ops/inspection/cpa-work-probe-operator.ts";

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

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
  let job: Resource = { ...structuredClone(reviewedPlan), metadata: { name: config.jobName, namespace: "cliproxyapi", uid: config.jobUid, resourceVersion: "1" } };
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

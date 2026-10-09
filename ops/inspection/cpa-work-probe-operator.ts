import { request } from "node:http";
import { spawn } from "node:child_process";
import { lstatSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { parseAllDocuments } from "yaml";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";
import { PROBE_BUDGET, probeBudget, timestamp, validateBudgets, type ContainerState, type ProbeBudgets, type ProbeObservation } from "./cpa-work-probe-budget.ts";

const NS = "cliproxyapi";
const CLAIM = "mtc-cpa-recovery-work-20261005";
const PVC_UID = "a5045b54-0f10-4f60-b1f5-18167620ba31";
const CORE = `/api/v1/namespaces/${NS}`;
const JOBS = `/apis/batch/v1/namespaces/${NS}/jobs`;
const POLICY = `/apis/networking.k8s.io/v1/namespaces/${NS}/networkpolicies/mtc-cpa-work-directio-20261006a`;
type Metadata = { name: string; namespace: string; uid: string; resourceVersion: string; labels?: Record<string, string>; deletionTimestamp?: string; ownerReferences?: { uid: string; kind: string; controller?: boolean }[] };
type ContainerStatus = { name: string; restartCount: number; state: ContainerState };
export interface Resource {
  metadata: Metadata;
  spec: Record<string, unknown>;
  status?: { startTime?: string; phase?: string; active?: number; failed?: number; succeeded?: number; conditions?: { type: string; status: string }[]; containerStatuses?: ContainerStatus[]; initContainerStatuses?: ContainerStatus[] };
}
export interface ProbeConfig {
  jobName: string; jobUid: string; jobResourceVersion: string;
  pvcUid: string; pvcResourceVersion: string; budgets: ProbeBudgets;
}
export interface ProbeApi { call(method: "GET" | "PATCH" | "DELETE", path: string, timeoutMs: number, body?: unknown): Promise<unknown> }
export interface ProbeClock { now(): number; sleep(ms: number): Promise<void>; cancelled(): boolean }
const realClock = (): ProbeClock => {
  const wall = Date.now(), mono = performance.now();
  let cancelled = false;
  const cancel = () => { cancelled = true; };
  process.once("SIGTERM", cancel); process.once("SIGINT", cancel);
  return { now: () => wall + Math.ceil(performance.now() - mono) + 1, sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)), cancelled: () => cancelled };
};
export class ApiFailure extends Error {
  readonly statusCode: number;
  constructor(statusCode: number) { super(statusCode === 404 ? "NOT_FOUND" : "API_FAILED"); this.statusCode = statusCode; }
}

// Transport exposes only the local Unix socket, never TCP or a credential read.
export function unixApi(socketPath: string): ProbeApi {
  return { call: (method, path, timeoutMs, body) => new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = request({ socketPath, path, method, headers: payload === undefined ? {} : { "Content-Type": method === "PATCH" ? "application/json-patch+json" : "application/json", "Content-Length": Buffer.byteLength(payload) } }, (res) => {
      const chunks: Buffer[] = []; let size = 0;
      res.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 1024 * 1024) req.destroy(new Error("API_RESPONSE_LIMIT")); else chunks.push(chunk); });
      res.on("error", () => reject(new Error("API_READ_FAILED")));
      res.on("end", () => {
        if ((res.statusCode ?? 500) >= 300) { reject(new ApiFailure(res.statusCode ?? 500)); return; }
        const text = Buffer.concat(chunks).toString("utf8");
        try { resolve(path.includes("/log?") ? text : JSON.parse(text)); } catch { reject(new Error("API_JSON_INVALID")); }
      });
    });
    const timer = setTimeout(() => req.destroy(new Error("API_DEADLINE")), Math.max(1, timeoutMs));
    req.on("close", () => clearTimeout(timer));
    req.on("error", () => reject(new Error("API_TRANSPORT_FAILED")));
    req.end(payload);
  }) };
}

function identity(resource: Resource, name: string, uid: string, rv?: string): void {
  if (!resource?.metadata || resource.metadata.name !== name || resource.metadata.namespace !== NS || resource.metadata.uid !== uid || !resource.metadata.resourceVersion || rv !== undefined && resource.metadata.resourceVersion !== rv) throw new Error("IDENTITY_MISMATCH");
}
function owned(pod: Resource, jobUid: string): boolean {
  const controllers = pod.metadata.ownerReferences?.filter((owner) => owner.controller) ?? [];
  return controllers.length === 1 && controllers[0]!.kind === "Job" && controllers[0]!.uid === jobUid;
}
function subset(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length && expected.every((value, i) => subset(actual[i], value));
  if (expected !== null && typeof expected === "object") return actual !== null && typeof actual === "object" && Object.entries(expected).every(([key, value]) => subset((actual as Record<string, unknown>)[key], value));
  return isDeepStrictEqual(actual, expected);
}
function validatePodSpec(actual: Record<string, unknown>, expected: Record<string, unknown>): void {
  if (!subset(actual, expected) || ["hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"].some((key) => actual[key] === true)) throw new Error("UNSAFE_POD_SPEC");
  if (!isDeepStrictEqual(actual.volumes, expected.volumes)) throw new Error("UNSAFE_VOLUMES");
  if (!isDeepStrictEqual(actual.securityContext, expected.securityContext)) throw new Error("UNSAFE_SECURITY_CONTEXT");
  for (const key of ["containers", "initContainers"]) {
    const containers = actual[key] as Record<string, unknown>[];
    const reviewed = expected[key] as Record<string, unknown>[];
    for (let i = 0; i < containers.length; i++) {
      const container = containers[i]!;
      const allowed = new Set([...Object.keys(reviewed[i]!), "imagePullPolicy", "terminationMessagePath", "terminationMessagePolicy"]);
      if (Object.keys(container).some((field) => !allowed.has(field)) || !isDeepStrictEqual(container.volumeMounts, reviewed[i]!.volumeMounts) || !isDeepStrictEqual(container.securityContext, reviewed[i]!.securityContext) || !isDeepStrictEqual(container.resources, reviewed[i]!.resources)) throw new Error("UNSAFE_CONTAINER_SPEC");
    }
  }
  if (actual.ephemeralContainers !== undefined) throw new Error("UNSAFE_CONTAINER_SPEC");
}
function listItems(value: unknown): Resource[] {
  const items = (value as { items?: Resource[] })?.items;
  if (!Array.isArray(items)) throw new Error("INVALID_POD_LIST");
  return items;
}
function configValid(config: ProbeConfig): void {
  validateBudgets(config.budgets);
  if (!/^mtc-cpa-work-directio-[a-z0-9-]+$/.test(config.jobName) || !/^[a-f0-9-]{36}$/.test(config.jobUid) || !/^\d+$/.test(config.jobResourceVersion) || config.pvcUid !== PVC_UID || !/^\d+$/.test(config.pvcResourceVersion)) throw new Error("INVALID_CONFIG_IDENTITY");
}

export async function runProbe(config: ProbeConfig, api: ProbeApi, plan: Resource, policy: Resource, clock: ProbeClock = realClock()) {
  configValid(config);
  const b = config.budgets;
  const jobPath = `${JOBS}/${config.jobName}`;
  const pvcPath = `${CORE}/persistentvolumeclaims/${CLAIM}`;
  const podsPath = `${CORE}/pods?labelSelector=${encodeURIComponent(`batch.kubernetes.io/controller-uid=${config.jobUid}`)}`;
  const expectedPod = (plan.spec.template as { spec: Record<string, unknown> }).spec;
  const expectedLabels = (plan.spec.template as { metadata: { labels: Record<string, string> } }).metadata.labels;
  if (plan.spec.activeDeadlineSeconds !== b.totalMs / 1000 || plan.spec.backoffLimit !== 0 || expectedPod.activeDeadlineSeconds !== b.totalMs / 1000) throw new Error("PLAN_BUDGET_MISMATCH");
  let attempted = false, pod: Resource | null = null;
  let attemptStart = clock.now(), phaseDeadline = attemptStart + b.totalMs;
  let result: ReturnType<typeof probeBudget> | null = null;
  let status = "PREFLIGHT_REJECTED";
  let execStartedAt: string | null = null;
  const cleanup = { complete: false, jobDeleted: false, podDeleted: false, errors: [] as string[] };
  const call = async (method: "GET" | "PATCH" | "DELETE", path: string, deadline: number, body?: unknown) => {
    const remaining = deadline - clock.now();
    if (remaining <= 0) throw new Error("READ_DEADLINE");
    const value = await api.call(method, path, Math.min(b.apiMs, remaining), body);
    if (clock.now() > deadline) throw new Error("READ_DEADLINE");
    return value;
  };
  const resource = async (path: string, deadline: number) => await call("GET", path, deadline) as Resource;
  const capture = async (deadline: number) => {
    const items = listItems(await call("GET", podsPath, deadline));
    if (items.length > 1 || items.some((item) => !owned(item, config.jobUid))) throw new Error("POD_OWNERSHIP_REJECTED");
    const found = items[0];
    if (found) {
      if (pod && (pod.metadata.uid !== found.metadata.uid || pod.metadata.name !== found.metadata.name)) throw new Error("POD_REPLACED");
      identity(found, found.metadata.name, pod?.metadata.uid ?? found.metadata.uid);
      if (!subset(found.metadata.labels, expectedLabels)) throw new Error("NETWORK_LABEL_MISMATCH");
      validatePodSpec(found.spec, expectedPod);
      pod = found;
    } else if (pod) throw new Error("POD_LOST");
  };
  try {
    const preflightDeadline = clock.now() + b.freshnessMs;
    const job = await resource(jobPath, preflightDeadline);
    identity(job, config.jobName, config.jobUid, config.jobResourceVersion);
    if (job.metadata.deletionTimestamp || job.spec.suspend !== true || job.status?.startTime || job.status?.active || job.status?.failed || job.status?.succeeded || job.status?.conditions?.length) throw new Error("ATTEMPT_ALREADY_USED");
    if (job.spec.backoffLimit !== 0 || job.spec.activeDeadlineSeconds !== b.totalMs / 1000 || (job.spec.parallelism ?? 1) !== 1 || (job.spec.completions ?? 1) !== 1 || !subset((job.spec.template as { metadata: unknown }).metadata, (plan.spec.template as { metadata: unknown }).metadata)) throw new Error("JOB_BUDGET_MISMATCH");
    validatePodSpec((job.spec.template as { spec: Record<string, unknown> }).spec, expectedPod);
    const pvc = await resource(pvcPath, preflightDeadline);
    identity(pvc, CLAIM, config.pvcUid, config.pvcResourceVersion);
    if (pvc.metadata.deletionTimestamp || pvc.status?.phase !== "Bound" || pvc.spec.volumeName !== `pvc-${PVC_UID}`) throw new Error("PVC_NOT_BOUND");
    const deny = await resource(POLICY, preflightDeadline);
    if (!isDeepStrictEqual(deny.spec, policy.spec)) throw new Error("NETWORK_DENY_MISMATCH");
    await capture(preflightDeadline);
    if (pod) throw new Error("ATTEMPT_ALREADY_USED");
    if (clock.cancelled()) throw new Error("CANCELLED");
    attemptStart = Math.floor(clock.now() / 1000) * 1000; phaseDeadline = attemptStart + b.startupMs;
    attempted = true; // Ambiguous PATCH completion still requires guarded cleanup.
    try {
      await call("PATCH", jobPath, Math.min(phaseDeadline, attemptStart + b.apiMs), [
        { op: "test", path: "/metadata/uid", value: config.jobUid },
        { op: "test", path: "/metadata/resourceVersion", value: config.jobResourceVersion },
        { op: "test", path: "/spec/suspend", value: true },
        { op: "replace", path: "/spec/suspend", value: false },
      ]);
    } catch (error) {
      // A definitive rejected PATCH acquires no attempt. Never stop another
      // actor's conflicting mutation. Transport/5xx ambiguity still cleans up.
      if (error instanceof ApiFailure && error.statusCode >= 400 && error.statusCode < 500) attempted = false;
      throw error;
    }
    for (;;) {
      if (clock.cancelled()) throw new Error("CANCELLED");
      if (clock.now() >= phaseDeadline) { status = clock.now() >= attemptStart + b.totalMs ? "TOTAL_DEADLINE" : pod?.status?.containerStatuses?.some((s) => s.name === "directio" && (s.state.running || s.state.terminated?.startedAt)) ? "EXEC_DEADLINE" : "STARTUP_DEADLINE"; break; }
      const collection = clock.now();
      const readDeadline = Math.min(phaseDeadline, collection + b.freshnessMs);
      const currentJob = await resource(jobPath, readDeadline);
      identity(currentJob, config.jobName, config.jobUid);
      if (currentJob.spec.suspend !== false || currentJob.spec.activeDeadlineSeconds !== b.totalMs / 1000 || currentJob.spec.backoffLimit !== 0 || (currentJob.spec.parallelism ?? 1) !== 1 || (currentJob.spec.completions ?? 1) !== 1) throw new Error("JOB_CHANGED");
      validatePodSpec((currentJob.spec.template as { spec: Record<string, unknown> }).spec, expectedPod);
      const currentPvc = await resource(pvcPath, readDeadline);
      identity(currentPvc, CLAIM, config.pvcUid);
      if (currentPvc.metadata.deletionTimestamp || currentPvc.status?.phase !== "Bound" || currentPvc.spec.volumeName !== `pvc-${PVC_UID}`) throw new Error("PVC_CHANGED");
      await capture(readDeadline);
      if (pod) {
        const captured: Resource = pod;
        const exact = await resource(`${CORE}/pods/${captured.metadata.name}`, readDeadline);
        identity(exact, captured.metadata.name, captured.metadata.uid);
        if (!owned(exact, config.jobUid)) throw new Error("POD_OWNERSHIP_REJECTED");
        validatePodSpec(exact.spec, expectedPod); pod = exact;
      }
      const currentPod = pod as Resource | null;
      if ((currentPod?.status?.containerStatuses?.filter((s) => s.name === "directio").length ?? 0) > 1) throw new Error("INVALID_CONTAINER_STATUS");
      const runtime = currentPod?.status?.containerStatuses?.find((s) => s.name === "directio");
      const init = currentPod?.status?.initContainerStatuses ?? [];
      if (runtime && runtime.restartCount !== 0 || init.some((s) => s.restartCount !== 0)) throw new Error("RETRY_REJECTED");
      for (const item of init) {
        if (item.state.terminated) {
          if (!Number.isInteger(item.state.terminated.exitCode) || item.state.terminated.exitCode < 0) throw new Error("INVALID_INIT_EXIT");
          const end = timestamp(item.state.terminated.finishedAt);
          const begin = item.state.terminated.startedAt ? timestamp(item.state.terminated.startedAt) : attemptStart;
          if (begin < attemptStart || end < begin || end > clock.now()) throw new Error("INVALID_INIT_END");
        }
      }
      const state = runtime?.state ?? null;
      const startedAt = state?.running?.startedAt ?? state?.terminated?.startedAt ?? null;
      if (execStartedAt !== null && startedAt !== execStartedAt) throw new Error("EXEC_START_CHANGED");
      if (startedAt) execStartedAt = startedAt;
      let logs = "";
      if (state?.running?.startedAt || state?.terminated?.startedAt) {
        const data = await call("GET", `${CORE}/pods/${currentPod!.metadata.name}/log?container=directio&limitBytes=4096&tailLines=100`, readDeadline);
        if (typeof data !== "string") throw new Error("INVALID_LOG_RESPONSE");
        logs = data;
        const afterLogs = await resource(`${CORE}/pods/${currentPod!.metadata.name}`, readDeadline);
        identity(afterLogs, currentPod!.metadata.name, currentPod!.metadata.uid, currentPod!.metadata.resourceVersion);
        if (!owned(afterLogs, config.jobUid)) throw new Error("POD_OWNERSHIP_REJECTED");
      }
      const observation: ProbeObservation = {
        jobUid: currentJob.metadata.uid, jobResourceVersion: currentJob.metadata.resourceVersion,
        pvcUid: currentPvc.metadata.uid, pvcResourceVersion: currentPvc.metadata.resourceVersion, claimName: CLAIM,
        podUid: currentPod?.metadata.uid ?? null, podResourceVersion: currentPod?.metadata.resourceVersion ?? null, ownerUid: currentPod ? config.jobUid : null,
        attemptStartedAt: new Date(attemptStart).toISOString(), collectionStartedAt: new Date(collection).toISOString(), observedAt: new Date(clock.now()).toISOString(),
        initFailed: init.some((s) => s.state.terminated && s.state.terminated.exitCode !== 0),
        jobFailed: Boolean(currentJob.status?.failed) || Boolean(currentJob.status?.conditions?.some((c) => c.type === "Failed" && c.status === "True")),
        podPhase: currentPod?.status?.phase ?? null, state,
        writeStarted: /^WRITE_START /m.test(logs), complete: /^DIRECTIO_COMPLETE /m.test(logs),
      };
      result = probeBudget(observation, { jobUid: config.jobUid, pvcUid: config.pvcUid, podUid: currentPod?.metadata.uid ?? null }, clock.now(), b);
      status = result.status;
      if (result.stopRequired) break;
      phaseDeadline = Math.min(result.totalDeadline, result.execDeadline ?? result.startupDeadline);
      await clock.sleep(Math.min(b.pollMs, Math.max(0, phaseDeadline - clock.now())));
    }
  } catch (error) {
    status = attempted && clock.now() >= attemptStart + b.totalMs ? "TOTAL_DEADLINE" : attempted && clock.now() >= phaseDeadline ? phaseDeadline === attemptStart + b.startupMs ? "STARTUP_DEADLINE" : "EXEC_DEADLINE" : error instanceof Error && /^[A-Z_]+$/.test(error.message) ? error.message : "OBSERVATION_REJECTED";
  } finally {
    if (attempted) {
      const deadline = clock.now() + b.cleanupMs;
      // Capture only the original controller's unique Pod if PATCH failed before adoption.
      if (!pod) { try { await capture(deadline); } catch { cleanup.errors.push("POD_CAPTURE_UNCONFIRMED"); } }
      try {
        const job = await resource(jobPath, deadline); identity(job, config.jobName, config.jobUid);
        await call("DELETE", jobPath, deadline, { apiVersion: "v1", kind: "DeleteOptions", propagationPolicy: "Orphan", gracePeriodSeconds: 5, preconditions: { uid: config.jobUid, resourceVersion: job.metadata.resourceVersion } });
        cleanup.jobDeleted = true;
      } catch (error) { if (error instanceof ApiFailure && error.statusCode === 404) cleanup.jobDeleted = true; else cleanup.errors.push("JOB_STOP_UNCONFIRMED"); }
      const originalPod = pod as Resource | null;
      if (originalPod && cleanup.jobDeleted) {
        try {
          const exact = await resource(`${CORE}/pods/${originalPod.metadata.name}`, deadline);
          identity(exact, originalPod.metadata.name, originalPod.metadata.uid);
          const controllers = exact.metadata.ownerReferences?.filter((owner) => owner.controller) ?? [];
          if (controllers.length && !owned(exact, config.jobUid)) throw new Error("POD_OWNER_CHANGED");
          validatePodSpec(exact.spec, expectedPod);
          await call("DELETE", `${CORE}/pods/${originalPod.metadata.name}`, deadline, { apiVersion: "v1", kind: "DeleteOptions", gracePeriodSeconds: 5, preconditions: { uid: originalPod.metadata.uid, resourceVersion: exact.metadata.resourceVersion } });
          cleanup.podDeleted = true;
        } catch (error) { if (error instanceof ApiFailure && error.statusCode === 404) cleanup.podDeleted = true; else cleanup.errors.push("POD_STOP_UNCONFIRMED"); }
      } else if (originalPod) cleanup.errors.push("POD_STOP_SKIPPED_JOB_UNCONFIRMED");
      else cleanup.podDeleted = cleanup.errors.length === 0;
      if (cleanup.jobDeleted && cleanup.podDeleted && !cleanup.errors.length) {
        try {
          for (;;) {
            let gone = true;
            for (const path of [jobPath, ...(originalPod ? [`${CORE}/pods/${originalPod.metadata.name}`] : [])]) {
              try { await resource(path, deadline); gone = false; } catch (error) { if (!(error instanceof ApiFailure && error.statusCode === 404)) throw error; }
            }
            // Also reject late orphan creation; never delete an unrecorded Pod.
            if (listItems(await call("GET", podsPath, deadline)).length) gone = false;
            if (gone) { cleanup.complete = true; break; }
            await clock.sleep(Math.min(b.pollMs, Math.max(0, deadline - clock.now())));
          }
        } catch { cleanup.errors.push("CLEANUP_DEADLINE_OR_UNCONFIRMED"); }
      }
    }
  }
  return { status, passed: status === "COMPLETE" && cleanup.complete, bytes: status === "COMPLETE" ? result?.bytes ?? null : null, budgets: b, attemptStartedAt: attempted ? new Date(attemptStart).toISOString() : null,
    jobUid: config.jobUid, podUid: (pod as Resource | null)?.metadata.uid ?? null, pvcUid: config.pvcUid, decision: result, cleanup };
}

if (invokedAsEntrypoint("cpa-work-probe-operator", import.meta.url)) {
  let directory: string | undefined;
  let proxy: ReturnType<typeof spawn> | undefined;
  try {
    const [authorization, configPath, socketOption, suppliedSocket] = process.argv.slice(2);
    if (authorization !== "--execute-authorized-target-only" || !configPath || socketOption !== undefined && (socketOption !== "--api-socket" || !suppliedSocket) || process.argv.length > 6) throw new Error("RUNTIME_AUTHORIZATION_REQUIRED");
    const config = JSON.parse(readFileSync(configPath, "utf8")) as ProbeConfig;
    configValid(config);
    const [policy, plan] = parseAllDocuments(readFileSync(new URL("./cpa-work-directio-20261006a.yaml", import.meta.url), "utf8")).map((doc) => doc.toJSON() as Resource);
    if (!policy || !plan) throw new Error("PLAN_MISSING");
    let socketPath = suppliedSocket;
    if (!socketPath) {
      directory = mkdtempSync(join(tmpdir(), "cpa-probe-api-")); socketPath = join(directory, "api.sock");
      proxy = spawn("kubectl", ["proxy", `--unix-socket=${socketPath}`, "--accept-paths=^/(api/v1|apis/(batch/v1|networking.k8s.io/v1))/namespaces/cliproxyapi/"], { stdio: "ignore" });
      let failed = false; proxy.on("error", () => { failed = true; });
      const deadline = Date.now() + config.budgets.freshnessMs;
      for (;;) {
        if (failed || proxy.exitCode !== null || Date.now() >= deadline) throw new Error("API_PROXY_STARTUP_FAILED");
        try { if (lstatSync(socketPath).isSocket()) break; } catch { /* bounded socket startup */ }
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    }
    const socket = lstatSync(socketPath);
    const parent = lstatSync(dirname(socketPath));
    if (!socket.isSocket() || socket.uid !== process.getuid?.() || !parent.isDirectory() || parent.uid !== process.getuid?.() || (parent.mode & 0o077) !== 0) throw new Error("UNSAFE_API_SOCKET");
    const receipt = await runProbe(config, unixApi(socketPath), plan, policy);
    console.log(JSON.stringify(receipt)); process.exitCode = receipt.passed ? 0 : 1;
  } catch { console.log(JSON.stringify({ status: "OPERATOR_REJECTED", passed: false, bytes: null, cleanup: { complete: false } })); process.exitCode = 1; }
  finally {
    if (proxy) {
      proxy.kill("SIGTERM");
      await Promise.race([new Promise<void>((resolve) => { if (proxy!.exitCode !== null) resolve(); else proxy!.once("exit", () => resolve()); }), new Promise<void>((resolve) => setTimeout(() => { proxy!.kill("SIGKILL"); resolve(); }, 1000))]);
    }
    if (directory) rmSync(directory, { recursive: true, force: true });
  }
}

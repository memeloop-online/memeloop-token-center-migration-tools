import { constants, closeSync, fstatSync, openSync, readSync } from "node:fs";
import { pathToFileURL } from "node:url";

type ObjectValue = Record<string, unknown>;

function object(value: unknown): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("expected a metadata object");
  return value as ObjectValue;
}

function count(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new Error("invalid metadata count");
  return Number(value);
}

function fence(value: unknown): bigint | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(value)) throw new Error("invalid ingest fence");
  return BigInt(value);
}

export function assessRecovery(input: unknown): ObjectValue {
  const evidence = object(input);
  const seal = object(evidence.seal);
  const live = object(evidence.live_stats);
  const comparisons = ["records", "sessions", "blobs", "compressed_bytes"].map((name) => ({
    field: name,
    sealed: count(seal[`source_${name}`]),
    live: count(live[name]),
  }));
  const changed = comparisons.some((entry) => entry.sealed !== entry.live);
  const sealedFence = fence(seal.source_ingest_fence);
  const liveFence = fence(evidence.live_ingest_fence);
  const blockers = ["sealed_artifact_manifest_checkpoint_verification_required", "target_import_replay_reconciliation_required"];
  let delta = "unknown_missing_comparable_ingest_fences";
  if (sealedFence !== undefined && liveFence !== undefined) {
    delta = liveFence > sealedFence ? "post_seal_mutations_present" : liveFence < sealedFence ? "source_fence_regressed" : "equal_fences_identity_unverified";
  }
  if (changed) delta = "source_counts_changed";
  blockers.push(delta);
  const job = object(evidence.export_job);
  const status = object(job.status ?? {});
  const failed = Array.isArray(status.conditions) && status.conditions.some((condition) => {
    const value = object(condition);
    return value.type === "Failed" && value.status === "True";
  });
  const pods = object(evidence.export_pods);
  if (!Array.isArray(pods.items)) throw new Error("expected a PodList");
  const jobUid = object(job.metadata).uid;
  if (typeof jobUid !== "string" || jobUid.length === 0) throw new Error("export Job UID is required");
  const exits: ObjectValue[] = [];
  for (const raw of pods.items) {
    const pod = object(raw);
    const metadata = object(pod.metadata);
    if (!Array.isArray(metadata.ownerReferences) || !metadata.ownerReferences.some((owner) => object(owner).uid === jobUid)) continue;
    const podStatus = object(pod.status ?? {});
    for (const group of ["initContainerStatuses", "containerStatuses"]) {
      if (!Array.isArray(podStatus[group])) continue;
      for (const rawContainer of podStatus[group] as unknown[]) {
        const container = object(rawContainer);
        const state = object(container.state ?? {});
        if (state.terminated === undefined) continue;
        const terminated = object(state.terminated);
        const exitCode = count(terminated.exitCode);
        if (exitCode === 0) continue;
        exits.push({ stage: group === "initContainerStatuses" ? "init" : "export", exit_code: exitCode,
          reason: ["Error", "OOMKilled", "ContainerCannotRun", "DeadlineExceeded"].includes(String(terminated.reason)) ? terminated.reason : "unclassified" });
      }
    }
  }
  if (failed && exits.length === 0) blockers.push("failed_job_original_exit_evidence_missing");
  return { version: 1, mode: "metadata-only-recovery-preflight", export_failed: failed,
    count_comparisons: comparisons, post_seal_delta: delta, container_failures: exits,
    failure_cause: exits.length ? "container_failure_observed_logs_required" : "not_established",
    recovery_ready: false, deletion_ready: false, blockers };
}

function readMetadata(path: string): unknown {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size > 1024n * 1024n) throw new Error("metadata must be a regular file of at most 1 MiB");
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let size = 0;
    while (size < buffer.length) {
      const read = readSync(descriptor, buffer, size, buffer.length - size, null);
      if (read === 0) break;
      size += read;
    }
    const bytes = buffer.subarray(0, size);
    const after = fstatSync(descriptor, { bigint: true });
    if (before.size !== after.size || before.mtimeNs !== after.mtimeNs || BigInt(bytes.length) !== before.size) throw new Error("metadata changed during read");
    return JSON.parse(bytes.toString("utf8"));
  } finally { closeSync(descriptor); }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    if (process.argv.length !== 3) throw new Error("one metadata receipt path is required");
    process.stdout.write(`${JSON.stringify(assessRecovery(readMetadata(process.argv[2]!)))}\n`);
  } catch {
    process.stderr.write("archive recovery preflight rejected invalid metadata\n");
    process.exitCode = 1;
  }
}

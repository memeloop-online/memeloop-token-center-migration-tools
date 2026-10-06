import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, rmSync } from "node:fs";
import { COPY, SAME_NODE_COPY, STREAM_PROFILES, profileCommand, requirePlacement, streamResourceName, validateEndpoint, validateIdentity, type Identity } from "../../ops/lib/cpa-stream.ts";
import { job, policies } from "../../ops/cpa-stream-resources.ts";

test("same-node profile changes only run/destination and keeps the original budgets/seal", () => {
  assert.deepEqual(SAME_NODE_COPY, { ...COPY, run: "cpa-stream-local-20261006a", destination: "/destination/recovery-stream-local-20261006a" });
  assert.equal(COPY.run, "cpa-stream-20261005a");
  assert.equal(COPY.destination, "/destination/recovery-stream-20261005a");
  assert.deepEqual(profileCommand("same-node-reader"), { profile: "same-node", command: "reader" });
  assert.deepEqual(profileCommand("diagnostic-receiver"), { profile: "diagnostic", command: "receiver" });
  assert.deepEqual(profileCommand("reader"), { profile: "original", command: "reader" });
});

test("placement and endpoints cannot cross profiles or accept broad network exceptions", () => {
  for (const profile of ["original", "diagnostic", "same-node"] as const) {
    const selected = STREAM_PROFILES[profile];
    for (const suffix of ["2", "65", "254"]) assert.equal(validateEndpoint(`${selected.receiverSubnet}.${suffix}`, profile), `${selected.receiverSubnet}.${suffix}`);
    for (const invalid of ["0", "1", "255", "256", "02", "2:18443", "2\n"]) assert.throws(() => validateEndpoint(`${selected.receiverSubnet}.${invalid}`, profile));
    for (const address of ["127.0.0.1", "0.0.0.0", "100.64.0.6", "10.42.0.2", "https://10.42.2.2"]) assert.throws(() => validateEndpoint(address, profile));
    assert.throws(() => validateEndpoint(profile === "same-node" ? "10.42.3.2" : "10.42.2.2", profile));
    for (const role of ["reader", "receiver"] as const) {
      const pod = `${streamResourceName(role, profile)}-fixture`;
      requirePlacement(role, profile, role === "reader" ? "sansheng-hv" : selected.receiverNode, pod);
      assert.throws(() => requirePlacement(role, profile, "haixia", pod), /NODE_PLACEMENT/);
      for (const other of ["original", "diagnostic", "same-node"] as const) {
        if (other !== profile) assert.throws(() => requirePlacement(role, profile, role === "reader" ? "sansheng-hv" : selected.receiverNode, `${streamResourceName(role, other)}-fixture`), /POD_IDENTITY/);
      }
    }
  }
});

test("same-node resources keep source double RO, work-only receiver and exact isolated NP", () => {
  const names = new Set<string>();
  for (const profile of ["original", "diagnostic", "same-node"] as const) {
    for (const role of ["reader", "receiver", "code"] as const) {
      const name = streamResourceName(role, profile);
      assert.equal(names.has(name), false);
      names.add(name);
    }
  }
  for (const role of ["reader", "receiver"] as const) {
    const rendered = JSON.parse(JSON.stringify(job(role, "10.42.2.65", "same-node")));
    assert.equal(rendered.metadata.name, `mtc-cpa-stream-local-${role}-20261006a`);
    assert.equal(rendered.spec.suspend, true);
    assert.equal(rendered.spec.backoffLimit, 0);
    assert.equal(rendered.spec.activeDeadlineSeconds, 1800);
    const pod = rendered.spec.template.spec;
    assert.equal(pod.nodeSelector["kubernetes.io/hostname"], "sansheng-hv");
    assert.equal(pod.automountServiceAccountToken, false);
    assert.equal(pod.hostNetwork, undefined);
    assert.equal(pod.securityContext.fsGroup, undefined);
    assert.deepEqual(pod.containers[0].resources.limits, { cpu: "250m", memory: "128Mi", "ephemeral-storage": "32Mi" });
    assert.deepEqual(pod.containers[0].command, ["node", "/tool/cpa-frozen-stream-copy.ts", `same-node-${role}`]);
    assert.equal(pod.volumes.find((volume: any) => volume.name === "code").configMap.name, "mtc-cpa-stream-local-code-20261006a");
    assert.deepEqual(pod.volumes.filter((volume: any) => volume.persistentVolumeClaim).map((volume: any) => volume.persistentVolumeClaim), [role === "reader" ? { claimName: "mtc-session-archive-v08-live-clone-20260919a", readOnly: true } : { claimName: "mtc-cpa-recovery-work-20261005" }]);
    assert.ok(pod.initContainers[0].volumeMounts.every((mount: any) => mount.name !== "source"));
    assert.ok(pod.volumes.every((volume: any) => !volume.secret && !volume.hostPath));
    if (role === "reader") assert.equal(pod.containers[0].volumeMounts.find((mount: any) => mount.name === "source").readOnly, true);
    else {
      assert.ok(pod.initContainers[0].args[0].includes(`mkdirSync('${SAME_NODE_COPY.destination}'`));
      assert.ok(pod.initContainers[0].args[0].includes("fsyncSync(parentDirectory)"));
      assert.equal(pod.initContainers[0].args[0].includes(COPY.destination), false);
    }
  }
  assert.throws(() => job("reader", "10.42.3.2", "same-node"), /RECEIVER_NOT_SANSHENG_POD/);
  assert.throws(() => job("reader", "10.42.2.2"), /RECEIVER_NOT_WESTLAKE_POD/);
  const normalized = JSON.stringify(policies("same-node")).replaceAll("local-", "").replaceAll("20261006a", "20261005a");
  assert.equal(normalized, JSON.stringify(policies()));
});

test("actual main and staging CLI fail closed on wrong node, run, endpoint and unsupported overrides", () => {
  for (const role of ["reader", "receiver"] as const) {
    for (const stage of ["", "stage-"]) {
      const env = { ...process.env, NODE_NAME: "sansheng-hv", POD_NAME: `mtc-cpa-stream-local-${role}-20261006a-fixture`, POD_IP: "10.42.2.65", CPA_RECEIVER_IP: "10.42.2.65" };
      for (const [changes, failure] of [
        [{ NODE_NAME: "westlake" }, "NODE_PLACEMENT"],
        [{ POD_NAME: `mtc-cpa-stream-${role}-20261005a-fixture` }, "POD_IDENTITY"],
        [role === "reader" ? { CPA_RECEIVER_IP: "10.42.3.2" } : { POD_IP: "10.42.3.2" }, "RECEIVER_NOT_SANSHENG_POD"],
      ] as const) {
        const result = spawnSync(process.execPath, ["ops/cpa-frozen-stream-copy.ts", `${stage}same-node-${role}`], { encoding: "utf8", env: { ...env, ...changes }, input: "" });
        assert.equal(result.status, 1);
        const report = JSON.parse(result.stderr.trim());
        assert.equal(report.run, SAME_NODE_COPY.run);
        assert.equal(report.phase, "preflight");
        assert.equal(report.failure, failure);
        assert.equal(report.passed, false);
      }
    }
  }
  for (const args of [["same-node-reader", "--source=/tmp/other"], ["same-node-diagnostic-reader"], ["same-node-stage-reader"]]) {
    const result = spawnSync(process.execPath, ["ops/cpa-frozen-stream-copy.ts", ...args], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stderr.trim()).failure, "ARGUMENTS");
  }
});

test("same-node identities use a new private RAM run and reject original/diagnostic SANs", () => {
  const directory = `/dev/shm/${SAME_NODE_COPY.run}`;
  let owned = false;
  try {
    const generated = spawnSync(process.execPath, ["ops/cpa-stream-identity.ts", "create-same-node"], { encoding: "utf8" });
    assert.equal(generated.status, 0, generated.stderr);
    owned = true;
    assert.equal(JSON.parse(generated.stdout).run, SAME_NODE_COPY.run);
    for (const role of ["reader", "receiver"] as const) {
      const identity = JSON.parse(readFileSync(`${directory}/${role}.json`, "utf8")) as Identity;
      validateIdentity(identity, role, SAME_NODE_COPY.run);
      for (const profile of ["original", "diagnostic"] as const) assert.throws(() => validateIdentity(identity, role, STREAM_PROFILES[profile].plan.run), /IDENTITY_ROLE/);
      assert.equal(lstatSync(`${directory}/${role}.json`).mode & 0o777, 0o600);
      assert.equal(generated.stdout.includes(identity.key), false);
      assert.equal(existsSync(`${directory}/${role}.key`), false);
    }
    assert.equal(existsSync(`${directory}/ca.key`), false);
    const repeated = spawnSync(process.execPath, ["ops/cpa-stream-identity.ts", "create-same-node"], { encoding: "utf8" });
    assert.equal(repeated.status, 1);
    assert.equal(repeated.stderr.trim(), "EEXIST");
  } finally { if (owned) rmSync(directory, { recursive: true }); }
});

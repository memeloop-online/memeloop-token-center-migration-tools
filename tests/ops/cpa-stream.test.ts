import assert from "node:assert/strict";
import { after, before, test, mock } from "node:test";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, readdirSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer as createTcpServer } from "node:net";
import { connect, type TLSSocket } from "node:tls";
import { setTimeout as pause } from "node:timers/promises";
import { COPY, Wire, checkBudget, frame, identityName, requireReadOnlyMount, runReader, safeFailure, startReceiver, validateEndpoint, validateIdentity, verifyDestination, type CopyPlan, type Identity } from "../../ops/lib/cpa-stream.ts";
import { job, policies } from "../../ops/cpa-stream-resources.ts";

const identityDirectory = "/dev/shm/cpa-stream-20261005a";
let readerIdentity: Identity;
let receiverIdentity: Identity;
let ownIdentities = false;

before(() => {
  const result = spawnSync(process.execPath, ["ops/cpa-stream-identity.ts", "create"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  ownIdentities = true;
  assert.equal(result.stdout.includes("PRIVATE"), false);
  readerIdentity = JSON.parse(readFileSync(`${identityDirectory}/reader.json`, "utf8"));
  receiverIdentity = JSON.parse(readFileSync(`${identityDirectory}/receiver.json`, "utf8"));
});
after(() => { if (ownIdentities) rmSync(identityDirectory, { recursive: true }); });

function fixture(overrides: Partial<CopyPlan> = {}) {
  const root = mkdtempSync(join(tmpdir(), "cpa-stream-"));
  const source = join(root, "archive.sqlite");
  const destination = join(root, "new-destination");
  const bytes = Buffer.alloc(256 * 1024, 71);
  writeFileSync(source, bytes, { mode: 0o400 });
  mkdirSync(destination, { mode: 0o700 });
  const plan: CopyPlan = { ...COPY, port: 0, source, destination, size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"), chunk: 65536, rate: 100 * 1024 ** 2, reserveBytes: 0, uid: process.getuid!(), gid: process.getgid!(), totalMs: 3000, verifyMs: 500, idleMs: 300, ...overrides };
  return { root, plan, bytes, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

async function pair(plan: CopyPlan, senderPlan: CopyPlan = plan) {
  const receiver = startReceiver(plan, receiverIdentity, "127.0.0.1");
  const completion = receiver.completion.catch((error: unknown) => { throw error; });
  const results = Promise.allSettled([completion, receiver.listening.then((port) => runReader({ ...senderPlan, port }, readerIdentity, "127.0.0.1"))]);
  try { return await results; } finally { receiver.close(); }
}

async function peer(port: number): Promise<TLSSocket> {
  const socket = connect({ host: "127.0.0.1", port, ...readerIdentity, servername: identityName("receiver", COPY.run), rejectUnauthorized: true });
  socket.allowHalfOpen = true;
  socket.on("error", () => {});
  await new Promise<void>((resolve, reject) => { socket.once("secureConnect", resolve); socket.once("error", reject); });
  return socket;
}

test("one-use short-lived role identities stay private in RAM and cannot overwrite", () => {
  validateIdentity(readerIdentity, "reader", COPY.run);
  validateIdentity(receiverIdentity, "receiver", COPY.run);
  assert.throws(() => validateIdentity(readerIdentity, "receiver", COPY.run), /IDENTITY_ROLE/);
  assert.throws(() => validateIdentity({ ...readerIdentity, key: receiverIdentity.key }, "reader", COPY.run), /IDENTITY_KEY/);
  assert.equal(lstatSync(`${identityDirectory}/reader.json`).mode & 0o777, 0o600);
  assert.equal(existsSync(`${identityDirectory}/ca.key`), false);
  assert.equal(existsSync(`${identityDirectory}/reader.key`), false);
  const result = spawnSync(process.execPath, ["ops/cpa-stream-identity.ts", "create"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.equal(result.stderr.includes(readerIdentity.key), false);
});

test("native failure diagnostics preserve allowlisted codes without paths, keys, or raw TLS messages", () => {
  const sensitive = `connect 10.42.3.159:18443 /identity/bundle.json ${readerIdentity.key}`;
  for (const code of ["ECONNREFUSED", "EHOSTUNREACH", "ETIMEDOUT", "EACCES", "ERR_TLS_CERT_ALTNAME_INVALID", "ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED"]) {
    const error = Object.assign(new Error(sensitive), { code });
    assert.equal(safeFailure(error), code);
    assert.equal(safeFailure(new Error(safeFailure(error))), code);
  }
  assert.equal(safeFailure(Object.assign(new Error(sensitive), { code: "ERR_SSL_PRIVATE_UNKNOWN" })), "COPY_FAILED");
  assert.equal(safeFailure(Object.assign(new Error(sensitive), { code: sensitive })), "COPY_FAILED");
  assert.equal(safeFailure(new Error(sensitive)), "COPY_FAILED");
  assert.equal(safeFailure({ message: sensitive, code: "ECONNREFUSED" }), "COPY_FAILED");
  assert.equal(safeFailure(new Error("SOURCE_HASH_MISMATCH")), "SOURCE_HASH_MISMATCH");
});

test("a refused connection reports its phase and errno without opening source or destination", async () => {
  const sample = fixture();
  const listener = createTcpServer();
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  const diagnostic = mock.method(console, "error", () => {});
  try {
    await assert.rejects(runReader({ ...sample.plan, port: address.port, source: join(sample.root, "missing-source") }, readerIdentity, "127.0.0.1"), { code: "ECONNREFUSED" });
    assert.deepEqual(diagnostic.mock.calls.map((call) => JSON.parse(String(call.arguments[0]))), [{ stage: "reader-tls-connect", failure: "ECONNREFUSED" }]);
    assert.deepEqual(readdirSync(sample.plan.destination), []);
  } finally { diagnostic.mock.restore(); sample.cleanup(); }
});

test("mTLS copy verifies source once, independent destination, durable receipt and preserved partial", async () => {
  const sample = fixture();
  const before = lstatSync(sample.plan.source, { bigint: true });
  try {
    const outcomes = await pair(sample.plan);
    for (const outcome of outcomes) assert.equal(outcome.status, "fulfilled", outcome.status === "rejected" ? String(outcome.reason) : "");
    assert.deepEqual(readFileSync(`${sample.plan.destination}/archive.sqlite`), sample.bytes);
    assert.equal(lstatSync(`${sample.plan.destination}/archive.sqlite`).ino, lstatSync(`${sample.plan.destination}/archive.sqlite.partial`).ino);
    const receipt = JSON.parse(readFileSync(`${sample.plan.destination}/copy-receipt.json`, "utf8"));
    assert.equal(receipt.destinationVerified, true);
    assert.equal(receipt.sourceVerified, true);
    assert.equal(receipt.sha256, sample.plan.sha256);
    const after = lstatSync(sample.plan.source, { bigint: true });
    assert.equal(after.mtimeNs, before.mtimeNs);
    assert.equal(after.ctimeNs, before.ctimeNs);
  } finally { sample.cleanup(); }
});

test("existing partial, unsafe directory, sidecar, writable source, and source symlink fail closed", async () => {
  for (const condition of ["partial", "directory", "sidecar", "writable", "symlink", "space"]) {
    const sample = fixture();
    try {
      if (condition === "partial") writeFileSync(`${sample.plan.destination}/archive.sqlite.partial`, "keep");
      if (condition === "directory") chmodSync(sample.plan.destination, 0o750);
      if (condition === "sidecar") writeFileSync(sample.plan.source + "-wal", "keep");
      if (condition === "writable") chmodSync(sample.plan.source, 0o600);
      if (condition === "space") sample.plan.reserveBytes = Number.MAX_SAFE_INTEGER;
      if (condition === "symlink") { symlinkSync(sample.plan.source, join(sample.root, "link")); sample.plan.source = join(sample.root, "link"); }
      const outcomes = await pair(sample.plan);
      assert.ok(outcomes.every((outcome) => outcome.status === "rejected"), condition);
      assert.equal(existsSync(`${sample.plan.destination}/archive.sqlite`), false);
      if (condition === "partial") assert.equal(readFileSync(`${sample.plan.destination}/archive.sqlite.partial`, "utf8"), "keep");
    } finally { sample.cleanup(); }
  }
});

test("source expected hash mismatch never yields a success artifact", async () => {
  const sample = fixture();
  try {
    const outcomes = await pair(sample.plan, { ...sample.plan, sha256: "0".repeat(64) });
    assert.equal(outcomes[1]!.status, "rejected");
    assert.equal(existsSync(`${sample.plan.destination}/archive.sqlite.partial`), true);
    assert.equal(existsSync(`${sample.plan.destination}/copy-receipt.json`), false);
  } finally { sample.cleanup(); }
});

test("source identity changes during a backpressured copy are rejected", async () => {
  const sample = fixture({ rate: 1024 * 1024, idleMs: 1500, totalMs: 5000 });
  try {
    const pending = pair(sample.plan);
    while (!existsSync(`${sample.plan.destination}/archive.sqlite.partial`)) await pause(5);
    await pause(40);
    utimesSync(sample.plan.source, new Date(), new Date(Date.now() + 2000));
    const outcomes = await pending;
    assert.ok(outcomes.every((outcome) => outcome.status === "rejected"));
    assert.equal(existsSync(`${sample.plan.destination}/archive.sqlite`), false);
  } finally { sample.cleanup(); }
});

test("receiver refuses unexpected client fingerprint before opening destination", async () => {
  const sample = fixture({ totalMs: 700 });
  const diagnostic = mock.method(console, "error", () => {});
  const receiver = startReceiver(sample.plan, { ...receiverIdentity, peerFingerprint: Array(32).fill("AA").join(":") }, "127.0.0.1");
  const outcomes = Promise.allSettled([receiver.completion, receiver.listening.then((port) => runReader({ ...sample.plan, port }, readerIdentity, "127.0.0.1"))]);
  try {
    assert.ok((await outcomes).every((outcome) => outcome.status === "rejected"));
    assert.deepEqual(readdirSync(sample.plan.destination), []);
    const messages = diagnostic.mock.calls.map((call) => JSON.parse(String(call.arguments[0])));
    assert.ok(messages.some((message) => message.stage === "receiver-peer-authorization" && message.failure === "PEER_PIN"));
    assert.ok(messages.every((message) => Object.keys(message).sort().join(",") === "failure,stage"));
    assert.equal(JSON.stringify(messages).includes(readerIdentity.key), false);
    assert.equal(JSON.stringify(messages).includes(receiverIdentity.key), false);
  } finally { diagnostic.mock.restore(); receiver.close(); sample.cleanup(); }
});

test("reader refuses unexpected server fingerprint", async () => {
  const sample = fixture();
  const receiver = startReceiver(sample.plan, receiverIdentity, "127.0.0.1");
  const outcomes = Promise.allSettled([receiver.completion, receiver.listening.then((port) => runReader({ ...sample.plan, port }, { ...readerIdentity, peerFingerprint: Array(32).fill("AA").join(":") }, "127.0.0.1"))]);
  try {
    assert.ok((await outcomes).every((outcome) => outcome.status === "rejected"));
    assert.equal(existsSync(`${sample.plan.destination}/archive.sqlite`), false);
  } finally { receiver.close(); sample.cleanup(); }
});

test("truncation, oversized frames, overflow, corrupt stream, bad seal, trailing bytes and stalled sender preserve partial", async () => {
  for (const condition of ["truncated", "frame", "overflow", "corrupt", "seal", "trailing", "idle"]) {
    const sample = fixture({ size: 16, sha256: createHash("sha256").update(Buffer.alloc(16, 71)).digest("hex") });
    const receiver = startReceiver(sample.plan, receiverIdentity, "127.0.0.1");
    const result = receiver.completion.then(() => "unexpected success", (error: Error) => error.message);
    let socket: TLSSocket | undefined;
    try {
      socket = await peer(await receiver.listening);
      const wire = new Wire(socket);
      await wire.take(8);
      if (condition === "idle") {
        await pause(500);
      } else if (condition === "frame") {
        const oversized = Buffer.alloc(5);
        oversized[0] = 1;
        oversized.writeUInt32BE(COPY.chunk + 1, 1);
        socket.end(oversized);
      } else if (condition === "overflow") {
        await frame(socket, 1, Buffer.alloc(17));
        socket.end();
      } else if (condition === "truncated") {
        socket.end();
      } else {
        await frame(socket, 1, Buffer.alloc(16, condition === "corrupt" ? 72 : 71));
        await wire.take(8);
        const seal = Buffer.alloc(40);
        seal.writeBigUInt64BE(16n);
        Buffer.from(sample.plan.sha256, "hex").copy(seal, 8);
        if (condition === "seal") seal[8] = seal[8]! ^ 1;
        await frame(socket, 2, seal);
        if (condition === "trailing") socket.end(Buffer.from([1]));
        else socket.end();
      }
      assert.notEqual(await result, "unexpected success", condition);
      assert.equal(existsSync(`${sample.plan.destination}/archive.sqlite.partial`), true);
      assert.equal(existsSync(`${sample.plan.destination}/archive.sqlite`), false);
      assert.equal(existsSync(`${sample.plan.destination}/copy-receipt.json`), false);
    } finally { socket?.destroy(); receiver.close(); sample.cleanup(); }
  }
});

test("destination hash detects stored corruption without rereading source", async () => {
  const sample = fixture();
  try {
    const partial = `${sample.plan.destination}/archive.sqlite.partial`;
    writeFileSync(partial, Buffer.alloc(sample.bytes.length, 70));
    await assert.rejects(verifyDestination(sample.plan, partial), /DESTINATION_HASH_MISMATCH/);
    await assert.rejects(verifyDestination(sample.plan, partial, AbortSignal.abort()), /TRANSFER_CANCELLED/);
  } finally { sample.cleanup(); }
});

test("fsync failure preserves partial and refuses publication", async () => {
  const sample = fixture();
  const handle = await open(join(sample.root, "probe"), "wx");
  const prototype = Object.getPrototypeOf(handle);
  const originalSync = handle.sync;
  await handle.close();
  const mocked = mock.method(prototype, "sync", async function(this: FileHandle) {
    if (readlinkSync(`/proc/self/fd/${this.fd}`) === `${sample.plan.destination}/archive.sqlite.partial`) throw new Error("FSYNC_FAILED");
    await originalSync.call(this);
  });
  try {
    assert.ok((await pair(sample.plan)).every((outcome) => outcome.status === "rejected"));
    assert.equal(existsSync(`${sample.plan.destination}/archive.sqlite.partial`), true);
    assert.equal(existsSync(`${sample.plan.destination}/archive.sqlite`), false);
  } finally { mocked.mock.restore(); sample.cleanup(); }
});

test("destination parent fsync precedes payload and failures cannot signal ready or success", async () => {
  for (const injectFailure of [false, true]) {
    const sample = fixture();
    const handle = await open(join(sample.root, "probe"), "wx");
    const prototype = Object.getPrototypeOf(handle);
    const originalSync = handle.sync;
    await handle.close();
    const synced: string[] = [];
    const mocked = mock.method(prototype, "sync", async function(this: FileHandle) {
      const path = readlinkSync(`/proc/self/fd/${this.fd}`);
      synced.push(path);
      if (injectFailure && path === sample.root) throw new Error("PARENT_FSYNC_FAILED");
      await originalSync.call(this);
    });
    try {
      const outcomes = await pair(sample.plan, injectFailure ? { ...sample.plan, source: join(sample.root, "must-not-open") } : sample.plan);
      assert.deepEqual(synced.slice(0, 2), [sample.plan.destination, sample.root]);
      if (injectFailure) {
        assert.ok(outcomes.every((outcome) => outcome.status === "rejected"));
        assert.match(String((outcomes[0] as PromiseRejectedResult).reason), /PARENT_FSYNC_FAILED/);
        assert.doesNotMatch(String((outcomes[1] as PromiseRejectedResult).reason), /ENOENT/);
        assert.deepEqual(readdirSync(sample.plan.destination), []);
      } else {
        assert.ok(outcomes.every((outcome) => outcome.status === "fulfilled"));
        assert.ok(synced.indexOf(sample.root) < synced.indexOf(`${sample.plan.destination}/archive.sqlite.partial`));
      }
    } finally { mocked.mock.restore(); sample.cleanup(); }
  }
});

test("exclusive directory init fails if its parent cannot be fsynced, retaining the new directory", () => {
  const root = mkdtempSync(join(tmpdir(), "cpa-stream-init-"));
  const identity = join(root, "identity");
  const parent = join(root, "destination");
  mkdirSync(identity, { mode: 0o700 });
  mkdirSync(parent, { mode: 0o700 });
  const destination = join(parent, "recovery-stream-20261005a");
  const manifest = job("receiver") as any;
  const script = (manifest.spec.template.spec.initContainers[0].args[0] as string)
    .replaceAll("'/identity'", JSON.stringify(identity))
    .replaceAll(`'${COPY.destination}'`, JSON.stringify(destination))
    .replaceAll("'/destination'", JSON.stringify(parent))
    .replaceAll(",10001,10001", `,${process.getuid!()},${process.getgid!()}`);
  try {
    assert.ok(script.includes("fsyncSync(parentDirectory)"));
    const failed = spawnSync(process.execPath, ["--input-type=module", "-e", script.replace("fsyncSync(parentDirectory)", "(() => { throw new Error('PARENT_FSYNC_FAILED'); })()")], { encoding: "utf8" });
    assert.equal(failed.status, 1);
    assert.match(failed.stderr, /PARENT_FSYNC_FAILED/);
    assert.ok(lstatSync(destination).isDirectory());
    assert.deepEqual(readdirSync(destination), []);
    const retry = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
    assert.equal(retry.status, 1);
    assert.match(retry.stderr, /EEXIST/);
  } finally { rmSync(root, { recursive: true }); }
});

test("endpoints, RO mount, deadline and throughput cannot silently bypass policy", () => {
  for (const address of ["1.1.1.1", "127.0.0.1", "10.42.2.161", "10.42.3.1", "10.42.3.255", "https://10.42.3.2", "10.42.3.2:443"]) assert.throws(() => validateEndpoint(address));
  assert.equal(validateEndpoint("10.42.3.123"), "10.42.3.123");
  assert.throws(() => requireReadOnlyMount("1 2 0:1 / /source rw - xfs /dev/mock rw"), /SOURCE_NOT_READ_ONLY/);
  requireReadOnlyMount("1 2 0:1 / /source ro - xfs /dev/mock rw");
  assert.throws(() => checkBudget(COPY, performance.now() - COPY.totalMs, 0), /COPY_DEADLINE/);
  assert.throws(() => checkBudget(COPY, performance.now() - 31000, 1024), /THROUGHPUT_INSUFFICIENT/);
});

test("resource render is suspended, two-node, one-port, no network/Secret/PVC creation or broad peers", () => {
  const manifests = [job("reader", "10.42.3.123"), job("receiver")] as any[];
  for (const manifest of manifests) {
    assert.equal(manifest.spec.suspend, true);
    assert.equal(manifest.spec.backoffLimit, 0);
    assert.equal(manifest.spec.activeDeadlineSeconds, 1800);
    const pod = manifest.spec.template.spec;
    assert.equal(pod.automountServiceAccountToken, false);
    assert.equal(pod.hostNetwork, undefined);
    assert.equal(pod.securityContext.fsGroup, undefined);
    assert.deepEqual(pod.containers[0].resources.limits, { cpu: "250m", memory: "128Mi", "ephemeral-storage": "32Mi" });
    assert.ok(pod.initContainers[0].volumeMounts.every((mount: any) => mount.name !== "source"));
    assert.equal(pod.volumes.some((volume: any) => volume.secret), false);
    assert.equal(pod.volumes.filter((volume: any) => volume.persistentVolumeClaim).length, 1);
  }
  assert.equal(manifests[0].spec.template.spec.nodeSelector["kubernetes.io/hostname"], "sansheng-hv");
  assert.equal(manifests[1].spec.template.spec.nodeSelector["kubernetes.io/hostname"], "westlake");
  assert.deepEqual(manifests[0].spec.template.spec.volumes.at(-1).persistentVolumeClaim, { claimName: "mtc-session-archive-v08-live-clone-20260919a", readOnly: true });
  const network = policies() as any[];
  assert.deepEqual(network[0].spec.ingress, []);
  assert.deepEqual(network[1].spec.egress, []);
  assert.equal(network[0].spec.egress[0].ports[0].port, 18443);
  assert.equal(network[1].spec.ingress[0].ports[0].port, 18443);
  assert.equal(JSON.stringify(network).includes("ipBlock"), false);
  assert.equal(JSON.stringify(network).includes("namespaceSelector"), false);
});

import { createHash, X509Certificate, createPrivateKey } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { open, lstat, readdir, readFile, statfs, link } from "node:fs/promises";
import { connect, createServer, checkServerIdentity, type TLSSocket } from "node:tls";
import { setTimeout as pause } from "node:timers/promises";

export const COPY = Object.freeze({
  run: "cpa-stream-20261005a",
  source: "/source/archive.sqlite",
  destination: "/destination/recovery-stream-20261005a",
  size: 30205399040,
  sha256: "d42a11cebe062ea6c908ebf2ff6cdbdae410e392a01af5faf577a4eab30e589f",
  port: 18443,
  chunk: 4 * 1024 * 1024,
  rate: 64 * 1024 * 1024,
  totalMs: 1650000,
  idleMs: 30000,
  verifyMs: 600000,
  sampleMs: 30000,
  reserveBytes: 20 * 1024 ** 3,
  uid: 10001,
  gid: 10001,
});

export type CopyPlan = { [Key in keyof typeof COPY]: (typeof COPY)[Key] extends number ? number : string };
export type Identity = { ca: string; cert: string; key: string; peerFingerprint: string };
export type Receipt = { run: string; passed: true; bytes: number; sha256: string; sourceVerified: true; destinationVerified: true };

export function requireCopy(condition: unknown, code: string): asserts condition {
  if (!condition) throw new Error(code);
}

export function safeFailure(error: unknown): string {
  const code = error instanceof Error ? error.message : "";
  return /^[A-Z][A-Z_]{1,60}$/.test(code) ? code : "COPY_FAILED";
}

export function validateEndpoint(address: string): string {
  requireCopy(/^10\.42\.3\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/.test(address), "RECEIVER_NOT_WESTLAKE_POD");
  return address;
}

export function identityName(role: "reader" | "receiver", run: string): string {
  return `${role}.${run}.internal`;
}

export function validateIdentity(identity: Identity, role: "reader" | "receiver", run: string): void {
  requireCopy(Object.keys(identity).sort().join(",") === "ca,cert,key,peerFingerprint", "IDENTITY_FIELDS");
  requireCopy(typeof identity.peerFingerprint === "string" && /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(identity.peerFingerprint), "IDENTITY_PIN");
  const certificate = new X509Certificate(identity.cert);
  const authority = new X509Certificate(identity.ca);
  const started = Date.parse(certificate.validFrom);
  const ended = Date.parse(certificate.validTo);
  requireCopy(authority.ca && !certificate.ca && certificate.verify(authority.publicKey), "IDENTITY_CA");
  requireCopy(started <= Date.now() && ended > Date.now() && ended - started <= 45 * 60000, "IDENTITY_LIFETIME");
  requireCopy(certificate.checkHost(identityName(role, run), { wildcards: false }) !== undefined, "IDENTITY_ROLE");
  requireCopy(certificate.checkPrivateKey(createPrivateKey(identity.key)), "IDENTITY_KEY");
}

function authorize(socket: TLSSocket, identity: Identity, peer: string): void {
  requireCopy(socket.authorized, "PEER_UNAUTHORIZED");
  const certificate = socket.getPeerCertificate();
  requireCopy(certificate.fingerprint256 === identity.peerFingerprint, "PEER_PIN");
  requireCopy(!checkServerIdentity(peer, certificate), "PEER_ROLE");
  const started = Date.parse(certificate.valid_from);
  const ended = Date.parse(certificate.valid_to);
  requireCopy(ended - started <= 45 * 60000 && started <= Date.now() && ended > Date.now(), "PEER_LIFETIME");
}

export class Wire {
  private readonly iterator: AsyncIterator<Buffer>;
  private pending: Buffer = Buffer.alloc(0);
  constructor(readonly socket: TLSSocket) {
    this.iterator = socket.iterator({ destroyOnReturn: false });
  }
  async take(length: number): Promise<Buffer> {
    requireCopy(length >= 0 && length <= COPY.chunk + 2048, "FRAME_SIZE");
    const output = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < length) {
      if (this.pending.length === 0) {
        const part = await this.iterator.next();
        requireCopy(!part.done, "TRUNCATED_STREAM");
        this.pending = part.value;
      }
      const copied = Math.min(length - offset, this.pending.length);
      this.pending.copy(output, offset, 0, copied);
      this.pending = this.pending.subarray(copied);
      offset += copied;
    }
    return output;
  }
  async eof(): Promise<void> {
    requireCopy(this.pending.length === 0 && (await this.iterator.next()).done, "EXTRA_BYTES");
  }
  async frame(): Promise<{ kind: number; body: Buffer }> {
    const header = await this.take(5);
    const size = header.readUInt32BE(1);
    requireCopy(size <= COPY.chunk, "FRAME_SIZE");
    return { kind: header[0]!, body: await this.take(size) };
  }
}

async function write(socket: TLSSocket, body: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => socket.write(body, (error) => error ? reject(new Error("STREAM_WRITE")) : resolve()));
}

export async function frame(socket: TLSSocket, kind: number, body: Buffer): Promise<void> {
  const header = Buffer.alloc(5);
  header[0] = kind;
  header.writeUInt32BE(body.length, 1);
  await write(socket, header);
  await write(socket, body);
}

function countBuffer(count: number): Buffer {
  const body = Buffer.alloc(8);
  body.writeBigUInt64BE(BigInt(count));
  return body;
}

function unchanged(before: BigIntStats, after: BigIntStats): boolean {
  return before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs && before.mode === after.mode;
}

async function noSidecars(source: string): Promise<void> {
  for (const suffix of ["-wal", "-shm", "-journal"]) {
    try { await lstat(source + suffix); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    throw new Error("SOURCE_SIDECAR");
  }
}

export function requireReadOnlyMount(mounts: string): void {
  requireCopy(mounts.trim().split("\n").some((line) => {
    const fields = line.split(" ");
    return fields[4] === "/source" && fields[5]?.split(",").includes("ro");
  }), "SOURCE_NOT_READ_ONLY");
}

export function checkBudget(plan: CopyPlan, started: number, copied: number): void {
  const elapsed = performance.now() - started;
  const available = plan.totalMs - plan.verifyMs - elapsed;
  requireCopy(available > 0, "COPY_DEADLINE");
  if (elapsed >= plan.sampleMs) {
    requireCopy(copied > 0 && (plan.size - copied) / copied * elapsed < available, "THROUGHPUT_INSUFFICIENT");
  }
}

async function throttle(plan: CopyPlan, started: number, copied: number): Promise<void> {
  const delay = copied / plan.rate * 1000 - (performance.now() - started);
  if (delay > 0) await pause(delay);
}

export async function sendFile(socket: TLSSocket, plan: CopyPlan, started: number): Promise<Receipt> {
  const wire = new Wire(socket);
  requireCopy((await wire.take(8)).equals(Buffer.from("CPA00001")), "PROTOCOL_READY");
  await noSidecars(plan.source);
  const source = await open(plan.source, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let copied = 0;
  try {
    const before = await source.stat({ bigint: true });
    requireCopy(before.isFile() && before.size === BigInt(plan.size) && (before.mode & 0o222n) === 0n, "SOURCE_METADATA");
    const buffer = Buffer.alloc(plan.chunk);
    const digest = createHash("sha256");
    const transferStarted = performance.now();
    while (copied < plan.size) {
      checkBudget(plan, started, copied);
      const { bytesRead } = await source.read(buffer, 0, Math.min(buffer.length, plan.size - copied), null);
      requireCopy(bytesRead > 0, "SOURCE_TRUNCATED");
      const data = buffer.subarray(0, bytesRead);
      digest.update(data);
      await throttle(plan, transferStarted, copied + bytesRead);
      await frame(socket, 1, data);
      copied += bytesRead;
      requireCopy((await wire.take(8)).equals(countBuffer(copied)), "ACK_MISMATCH");
    }
    await noSidecars(plan.source);
    requireCopy(unchanged(before, await source.stat({ bigint: true })) && unchanged(before, await lstat(plan.source, { bigint: true })), "SOURCE_CHANGED");
    requireCopy(digest.digest("hex") === plan.sha256, "SOURCE_HASH_MISMATCH");
  } finally { await source.close(); }
  socket.setTimeout(plan.verifyMs + plan.idleMs);
  await frame(socket, 2, Buffer.concat([countBuffer(copied), Buffer.from(plan.sha256, "hex")]));
  socket.end();
  const reply = await wire.frame();
  requireCopy(reply.kind === 3 && reply.body.length <= 2048, "RECEIPT_FRAME");
  const receipt = JSON.parse(reply.body.toString("utf8")) as Receipt;
  requireCopy(receipt.run === plan.run && receipt.passed === true && receipt.bytes === plan.size && receipt.sha256 === plan.sha256 && receipt.sourceVerified === true && receipt.destinationVerified === true, "RECEIPT_MISMATCH");
  await wire.eof();
  return receipt;
}

export async function verifyDestination(plan: CopyPlan, file: string, signal?: AbortSignal): Promise<void> {
  const source = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await source.stat({ bigint: true });
    requireCopy(before.isFile() && before.size === BigInt(plan.size), "DESTINATION_SIZE");
    const digest = createHash("sha256");
    const buffer = Buffer.alloc(plan.chunk);
    let copied = 0;
    const started = performance.now();
    while (copied < plan.size) {
      requireCopy(!signal?.aborted, "TRANSFER_CANCELLED");
      requireCopy(performance.now() - started < plan.verifyMs, "VERIFY_DEADLINE");
      const { bytesRead } = await source.read(buffer, 0, Math.min(buffer.length, plan.size - copied), null);
      requireCopy(bytesRead > 0, "DESTINATION_TRUNCATED");
      digest.update(buffer.subarray(0, bytesRead));
      copied += bytesRead;
      await throttle(plan, started, copied);
    }
    requireCopy(unchanged(before, await source.stat({ bigint: true })) && unchanged(before, await lstat(file, { bigint: true })), "DESTINATION_CHANGED");
    requireCopy(digest.digest("hex") === plan.sha256, "DESTINATION_HASH_MISMATCH");
  } finally { await source.close(); }
}

export async function receiveFile(socket: TLSSocket, plan: CopyPlan, signal?: AbortSignal): Promise<Receipt> {
  const directory = await lstat(plan.destination);
  requireCopy(directory.isDirectory() && !directory.isSymbolicLink() && directory.uid === plan.uid && directory.gid === plan.gid && (directory.mode & 0o7777) === 0o700, "DESTINATION_NOT_PRIVATE");
  requireCopy((await readdir(plan.destination)).length === 0, "DESTINATION_NOT_EMPTY");
  const space = await statfs(plan.destination, { bigint: true });
  requireCopy(space.bavail * space.bsize >= BigInt(plan.size + plan.reserveBytes), "DESTINATION_SPACE");
  const partial = `${plan.destination}/archive.sqlite.partial`;
  const output = await open(partial, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  const wire = new Wire(socket);
  const digest = createHash("sha256");
  let copied = 0;
  const transferStarted = performance.now();
  try {
    requireCopy(!signal?.aborted, "TRANSFER_CANCELLED");
    await write(socket, Buffer.from("CPA00001"));
    while (copied < plan.size) {
      const message = await wire.frame();
      requireCopy(!signal?.aborted, "TRANSFER_CANCELLED");
      requireCopy(message.kind === 1 && message.body.length > 0 && message.body.length <= plan.chunk && copied + message.body.length <= plan.size, "DATA_FRAME");
      let written = 0;
      while (written < message.body.length) {
        const { bytesWritten } = await output.write(message.body, written, message.body.length - written);
        requireCopy(bytesWritten > 0, "SHORT_WRITE");
        written += bytesWritten;
      }
      digest.update(message.body);
      copied += message.body.length;
      await throttle(plan, transferStarted, copied);
      await write(socket, countBuffer(copied));
    }
    const seal = await wire.frame();
    requireCopy(seal.kind === 2 && seal.body.equals(Buffer.concat([countBuffer(plan.size), Buffer.from(plan.sha256, "hex")])), "SOURCE_SEAL");
    await wire.eof();
    requireCopy(digest.digest("hex") === plan.sha256, "STREAM_HASH_MISMATCH");
    requireCopy(!signal?.aborted, "TRANSFER_CANCELLED");
    await output.sync();
  } finally { await output.close(); }
  socket.setTimeout(plan.verifyMs + plan.idleMs);
  await verifyDestination(plan, partial, signal);
  requireCopy(!signal?.aborted, "TRANSFER_CANCELLED");
  const receipt: Receipt = { run: plan.run, passed: true, bytes: copied, sha256: plan.sha256, sourceVerified: true, destinationVerified: true };
  const receiptPath = `${plan.destination}/copy-receipt.pending.json`;
  const receiptFile = await open(receiptPath, "wx", 0o600);
  try { await receiptFile.writeFile(JSON.stringify(receipt) + "\n"); await receiptFile.sync(); }
  finally { await receiptFile.close(); }
  const directoryFile = await open(plan.destination, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    requireCopy(!signal?.aborted, "TRANSFER_CANCELLED");
    await link(partial, `${plan.destination}/archive.sqlite`);
    await directoryFile.sync();
    requireCopy(!signal?.aborted, "TRANSFER_CANCELLED");
    await link(receiptPath, `${plan.destination}/copy-receipt.json`);
    await directoryFile.sync();
  } finally { await directoryFile.close(); }
  await frame(socket, 3, Buffer.from(JSON.stringify(receipt)));
  await new Promise<void>((resolve) => socket.end(resolve));
  return receipt;
}

function watchSocket(socket: TLSSocket, idleMs: number): void {
  socket.setTimeout(idleMs, () => socket.destroy(new Error("IDLE_DEADLINE")));
  socket.on("error", () => {});
  socket.setNoDelay(true);
}

export async function runReader(plan: CopyPlan, identity: Identity, host: string): Promise<Receipt> {
  validateIdentity(identity, "reader", plan.run);
  const started = performance.now();
  const socket = connect({ host, port: plan.port, ca: identity.ca, cert: identity.cert, key: identity.key, servername: identityName("receiver", plan.run), minVersion: "TLSv1.3", rejectUnauthorized: true, allowHalfOpen: true });
  watchSocket(socket, plan.idleMs);
  const deadline = setTimeout(() => socket.destroy(new Error("TOTAL_DEADLINE")), plan.totalMs);
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once("secureConnect", resolve);
      socket.once("error", reject);
    });
    authorize(socket, identity, identityName("receiver", plan.run));
    return await sendFile(socket, plan, started);
  } finally { clearTimeout(deadline); socket.destroy(); }
}

export function startReceiver(plan: CopyPlan, identity: Identity, host: string): { completion: Promise<Receipt>; listening: Promise<number>; close: () => void } {
  validateIdentity(identity, "receiver", plan.run);
  let active: TLSSocket | undefined;
  const cancellation = new AbortController();
  let claim = false;
  let fail!: (error: Error) => void;
  let succeed!: (receipt: Receipt) => void;
  const completion = new Promise<Receipt>((resolve, reject) => { succeed = resolve; fail = reject; });
  const server = createServer({ ca: identity.ca, cert: identity.cert, key: identity.key, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3", allowHalfOpen: true, handshakeTimeout: plan.idleMs }, (socket) => {
    try {
      requireCopy(!claim, "ALREADY_CLAIMED");
      authorize(socket, identity, identityName("reader", plan.run));
      claim = true;
      active = socket;
      watchSocket(socket, plan.idleMs);
      socket.on("error", () => cancellation.abort());
      server.close();
      void receiveFile(socket, plan, cancellation.signal).then(succeed, (error: unknown) => { socket.destroy(); fail(new Error(safeFailure(error))); });
    } catch { socket.destroy(); }
  });
  server.maxConnections = 1;
  server.on("tlsClientError", () => {});
  server.on("error", (error) => fail(new Error(safeFailure(error))));
  const deadline = setTimeout(() => { cancellation.abort(); active?.destroy(); server.close(); fail(new Error("TOTAL_DEADLINE")); }, plan.totalMs);
  const listening = new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(plan.port, host, () => {
      const address = server.address();
      if (address && typeof address !== "string") resolve(address.port);
      else reject(new Error("LISTEN_FAILED"));
    });
  });
  const close = () => { cancellation.abort(); clearTimeout(deadline); active?.destroy(); server.close(); };
  void completion.then(() => clearTimeout(deadline), () => clearTimeout(deadline));
  return { completion, listening, close };
}

export async function loadIdentity(role: "reader" | "receiver"): Promise<Identity> {
  const metadata = await lstat("/identity/bundle.json");
  requireCopy(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= 32768 && metadata.uid === COPY.uid && (metadata.mode & 0o7777) === 0o600, "IDENTITY_FILE");
  const identity = JSON.parse(await readFile("/identity/bundle.json", "utf8")) as Identity;
  validateIdentity(identity, role, COPY.run);
  return identity;
}

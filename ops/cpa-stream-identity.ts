import { mkdirSync, writeFileSync, readFileSync, statfsSync, chmodSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { COPY, identityName, requireCopy, safeFailure } from "./lib/cpa-stream.ts";

export const IDENTITY_DIRECTORY = "/dev/shm/cpa-stream-20261005a";

function openssl(args: string[]): void {
  const result = spawnSync("openssl", args, { stdio: ["ignore", "ignore", "pipe"], timeout: 15000 });
  requireCopy(result.status === 0, "CERTIFICATE_GENERATION");
}

function timestamp(milliseconds: number): string {
  return new Date(milliseconds).toISOString().replace(/[-:]/g, "").replace(/T/, "").slice(0, 14) + "Z";
}

function main(): void {
  if (process.argv.length === 3 && process.argv[2] === "--help") {
    console.log("cpa-stream-identity create; fixed-purpose 40-minute internal copy identities, RAM only, no private stdout");
    return;
  }
  requireCopy(process.argv.length === 3 && process.argv[2] === "create", "ARGUMENTS");
  requireCopy(statfsSync("/dev/shm").type === 0x01021994, "IDENTITY_NOT_RAM");
  process.umask(0o077);
  mkdirSync(IDENTITY_DIRECTORY, { mode: 0o700 });
  const file = (name: string) => `${IDENTITY_DIRECTORY}/${name}`;
  openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-config", "/dev/null", "-keyout", file("ca.key"), "-out", file("ca.crt"), "-subj", `/CN=${COPY.run}`, "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  writeFileSync(file("index"), "", { flag: "wx", mode: 0o600 });
  writeFileSync(file("serial"), "01\n", { flag: "wx", mode: 0o600 });
  const extensions = ["reader", "receiver"].map((role) => `[${role}]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=${role === "reader" ? "clientAuth" : "serverAuth"}\nsubjectAltName=DNS:${identityName(role as "reader" | "receiver", COPY.run)}\n`).join("\n");
  writeFileSync(file("ca.cnf"), `[ca]\ndefault_ca=copy\n[copy]\ndatabase=${file("index")}\nserial=${file("serial")}\nnew_certs_dir=${IDENTITY_DIRECTORY}\ncertificate=${file("ca.crt")}\nprivate_key=${file("ca.key")}\ndefault_md=sha256\npolicy=identity\nunique_subject=no\n[identity]\ncommonName=supplied\n${extensions}`, { flag: "wx", mode: 0o600 });
  const started = timestamp(Date.now() - 30000);
  const ended = timestamp(Date.now() + 40 * 60000);
  for (const role of ["reader", "receiver"] as const) {
    openssl(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-config", "/dev/null", "-keyout", file(`${role}.key`), "-out", file(`${role}.csr`), "-subj", `/CN=${identityName(role, COPY.run)}`]);
    openssl(["ca", "-batch", "-notext", "-config", file("ca.cnf"), "-extensions", role, "-startdate", started, "-enddate", ended, "-in", file(`${role}.csr`), "-out", file(`${role}.crt`)]);
    chmodSync(file(`${role}.key`), 0o600);
  }
  for (const role of ["reader", "receiver"] as const) {
    const peer = role === "reader" ? "receiver" : "reader";
    const identity = { ca: readFileSync(file("ca.crt"), "utf8"), cert: readFileSync(file(`${role}.crt`), "utf8"), key: readFileSync(file(`${role}.key`), "utf8"), peerFingerprint: new X509Certificate(readFileSync(file(`${peer}.crt`))).fingerprint256 };
    writeFileSync(file(`${role}.json`), JSON.stringify(identity), { flag: "wx", mode: 0o600 });
  }
  console.log(JSON.stringify({ run: COPY.run, generated: true, expires: ended }));
}

try { main(); } catch (error) { console.error(safeFailure(error)); process.exitCode = 1; }

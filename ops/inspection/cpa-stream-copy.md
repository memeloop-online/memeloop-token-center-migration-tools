# Fixed CPA frozen-copy transport candidate

This candidate is for review and GHA validation only. Implementing/merging it does not authorize deployment, source attachment, transfer, new storage, digest preparation, production import or deletion. It does not replace any production service or modify MTU, routes, Longhorn settings or old failed Jobs.

## Fixed resource inventory

All resources belong to namespace `cliproxyapi`, run `cpa-stream-20261005a`.

| Resource | Exact identity / constraint |
| --- | --- |
| Reader Job | `mtc-cpa-stream-reader-20261005a`, node `sansheng-hv` |
| Reader volume | ONLY `mtc-session-archive-v08-live-clone-20260919a`, claim readOnly + mount readOnly |
| Source file | `/source/archive.sqlite`, exactly 30205399040 bytes, mode without write bits, no WAL/SHM/journal |
| Source SHA256 | `d42a11cebe062ea6c908ebf2ff6cdbdae410e392a01af5faf577a4eab30e589f` |
| Receiver Job | `mtc-cpa-stream-receiver-20261005a`, node `westlake` |
| Receiver volume | ONLY existing `mtc-cpa-recovery-work-20261005`, no allocation |
| Destination | NEW `/destination/recovery-stream-20261005a`; mkdir exclusive; existing directories are rejected, never repaired |
| Storage check | work PV `pvc-a5045b54-0f10-4f60-b1f5-18167620ba31`, Retain, exactly one replica on westlake `/data2/longhorn`, disk UUID `417d9e01-7601-4cba-9898-8b1ab4d9cfad` |
| Code ConfigMap | `mtc-cpa-stream-code-20261005a`, immutable, SHA256 annotation of exact two-file runtime source |
| Runtime image | `ghcr.io/memeloop-online/memeloop-token-center-migration-tools@sha256:348c6ef444e1744798a0ec0d13ca394a8dd413e5fb7d1fe277b7f52684892126` |
| Main limits | each 250m CPU / 128Mi memory; combined 500m / 256Mi; requests each 50m / 48Mi |
| Init limits | each 100m / 64Mi, sequential with own main; only CHOWN capability, no source mount; maximum combined remains 500m / 256Mi |
| Lifetime | both suspended by default, 1800s Job deadline, backoffLimit=0; application deadline 1650s, identity wait <=120s, idle <=30s; verification wait bounded |
| Transient secrets | each private memory emptyDir <=4Mi, no Kubernetes Secrets, no production credentials, no service-account token |
| Networking | one mTLS connection, TCP 18443, Pod IP only, no Service/Ingress/public listener/DNS/general egress |

Code is delivered as two exact, immutable ConfigMap files over the pinned existing Node runtime, not an unbuilt executable silently assumed to be in the old image. GHA tests the runtime's ability to execute the TypeScript entrypoint. Source and code hash must match the reviewed commit before deployment. No arbitrary source/destination path, URL, port, expected hash, size or rate is exposed by the CLI. Receiver IP must be a westlake Pod address in `10.42.3.2–254`, and the peer must have the exact one-use pinned certificate; a subnet address alone is not authorization.

## NetworkPolicy contract

Two policies, named exactly like the Jobs, select the run label plus distinct reader/receiver app labels. Reader ingress is empty; reader egress allows only the receiver selector on TCP 18443. Receiver egress is empty; receiver ingress allows only the reader selector on TCP 18443. Both selectors are namespace-local: no namespaceSelector, ipBlock, DNS, node-CIDR exception or public ingress. Return traffic relies on established-connection handling.

Existing Tailnet subnet SNAT may prevent a CNI from recognizing the source selector. Kubernetes policy behavior around node-originated/NAT traffic must not be treated as proven by rendering. Before opening the archive, require mutual TLS with exact short-lived role certificates. If the selector-only handshake cannot work, STOP; never widen to the cni0 address or node CIDR automatically. Peer mTLS is mandatory even if node-originated traffic bypasses a CNI rule. Fresh review must also exclude other additive allow policies selecting these Pods and duplicate Pods carrying these exclusive run labels.

## Transfer/acceptance contract

The reader and source engine must both be on sansheng-hv with the only usable frozen-source replica local there. The receiver and work engine/replica must remain on westlake. Parent/operator read-only Longhorn placement/consumer checks are mandatory before enabling the reader; nodeSelector by itself does not prove replica locality. No original volume settings may be changed to force this condition.

The receiver's exclusive-directory init fsyncs the parent `/destination` after mkdir/chown and fails if that fsync fails. Before creating any partial or sending READY, the unprivileged receiver independently fsyncs the private child directory and its parent in that order, making the new directory entry part of the durability boundary. A parent-fsync failure must prevent source opening, transfer and success, not merely appear in a later warning.

Source opens only after the authenticated receiver has checked private empty destination, free space of payload plus 20GiB, completed those directory fsyncs, and exclusively created its partial. One source pass hashes while reading through bounded buffers. Each <=4MiB frame is acknowledged only after the receiver writes it, providing end-to-end backpressure. Both ends pace payload <=64MiB/s. Source metadata/identity and sidecars are checked before/after that one pass; source hash must match the old seal before the source-success frame and TLS half-close.

Receiver enforces exact byte length, frame bounds, source-success frame, EOF (rejecting appended bytes) and stream SHA256. It fsyncs the new partial, independently rereads/hashes ONLY that destination, and fsyncs the new receipt. Exclusive hardlinks publish archive and receipt with directory fsyncs. The partial and pending-receipt links are intentionally retained even on success; they do not allocate another payload copy. Failure never deletes or overwrites existing data. A failure after publication or lost final acknowledgment is NOT permission to retry: inspect retained state first.

Acceptance requires BOTH Job successes, matching termination receipts and the durable destination receipt; a pending receipt alone is not acceptance. Hash mismatch, timeout, EOF, extra bytes, source change, stored corruption, fsync failure or insufficient throughput refuses success. The reader reserves verification time and stops early if receiver-confirmed throughput cannot fit the remaining budget. Local-reader/app-stream removes remote Longhorn block RPCs, NOT loss on the underlying Tailnet; ping does not promise completion within 1800 seconds.

Failure diagnostics retain only explicitly allowlisted native errno/TLS codes, never raw native messages, paths, peer addresses, keys or TLS error details. Reader failures distinguish TLS connection, peer authorization and stream phases; receiver handshake/peer rejection logs use the same sanitizer. `source-ready` means the authenticated receiver sent READY, not that the source hash or transfer succeeded. Unknown errors remain `COPY_FAILED`; do not infer a network root cause from that generic value. These diagnostics do not authorize a retry or make an already-created exclusive directory reusable.

## One-shot RAM-only network diagnostic

The separate fixed run `cpa-stream-diagnostic-20261006a` uses `diagnostic-reader`, `diagnostic-receiver` and `stage-diagnostic-reader|receiver` on the same CLI/library and pinned image. It transfers exactly 1MiB of synthetic byte 71, never an archive. Reader `/source` and receiver `/destination` must be tmpfs; no PVC, hostPath, production credential or arbitrary path/size/hash override is exposed. Each data emptyDir is Memory/8Mi, identity Memory/4Mi. The init creates the synthetic reader file mode0400; the main mounts it RO. Receiver exclusively creates `/destination/recovery-diagnostic-20261006a`. The same nodes, 250m/128Mi per role, 64MiB/s ceiling, 1800s/backoff0, TLS identities and namespace-local TCP18443 role-selector policy shape apply, with diagnostic-only names/labels.

Render `diagnostic-code|diagnostic-policies|diagnostic-receiver|diagnostic-reader` with `ops/cpa-stream-resources.ts`; the real reader still requires the dedicated receiver IP. Generate identities using `node ops/cpa-stream-identity.ts create-diagnostic`, solely under `/dev/shm/cpa-stream-diagnostic-20261006a`. Stage each bundle via stdin immediately once its container runs, without waiting for source-volume checks: this run has no data volumes. GHA executes the actual CLI and staging commands in two 128Mi/250m containers with RAM-backed data, RO reader bind mount, internal network and matching receipts. A diagnostic result does not authorize another archive copy; do not reuse the consumed production run or its preserved exclusive directory.

## GHA-only constrained-stream evidence

The memory budget is **128Mi per role, 256Mi total**, and the CPU budget is **250m per role, 500m total**. **64MiB/s is the throughput ceiling, not a 64Mi memory allocation.** The runtime `--help` smoke test is not memory acceptance.

In addition to mTLS/failure tests, CI runs a real 256MiB synthetic fixture through two separate containers of the pinned image, each `--memory 128m --memory-swap 128m --cpus 0.25`, UID 10001, capabilities dropped, read-only root filesystem. Their dedicated Docker network is internal with no published port. The source fixture is bind-mounted RO only in the reader; the work directory is mounted only in the receiver. Certificates remain in the runner's private tmpfs and are mounted per-role. The fixture worker and plan overrides live only under tests; they are not included in the runtime ConfigMap or exposed by the production CLI.

The receiver deliberately paces at 8MiB/s against a reader ceiling of 64MiB/s. CI records each role's cgroup memory/swap/CPU limits, memory peak, maximum process RSS, OOM status and timestamped source-fd read positions / receiver file sizes. Acceptance requires both roles exit zero, no OOM, exact 128Mi/no-swap/250m cgroups, RSS below each role's cap, matching verified receipts for the 256MiB payload (twice either memory cap, 64 times the frame buffer), and retained partial. Sampled source read-ahead must be at most three 4MiB frames with overlapping timestamps; its near-EOF read span must be at least 25 seconds under the slower receiver, not a whole-file preload. This is a bounded-memory/backpressure test, not a production-link throughput promise.

`cpa-stream-bounded-${github.sha}` contains the JSON measurement report only if the test actually ran; its `passed` flag, Job outcome and recorded tested commit must all be checked. Kernel cgroup peak and process RSS are reported separately. Do not call a queued run, missing artifact, runtime-help smoke, or failure report successful validation. Parent/child fsync ordering and injected parent-fsync failure are separately covered, including no READY/no partial/no success on a parent failure and retained directory/no init retry after failure. A partial-file fsync failure continues to preserve partial and refuse publication.

## Preparation commands — not permission to run in the cluster

Use the reviewed repository checkout and locked dependencies. Rendering is not a build/test. GHA publishes a review artifact with ConfigMap, policies, suspended receiver, checksums and an explicitly NON-APPLY example reader IP. The real reader manifest must be rendered after the dedicated receiver Pod IP exists; never apply the example IP.

```text
node ops/cpa-stream-resources.ts code
node ops/cpa-stream-resources.ts policies
node ops/cpa-stream-resources.ts receiver
CPA_RECEIVER_IP=<approved-receiver-pod-ip> node ops/cpa-stream-resources.ts reader
```

Only AFTER a separate execution approval: verify unique resource/label ownership, source consumers=0, both storage placements and fresh capacity, no conflicting policy, and pinned image cached on both nodes. Create reviewed code/policies and the suspended receiver. Create ephemeral transport identities immediately before starting, not hours in advance:

```text
node ops/cpa-stream-identity.ts create
```

The helper has no path/subject/lifetime overrides. It exclusively creates `/dev/shm/cpa-stream-20261005a` after checking tmpfs, uses OpenSSL to issue a unique internal CA and role-specific 40-minute leaf certificates, and prints no private material. After packaging the role bundles it removes its newly generated CA signing key and redundant individual key files; only the two role bundles retain private material, in RAM. On generation failure, preserve diagnostics without printing contents and explicitly clear only this newly owned RAM directory. These certificates are solely internal test/data-copy transport identities, not user-service credentials.

After approved unsuspend of the receiver, deliver only its bundle through exec stdin within the 120-second readiness window (no shell tracing, printing or base64 output). Then render/create the reader with the actual receiver Pod IP; after placement approval unsuspend it and deliver its bundle:

```text
kubectl -n cliproxyapi exec -i <exact-receiver-pod> -c receiver -- node /tool/cpa-frozen-stream-copy.ts stage-receiver < /dev/shm/cpa-stream-20261005a/receiver.json
kubectl -n cliproxyapi exec -i <exact-reader-pod> -c reader -- node /tool/cpa-frozen-stream-copy.ts stage-reader < /dev/shm/cpa-stream-20261005a/reader.json
```

Staging validates exact node/Pod role, runtime UID, tmpfs, key/certificate match, CA signature, SAN and <=45-minute lifetime. It creates a new private bundle, never overwrites one, and publishes it atomically. An absent bundle times out without source access. Preflight/handshake must fit the original deadline; do not suspend/resume to reset it. No retry after any partial, failure or late acknowledgment.

## Cleanup proposal — separate operator decision

Capture Job/Pod status, code hash and nonsecret receipts first. Verify source/work detach and no consumers; do not rehash source. After explicit approval, delete ONLY these two new Jobs/owned Pods, the two run-specific NetworkPolicies and immutable code ConfigMap. Job deletion also removes each Pod's memory-backed identity; delete ONLY the freshly owned parent `/dev/shm/cpa-stream-20261005a` directory after identities are no longer needed. Never print keys in audit commands.

Do NOT delete any PVC, PV, original source, old Job, source Service, new/old partial, archive or receipt. No automatic TTL/cleanup controller is created. No digest, sealed 50Gi, export/import, production ingress or deletion authorization is implied by this PR.

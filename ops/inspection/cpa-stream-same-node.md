# Same-node CPA copy profile and target-only performance proposal

This change authorizes code review and GHA only. Neither merge nor green CI authorizes a source attach, a target attach, a performance write or another archive copy. The original and RAM-diagnostic profiles remain available with their original names and westlake-only receiver addresses; their previously consumed runs must not be reused. There is no node iptables/SNAT exception path.

## Fixed same-node contract

| Item | Exact value |
| --- | --- |
| Run / label | `cpa-stream-local-20261006a` |
| Reader Job / NP | `mtc-cpa-stream-local-reader-20261006a` |
| Receiver Job / NP | `mtc-cpa-stream-local-receiver-20261006a` |
| Immutable code CM | `mtc-cpa-stream-local-code-20261006a` |
| Namespace / both nodes | `cliproxyapi` / `sansheng-hv` |
| Source | unchanged `mtc-session-archive-v08-live-clone-20260919a`, claim AND mount RO, no source mount in init |
| Target | only existing `mtc-cpa-recovery-work-20261005`, RW, no new PVC |
| New destination | `/destination/recovery-stream-local-20261006a`, exclusive mkdir, parent/child fsync, no reuse/repair |
| RAM identities | `/dev/shm/cpa-stream-local-20261006a`, unique CA, role SANs, 40-minute leaves, peer pins |
| Receiver endpoint | actual dedicated Pod address in `10.42.2.2–254`, never example address or subnet/node-wide NP exemption |
| Runtime | `ghcr.io/memeloop-online/memeloop-token-center-migration-tools@sha256:348c6ef444e1744798a0ec0d13ca394a8dd413e5fb7d1fe277b7f52684892126` plus the reviewed immutable two-file code CM |

Only profile selection, fixed placement, endpoint range, resource names, destination and run-bound identity differ. Source size/seal, one source hash pass after authenticated READY, mutual TLS/pins, backpressure, 64MiB/s ceiling on transfer and target verification, fsync/O_EXCL publication and matching two-ended/durable receipts are unchanged. Both suspended Jobs retain 1800s/backoff0, each main 250m/128Mi (total 500m/256Mi), with unchanged lower init limits. No overrides for path, node, subnet, source seal or budget are exposed.

Policies still select only this run's two roles in this namespace on TCP18443. Reader has no ingress; receiver has no egress. No Service, DNS, public endpoint, Secret, service-account token, host networking or node-rule change is created. A matching subnet does not grant access: selector policy and short-lived pinned mTLS are both required. Exclude duplicate run-labelled Pods and other additive allow policies before an approved run.

Source placement is an operator-attested storage condition, not something the unprivileged process can discover. Before staging the reader's identity, capture that the source engine is on sansheng-hv and its active RW backend is ONLY the original local replica there; both PVC/mount readOnly flags must be present. Do not move the source or modify its Longhorn settings to meet this condition. A wrong backend, competing consumer or inadequate capacity stops the run with identities unstaged and partials preserved. Account for automatic extra source replica reservation without changing replica count.

The target frontend/engine may run on sansheng-hv, but its single replica must remain on westlake `/data2/longhorn`, disk `417d9e01-7601-4cba-9898-8b1ab4d9cfad`, PV/CSI volume handle `pvc-a5045b54-0f10-4f60-b1f5-18167620ba31`, SC `mtc-cpa-recovery-westlake-data2-20261005`, 100Gi RWO/XFS/Retain. Do not mutate SC, selectors, locality or replica count. This avoids the cross-node application REJECT path, NOT cross-node Longhorn target I/O. Kernel/storage-manager CPU and memory are outside the copy-container cgroups. Production throughput within 1800s is not established by GHA.

## Review artifacts and later commands

GHA renders `same-node-code.yaml`, `same-node-policies.yaml`, `same-node-receiver.yaml`, and `same-node-reader-EXAMPLE-IP-NOT-FOR-APPLY.yaml`, with SHA256SUMS in `cpa-stream-review-${github.sha}`. For a PR, that suffix is the checked-out merge-tree SHA, not automatically the source head. Check run checkout evidence, source head and artifact checksums together. Never apply the example reader manifest.

Rendering with the reviewed checkout/locked runtime (no deployment):

```text
node ops/cpa-stream-resources.ts same-node-code
node ops/cpa-stream-resources.ts same-node-policies
node ops/cpa-stream-resources.ts same-node-receiver
CPA_RECEIVER_IP=<actual-dedicated-receiver-pod-ip> node ops/cpa-stream-resources.ts same-node-reader
```

Only after separate run approval and the existing storage/consumer checks, create RAM identities immediately before starting the Jobs:

```text
node ops/cpa-stream-identity.ts create-same-node
kubectl -n cliproxyapi exec -i <exact-receiver-pod> -c receiver -- node /tool/cpa-frozen-stream-copy.ts stage-same-node-receiver < /dev/shm/cpa-stream-local-20261006a/receiver.json
kubectl -n cliproxyapi exec -i <exact-reader-pod> -c reader -- node /tool/cpa-frozen-stream-copy.ts stage-same-node-reader < /dev/shm/cpa-stream-local-20261006a/reader.json
```

Stage receiver within its existing identity deadline, capture its actual IP, then create the correctly addressed reader. Stage reader only after local-backend attestation. No timeout reset, automatic retry or extra source hash. Capture both termination receipts, durable target receipt, statuses, placement and code hash before any approved cleanup. Cleanup names are only the two new Jobs/their owned Pods, two same-name NPs, the exact new CM, and the newly owned RAM identity directory. No PVC/PV, original data, archive, receipt, old/new failed directory or partial is deleted. In particular preserve `recovery-20261005`, `recovery-stream-20261005a`, and any failed `recovery-stream-local-20261006a`.

GHA adds profile/CLI/identity isolation tests and runs the existing 256MiB >128Mi bounded/backpressure fixture for BOTH profiles. The same-node fixture executes the actual staging CLI, uses same-node IP/placement validation and identity loading, then the unchanged streaming functions with test-only payload/deadline overrides. Those overrides are confined to tests, absent from the code CM and production CLI. It verifies matching run-bound receipts, retained partial and no OOM in two 128Mi/250m containers. This is not a 30GB source read or a live-cluster network test.

## Separate target-only direct-I/O proposal — execution NOT approved

The exact suspended Job and deny-all NP are in `cpa-work-directio-20261006a.yaml`; GHA also publishes it as `target-only-directio-SUSPENDED-NOT-APPROVED.yaml`. Both are named `mtc-cpa-work-directio-20261006a`; label is `memeloop.io/cpa-work-probe=directio-20261006a`. It mounts ONLY the work PVC on sansheng-hv, never source. No network, TLS identity, credential, service-account token or privileged container is required. Init has only CHOWN for an exclusive new private directory and parent fsync. There is no fsGroup/recurse/chmod of existing data.

Preconditions for a separate parent execution approval: exact reviewed manifest/head and green pinned-image command test; unique Job/label/path ownership; target PVC bound to the exact PV/CSI handle, SC and westlake disk above; no competing target consumer; source remains detached; adequate current disk headroom. After approved target-only attach, confirm target engine on sansheng-hv with the unchanged westlake replica. The probe checks filesystem free space >=21GiB before its <=1GiB allocation. Unsupported direct I/O or any placement/capacity mismatch means stop, NOT buffered fallback, source attach, replica relocation or retry.

Exact container image is the same digest listed above. Main command is `timeout -s TERM -k 5 165 sh -ec` with the reviewed literal script in the manifest. Its measured operations are:

```text
dd if=/dev/urandom of=/destination/perf-directio-20261006a/probe.bin bs=4M count=256 iflag=fullblock oflag=direct conv=notrunc,fsync
dd if=/destination/perf-directio-20261006a/probe.bin of=/dev/null bs=4M count=256 iflag=direct
```

The script first validates UID:GID10001, the new private directory, capacity and exclusive file creation; it never runs these dd commands against an existing file. Exactly 1GiB is written, fsynced, then independently reopened/read with O_DIRECT. This is a performance probe, NOT a content-integrity receipt. Random generation and 250m CPU may lower measured write throughput. Direct I/O avoids a page-cache-only success; no cache drop/global tuning is used. Write/read phase timestamps and dd counts/rates remain in Pod logs; GHA verifies the exact pinned runtime/commands against its own scratch disk, not Longhorn.

Limits: main 250m/128Mi, init sequential 100m/64Mi; Job activeDeadlineSeconds180/backoff0, process timeout165 with kill-after5, termination grace5. Blocked kernel I/O can still delay actual teardown; no claim that a watchdog can forcibly interrupt uninterruptible kernel work. No source-dependent action follows automatically. The trap unlinks ONLY its successfully exclusively created `probe.bin`; private directory is retained as consumed-run evidence. SIGKILL may leave that owned file: report it for exact-file cleanup, never recursively delete the directory or retry. Every old/new copy partial and receipt remains untouched. Capture results and delete only the probe Job/owned Pod/NP after separately approved cleanup; target detach does not delete data.

The 64MiB/s production stream cap is unchanged. The proposed direct-I/O commands measure raw bounded 1GiB write/read throughput under 250m/128Mi; they do not impose a 64MiB/s I/O-rate cap and must not be presented as doing so. This distinction is part of the separate probe approval, not permission to run it now.

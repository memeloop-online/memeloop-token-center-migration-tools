# Segmented RAM diagnostic — review only, no runtime GO

Use the existing `segmented-*` renderer/CLI and `create-segmented` identity helper.
Fixed run `cpa-stream-segmented-20261011a`, Sansheng to Versetensor, 18443,
same unique receiver NP with source `100.64.0.6/32`. CA, peer fingerprint and
role/run SAN remain mandatory; node address never replaces mTLS identity.

Synthetic byte-71 data only: four 4MiB frames, one connection, one outstanding
frame, 64MiB/s, unchanged 128Mi/250m limits. Source/destination are 32Mi memory
emptyDirs, source mounted RO. Identity is private RAM. No PVC, hostPath, Service
or real source/work volume. Full synthetic stream hash, independent destination
hash/fsync and matching receipts remain required, not an archive/import PASS.

Application/Job business deadline 120s; verification reserve 20s. Operator must
start an external 180s window and reserve its last 60s for normal UID-checked
cleanup of owned Jobs/Pods/NP/CM, RAM identity and any port-forward. No automatic
TTL or forced deletion. Unknown ACK: GET original handle, never replay start.
Record exact remaining UIDs if cleanup fails. CI+independent review+parent GO
are required before any runtime execution. This PR starts no cluster resources.

Bounded trace: 22 records per role, 44 total, each under 512 bytes. Fixed fields
stage/run/role/segment/phase/elapsedMs/durationMs only; no payload or credentials.
Reader frame phases: start, read-hash, throttle, frame-write, ack-read;
receiver: start, frame-read, write-hash, throttle, ack-write. Final phases are
reader receipt-start/read and receiver fsync/verify. An absent next completion
marks the unfinished phase. Times are local monotonic; correlate frame indices,
never subtract clocks across nodes. Frame-write measures existing TLS write
callbacks, not remote delivery or a separately measured kernel drain. Frame-read
includes sender pacing/arrival wait. Timings alone cannot establish RTT/loss,
CPU throttling or physical disk limits.

Existing GHA exercises the actual staged CLI in the pinned immutable runtime,
RAM data, unchanged limits; validates receipts, four frame sequences and bounded
trace, generator no-PVC/exact NP and full identity isolation. Exact revision
trace and rendered resources join existing artifacts. No local tests/build/install.

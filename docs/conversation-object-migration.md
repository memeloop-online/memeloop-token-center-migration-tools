# Conversation object migration

This command is owned here, not in the product repository. CI assembles it
against an exact reviewed product revision and its Cargo.lock. It reuses
`ArchiveStore` and does not modify the existing CPA importer or its runtime pin.

Current executable scope: exact `semantic_atoms` body transfer and context-node
parent/depth/hash reconstruction. This is **not yet a whole-store cutover tool**.
`copy-locators` / `verify-locators` also stream request/response objects (including
chunked legacy inline JSON) and indexed media into tenant CAS, with independent
source/target hash, byte, count and ordered-receipt verification. Source
credentials use `MTC_SOURCE_S3_*` environment references; destination keeps
existing `MTC_S3_*` configuration. These phases never replace source locators
or delete original objects. Media bytes must match the existing index digest.

`copy-spools` / `verify-spools` decode retained legacy v2/zstd1 chunks with
authenticated tenant/request/reservation/sequence AAD, stream plaintext into
CAS, verify chunk sequence/count/bytes and independent readback, and retain the
entire source. The source encryption key uses the existing key-pepper
environment reference. Failed authentication stops transfer without clearing
source rows. Preserving a partial spool does not certify a complete response;
its original state is retained in the receipt.

`copy-payloads` / `verify-payloads` stream the original semantic payload and
outbox request/snapshot/key-snapshot/hints fields into CAS, without normalizing
their JSON or clearing source. The receipt retains field identity and exact
source digest. This covers original payload bodies as well as branch/tool
metadata that cannot be discarded on the strength of atom verification alone.

Locator transfer also inventories import records (including previous locators),
unlinked requests, quarantine records and immutable quarantine versions. Each
source class has its own ordered receipt identity; legacy inline originals
stream from their exact source columns. This does not modify the CPA importer.
Do not use atom counts to claim complete dialogue/media migration.

`reconstruct` / `verify-reconstruction` walk each retained observation's exact
prefix ancestry and stream a separate NDJSON object per observation. Event
records carry explicit descending ordinals, parent hashes and verified body
references; media records carry verified type/part/hash/length references.
Observation metadata preserves agent/parent relationships without flattening
branches. Exact original request/response references are mandatory: missing
raw evidence fails closed. Independent reconstruction must reproduce the same
object hash, event/media counts and ordered receipt digest. This certifies the
retained historical projection, not that older normalization captured every
unknown provider field. Raw JSON/SSE remains the original evidence.

Verified raw-locator transfer publishes the product's immutable raw roots only
after source/destination byte verification, allowing direct product reads without
inline-body or old-bucket fallback. It never alters source rows.

The command defaults to read-only `inventory`. Credentials and source database
URL use existing `MTC_*` environment configuration; the configured archive is
the destination. No credentials are accepted in command arguments or emitted
in receipts. Checkpoint identity binds the credential-free source identity and
target endpoint/bucket/path.

Inventory uses a repeatable-read, read-only transaction and reports exact text
and inline byte counts, source-class counts, missing/gap locators, retained
encrypted chunk bytes and headers with no retained chunks. Indexed media bytes
are labelled as index claims, not GET/hash verification. It never treats physical
relation size, missing originals or an empty transfer set as proof of fidelity.

Run `copy --writers-quiesced`, then `verify --writers-quiesced`, using the
`--phase` argument and the same private `--checkpoint` file. Copy streams
65536-character source fragments through bounded multipart object writes.
There is no total document-byte limit. Source bodies remain unchanged.
Destination bytes, BLAKE3, Unicode character counts and per-row readback are
verified before checkpoint advance. Retry reuses immutable tenant CAS objects.

`verify` independently rereads every source object and compares row count,
byte count, ordered digest and all context-node parent/depth/content identities.
It does not label absent raw responses or external media as recovered.

Only `--phase cutover-test --writers-quiesced` mutates source rows. It requires
a completed atom and dialogue-reconstruction verification receipt and a database
named `*_test` or `mtc_test_*`. Before the first source mutation it reruns atom
and reconstruction verification; a stale receipt alone is insufficient.
Each target object is verified again before conditional replacement of the
old body with its object reference. A changed source stops cutover rather than
being deleted. Checkpoint resume tolerates a committed row whose checkpoint
write was interrupted. No production mutation or table-drop command exists.

Checkpoint files are atomically replaced, fsynced and protected by an exclusive
file lock plus a database advisory lock. Store them on persistent private
storage. Lost checkpoints can restart copy before cutover; never invent a
verification receipt to continue a partial cutover.

CI exercises an isolated PostgreSQL database and memory-backed ArchiveStore.
RustFS TEST restore, throughput, CPU and memory measurements remain required;
an in-memory fixture is not evidence for deployment resource sizing.

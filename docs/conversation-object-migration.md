# Conversation object migration

This command is owned here, not in the product repository. CI assembles it
against an exact reviewed product revision and its Cargo.lock. It reuses
`ArchiveStore` and does not modify the existing CPA importer or its runtime pin.
The dedicated object runtime now includes the uncapped streaming compressed
archive decoder. Real RustFS CI copies and independently verifies a 130 MiB
compressed historical source while preserving the original source hash/bytes.

Preexisting atom body references also require explicit `MTC_SOURCE_S3_*`
configuration. Copy reads their source CAS, verifies full byte/hash/UTF-8
character counts, streams the body to target CAS, and verifies target readback.
A readable target object alone does not prove a source copy. Wrong or missing
source credentials/body/count evidence stops verification and preserves source.

`copy-durable-roots` / `verify-durable-roots` independently discover source
`tenants/*/raw/v1` and `tenants/*/conversations/v1` roots, including captures
that never acquired a SQL index, supplier summaries, outbound failover attempts,
and explicit failure markers. The conversation walk verifies manifest/prefix
ancestry, branch/event links, original captures and media references. JSON event
documents are skipped through a bounded streaming parser while their complete
CAS bytes are copied and hashed. Compressed locators retain their original
format and decoded byte/hash identity across both the SQL-locator and root
phases. Existing atom CAS keys retain that same identity. A readable CAS object
whose actual hash disagrees with its source key stops migration. Only objects reachable from these roots
are copied: unreferenced CAS, staging and raw FIFO cache stay outside the set.
Counts distinguish exact roots, distinct referenced CAS objects, decoded bytes
and unresolved gap roots. Deduplication uses temporary disk markers rather
than keeping a body/key inventory in RAM. Every rerun starts enumeration from
the beginning because backend list order is not a safe resume cursor; immutable
CAS and exact root creation make this idempotent. A changed source, unknown root
schema, unreadable object or conflicting target root refuses verification.
Missing originals remain explicit; an earlier failure marker is only healed by
a real readable source capture. Run these phases before `verify-all`; previous
aggregate receipts lacking this independently verified input cannot authorize
cutover. The default SQL inventory explicitly does not scan object-only roots.

Current executable scope includes durable object roots, exact `semantic_atoms`
body transfer and context-node parent/depth/hash reconstruction. This is **not yet a whole-store cutover tool**.
`copy-locators` / `verify-locators` also stream request/response objects (including
chunked legacy inline JSON) and indexed media into tenant CAS, with independent
source/target hash, byte, count and ordered-receipt verification. Source
credentials use `MTC_SOURCE_S3_*` environment references; destination keeps
existing `MTC_S3_*` configuration. These phases never replace source locators
or delete original objects. Media bytes must match the existing index digest.
After `verify-all`, `cutover-locators-test --writers-quiesced` can conditionally
replace all 13 supported locator kinds with their verified target CAS keys:
live request/response, indexed media, imports including previous versions,
unlinked requests, quarantine records and quarantine versions. It uses the
same TEST database guard as atom cutover. It never deletes source objects,
spool chunks or historical payloads and does not change runtime configuration.
Declared `gap://`, metadata-only and unresolved provider references receive
separate immutable-source-identity gap receipts. Copy continues through later
readable objects and reports `gap_rows` separately from copied objects/bytes.
Verification rereads both kinds of receipt, retains all gap evidence, and fails
with `verified:false` if any gap remains; neither reconstruction nor cutover
can claim complete originals from that checkpoint. Source read/auth/integrity
errors still stop without being relabelled as historical gaps. Null/empty
locator fields remain separately counted by the read-only inventory.

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
branches. Version 2 reconstruction also emits every incoming conversation edge
exactly once, in edge-ID order, preserving the complete relation/evidence record.
It checks parent tenant ownership and compares the exported edge count with the
entire source edge table; dangling parents or targets invalidate verification.
Version 1 reconstruction checkpoints cannot authorize cutover under this contract.
Exact original request/response references are mandatory: missing
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

Only `--phase cutover-test --writers-quiesced` and
`--phase cutover-locators-test --writers-quiesced` mutate source rows. Atom cutover requires
a completed atom and dialogue-reconstruction verification receipt and a database
named `*_test` or `mtc_test_*`. Before the first source mutation it reruns atom
and reconstruction verification; a stale receipt alone is insufficient.
Each target object is verified again before conditional replacement of the
old body with its object reference. A changed source stops cutover rather than
being deleted. Checkpoint resume tolerates a committed row whose checkpoint
write was interrupted. No production mutation or table-drop command exists.

Locator cutover independently rechecks every target body and request/response
raw root against the verified receipt. A bounded SQL MD5 of the original full
locator is used only to fence conditional updates, including arbitrarily long
inline JSON; the body itself is independently verified with BLAKE3 and length.
Media hash/length must still match its index at the update. Each row commits
only when exactly one tenant-scoped identity matches. On resume, already
switched CAS locators are accepted, but all targets are reverified from the
first identity and total count/bytes must match the copy. A failed rerun first
revokes `locator-cutover.json` completion. Receipts made before the conditional
locator fingerprint was added cannot authorize this phase; use a new checkpoint
and rerun the full copy/verification sequence. The two TEST cutover phases may
share that checkpoint; no fresh verification receipt may be fabricated after
partial source mutation.

Checkpoint files are atomically replaced, fsynced and protected by an exclusive
file lock plus a database advisory lock. Store them on persistent private
storage. Lost checkpoints can restart copy before cutover; never invent a
verification receipt to continue a partial cutover.

CI exercises an isolated PostgreSQL database and an official, digest-pinned
RustFS 1.0.4 target. The source object store is isolated in memory. The same
copy/resume/independent verification, source-retention and TEST atom cutover
contracts cover a multipart Unicode tool result, raw SSE, media and fork edges.
RustFS TEST restore, throughput, CPU and memory measurements remain required;
an in-memory fixture is not evidence for deployment resource sizing.

`--phase verify-all --writers-quiesced` independently reruns durable-root/CAS graphs, atom/context,
locator/media, authenticated spool, payload and dialogue verification under the
same source advisory lock. It compares exact inventories before and after,
records every phase result and binds their checkpoint digests in `*.all.json`.
A failed rerun first revokes the aggregate receipt. TEST atom cutover requires
this aggregate as well as its existing raw/reconstruction checks; individual
green phase files cannot authorize cutover. The receipt continues to label
historical training fidelity as uncertified rather than inventing missing data.

The dedicated workflow also packages the tested command as a non-root OCI
runtime, runs `--help` with no network and a read-only filesystem, and uploads
`runtime.tar.gz` with `SHA256SUMS`. A manual workflow dispatch with
`publish_runtime=true` publishes only the separate
`conversation-objects-<tools commit>` tag in the canonical tools image. The
existing CPA importer/runtime pins and running worktrees remain unchanged.
A TEST Job uses the published digest, a persistent private checkpoint volume,
source credential Secret refs and separate RustFS credential refs. The default
phase remains inventory; copying requires quiesced writers, and source mutation
remains restricted to explicitly named TEST databases.

The historical TEST database is named `memeloop_token_center`, like production.
For that database, `cutover-test` additionally requires
`MTC_OBJECT_MIGRATION_TEST_NAMESPACE` from the Pod namespace downward API and
an explicit TEST CNPG service hostname in `MTC_DATABASE_URL`. Production hosts,
a missing namespace, and a database identity mismatch are rejected. Existing
explicitly named test databases remain supported. This guard does not replace
the quiesced writer requirement or the current `verify-all` receipt.

Before transfer, `node ops/object-migration-runtime/prepare-target.ts` probes
the exact configured TEST bucket using signed S3 HEAD. It fails on a missing
bucket; explicit `--create` may create that empty bucket and verifies it with
HEAD. It never lists, overwrites or deletes objects. Supply only target
`MTC_S3_*` Secret references and the TEST namespace downward API value.
GHA exercises missing-target rejection, creation and repeated readiness
against the isolated real RustFS fixture. This probe does not certify migrated
data; transfer and `verify-all` remain required.

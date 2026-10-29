# Conversation object migration

This command is owned here, not in the product repository. CI assembles it
against an exact reviewed product revision and its Cargo.lock. It reuses
`ArchiveStore` and does not modify the existing CPA importer or its runtime pin.

Current executable scope: exact `semantic_atoms` body transfer and context-node
parent/depth/hash reconstruction. This is **not yet a whole-store cutover tool**.
Raw request records, encrypted legacy spool chunks, outbox payload snapshots,
media indexes and imported archive records need separate verified transfer
receipts before retiring their source tables. Do not use atom counts to claim
complete dialogue/media migration.

The command defaults to read-only `inventory`. Credentials and source database
URL use existing `MTC_*` environment configuration; the configured archive is
the destination. No credentials are accepted in command arguments or emitted
in receipts. Checkpoint identity binds the credential-free source identity and
target endpoint/bucket/path.

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
a completed verification receipt and a database named `*_test` or `mtc_test_*`.
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

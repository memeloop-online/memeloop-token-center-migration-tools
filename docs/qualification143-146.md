# Original142 → exact59b6 qualification (CI only)

This is synthetic engineering evidence, not production authorization or a new
release path. It uses the existing CI workflow and official published59b6 image.
The original61d source builds a fixture test in Actions: `Database::migrate()`
followed by `convert_sealed_state()` creates the genuine142 receipt. All old SQL
bytes are checked against59b6. No ledger row is inserted/deleted/renamed by the
qualification harness.

PostgreSQL17.5 gets the observed78 request-record leaves (including DEFAULT),
per-leaf row estimates and approximate heap widths,544084 response spools and
618794 request spools. Distributions of owners and spool states are explicitly
synthetic assumptions, not private-data observations. Config and finance rows
are synthetic. Six sustained writer sessions have no lock, statement or
transaction deadline; only the migrator receives abort controls.

Focused comparisons:

- One-at-a-time concurrent146 leaf builds under sustained writes.
- Original143/144/146 with146 prepared, but ordinary143 index builds retained.
- Four exact named143 concurrent builds, then unchanged official upgrade;
  first exercise a held-writer abort and verify rollback.

Every run retains raw write cohorts, lock/blocker/index-progress samples, source
hashes, per-index timings/OIDs/validity, original and final genuine ledger,
WAL/I/O counters, PostgreSQL statement-duration logs and official image identity.
PostgreSQL logs measure each statement and COMMIT separately from Docker startup.
There is no replica in CI; null replica lag is **not** a zero-lag measurement.
The test is not HTTP forwarding or capacity acceptance.

No product migration is rewritten. Prebuilt146 only shortens146 and cannot remove
143 ALTER locks. Parent must review measured total writer blocking through COMMIT,
including144 and partition maintenance, before deciding any production method.
Do not ship or execute this destructive fixture harness against a live database.
Any eventual operational wrapper must be separately reviewed in this canonical
repository and published through existing release machinery.

## Exact59b6 connection-profile caveat

`src/db/mod.rs` in the product resets migration `lock_timeout` to60000ms and
`statement_timeout` to900000ms in `after_connect`. URL options requesting smaller
values are therefore overwritten. `transaction_timeout` is not reset. The
qualification deliberately records both requested URL options and effective
profile values, retaining server SET statements and abort outcomes as evidence.
Do not describe a held-writer failure under a5s transaction limit as proof of a
200ms lock timeout. Fixing migration-only timeout configuration belongs in the
product source and a separately reviewed official release, not a wrapper that
pretends startup options survive.

## First complete measured run

[CI41251478842](https://github.com/memeloop-online/memeloop-token-center-migration-tools/actions/runs/41251478842)
passed all jobs at tooling head `5671b44f777b5352068fff8cb40504a6fb4ad734`
(tested merge `401f97e8f01a3021a4bf61269762a55a7ec48e6a`).

| Measurement (milliseconds) |146 prepared only|143+146 indexes prepared|
|---|---:|---:|
|BEGIN through COMMIT|1185|609|
|Original143 raw SQL aggregate|1030.404|455.968|
|Original144 config update|68.000|71.052|
|Original146 parent statement|10.013|10.075|
|Partition-maintenance start through COMMIT|20|18|
|Longest response-spool write|1130.987|551.775|
|Longest request-spool write|1040.727|467.523|

All78 original child OIDs were reused in both comparisons. Leaf CIC total1004ms;
four spool CICs total962ms; their writer-cohort maxima were below3.2ms. All
writer cohorts had zero errors. A new future partition inherited a valid index.
The held-writer experiment aborted at5000ms via transaction timeout and briefly
queued response writers for4947ms; a100ms transaction timeout rolled back begun
DDL. Original ledger142 and finance fixture were preserved, and the official
runner alone added143/144/146 after successful COMMIT.

This is **not uninterrupted-writer qualification**: original143 still monopolizes
spool writer locks. The shortest measured unchanged method is all82 concurrent
index preparations followed by the official transaction, but it remains a
parent-approved short blocking window, not lock-free ordinary migration.
For the stricter forwarding priority, see the separate
[product-source proposal](migration143-source-followup.md). No product-source
change, deployment or production authorization is contained in this PR.

The fixture has exactly1279875 records,544084 response spools and618794 request
spools. Request heap pages113315 versus observed131216 are13.6% smaller; spool
heap pages are3.7% smaller. CI hardware/cache/replication differ from production.
143 timing is the original multi-statement aggregate, not individual CHECK
timings. Ordinary-versus-prebuilt timing differences include cache/order effects.
Raw cohorts, catalogs, logs and resource samples remain authoritative.

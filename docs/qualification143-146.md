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

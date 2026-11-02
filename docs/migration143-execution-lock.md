# PostgreSQL143 runner-order qualification

This follows the existing PR51 production-shaped rehearsal. It is CI-only and
must never be pointed at production. The original PR51 topic is not rewritten.

Product PR733 exact source `f828af8fb42deb746323c5ff1a0a9f2cac642924` is
checked out and built only by Actions. This debug binary is a source-regression
artifact, not an official deployable release image. Existing official release
machinery must later produce an exact reviewed master image before TEST/release.

The genuine142 fixture still comes from the unchanged original61d426a0 runner
and plaintext conversion. No ledger is deleted or synthesized by the harness.
All published migration SQL is unchanged, including PostgreSQL143 SHA256
`f64b44d38302f50225711de74e4385f195e40b54353c18dc1063efd118df6716` and
its common index SQL
`156e5beeb6ff694fc069ff3328398fb6b31d73a2e8ffe84ee0477e15aae0d0be`.

The fixture has the original approximately1.28M requests,619K request spools,
544K response spools, plus one empty daily leaf to represent79 prepared leaves.
Together with the four143 spool indexes,83 CIC indexes are prebuilt and their
OIDs checked before/after every abort and after successful migration. Ordinary
partition maintenance may add later daily leaves; existing OIDs must survive.

Six persistent writers and two readers run concurrently. Readers use the
business request-record→request-spool→response-spool join shape. CI-only workload
record writers insert a record and update both spool relations in one real
transaction, exercising the cross-migration146 dependency rather than only
unrelated single-table writes. Spool scheduling writers retain their existing
single-table operations. Catalog identity comparisons exclude physical byte
growth caused by these concurrent writers, but keep OIDs/definitions/options/
validity/readiness/live/attachment checks.

Workload
sessions use the product serve profile's existing30s statement/10s lock limits,
not infinite lock waits and not changed live business settings. These closed-loop
SQL clients are not full HTTP request or production-capacity acceptance.

Each of four143 DDL target relations is separately held by a reader and writer.
The later146 request-record index and final partition maintenance dependencies
are included. The runner pre-acquires recursive ACCESS EXCLUSIVE NOWAIT on
request_records and request_events before any spool lock when the143 batch
includes146. SHARE alone is insufficient: trailing CREATE TABLE PARTITION OF
can upgrade the parent to ACCESS EXCLUSIVE while business readers already hold
parent AccessShare and wait for spools. Held readers and writers are exercised
on both parents too. This intentionally pauses record/event reads and writes
until the shared transaction commits; it is not a read-transparent upgrade.
The exact source migrator must exit nonzero in under2s with actual server
SQLSTATE55P03, without40P01;2s is a test assertion, not a new migration timeout.
All83 index catalogs, spool row/cipher/plain/chunk totals, finance fixture and
ledger remain identical, and a fresh writer can immediately acquire every
target after maintenance rollback. The original held business transaction is
rolled back normally, never terminated by the harness.

Concurrent work may conflict on an earlier relation than the deliberately held
target. The result records the actual server failure relation and whether that
held target was the first conflict; it does not pretend all busy scenarios
prove each specific lock. Product PR733's isolated PostgreSQL unit cases prove
each exact target with no other workload competing for earlier locks.

The normal upgrade runs with the same workload active. At most five CI-only
attempts are retained: a failure qualifies only if the actual server log proves
55P03, the process exits promptly, and its ledger is unchanged. This is not a
production retry loop or authorization. At least one attempt must commit,
including all current pinned-source migrations143/144/145/146/147/148 and
partition maintenance. Zero workload errors are required and all latency
samples, lock samples, server statements and attempts are retained, including
failures. Re-running after commit while all four tables have held readers must
skip143 and leave its original ledger/name/timestamp unchanged.

The first retained run41445735610 at tools1cf1d30 failed because all five
uncoordinated attempts correctly exited55P03 under active workload. It did not
prove normal commit, and is not relabeled successful or simply rerun. The
follow-up retains those five attempts unchanged. If none acquires the locks,
the eight synthetic generators acknowledge a between-transaction barrier;
the coordinator starts one migration, observes all four actual granted spool
locks, and immediately resumes all generators while DDL is still active.
This deterministically measures concurrent business waiting/completion/errors
and normal migration, without relying on a lucky idle gap or expanding retry
counts. Both the successful boundary-entry cohort and failed uncoordinated
cohort remain separate in the receipts. This CI barrier is not a product
admission feature, production pause policy, or evidence that the migration
will acquire NOWAIT locks under an arbitrary uninterrupted arrival rate.

The existing final PostgreSQL log analyzer reports prelock-to-COMMIT span in
addition to DDL/transaction durations. Final logs must contain no40P01. Existing
83 OIDs, validation bits and old ledger/finance integrity are checked. Source
regression evidence does not substitute for parent-reviewed official-image
TEST or confer production authority.

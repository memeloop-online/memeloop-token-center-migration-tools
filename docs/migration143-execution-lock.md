# PostgreSQL143 runner-order qualification

This follows the existing PR51 production-shaped rehearsal. It is CI-only and
must never be pointed at production. The original PR51 topic is not rewritten.

Product PR733 exact source `56658c80ed4b6aada32c531570653dc45aaabb97` is
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
sessions use the product serve profile's existing30s statement/10s lock limits,
not infinite lock waits and not changed live business settings. These closed-loop
SQL clients are not full HTTP request or production-capacity acceptance.

Each of four143 DDL target relations is separately held by a reader and writer.
The exact source migrator must exit nonzero in under2s with actual server
SQLSTATE55P03, without40P01;2s is a test assertion, not a new migration timeout.
All83 index catalogs, spool row/cipher/plain/chunk totals, finance fixture and
ledger remain identical, and a fresh writer can immediately acquire every
target after maintenance rollback. The original held business transaction is
rolled back normally, never terminated by the harness.

The normal upgrade runs with the same workload active. At most five CI-only
attempts are retained: a failure qualifies only if the actual server log proves
55P03, the process exits promptly, and its ledger is unchanged. This is not a
production retry loop or authorization. At least one attempt must commit,
including all current pinned-source migrations143/144/145/146/147/148 and
partition maintenance. Zero workload errors are required and all latency
samples, lock samples, server statements and attempts are retained, including
failures. Re-running after commit while all four tables have held readers must
skip143 and leave its original ledger/name/timestamp unchanged.

The existing final PostgreSQL log analyzer reports prelock-to-COMMIT span in
addition to DDL/transaction durations. Final logs must contain no40P01. Existing
83 OIDs, validation bits and old ledger/finance integrity are checked. Source
regression evidence does not substitute for parent-reviewed official-image
TEST or confer production authority.

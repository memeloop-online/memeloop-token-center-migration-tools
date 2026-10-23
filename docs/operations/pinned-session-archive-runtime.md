# Pinned session archive import runtime

The one-shot importer closure is owned by migration-tools and assembled against
the pinned current product APIs in CI. This does not authorize cleanup or real import.

## Immutable source and build

- Product source: `memeloop-online/memeloop-token-center`,
  revision `a31f28f497036b0374a37077c218505a63aecbc0`, target schema133.
- Cargo.lock SHA-256:
  `083e616fe14a58cde159c7ff33607389f91be4df90e5bbb7c4cbe266ddd7705a`.
- Rust `1.95.0`, `cargo --locked`, Ubuntu 24.04, Linux x86_64 GNU.
- CI executes the importer unit tests and session import/quarantine/unlinked
  integration tests with an isolated PostgreSQL service, then builds only the
  `import-cpa-session-archive` release binary.

Release assets include `commands/runtime/import-cpa-session-archive`,
`compatibility.json`, and an exact assembled `source.tar` retained independently
of future product-tree cleanup. The outer release manifest hashes all three.
The compatibility manifest also binds binary/source bytes, revision, Cargo.lock,
Rust version, target and CLI contract. Verify the fixed release archive and all
outer manifest hashes **before execution**; the inner checksum manifest is not
an independent signature or substitute for release provenance.

The packager refuses unexpected source changes or closure/lock/compiler drift and
exercises the compiled CLI contract. Isolated release verification executes its
`--help` outside the source tree and node_modules. Synthetic verifier tests
reject missing/tampered manifest fields, changed payloads, absent executable
permission and symbolic links.

## Runtime contract

The wrapper defaults to its adjacent `runtime/import-cpa-session-archive`; it
does not fall back to PATH. `MTC_SESSION_ARCHIVE_IMPORT_BIN` can relocate the
same verified runtime, but its sibling compatibility manifest and retained
source archive are mandatory and must match the compiled pin. It cannot select
an arbitrary replacement executable. Overrides must be absolute paths; the
verifier returns the canonical absolute path and the wrapper executes exactly
that path, never a same-named executable found through PATH.

The runtime requires Linux x86_64 and glibc 2.39 or newer. The target database,
archive store and approved credentials/configuration remain external inputs.
No cargo, source checkout, package install, network download or product process
is needed to launch the delivered executable. Verify host dynamic-library
availability with the isolated `--help` check before supplying real inputs.

Dry-run remains the default. `SESSION_ARCHIVE_APPLY=true` is an explicit write
decision; the finalizer additionally requires its separately bound approval.
The engine checks exact target schema133 read-only before import, validates
identity, and retains the existing gap/quarantine/provenance/replay semantics.
This release does not implement product schema upgrades and does not relax
import acceptance for a newer target schema.

## Tools-owned closure

`src/bin/import-cpa-session-archive.rs` invokes
the tools-owned minimal target configuration loader,
`Database::ensure_session_archive_import_schema`,
`ArchiveStore::from_config`, `validate_session_archive_import_options` and
`import_session_archive`.

The remaining engine modules are `src/session_archive_import/{mod,plan,parsing,
correlation,apply}.rs`. Their DB closure includes request matching, exact and
unlinked transaction commits, quarantine, snapshot projection/staging,
checkpoint chains and tombstone preflight/apply through
`src/db/requests/session_archive*.rs`, plus shared model, conversation,
configuration, archive and error types. Extracting just the CLI file does not
extract this closure.

These retired one-shot modules and their regression fixtures now live in
`ops/runtime-engine`, with PR44's large-record changes incorporated directly.
Current conversation/prefix, archive, model and error implementations remain
supplied by product; no old observation decoder is restored. The hash-bound
assembly adds only module exports to three current product files in CI.
See [the exact source plan, schema impact and CI matrix](schema133-importer-closure.md).
Retained source does not authorize production cleanup or import.

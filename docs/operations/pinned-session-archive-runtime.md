# Pinned session archive import runtime

The one-shot importer closure is owned by migration-tools and assembled against
the pinned current product APIs in CI. This does not authorize cleanup or real import.

## Immutable source and build

- Product source: `memeloop-online/memeloop-token-center`,
  revision `3150445f4841e74faf7a526aa933fe6558c747ed`, target schema146.
- Cargo.lock SHA-256:
  `2caa9ebd39770325fc0743dccc2c221612691dbd9a75a99f24d6baaaea15cc38`.
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

### OCI delivery qualification

Release hashes alone do not qualify the container's dynamic loader. An Alpine
delivery base cannot execute the GNU importer even when every release file
matches its manifest. The bundle image uses digest-pinned Node24.18.0 on Debian
Trixie, with the GNU loader, OpenSSL, PostgreSQL and SQLite clients installed by
CI. The base pin comes from the
[official Node image metadata](https://github.com/docker-library/repo-info/blob/042a77456cc28ec8543b1cd1770ed4d3f5cef63c/repos/node/remote/24.18.0-trixie-slim.md).

Both PR CI and the official publisher build the same Dockerfile. Its non-root,
network-disabled build step verifies release checksums and actually launches
the packaged GNU importer, Node exporter and SQLite backup helper. Missing
loaders or shared libraries fail publication; no host executable or PATH
fallback can substitute for the packaged importer. This startup gate is not a
real database import or reconciliation receipt.

The publisher can deliver an already verified older release without rebuilding
or relabelling its payload. The tag binds both identities:
`release-bundle-<payload-revision>-delivery-<delivery-definition-revision>`.
Record the resulting OCI digest and official workflow run; old payload-only
tags are not overwritten. Target schema must still match that payload's exact
compatibility contract, independently of the delivery definition's revision.

Dry-run remains the default. `SESSION_ARCHIVE_APPLY=true` is an explicit write
decision; the finalizer additionally requires its separately bound approval.
The engine checks exact target schema146 read-only before import, validates
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
See [the exact source plan, schema impact and CI matrix](schema146-importer-closure.md).
Retained source does not authorize production cleanup or import.

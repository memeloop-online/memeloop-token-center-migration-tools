# Extraction boundaries

Source repository: `memeloop-online/memeloop-token-center`

Source tree: `8cdd681246924debc5c9752422aa422c0afce331`

This repository contains exact copies of the reviewed TypeScript migration surface. The following source-owned areas remain intentionally outside this repository.

## Public repository and reproducible runtime boundary

This repository is publicly reusable as a one-shot migration-tool source
distribution. It contains implementation, contracts, documentation and
synthetic fixtures only. It must never contain business data or dynamic
operational evidence: database/SQLite/archive exports, request or object
payloads, production identities, keys, grants, balances, policy snapshots,
source/target inventories, route or policy mappings, checkpoints, plans,
receipts, logs, screenshots, Secret values, credentials, ciphertext or
registry login material. Non-sensitive hashes and owner-approval references
may be retained in an external evidence store and documented without copying
the evidence itself into Git.

The reproducible execution boundary is a CI-built container for an exact Git
revision, consumed by immutable image digest with its manifest, SBOM and
provenance. Dependencies are installed from the lockfile during image build;
the final layer contains only the reviewed TypeScript entrypoints and runtime
libraries. A generic `node` image must not clone this repository, fetch source,
or run `npm install`/`npm ci` at startup. That pattern permits mutable code and
dependency drift, requires runtime network/registry access, risks exposing
injected credentials, and bypasses the digest/attestation boundary. The full
verification suite is CI-only; local validation is limited to
`git diff --check`. Real inputs are injected only by the approved execution
environment.

The copied CLI and path names intentionally retain current source-product
terminology for migration compatibility. Removing CPA/Token Center-specific
names, introducing generic provider/source/target adapters, or changing CLI
aliases is a separately versioned compatibility follow-up, not an extraction
cleanup. Until that work has its own fixtures and dual review, existing names
must not be renamed.

## Compiled migration/runtime boundary

The approved intermediate [pinned runtime delivery](operations/pinned-session-archive-runtime.md)
builds the fixed product archive engine in migration-tools Release CI and retains
its exact source tar, binary and compatibility manifest. This supersedes only
the missing-binary delivery limitation below: it does not extract the closure,
introduce a runtime dependency on the product process, or authorize deletion.
No source fetch or compiler runs at execution time.

The session-archive importer is implemented in Rust and is coupled to product database, archive, configuration and authorization modules. It was not copied or mechanically rewritten:

- `src/bin/import-cpa-session-archive.rs`
- `src/session_archive_import/`
- `src/db/providers/imports.rs`
- `src/db/requests/session_archive*.rs`
- `src/api/upstreams/managed_import.rs`
- `src/oauth/managed/legacy_gemini.rs`
- `tests/imported_account_ledger.rs`
- `tests/legacy_credential_continuity.rs`
- `tests/legacy_credentials_bulk_ops.rs`
- `tests/legacy_credentials_bulk_postgres.rs`
- `tests/managed_oauth_import_api.rs`
- `tests/managed_oauth_imports.rs`
- `tests/session_archive_import.rs`
- `tests/session_archive_quarantine.rs`
- `tests/session_archive_unlinked.rs`

Closing this boundary requires an owner-reviewed architecture decision: either expose a stable product API consumed by a TypeScript client or move a deliberately bounded compiled migration executable with its minimal reusable crates. Do not duplicate product database or crypto logic in TypeScript.

No Go migration executable exists in the source tree at this source commit. If one is discovered in another repository or historical commit, inventory and review it before extraction; do not rewrite it opportunistically.

## Schema boundary

The CPAMP PostgreSQL acceptance bundle needs exact historical schema slices. Those SQL files are copied as immutable test inputs. Product migrations that define legacy/import ledgers, quarantine, compatibility credential tables and managed-import state remain product-owned until the final incremental migration proves:

- zero unlinked or quarantined useful records;
- all credentials are rewrapped into the current envelope;
- zero retired drivers, accounts and routes;
- request, session, archive, price, cache and ledger reconciliation matches;
- a cleanup migration and fresh schema baseline pass fresh-install and upgrade gates.

The explicit product-owned schema residue at the pinned source tree includes:

- `migrations/{postgres,sqlite}/0011_legacy_key_credentials.sql`
- `migrations/common/0028_session_archive_unlinked.sql`
- `migrations/common/0033_legacy_credential_one_to_one.sql`
- `migrations/common/0036_session_archive_quarantine.sql`
- `migrations/common/0043_routing_groups.sql` and `migrations/sqlite/0043_drop_model_route_legacy_unique.sql`
- `migrations/common/0051_session_usage_rollups.sql`
- `migrations/{postgres,sqlite}/0052_retire_allowed_models.sql`
- `migrations/common/0056_session_archive_snapshot_v2.sql`
- `migrations/common/0057_session_archive_quarantine_versions.sql`
- `migrations/common/0058_session_archive_snapshot_staging.sql`
- `migrations/{postgres,sqlite}/0060_normalize_key_credentials.sql`

## Deployment and evidence boundary

The following were not copied because this repository must not deploy workloads or retain live operational data:

- `Dockerfile.importer` and importer release/publish matrices;
- `tests/ops/importer-image-contract.test.ts`;
- `tests/ops/helpers/importer-runtime-check.ts`;
- `tests/ops/release-packaging-contract.test.ts`;
- `tests/ops/session-archive-import-job-contract.test.ts`;
- `ops/kubernetes/cpa-upstream-import-dry-run-job.yaml`;
- `ops/kubernetes/cpamp-import-job.yaml`;
- `ops/kubernetes/legacy-credential-import-job.yaml`;
- `ops/kubernetes/legacy-key-policy-import-job.yaml`;
- `ops/kubernetes/legacy-route-import-job.yaml`;
- `ops/kubernetes/session-archive-import-job.yaml`;
- GitHub Actions and cluster manifests;
- `docs/evidence/` and live API2 acceptance reports;
- database dumps, JSONL exports, checkpoints, plan files, receipts, screenshots, ciphertext and Secret material.

Evidence must remain in the approved external audit store by digest. A future operator may record only non-secret content hashes and owner approvals here.

The provenance-locked runbooks intentionally retain their original relative links. Deployment dependencies are available only in the pinned private source tree:

- [`Dockerfile.importer`](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/Dockerfile.importer)
- [CPA upstream dry-run Job](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/ops/kubernetes/cpa-upstream-import-dry-run-job.yaml)
- [legacy credential Job](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/ops/kubernetes/legacy-credential-import-job.yaml)
- [legacy key-policy Job](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/ops/kubernetes/legacy-key-policy-import-job.yaml)
- [legacy route Job](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/ops/kubernetes/legacy-route-import-job.yaml)
- [CPAMP import Job](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/ops/kubernetes/cpamp-import-job.yaml)
- [session archive import Job](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/ops/kubernetes/session-archive-import-job.yaml)

Likewise, the Docker/deployment contracts remain source-owned and are linked rather than copied:

- [importer image contract](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/tests/ops/importer-image-contract.test.ts)
- [importer runtime helper](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/tests/ops/helpers/importer-runtime-check.ts)
- [release packaging contract](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/tests/ops/release-packaging-contract.test.ts)
- [session archive Job contract](https://github.com/memeloop-online/memeloop-token-center/blob/8cdd681246924debc5c9752422aa422c0afce331/tests/ops/session-archive-import-job-contract.test.ts)

## Uncommitted-source boundary

Dirty working-tree files such as `ops/release/converge-legacy-bridge.ts` and its test were not copied because they are absent from the pinned source tree. They require an owner commit, independent review and a new provenance manifest entry before extraction.

## Deletion gate

Nothing in the source product repository may be deleted merely because this snapshot exists. Removal requires final migration receipts, a dual-repository review, source/target SHA verification and confirmation that no product build, runtime, API, schema upgrade or rollback still imports the extracted files.

# Legacy source compatibility gate — 2026-08-26

This note retains the non-secret evidence that blocked deployment of otherwise
green SHA `888f60fc01780dcddb13738434d32c461ddacede`, and the local acceptance
state of its successor. It is not rollout or production evidence.

## Read-only source facts

- The sealed CPA source contains one API-key-entry-level private SOCKS5 proxy.
  It has no username/password. No URL, host, port, API key or source file name is
  retained here.
- The running CPA archive plugin is v0.7.21. A read-only 1,000-session sample
  found RFC3339 numeric offsets on every `first_at`/`last_at`; fractional seconds
  range from five to nine digits and are predominantly nine digits. No epoch,
  timezone-less or `Z` timestamps were present.
- The later stable-snapshot contract requires canonical UTC with exactly six
  fractional digits and `Z`; the legacy endpoint predates that contract.
- Source and target remained read-only for upstream/archive after both gaps were
  found. No trial rollout or API3 change was made.

## Implemented boundary

- CPAMP migration, archive-import wrapping, and the combined migration audit
  run as Node 24 TypeScript (`node ops/migrate-cpamp.ts`,
  `node ops/import-cpa-session-archive.ts`, and
  `node ops/audit-cpa-migration.ts`). They invoke `psql`, `sqlite3`, and the Rust
  importer with `shell:false`; database credentials remain environment/file
  only and are never placed in argv.
- `api_key_proxy` keeps the proxy URL and any optional authentication inside the
  versioned encrypted upstream-credential envelope. Account views, errors and
  dry-run output expose no URL; the importer reports only
  `proxied_api_account_count`.
- The importer defaults direct targets to public. A separate strict owner-only
  versioned policy may approve exact target base URLs as private; output adds
  only `private_target_api_account_count`. Scope is not inferred from proxy
  presence, but every private-target account must have a private SOCKS5 proxy
  or inventory fails before any target request. The server
  revalidates both scopes.
- Private `socks5` and `socks5h` are accepted with their original DNS semantics.
  `socks5` pins the locally validated target IP. `socks5h` is restricted to a
  safe private IP-literal proxy and sends the original hostname to that trusted
  proxy after MTC's local target policy check. HTTP(S), public SOCKS and
  hostname-addressed `socks5h` proxies fail closed. In-process SOCKS handshake
  tests cover both the pinned-IP and original-hostname paths.
- Creating or explicitly changing the private proxy requires a global service
  credential. A tenant-scoped API-key-only rotation preserves the already
  approved proxy and cannot replace or remove it.
- Legacy archive times are compared at nanosecond precision, then emitted as
  canonical six-digit UTC values. The stable-cursor path still compares the raw
  timestamp with its canonical form and rejects a non-canonical source before
  accepting its projection digest.

## Local evidence before the final fixed-SHA CI

- `cargo fmt --check` and Clippy with all targets/features and warnings denied:
  pass.
- `cargo test --locked --all-targets --all-features`: pass, including 370 library
  tests, all integration binaries, and Rust Cucumber 69/69 scenarios with
  373/373 steps.
- Root TypeScript typecheck and all five Node test files: 45/45 pass. OpenAPI:
  106 paths, 126 operations, no source/boundary drift.
- Web typecheck, 24/24 localization/security contracts, production build and
  Chromium Cucumber 19/19 scenarios with 140/140 steps: pass.
- Release-binary short memory gate: pass. Standard Images delta 95.879 MiB,
  Responses-tool Images delta 61.719 MiB, 100 MiB archive-download gateway delta
  0.277 MiB, soak failures zero, process lifetime HWM 123.641 MiB against the
  224 MiB process budget. The run was intentionally marked dirty and is local
  regression evidence only.
- Legacy credential attachment now uses an immediate SQLite write transaction.
  A deterministic competing-writer test passes, and the exact migrated-key
  Cucumber scenario passed five focused repetitions plus both full suites; the
  former deferred lock-upgrade HTTP 500 is no longer reproducible.
- Root and web npm audits: zero vulnerabilities. Tracked Python files: zero.

One final clean SHA must pass the unchanged 900-second/500 MiB GitHub Actions
gate and publish three newly verified immutable digests. Only those new digests
may resume real upstream dry-run/apply/replay, archive dry-run/apply/replay and
the reversible API2 trial. API3 remains forbidden until the user explicitly
opens the production window.

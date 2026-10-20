# Schema130 importer source closure

The importer is owned exclusively by migration-tools. The product retired its one-shot importer surface, so changing the old engine70 pin alone cannot produce a current importer.

## Source plan and ownership

Use product base `63022be5856ff584191321b76f314682c8ec67bf`, whose SQLite/PostgreSQL migration lists end at130. Do not use the unmerged schema131 work. This is a build compatibility target; a production owner must separately confirm the actual import target and window.

`ops/runtime-engine` extracts the existing one-shot parser/plan/apply modules, CLI, three archive DB adapters, archive session-total helper and regression fixtures from `a65097f952e174ac482abe6ff719966fa9d330cb`. PR44's configurable large-record reader and regressions are incorporated directly; digest/export implementation stays in its existing location. There is one importer implementation, not a second runtime path.

CI assembles this closure into an isolated checkout of the exact product base using three module/export additions. The closure calls the product's current `record_conversation_observation_in_transaction` API with explicit upstream-response and materialization state. Product owns prefix construction, fingerprint encoding, tenant path validation, archive storage and conversation reading. No prefix storage implementation, migration, old observation decoder or serving fallback is copied into the closure.

The tools-owned CLI reads only target DB/object-store configuration and never migrates. Its read-only precondition requires the complete exact130 migration set and importer relations, rejecting missing versions and newer131 targets. Retained source export formats are migration inputs, not a product runtime storage fallback.

`schema130-files.json` binds every extracted file and assembled product module to exact SHA256 bytes. The immutable product revision, Cargo.lock, closure manifest hash, compiler and target are checked before CI build and again before sealing. The retained source archive includes all extracted untracked files. Release verification rejects stale closure, substituted artifacts and a different target schema manifest.

Compiling the product library tests also requires its reviewed `memeloop-token-center-example-plugins` fixture repository at `21489f4fee6266de99fe7e258349468ce77af8bd`, the same pin as the product's checkout action. CI checks that out under the ignored `.plugin-examples` directory; its identity is retained in the compatibility manifest. It is a test compile dependency, not a runtime fallback or a production plugin installation.

## CI acceptance matrix

- Current product library: importer parser/bounded reader tests, including the PR44 20921650-byte case and exact configured budget rejection.
- SQLite130: existing import, exact/unlinked/quarantine, full stable snapshot/delta, tenant/replay/CAS/financial invariants; large-record current-format fingerprint and conversation readback; missing127/newer131 read-only rejection.
- PostgreSQL130 service: existing native-type quarantine/unlinked/locator-CAS/advisory-lock cases; full large-record import/dry-run/replay/financial invariant fixture in its own schema with current fingerprint and conversation readback. CI requires the PostgreSQL URL, so this row cannot silently skip.
- Locked release build: importer CLI help, packaged byte identity, complete retained source closure, compatibility manifest and existing standalone release verification.

No local build/test/install, source-volume read, import, PG write, storage placement change or production rollout is part of implementation. Placement remains a separate unresolved operational dependency. The original visible CLI root remains stopped; the parent alone updates Wiki.

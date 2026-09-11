# Preserved source engineering debt

The files listed in `SOURCE-MANIFEST.json` are byte-identical evidence from the pinned source tree, not a claim that every historical tool meets the current product engineering standard.

## Environment coupling

Imported tools may retain historical default tenant/source labels. Defaults must be reviewed against the exact migration plan; owner identity, target URL, data digest and apply authorization must stay explicit. Environment-specific endpoint identities and topology must remain in protected operator inputs, never in this repository or in ambient Kubernetes context.

## Module size

The largest preserved TypeScript modules are:

- `ops/export-cpa-session-archive-delta.ts` — about 915 lines;
- `ops/cpa-upstreams/import-cpa-upstreams.ts` — retained source parsing and shared protected I/O only;
- `ops/migrate-cpamp.ts` — about 448 lines;
- `ops/legacy-policy/import-cpa-key-policy.ts` — about 388 lines.

Do not expand these files. A future change must first split protocol parsing, typed configuration, I/O adapters, planning, execution and receipt verification behind testable module boundaries. Prefer maintained libraries for standard formats and protocols, but retain custom code where strict canonicalization, duplicate-field rejection or migration-specific fail-closed behavior is part of the reviewed contract.

Any refactor invalidates the corresponding provenance hash and must be recorded as a separate reviewed commit, with the original source hash retained in the manifest history.

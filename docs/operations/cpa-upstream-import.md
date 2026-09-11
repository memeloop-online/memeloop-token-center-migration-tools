# CPA upstream source audit

The former target importer is retired. It is not a release command and its
target/apply arguments fail closed. This repository deliberately contains no
target write endpoint or authorization scope for that workflow.

The retained TypeScript module is a source-side parser used by read-only
inventory, route-evidence, and reconciliation tools. It validates protected
CPA configuration and auth documents, classifies direct accounts and managed
OAuth source formats, derives domain-separated opaque identities, and emits
count-only summaries. It must not contact a target or mutate source data.

Target migration requires a separately reviewed, provider-neutral ABI and
release command. That work is intentionally outside this compatibility and
repository-sanitization change. Operators must not substitute the removed ABI,
call unpublished source files as target importers, or infer target bindings.

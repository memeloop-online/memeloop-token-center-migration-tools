# Native Kimi source audit

The former native Kimi target importer is retired and is not packaged in a
release. Its retained source-side validator only inspects a protected, sealed
Kimi capture: it validates document shape, token identity consistency,
freshness, capture digests, and route evidence, then writes a redacted offline
audit receipt. Target access and target writes are always zero.

Former target/apply flags are rejected before source material is read. The
repository contains no target write endpoint or authorization scope for this
workflow. A future migration path must use a separately reviewed,
provider-neutral target ABI; it is intentionally not introduced here.

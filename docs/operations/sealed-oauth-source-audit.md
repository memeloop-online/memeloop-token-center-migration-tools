# Sealed managed-OAuth source audit

`sealed-oauth-source-audit` is an offline source validator. It validates a
protected capture, token identity consistency, freshness, capture digests and
the exact owner-approved source shape, then writes a redacted receipt. It has
no network client, remote endpoint, service credential, write authorization or
automatic retry path and is not packaged in a Release.

Exact cohort shape is supplied at execution time in an owner-only expectation
file instead of being encoded in this public repository. The strict JSON
document has these fields:

```text
version
capture_mode
source_policy_file
source_type
source_account_count
source_policy_count
source_grant_count
provider_model_policy_counts
```

All counts are bounded positive integers. `provider_model_policy_counts` maps
each expected provider model to the exact number of distinct source policies
that grant it. The expectation file, capture receipt, source configuration,
policy, identity key and every auth document must be owner-only regular files;
their bindings are fully validated before the receipt path is opened.

A validation or output-path failure is a definite failure and produces no new
receipt. Receipt persistence uses an exclusive, atomic write. An I/O exception
during that final persistence step is classified as `uncertain`: operators
must inspect the path and filesystem evidence and must not automatically retry,
overwrite or reuse the path. No failure includes source material or an
underlying exception message.

The retained parser currently recognizes one source document type. Adding a
remote write path is deliberately out of scope. If a future migration needs
one, it must be implemented from a separately reviewed, provider-neutral ABI
in a private operations boundary; no retired endpoint or authorization
contract may be restored here.

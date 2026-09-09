# Existing client identity recovery preflight

`credential-recovery-preflight` authenticates each owner-approved existing client
key through the fixed gateway `GET /self/v1/key`, then reads exactly that stable
key from the private control API with the explicitly selected tenant. It checks
active status, exact stable identity, current generation, and the recovery flag.
All source keys are reauthenticated after the batch to detect intervening
rotation. It makes no billable model request and never calls PUT/POST/PATCH/DELETE
or connects to a database.

Use only the exact CI-verified immutable Release command. Required arguments:

- `--source-config-file`: already approved owner-only source configuration.
- `--source-receipt-file`: owner-only capture receipt binding its exact SHA.
- `--expected-count`: approved source client-key count; duplicates fail closed.
- `--tenant`: explicit target tenant; never inferred from a token filename.
- `--gateway-api-base-url` and `--control-api-base-url`: approved HTTPS roots.
- `--service-token-file`: existing owner-only control token with `keys:read`.
- `--receipt-output`: new absolute path under a protected directory.

An explicitly approved temporary loopback port-forward may use
`--allow-http-loopback`; close it afterwards. This is not canonical HTTPS
acceptance. Every request is bounded by 30 seconds and 256 KiB, never redirects
or retries, and a failure stops the entire batch without a partial receipt.
Only count-only success status or a fixed value-free error reaches stdout/stderr.

The tool reads original keys from the existing protected source into memory only.
It does not create a plaintext identity-to-key mapping. The `0600`, no-overwrite
receipt contains source capture/config hashes plus source array positions, stable
key UUIDs, generations and recovery-availability flags. It contains no original
key, key hash/fingerprint, alias, balance, URL or token.

A successful receipt is an identity preflight, not permission to supplement
recovery envelopes. Send its count-only summary for owner approval before any
write. Subsequent approved supplementation must reread this exact approved source
in memory and revalidate the receipt's identity and generation; existing product
PUT verifies the active authentication hash again and stores only encrypted
recovery material. Never rotate a credential, recreate a key, persist plaintext,
or borrow runtime database credentials to make a missing match pass.

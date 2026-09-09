# Source-bound credential recovery

`source-credential-recovery-apply` is a separate fixed release command. It does
not alter the independent identity-mapping backfill command. Do not create an
intermediate plaintext mapping. Supply the existing owner-private source YAML,
its capture receipt, the explicitly reviewed successful identity preflight
receipt, and the existing authorized service token file.

Required flags:

```
--source-config-file ABSOLUTE_FILE
--source-receipt-file ABSOLUTE_FILE
--approved-identity-receipt-file ABSOLUTE_FILE
--expected-count 10
--tenant EXACT_TENANT
--gateway-api-base-url HTTPS_ORIGIN
--control-api-base-url HTTPS_ORIGIN
--service-token-file ABSOLUTE_FILE
--receipt-output NEW_ABSOLUTE_FILE
```

Default mode performs GET-only dry-run checks. `--apply` is the sole recovery
write authorization. `--verify-only` performs no PUT and independently checks
the recovery flags, unchanged self identity/generation, and two copy responses
per approved source key. The original approval receipt must still describe the
ten keys before recovery; a newly minted credential or replacement mapping is
not accepted. HTTP requires `--allow-http-loopback` and is limited to loopback
for CI mocks.

Before apply, every key authenticates against the gateway and is joined to one
active control-plane row under the exact approved tenant/key/generation, twice
for the full batch. Protected source/capture/approval/token bytes are reread and
digest checked. Each fixed PUT is preceded by another identity/state check.
Only `/internal/v1/keys/{approved-id}/credential-recovery` receives `{key}`.
The product verifies the plaintext against its retained hash. No key rotation,
grant, policy, route, or database writes are implemented.

After every PUT, the command checks recovery availability and authenticates the
unchanged key, then compares two independent copy responses in memory, including
identity and generation. A final full-batch identity check fences later changes.
No plaintext or identity appears in logs or the count-only receipt; successful
receipts also bind input digests. Files remain owner-private.

Each HTTP request has a 30-second absolute deadline and a 256-KiB response bound.
The batch has a 15-minute deadline. Redirects and automatic retries are forbidden.
A failed apply may already have stored some envelopes: inspect `stored_count`,
`attempted_count`, and `write_outcome_uncertain`. Stop and review; do not rerun
automatically. A lost PUT response can leave its storage outcome unknown. The
tool deliberately refuses mixed already-recovered batches in apply mode.

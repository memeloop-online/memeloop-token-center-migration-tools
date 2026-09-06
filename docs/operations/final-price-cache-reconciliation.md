# Final CPAMP price/cache reconciliation

`ops/reconcile-final-price-cache.ts` is the final incremental-import receipt
for historical CPAMP price and cache accounting. It is a PostgreSQL
`REPEATABLE READ READ ONLY` transaction and has no apply mode, cluster write,
or source-system connection. Its default invocation is dry-run.

The tool needs only non-secret scope and connection metadata. Authentication is
delegated to a mode-`0600`, regular, non-symlink `pgpass` file; it is never
opened by the TypeScript process, printed, or placed in argv. Do not use
`PGPASSWORD` for this receipt.

```text
PRICE_RECON_PGHOST=REPLACE_HOST \
PRICE_RECON_PGPORT=5432 \
PRICE_RECON_PGUSER=REPLACE_READONLY_USER \
PRICE_RECON_PGDATABASE=REPLACE_DATABASE \
PRICE_RECON_PGPASSFILE=/private-evidence/pgpass \
PRICE_RECON_TENANT_EXTERNAL_ID=REPLACE_TENANT \
PRICE_RECON_IMPORT_SOURCE=REPLACE_CPAMP_SOURCE \
PRICE_RECON_CURRENCY=USD \
node ops/reconcile-final-price-cache.ts --dry-run \
  > /private-evidence/final-price-cache-receipt.json
```

`PRICE_RECON_STATEMENT_TIMEOUT_MS` optionally bounds the one read-only
snapshot; it defaults to `30000`. Tenant/source identifiers are bound as psql
variables and appear in the receipt only as SHA-256 scope bindings. Per-key
rows use a SHA-256 of the target key ID; neither API-key material nor a request
or response locator/body is selected or emitted.

The JSON receipt includes aggregate provenance/link/fact coverage, token and
cost deltas, per-key/model/day cache-read/cache-write reconciliation,
data-driven current-price model/tier gaps, and duplicate-billing checks. All
counts and monetary/token amounts are decimal strings so large PostgreSQL
integers remain exact. Missing current prices, incomplete provenance, cache
partition errors, amount differences, or any imported usage reservation/ledger
entry make the command exit nonzero after writing the complete receipt. This is
intentional: retain the receipt for investigation and do not acknowledge a
known gap by changing tool code or substituting a global price book.

Historical CPAMP source price snapshots remain the accounting provenance. The
current price-tier check is only a cutover visibility gap check; this tool never
creates, updates, or infers a current price.

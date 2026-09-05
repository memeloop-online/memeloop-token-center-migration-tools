# CPA upstream account import

`ops/cpa-upstreams/import-cpa-upstreams.ts` inventories a mounted CPA v7
`config.yaml` and its real `auth-dir`, then imports the supported accounts through
the Token Center control API. It is dry-run by default. It does not read CPA
through its management API and never mutates the source snapshot.

This importer migrates upstream account connections. CPA model aliases,
per-key prefixes, excluded-model lists and Token Center model routes remain a
separate reviewed routing migration.

## Supported source records

The TypeScript parser uses `yaml` in strict unique-key/no-alias mode and accepts
these CPA configuration sections:

- `openai-compatibility[].api-key-entries[]`;
- `gemini-api-key[]`, using `x-goog-api-key`;
- `codex-api-key[]`, when every entry has an explicit `base-url`;
- `claude-api-key[]`, using `x-api-key`;
- auth JSON with the explicit normalized shape `type: api_key`, `base_url` and
  `api_key`; and
- Codex and legacy Gemini OAuth documents, imported into the matching managed
  OAuth provider supplied by Token Center.

Per-account private `socks5` and `socks5h` proxy URLs are preserved in
the same encrypted credential envelope as the API key. The URL is write-only and
may contain proxy authentication; inventory, account views and errors expose only
the proxied-account count. Proxied accounts require a global service credential.
The target and proxy addresses are resolved and checked independently.
Local-DNS `socks5` uses the client's pinned target resolution. Remote-DNS
`socks5h` is preserved only for a safe private IP-literal proxy; the target is
still locally policy-checked, while the trusted proxy resolves the hostname for
the connection. HTTP(S), public SOCKS and hostname-addressed `socks5h` proxies
fail closed. Custom
upstream headers and Claude request cloaking still stop the entire import.
Unknown `*-api-key`/`*-compatibility` sections and unknown auth JSON types also
stop the import. No supported accounts are written before source inventory and
target metadata conflict checks finish.

Target reachability is approved separately from proxy reachability. Targets are
public by default. A reviewed owner-only transport-policy file may classify an
exact normalized base URL as private; the importer then writes
`network_scope: "private"` for every source account using that URL. It never
infers a private target merely because an account has a proxy. Every account
classified as a private target must also carry an approved private SOCKS5
proxy; the complete inventory fails before any target request if even one
such account lacks it. The control plane still resolves and classifies the
target and proxy independently, pins local-DNS connections, and requires global
authority for private transport.

Opaque Copilot and Cursor handle records cannot be used as native credentials.
The importer never sends their handle, login, label or source document to Token
Center and never creates an upstream for them. Dry-run and apply instead include
each record in `native_reauthorization_required` with only its provider,
disabled state and keyed `source_stable_id`. Connect those accounts again
through their native or plugin-provided authorization flow.

## Secret and transport boundary

Before starting, make an immutable CPA volume snapshot and stage only its
`config.yaml` and declared auth directory for the importer UID. The importer
requires:

- `config.yaml`, every auth JSON, the target service token, the optional
  transport policy and, when opaque records exist, the source identity key to
  be owner-owned, single-link, regular mode-`0600` files;
- the auth root and every nested directory to be owner-owned mode `0700`;
- no symlink or non-JSON file anywhere below the auth root; and
- source and target sizes to remain within the built-in bounded-read limits.

Do not pass a credential, service token, source identity key or private target
URL in argv, an environment variable, a ConfigMap or a shell substitution.
Normal output is one JSON inventory object. Errors do not include filenames,
URLs, response bodies, credential values or secret-derived hashes. Core dumps
are disabled.

Every public target and provider URL must use HTTPS. A URL explicitly listed in
the private transport policy may use HTTP, but the server independently rejects
it unless DNS and every resolved IP satisfy the private-destination policy. The
`--allow-http-loopback` option permits only loopback HTTP and exists for
black-box tests. The importer HTTP client never follows redirects. Use
`--ca-file` for a private control-plane CA instead of disabling TLS verification.

The apply service credential needs `providers:read`, `providers:write` and, for
managed OAuth documents, `imports:cpa:write`. A private target or private
per-account proxy also requires a global (not tenant-bound) service credential.
Route it only to the private control Service.

## Dry-run and apply

Run the checked-in release importer image as its non-root UID. This example shows
the command inside that image; `/source` must already meet the ownership and mode
requirements above:

```sh
/usr/local/bin/import-cpa-upstreams \
  --config /source/config.yaml \
  --auth-dir /source/auth \
  --source-identity-key-file /secrets/migration/source-identity.key \
  --transport-policy-file /secrets/migration/transport-policy.json \
  --tenant cpa-dogfood-import
```

The optional transport policy is strict JSON with exactly this versioned shape:

```json
{
  "contract_version": 1,
  "private_target_base_urls": ["https://reviewed-private.example/v1"],
  "result_origins_by_base_url": {
    "https://reviewed-image-provider.example/v1": [
      "https://reviewed-image-assets.example"
    ]
  }
}
```

`private_target_base_urls` classifies exact provider targets. The optional
`result_origins_by_base_url` maps an exact source provider base URL to the exact
HTTPS origins from which its generated assets may be archived. It is an SSRF
allowlist, not a URL-prefix or wildcard mechanism; paths, duplicate origins and
entries for providers absent from the source are rejected. Omit the option when
every target is public and no provider returns asset URLs from another origin.
Duplicate or unmatched entries, unknown fields and unsupported versions stop
the complete inventory before any target request. The path must be absolute.
Preserve the approved file and its SHA-256 digest with the migration ledger;
changing transport configuration on replay keeps the same stable source
identity and fails as an account configuration conflict.

`--source-identity-key-file` is required only when the snapshot contains opaque
Copilot/Cursor records. It must be an absolute path to a mode-`0600` regular,
non-symlink, single-link file owned by the importer UID. Generate it only with
the release image's `/usr/local/bin/generate-source-identity-key` command. The
command takes one new absolute target path, requires its parent directory to be
owned by the current UID and not writable by group or other users, rejects every
symlink path component and refuses to overwrite an existing target. It writes a
private random temporary file completely, fsyncs it, publishes it with a
hard-link that cannot replace the target, removes only the private temporary
name, and fsyncs the parent. A failed run never unlinks the public target name
and produces no key material on stdout.

The file format is a fixed magic and version followed by exactly 32 bytes from
Node.js' operating-system-backed `randomBytes`. The importer accepts
only that exact binary format; passwords, raw keys, hex/base64 text, a trailing
LF, wrong versions and wrong lengths fail before any target request. Format
validation is not presented as proof that arbitrary caller-written bytes are
random. Use the reviewed generator, store the resulting file in the migration
secret manager as binary data; never use `stringData` or an environment
variable.

Do not point the importer at a Kubernetes Secret projected-volume path. The
projection uses root-owned symbolic links, while the importer deliberately
requires a real current-UID-owned, single-link regular file. Use the checked-in
[`ops/kubernetes/cpa-upstream-import-dry-run-job.yaml`](../../ops/kubernetes/cpa-upstream-import-dry-run-job.yaml)
example: its least-privilege init container copies the source key and reviewed
transport-policy Secret entries into a memory-backed private `emptyDir`, sets
owner `10001:10001` and mode `0600`, and verifies both files. The importer mounts
that `emptyDir` read-only and never mounts either Secret itself. Even an all-public
run supplies the version-1 policy with an empty list. Replace every explicit
placeholder, record the policy digest and approval reference in the immutable
Job annotations, stage the CPA snapshot for UID `10001`, inspect the manifest,
and keep the example in dry-run mode until its output is approved.

A successful dry-run returns counts and the non-secret native-authorization
worklist:

```json
{"api_account_count":6,"created_count":0,"created_managed_oauth_count":0,"disabled_source_count":0,"managed_oauth_account_count":0,"managed_oauth_source_type_counts":{},"mode":"dry-run","native_reauthorization_required":[{"provider":"copilot","source_disabled":false,"source_stable_id":"3e37cd527b6365313440b4be4df9184b4dbe06c2aeb4c80628134bd38cb0ea38"},{"provider":"cursor","source_disabled":false,"source_stable_id":"2a8d8d1ee60dad9b93c5f8a479fb24fd38f48095da0c1e9cde5a00fc7ad650b3"}],"native_reauthorization_required_count":2,"private_target_api_account_count":2,"proxied_api_account_count":2,"replayed_count":0,"replayed_managed_oauth_count":0}
```

Preserve the source snapshot and inventory output for review. Do not reorder API
key entries or rename auth files between dry-run and apply: section/provider plus
list ordinal, or auth relative path, is the stable CPA source identity.

Preserve `native_reauthorization_required` alongside the migration ledger. Its
`source_stable_id` is derived from the non-secret source identity, not the opaque
handle, using domain-separated HMAC-SHA256 and the source identity key. This
prevents common auth filenames from being recovered with an offline dictionary.
The ID is the durable join key for historical account/request mapping and the
later native reauthorization record. Replaying the same immutable snapshot with
the same key produces the same worklist; another key intentionally produces
different IDs. Preserve the key in the migration secret store and use the same
key for every dry-run, apply and recovery. Renaming an auth file changes its
source identity, so never rename or reorganize the reviewed snapshot between
runs.

After approval, mount a least-privilege Token Center token as a mode-`0600` file
and add:

```text
--apply
--target-api-base-url https://token-center-control.internal.example
--service-token-file /secrets/target/service-token
```

If the snapshot contains only Copilot/Cursor opaque handles, `--apply` remains a
report-only operation: it still requires the source identity key, but needs no
target URL or service token and performs no HTTP request. This is intentional
because those records require a fresh native authorization.

For API accounts, the target name includes a deterministic hash of the non-secret
source identity. Apply first lists the tenant and rejects any same-name account
whose driver or configuration differs. A newly created account is then converged
through `PUT /internal/v1/upstreams/{id}/credential` with a source-derived
`Idempotency-Key`. This second write makes an ambiguous create response
recoverable: replay finds the deterministic account and obtains the exact stored
rotation result. The key contains no credential hash. Reusing the same immutable
source does not add an account or credential generation; changing credential
material under the same source identity conflicts instead of silently rotating
an audited migration source.

Create a fresh apply Job for the replay. It must report every API account under
`replayed_count` and keep the target account count unchanged. An interrupted run
is recovered by replaying the same
immutable snapshot, never by editing the snapshot or weakening a conflict gate.
The source-derived credential idempotency key also makes a committed write with
an ambiguous network response safe to replay without adding a credential
generation.

## Managed OAuth import

Managed OAuth auth files are imported one at a time through
`POST /internal/v1/imports/cpa/managed-oauth`. The caller supplies only contract
version `1`, the tenant, a strict POSIX auth-file relative path, a server-advertised
`source_type`, and the opaque CPA document. It cannot supply an account name,
provider driver, provider configuration, adapter destination, or refresh URL.
Those values come from the installed server catalog and its versioned adapter.

The importer must call
`GET /internal/v1/imports/cpa/managed-oauth/capabilities` during its no-write
preflight. The response is intentionally limited to the contract version and a
sorted, unique list of source types; it contains no driver, URL, token, or
internal topology. If any inventoried managed OAuth record is unsupported, apply
must stop before its first target write.

Both operations require a global service credential with the dedicated
`imports:cpa:write` scope. A tenant-bound credential is rejected even if it has
that scope. Do not substitute `providers:write` or `oauth:write`.

The auth relative path is limited to 512 UTF-8 bytes. It must be a non-empty
POSIX relative path with no absolute prefix, empty segment, `.` or `..` segment,
backslash, NUL, or control character. The canonical JSON document is limited to
1 MiB, and the complete JSON request has a bounded 64 KiB envelope allowance.
Neither the path nor document is returned or logged.

Token Center derives the source identity and immutable payload digest with
domain-separated HMAC-SHA256 using its key pepper. Canonical JSON sorts object
keys recursively while retaining array order. The source path, document, token,
and keyed digests are never stored in response-visible account metadata. An
exact replay returns HTTP 200 with `disposition: replayed` and the same stable
account without resolving or calling an adapter. Changed `source_type` or
document material under the same source returns static HTTP 409. A new atomic
import returns HTTP 201 with `disposition: created`; a concurrent identical
winner is returned as a replay.

Before the atomic write, the normalized account must pass the active provider's
configuration and credential schemas and the complete outbound destination/SSRF
policy. An enabled, unexpired source becomes active. An enabled but expired and
refreshable source, or a disabled source, is stored disabled for managed refresh.
An expired credential without refresh state is rejected with HTTP 400 and no
write. Adapter rejection, timeout, oversized response, or invalid normalized
output returns a static HTTP 502 without exposing its response.

# Service and plugin runtime preflight — 2026-08-24

This evidence explains the final-runtime change made after GitHub Actions run
`32678530047`. It contains no credentials and does not replace the final image
contracts, Trivy scans, SBOM/provenance verification or combined release
manifest.

## Observed release failure

Run `32678530047` passed every pre-publication gate for clean source `79d2b08`,
including the formal 15-minute memory acceptance. Its Alpine importer image
also passed the final-image scan and provenance checks. The plugin-installer
build stopped before publication because the TUNA Debian mirror rejected plain
HTTP with status 403. The service build was cancelled immediately because a
complete release was no longer possible.

An initial replacement attempted to use the TUNA HTTPS mirror, but the
build-only Debian slim stage did not yet contain a CA bundle and correctly
refused the certificate. Run `32684971435` exposed this in its plugin image
contract and was cancelled after about one minute. The final replacement
removes the custom mirror override and retains the signed repository
configuration supplied by the official Debian build images. A packaging
contract rejects restoration of the custom mirror.

## First final-runtime attempt and scan result

Run `32686030562` for clean SHA `16e46820645c2a8b37ae660fed1fde488ff4b330`
proved that all source, packaging and formal memory gates pass. It also proved
that the importer publishes and scans successfully and that the plugin image
builds. The plugin final-image scan then correctly rejected two independent
runtime vulnerability sources:

- `libssl3t64` from `gcr.io/distroless/cc-debian13:nonroot` had deferred
  `CVE-2026-14456` remediation even though neither product binary uses OpenSSL;
- the official Cosign 3.1.3 binary was built with Go 1.26.4 and contained fixed
  HIGH findings in the standard library, `golang.org/x/mod`,
  `golang.org/x/text`, and `google.golang.org/grpc`.

The service publication was cancelled immediately and the partial importer and
plugin digests remain forbidden. There is no combined release manifest.

## Minimal final runtime and Cosign security backport

The final service and plugin-installer stages now use
`gcr.io/distroless/base-nossl-debian13:nonroot`, which keeps glibc and CA
certificates but excludes the unused OpenSSL runtime. The Rust builder copies
only its resolved `libgcc_s.so.1` into `/usr/local/lib`; `LD_LIBRARY_PATH` is
fixed to that directory. The upstream Distroless project documents the image
contents and supported `nonroot` tags at
`https://github.com/GoogleContainerTools/distroless`.

All three locally built release binaries requested only these shared objects:

```text
libgcc_s.so.1
libm.so.6
libc.so.6
/lib64/ld-linux-x86-64.so.2
```

Cosign had no release newer than 3.1.3 when checked on 2026-08-24. Its annotated
`v3.1.3` tag is GitHub-verified and resolves to commit
`11926fa5bbbbde47e88fc006b625a17769b743b2`. The image build pins that commit's
source archive SHA-256
`3a718446bac51466efff6853639e1ca108b456ecbf07cd92938f548715d22d6b`, applies
the checked-in `packaging/cosign/v3.1.3-security.patch`, verifies `go.sum`, and
builds `v3.1.3-mtc.2` with fixed Go 1.26.7. The backport now includes
`google.golang.org/grpc` 1.83.1, which fixes CVE-2026-84304 detected by the
exact-digest release scan on 2026-09-02. The locally used official Go archive
matched SHA-256
`ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca`.
The patch moves only the related Go dependency family and gRPC to versions
needed by the fixes; it is not described as an official upstream binary.

The locally rebuilt amd64 binary reported the expected tag commit, clean tree,
and Go 1.26.7 and had SHA-256
`5651806b982c4cb91f954845faabaea741a3c5e3c1558cc92f0395528ab07403`.
A local password-protected key generation, blob sign and public-key verify smoke
test completed successfully. Trivy 0.70.0, vulnerability DB v2 updated at
`2026-08-23T19:09:39Z`, reported zero HIGH/CRITICAL findings for that rebuilt
binary at `2026-08-24T05:28:03Z`. This is local preflight evidence only.

The current host has no Docker client, and a direct Trivy remote scan of the
public base timed out connecting to `gcr.io`; no pass is inferred for the
assembled base-nossl images. The next exact-SHA GitHub Actions run must build and execute
both Docker image contracts, then scan the exact three published digests with the unchanged
HIGH/CRITICAL `exit-code: 1` policy. No image is deployable until the combined
release manifest is verified.

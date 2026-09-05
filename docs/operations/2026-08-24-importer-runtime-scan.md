# Importer runtime scan evidence — 2026-08-24

This evidence records the local runtime-rootfs validation used to select the
release importer base image. It contains no credentials or private registry
material. It is not a substitute for the final Docker image build and scan in
GitHub Actions.

## Failed Debian candidate

GitHub Actions run `32671474947` tested source
`69a23aa4d8e72669b97904e9ecc70dce750f7f1b`. All pre-publication jobs,
including the exact-SHA 15-minute memory acceptance, passed. The importer image
was pushed as the incomplete release candidate
`sha256:cad3c27966324bc92580443fda501648ef9c7497d16f69e12c5202f090f52ea9`,
but its HIGH/CRITICAL Trivy gate failed. The service and plugin-installer
publish jobs were cancelled and the combined release manifest was not created.
The partial importer digest is therefore not deployable.

The Debian 12 runtime findings covered `bsdutils`, `libnode108`/`nodejs`,
Perl packages, `libsqlite3`/`sqlite3`, `libssl3`, `node-undici`, `util-linux`
and `zlib1g`. Several findings were marked fix deferred or will not fix, so an
`apt-get upgrade` was not an adequate release fix.

## Alpine replacement validation

`Dockerfile.importer` now pins `alpine:3.23.5`. The official x86_64 minirootfs
used for local validation was:

- URL: `https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/alpine-minirootfs-3.23.5-x86_64.tar.gz`
- published release date: 2026-06-21
- SHA-256: `fae0d78ad39563573ddececfdd55ae1040ed428442e95ea5401cf66d9079b327`

The rootfs was populated with the exact runtime dependency expression from the
Dockerfile: `ca-certificates nodejs postgresql-client sqlite`. Alpine resolved
38 packages. The primary tool versions were Node.js `24.18.1-r0`, PostgreSQL
client `18.6-r0` and SQLite `3.53.4-r0`.

The scanner was the official Trivy `0.70.0` Linux amd64 archive, whose tarball
SHA-256 was
`8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9`.
Its database was pulled from `ghcr.io/aquasecurity/trivy-db:2`. A filesystem
scan with `--severity HIGH,CRITICAL --exit-code 1` reported zero findings.

The compiled TypeScript operator entry points were copied into the same rootfs.
The Alpine Node loader accepted all three with `node --check`, and every entry
point completed its `--help` contract. The rootfs also ran PostgreSQL 18 `psql`
and SQLite successfully. A second offline scan of the completed rootfs again
reported zero HIGH/CRITICAL findings.

Docker, Podman and Buildah were unavailable in this workspace. Consequently,
this is reproducible equivalent-rootfs evidence, not the immutable image
attestation. The next exact-SHA GitHub Actions run must still build the image,
execute `node --test tests/ops/importer-image-contract.test.ts`, scan the final image, publish all
three images, and verify the combined digest manifest before any deployment.

## 2026-08-26 OpenSSL security refresh

GitHub Actions run `32943606008` tested source
`f3c342027e52c21f455b7c17d201bd8d133b858e`. Every pre-publication job and the
exact-SHA memory acceptance passed. The importer publish job then correctly
failed its unchanged HIGH/CRITICAL Trivy gate: Alpine 3.23.5 contained
`libcrypto3` and `libssl3` `3.5.7-r0`, while CVE-2026-14456 is fixed in
`3.5.8-r0`. The partial importer image
`sha256:cad6780cbb78d18b18a0baa804be81ddb9dc9d482df871685a3c7cf88e64b951`
is not deployable and no complete release manifest was produced.

The Dockerfile retains the reproducible Alpine 3.23.5 base but now upgrades the
two base OpenSSL runtime packages from the signed v3.23 repository before
installing the existing runtime dependency set. On 2026-08-26 the official
x86_64 v3.23 APK index resolved `libcrypto3` to `3.5.8-r0` from OpenSSL commit
`2b4b2590f782b95276d31dcaaf41554b1a597a0b`. The packaging contract requires
the explicit upgrade. No CVE waiver, Trivy ignore, severity reduction or
`ignore-unfixed` relaxation was introduced. A new exact-SHA final-image scan is
still mandatory.

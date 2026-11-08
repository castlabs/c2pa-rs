# Native 1.0.10 Audit Exceptions

Status: operator-authorized, time-boxed risk acceptance, not a vulnerability fix
or an audit-clean claim. The release owner accepted the reviewer's proposed
crypto-bigint exception while retaining the two existing exceptions below.

## Assessed Source

The assessed native candidate is
`11f121244a2e063b2f0535554ae3d761c4b015d6`, with Cargo.lock SHA-256
`10fcb5c1c096ed573f687faef9a104eeff6d4883484a45efb843624c16606a48`.
This separate policy change does not alter that commit, lock, runtime code,
Python/native pin or immutable published artifacts. It applies to the stated
dependency graph and profile, not arbitrary local-key applications.

The older maintained base `6021100c` still has three TLS/Tokio advisories fixed
by the assessed candidate: RUSTSEC-2026-0381, RUSTSEC-2026-0382 and
RUSTSEC-2026-0386. They are not ignored here. Integrate the reviewed candidate
before considering the maintained native line ready; this exception alone does
not remediate or accept those older dependencies.

## crypto-bigint: RUSTSEC-2026-0387

- Locked `crypto-bigint` 0.5.5 enters through `elliptic-curve` 0.13.8 and the
  ECDSA/P-256/P-384/P-521/primeorder stack, including `c2pa_raw_crypto` 0.1.2 and
  experimental live-video dependencies.
- The advisory concerns secret-dependent timing in operations intended to be
  constant-time. Native local EC private-key signing remains exposed. Calling
  the library's local PEM signing API is not made safe by this exception.
- Public-key/signature verification does not supply secrets to those operations.
  The selected callback-backed keystore signing path keeps EC private keys out
  of native RustCrypto. Local Ed25519 uses a different arithmetic implementation.
  The reviewed c2patool profile uses OpenSSL for private signing; parsing public
  session keys with P-256 is not local private-key signing.
- There is no compatible fix on the 0.5 line. Remediation needs the newer
  raw-crypto/RustCrypto stack, not a checksum-only or semver-compatible patch.
- The release owner accepts the residual local-key exposure for this candidate
  until the deadline below. Consumers must assess their actual mode; the
  callback/verification analysis is not a universal `not_affected` declaration.

**Deadline:** review on 2026-12-04 UTC. The ignore is valid only before that date;
the existing audit job fails from 00:00 UTC on 2026-12-04 while the ignore is
present. Remove it after remediation or record a new reviewed disposition before
changing the deadline. The pinned cargo-deny 0.19.8 supports reasons but no expiry
field, so the small workflow check enforces the date. This is an audit/release
control, not a timer that stops already deployed services.

The native migration is tracked by the release owner's existing
[native-lock remediation issue](https://github.com/castlabs/stardustproof-c2pa-signer/issues/70)
(internal repository). Port the appropriate upstream `c2pa_raw_crypto` 0.2+
implementation and its compatible RustCrypto stack, then qualify all affected
signing, verification, FFI and WASM paths before removing the ignore. Source,
feature, private-key mode or relevant dependency changes require reassessment;
do not inherit this disposition automatically for a new graph.

## Existing Exceptions

| Advisory | Disposition and limits |
|---|---|
| RUSTSEC-2023-0071, `rsa` 0.9.10 | Retain the existing Marvin exception, replacing the upstream internal-ticket comment with this fork's rationale. Private RSA signing is exposed; the selected ES256 callback and public-verification paths do not exercise that private-key mode. No fixed RSA release exists in the reviewed graph. Review on 2026-12-04 UTC; do not describe the whole Python wheel as unaffected. |
| RUSTSEC-2024-0370, `proc-macro-error` 1.0.4 | Retain the existing unmaintained/informational exception. It is a build-time macro dependency, not runtime signing code. Reassess during dependency/toolchain migration. |

Passing cargo-deny with these entries means the explicit dispositions were
applied. It does not remove the advisories from the native library, approve
local private-key modes as unaffected, or replace downstream source-bound
security records and installed-artifact qualification.

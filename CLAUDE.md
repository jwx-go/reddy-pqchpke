# reddy-pqchpke — Agent Notes

## Overview

This module (`github.com/jwx-go/reddy-pqchpke/v4`) implements a subset of
[draft-reddy-cose-jose-pqc-hybrid-hpke](https://datatracker.ietf.org/doc/draft-reddy-cose-jose-pqc-hybrid-hpke/):
specifically the X25519+ML-KEM-768 HPKE ciphersuites in key-encryption
(`-KE`) mode.

The draft is an individual submission, not WG-adopted. Treat all algorithm
ids, KDF info bytes, and wire formats as subject to change until adoption.

## Architecture

Registers support via jwx's extension points in `init()`:

| JWX Package | Registration | Purpose |
|-------------|--------------|---------|
| `jwk` | `RegisterKeyImporter` / `RegisterKeyExporter` | Hybrid AKP keys ↔ raw `*HybridPublicKey` / `*HybridPrivateKey` |
| `jwa` | `RegisterKeyEncryptionAlgorithm` | `HPKE-10-KE`, `HPKE-11-KE` |
| `jwebb` | `RegisterHPKEAlgorithm` | Routes these algs through jwx's HPKE-KE dispatch |

Wrapper types `HybridPublicKey` / `HybridPrivateKey` implement
`jwebb.HPKEKeyEncrypter` / `jwebb.HPKEKeyDecrypter`, so `jwe.Encrypt` and
`jwe.Decrypt` delegate to this module when it sees one of these keys.

## Sub-packages (planned)

| Package | Purpose |
|---------|---------|
| `internal/kemhpke` | Hand-rolled HPKE engine: RFC 9180 §5.1 KeySchedule on cSHAKE256, plus the X25519+ML-KEM-768 KEM combiner |
| (root) | `HybridPublicKey` / `HybridPrivateKey`, `init()` registration, JWK import/export |

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Key design points

**READ `docs/design.md` FIRST.** It records the draft delegation chain,
the X-Wing decision, the SHA3-256/SHAKE256 distinctions, and the AKP JWK
encoding rationale. Everything below is a one-line summary; the design
doc is authoritative.

- **X-Wing KEM via `filippo.io/mlkem768/xwing`** — not hand-rolled. The
  draft-irtf-cfrg-concrete-hybrid-kems §4.2 declares MLKEM768-X25519
  "identical to X-Wing", so we use the named construction.
- **Hand-rolled HPKE key schedule.** Stdlib `crypto/hpke` is HKDF-only
  and DHKEM-only with no extension points. Draft-ietf-hpke-pq mandates
  SHAKE256 as the HPKE KDF, so we reimplement RFC 9180 §5.1 on top of
  `golang.org/x/crypto/sha3`.
- **Encapsulated key wire format**: `ct_mlkem (1088) || ct_x25519 (32)`
  = 1120 bytes, defined by X-Wing §5.4.
- **AKP JWK**: `pub = 1216 bytes` (ML-KEM first), `priv = 32 bytes` (the
  X-Wing seed). **Note the 32**, not 64 — X-Wing derives everything
  from a single seed via `SHAKE256(seed, 96)`. The `z` extension field
  from the jwx main `v4-mlkem.md` design does **not** apply here.

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

## References

- [draft-reddy-cose-jose-pqc-hybrid-hpke](https://datatracker.ietf.org/doc/draft-reddy-cose-jose-pqc-hybrid-hpke/)
- [RFC 9180 (HPKE)](https://datatracker.ietf.org/doc/rfc9180/) — key schedule lives in §5.1
- [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf) — cSHAKE256
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM
- [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/) — JOSE HPKE-KE info-bytes convention we inherit

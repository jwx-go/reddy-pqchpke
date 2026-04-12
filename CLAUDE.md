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

- **Hand-rolled HPKE key schedule.** Go stdlib `crypto/hpke` is HKDF-only
  and DHKEM-only. The draft's ciphersuites use SHAKE256 as the KDF and a
  hybrid KEM, so we reimplement RFC 9180 `LabeledExtract` /
  `LabeledExpand` / `KeySchedule` on top of `golang.org/x/crypto/sha3`.
- **KEM combiner.** X25519 DH and ML-KEM-768 encap/decap run independently,
  shared secrets are concatenated, then fed through a SHAKE256-based KDF
  per draft §4 to produce the HPKE KEM shared secret.
- **Encapsulated key wire format.** `enc_mlkem || enc_x25519` — ML-KEM
  ciphertext first, X25519 ephemeral public second, no delimiter. Sizes
  are fixed so splitting is by offset.
- **AKP JWK encoding.** `pub = ek_mlkem || pub_x25519` (1184B + 32B).
  `priv = dk_mlkem_seed || scalar_x25519` (32B + 32B). See the existing
  `jwk/akp.go` `z` extension handling in the main jwx module for how
  ML-KEM seeds round-trip.

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

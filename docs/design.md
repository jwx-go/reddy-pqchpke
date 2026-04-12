# Design Notes: reddy-pqchpke

This document records **why** this module is shaped the way it is. It
exists so future agents modifying this code don't have to re-investigate
the IETF draft chain from scratch. Read this before making any change to
the crypto layer or the AKP JWK encoding.

## 1. Draft delegation chain

The scope is "implement `draft-reddy-cose-jose-pqc-hybrid-hpke` for JOSE,
specifically the X25519+ML-KEM-768 ciphersuites." Pinning down the
concrete cryptographic details requires following a chain of delegations:

```
draft-reddy-cose-jose-pqc-hybrid-hpke      (JOSE-facing: alg strings, JWK)
  └─ §3.3 delegates KEM details to ─►
     draft-ietf-hpke-pq                    (HPKE KEM registrations)
       └─ §4 delegates hybrid construction to ─►
          draft-irtf-cfrg-concrete-hybrid-kems
            └─ §4.2 declares the hybrid "identical to X-Wing"
  └─ delegates JWE framing to ─►
     draft-ietf-jose-hpke-encrypt          (Recipient_structure, "ek" header)
```

Draft-reddy itself contains very few concrete bytes. Everything crypto
lives in the docs it references. The chain is non-obvious; retracing it
takes real time.

## 2. Why X-Wing

The load-bearing sentence lives in
`draft-irtf-cfrg-concrete-hybrid-kems` §4.2, which states that the
`MLKEM768-X25519` construction is **"identical to the X-Wing construction
from draft-connolly-cfrg-xwing-kem"**. Without this sentence, we would
have to pick between a generic `UniversalCombiner` (hash all secrets,
ciphertexts, and public keys) or `C2PRICombiner` (hash the PQ secret
alone plus the classical ciphertext/pubkey) — both defined in
`draft-irtf-cfrg-hybrid-kems`. We'd have no principled way to choose.

X-Wing is a named, published, peer-reviewed construction with its own
test vectors in the draft appendix. Inheriting it means we're implementing
"X-Wing" — a known quantity — rather than "one of several possible
MLKEM768-X25519 combiners."

## 3. Why `filippo.io/mlkem768/xwing` and not hand-rolled

We depend on `filippo.io/mlkem768/xwing` as a **runtime** dependency
rather than hand-rolling X-Wing inside `internal/xwing/`.

Rationale:

- Maintained by Filippo Valsorda, who is a co-editor of
  `draft-connolly-cfrg-xwing-kem` and a Go stdlib `crypto` maintainer.
  When the draft moves, the library moves.
- The public API is exactly the shape we need for the AKP JWK
  round-trip:
  - `NewKeyFromSeed(seed []byte)` takes a 32-byte seed → matches AKP's
    `priv` field (also 32 bytes) directly
  - `(*DecapsulationKey).EncapsulationKey() []byte` returns the full
    1216-byte public key → matches AKP's `pub` field directly
  - `Encapsulate` and `Decapsulate` return the raw 32-byte shared secret,
    which feeds directly into our HPKE key schedule without any
    intermediate wrapping
- Minimal dep surface (BSD-3-Clause; depends only on stdlib `crypto/mlkem`,
  `crypto/ecdh`, and `golang.org/x/crypto/sha3`)
- **Precedent**: the `jwx-go/x448` companion module pulls in
  `cloudflare/circl` for exactly the same reason — Go stdlib doesn't have
  X448, a trusted third-party library does, so we use it. This module
  inherits that pattern.

The obvious alternative — "avoid external crypto dependencies, hand-roll
X-Wing from the draft pseudocode" — was considered and rejected. Record
here so anyone tempted to rewrite understands why: the tradeoff was
~80 LOC of hand-rolled crypto we'd have to audit and maintain against a
trivially-importable library whose author maintains the reference
implementation of the underlying spec.

## 4. Why we still hand-roll the HPKE key schedule

Go's `crypto/hpke` is **HKDF-only** (for the KDF) and **DHKEM-only** (for
the KEM). It has no extension points for plugging in custom KDFs or
custom KEMs. `draft-ietf-hpke-pq` §5 mandates **SHAKE256** as the HPKE
KDF for PQ ciphersuites, and the KEM is X-Wing (not DHKEM). There is no
supported way to use stdlib HPKE for this.

Therefore `internal/hpke/` reimplements the RFC 9180 §5.1 HPKE key
schedule:

- `LabeledExtract(salt, label, ikm)` on SHAKE256
- `LabeledExpand(prk, label, info, L)` on SHAKE256
- `KeySchedule(mode_base, shared_secret, info)` producing AEAD key and
  base nonce

We do **not** reimplement streaming Sender/Recipient — just enough to
`Seal(cek)` / `Open(sealed)` for the JWE key-encryption path. The adaptation
from HKDF to SHAKE256 is mechanical; follow `draft-ietf-hpke-pq` §5 for
the exact cSHAKE framing.

## 5. SHA3-256 vs SHAKE256 — critical distinction

Three different Keccak-family primitives are in use here. Confusing them
is an easy source of silent interop bugs.

| Primitive | Where it's used | Why |
|-----------|----------------|-----|
| **SHA3-256** | Inside X-Wing's shared-secret combiner (`SHA3-256(ss_M \|\| ss_X \|\| ct_X \|\| pk_X \|\| XWingLabel)`) | Defined by X-Wing §5.3. Fixed-output, 32 bytes. |
| **SHAKE256** | X-Wing key expansion (`SHAKE256(seed, 96)` → splits into ML-KEM seed + X25519 scalar) | Defined by X-Wing §5.2. Variable-output, used as a PRG. |
| **SHAKE256** | Our HPKE key schedule (`LabeledExtract` / `LabeledExpand`) | Defined by draft-ietf-hpke-pq §5 as the HPKE KDF for PQ ciphersuites. Variable-output XOF. |

If you find yourself passing a SHAKE256 result where SHA3-256 is expected
(or vice versa), stop and re-read this section.

Both primitives live in `golang.org/x/crypto/sha3`:

- `sha3.New256()` → SHA3-256
- `sha3.NewShake256()` → SHAKE256 XOF

X-Wing itself lives in `filippo.io/mlkem768/xwing`, so the primitives
inside it are not our concern — we only care about the SHAKE256 KDF we
use in `internal/hpke/`.

## 6. AKP JWK encoding

`draft-reddy-cose-jose-pqc-hybrid-hpke` §6.1.2.3 and §6.1.2.4 define the
AKP wire format for hybrid keys:

- `kty = "AKP"`
- `alg` is mandatory and one of `"HPKE-10-KE"`, `"HPKE-11-KE"` (for the
  ciphersuites this module supports)
- `pub` is **1216 bytes** = `pk_M (1184) || pk_X (32)` — PQ KEM public
  key first, classical X25519 public key second, no delimiter, no length
  prefix. Byte order is mandated by the draft.
- `priv` is **32 bytes** — the X-Wing seed, not the expanded
  decapsulation key.

The critical point is **`priv` is 32 bytes, not 64**, because X-Wing
derives everything deterministically from the seed:

```
SHAKE256(seed, 96) →
  bytes[0:32]   → ML-KEM KeyGen_internal d
  bytes[32:64]  → ML-KEM KeyGen_internal z
  bytes[64:96]  → X25519 scalar
```

This matters because the earlier `v4-mlkem.md` design doc (in jwx main
for pure ML-KEM-768/1024) introduced a private extension field `"z"` to
round-trip the full ML-KEM seed. **That `z` hack does not apply here.**
Do not carry it over. X-Wing's seed-based construction makes it
unnecessary: you store 32 bytes, call `xwing.NewKeyFromSeed(priv)`, and
get back a fully usable decapsulation key with zero ambiguity.

Import-side length checks:

- `pub` must be exactly 1216 bytes — reject otherwise
- `priv` must be exactly 32 bytes — reject otherwise

## 7. HPKE KEM ID and suite bytes

`draft-ietf-hpke-pq` registers MLKEM768-X25519 in the IANA HPKE KEM
registry with ID **`0x647a`** (25722 decimal).

The suite ID bytes used inside RFC 9180's `LabeledExtract` /
`LabeledExpand` KEM-context calls are:

```
"KEM" || 0x64 || 0x7a
= 0x4b 0x45 0x4d 0x64 0x7a
```

This is only relevant inside the KEM-level HPKE key schedule — X-Wing
itself does its own shared-secret computation and does not use this
label. We use it inside `internal/hpke/` when building the HPKE context.

The HPKE KDF and AEAD suite IDs per ciphersuite:

| alg | KEM | KDF | AEAD |
|-----|-----|-----|------|
| `HPKE-10-KE` | MLKEM768-X25519 (`0x647a`) | SHAKE256 (`0x0011`) | AES-256-GCM (`0x0002`) |
| `HPKE-11-KE` | MLKEM768-X25519 (`0x647a`) | SHAKE256 (`0x0011`) | ChaCha20-Poly1305 (`0x0003`) |

Full HPKE suite ID (per RFC 9180 §5.1): `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.

## 8. Draft status warning — API instability

**`draft-reddy-cose-jose-pqc-hybrid-hpke` is an individual submission,
not a working-group document.** The JOSE WG's adopted PQ draft is
`draft-ietf-jose-pqc-kem` (pure ML-KEM, no HPKE), which jwx main already
implements. Hybrid HPKE for JOSE is still making its way through the
process.

Consequences for this module:

- The alg strings `HPKE-10-KE` and `HPKE-11-KE` may be renumbered if the
  draft is restructured before WG adoption.
- The JOSE info bytes (`"JOSE-HPKE rcpt"` prefix) come from
  `draft-ietf-jose-hpke-encrypt`, which *is* WG-adopted but not yet an
  RFC, so those can also drift.
- The draft may decide that only a subset of the 9 ciphersuites should
  be registered, in which case ours might disappear.

The module name begins with `reddy-` as a deliberate signal. The README
calls this out. Anyone considering "let's stabilize the API" should
understand that **the upstream isn't stable yet**. Stabilize when the
draft is adopted by the WG, not before.

If you're reading this because a user reported their serialized JWE
broke after a `go get -u`, the first thing to check is whether any of
the upstream drafts moved.

---

## Quick reference: what each file is for

- `pqchpke.go` — wrapper types (`HybridPublicKey`, `HybridPrivateKey`),
  `jwebb.HPKEKeyEncrypter` / `HPKEKeyDecrypter` implementations. This is
  the JWE integration seam.
- `akp.go` — AKP JWK importer/exporter `init()` registrations, mapping
  hybrid raw types ↔ AKP JWKs.
- `register.go` — `jwa.RegisterKeyEncryptionAlgorithm` and
  `jwebb.RegisterHPKEAlgorithm` calls at `init()`. These are what make
  `jwa.KeyAlgorithmFrom("HPKE-10-KE")` resolve and route through the
  existing jwx HPKE-KE dispatch.
- `internal/hpke/` — the SHAKE256 HPKE key schedule. This is the
  hand-rolled crypto. Never edit the labels or suite IDs without
  re-checking `draft-ietf-hpke-pq` §5.

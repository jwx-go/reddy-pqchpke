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

## 3. Why `cloudflare/circl` and not hand-rolled

We depend on `github.com/cloudflare/circl` — specifically
`circl/kem/xwing` for the X-Wing KEM and `circl/hpke` as an HPKE test
oracle — rather than hand-rolling X-Wing inside `internal/xwing/`.

Rationale:

- **Precedent**: the `jwx-go/x448` companion module already pulls in
  `cloudflare/circl` for the same reason — Go stdlib doesn't have X448,
  circl does, so x448 uses circl. This module inherits that pattern.
- **One dep, two purposes**: `circl/kem/xwing` gives us the runtime
  X-Wing KEM; `circl/hpke` gives us a structural test oracle for our
  hand-rolled HPKE key schedule (see §4). Using circl for both means we
  don't need a second third-party dep for testing.
- **API fit**: `xwing.DeriveKeyPair(seed)` takes a 32-byte seed —
  matches AKP `priv` (32 bytes) directly. `PrivateKeySize == 32` means
  `sk.MarshalBinary()` round-trips the seed losslessly. `pk.Pack(buf)`
  / `pk.Unpack(buf)` cover the 1216-byte `pub` round-trip. `Encapsulate`
  and `Decapsulate` return the raw 32-byte shared secret directly.
- **Authoritative source**: circl's PQ crypto work is maintained by Bas
  Westerbaan, who is a co-editor of `draft-ietf-hpke-pq` and
  `draft-connolly-cfrg-xwing-kem`. Upstream moves track the drafts.

Two alternatives were considered and rejected:

- **Hand-rolling X-Wing** (~80 LOC from the draft pseudocode): rejected
  because circl's implementation already exists, is maintained by a
  draft co-editor, and gives us a free test oracle as a side effect.
- **`filippo.io/mlkem768/xwing`** (Filippo Valsorda's tiny focused
  package, also by a draft co-editor): rejected in favor of circl
  because it would be a second dep alongside circl-for-tests. Single
  dep is simpler to upgrade and matches the x448 companion's pattern.
  Filippo's API is arguably cleaner (direct-byte inputs, no
  caller-allocated `Pack` buffers), but not by enough to justify a
  second import path.

### Minor circl API ceremony (wrap once and forget)

- `sk.Pack(buf)` / `pk.Pack(buf)` panic on wrong-size buffers. Our
  wrapper types pre-allocate at the known sizes (`SeedSize`,
  `PublicKeySize`).
- `xwing.Decapsulate(ct, sk)` returns `ss` with no error. X-Wing has
  implicit rejection — it semantically cannot fail. Our
  `jwebb.HPKEKeyDecrypter.DecryptHPKE` still returns an error for
  downstream AEAD failures in the HPKE key schedule.
- The package-level `xwing.Encapsulate` returns `(ss, ct)` — note this
  is the reverse of circl's generic `kem.Scheme` interface; the package
  doc explicitly warns. We use the package-level function so the order
  is per the X-Wing standard, but don't get confused if you also touch
  `xwing.Scheme()`.

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

### Exit strategy: cloudflare/circl PR #553

Bas Westerbaan has an open WIP PR against cloudflare/circl that adds
exactly the support we need:

> [cloudflare/circl#553 "[WIP] HPKE updates"](https://github.com/cloudflare/circl/pull/553)
>
> - One-stage SHAKE-based KDFs in the HPKE key schedule
> - Hybrid QSF-X25519-MLKEM768 KEM (X-Wing)
> - Pure ML-KEM-{512,768,1024} KEMs
>
> Implements draft-ietf-hpke-pq-01. Draft status since July 2025.

When that PR merges and lands in a circl release, `internal/hpke/`
becomes ~30 lines of glue around
`circl/hpke.NewSender(KEM_XWING, KDF_SHAKE256, AEAD_AES256GCM, ...)`
instead of the full ~120 LOC we hand-rolled. Delete our key schedule,
swap in circl's, keep the wrapper types.

Until that PR merges, we can't use it — it's force-pushable and
undocumented, and we'd be shipping on top of someone else's
work-in-progress. But the PR's existence is the reason the hand-rolled
code in `internal/hpke/` is labeled "temporary" — future maintainers
should drop it rather than polishing it.

When editing `internal/hpke/schedule.go`, include a
`// TODO(circl#553)` comment linking the PR so the exit strategy is
discoverable without rereading this doc.

### KDF-pluggable key schedule

`internal/hpke/` is structured so the KDF primitive is a parameter
(hash/XOF constructor) rather than hard-coded to SHAKE256. This lets
us instantiate the same code with HKDF-SHA256 in tests and compare
byte-for-byte against circl's `KEM_XWING + KDF_HKDF_SHA256 + AEAD_AES256GCM`
HPKE — see §9 of this doc. The ~20-30 LOC design overhead is the cost of
admission for the structural test we can't otherwise run until SHAKE256
HPKE has an independent reference.

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
unnecessary: you store 32 bytes, call `xwing.DeriveKeyPair(priv)`, and
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

## 9. Test strategy

There is no draft-level HPKE test vector for the
`MLKEM768-X25519 + SHAKE256 + AES-256-GCM` ciphersuite as of 2026-04.
Until `draft-ietf-hpke-pq` publishes vectors or circl#553 lands in a
release, we validate in layers instead:

**X-Wing KEM correctness.** Trusted to `circl/kem/xwing` and its upstream
tests. We do not re-validate. If draft-connolly moves, `go get -u`
circl.

**HPKE key schedule structural cross-check** (the load-bearing test).
Because `internal/hpke/` is KDF-pluggable, we instantiate it with
HKDF-SHA256 in a test and compare byte-for-byte against
`circl/hpke.NewSender(KEM_XWING, KDF_HKDF_SHA256, AEAD_AES256GCM, ...)`
for a fixed `(seed, cek, info)` triple. This validates:

- The `0x647a` KEM suite_id bytes (`"KEM" || 0x64 0x7a`)
- Every RFC 9180 label string (`"eae_prk"`, `"shared_secret"`,
  `"secret"`, `"key"`, `"base_nonce"`, `"exp"`)
- The `labeled_info` framing (`I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`)
- The mode_base sequencing through `KeySchedule`
- The AEAD key and nonce derivation

Everything except the SHAKE256 primitive itself. If this test passes, a
SHAKE256 instantiation of the same code is overwhelmingly likely to be
correct too — the KDF primitive is swapped inside a single function, not
smeared across the key schedule.

**HPKE SHAKE256 self-consistency.** The production path (SHAKE256 KDF)
can only be tested sender-vs-receiver: encrypt a CEK, decrypt it, assert
they match. This catches obvious primitive-swap bugs (passing SHA3-256
where SHAKE256 is expected) but cannot catch a consistent label-spelling
error on both sides. The HKDF-SHA256 cross-check above is what catches
those.

**JWE round-trip.** For each of `HPKE-10-KE` and `HPKE-11-KE`, generate
a hybrid key pair, encrypt a random plaintext with
`jwe.Encrypt(..., jwe.WithKey(alg, pub))`, decrypt with the private key,
assert the plaintext matches. Exercises the full integration seam into
jwx.

**JWK round-trip.** Marshal a hybrid `jwk.Key` to JSON, unmarshal,
export to raw `*HybridPrivateKey`, encrypt again, verify. Assert
`len(pub) == 1216`, `len(priv) == 32`, `kty == "AKP"`, `alg` present.

**Pinned wire bytes.** Lock down the exact JWE produced by a fixed
`(seed, plaintext, rand)` triple in a test file. Any future tweak to
labels, info bytes, or suite constants will flag this test and force a
conscious re-review against the current draft revision.

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

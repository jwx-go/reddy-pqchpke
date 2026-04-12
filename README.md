# github.com/jwx-go/reddy-pqchpke/v4 [![Go Reference](https://pkg.go.dev/badge/github.com/jwx-go/reddy-pqchpke/v4.svg)](https://pkg.go.dev/github.com/jwx-go/reddy-pqchpke/v4)

Hybrid post-quantum HPKE key encryption for [github.com/lestrrat-go/jwx/v4](https://github.com/lestrrat-go/jwx), implementing a subset of [draft-reddy-cose-jose-pqc-hybrid-hpke](https://datatracker.ietf.org/doc/draft-reddy-cose-jose-pqc-hybrid-hpke/).

> **⚠ Experimental.** This module tracks an individual IETF submission that has **not been adopted by a working group**. Algorithm identifiers, KDF info bytes, and key encodings may change without notice as the draft evolves. Do not use this for interoperable production traffic yet.

This is a companion module to `github.com/lestrrat-go/jwx/v4` and has no stability guarantees of its own. Its API may change without notice to track changes in `github.com/lestrrat-go/jwx/v4` and in the underlying draft.

# Features

Importing this module registers the following with jwx/v4:

- **JWK**: AKP keys whose `alg` is a hybrid HPKE identifier (import, export)
- **HPKE**: Two key-encryption-mode HPKE algorithms built on a hand-rolled HPKE key schedule (SHAKE256 KDF) over an X25519+ML-KEM-768 hybrid KEM:
  - `HPKE-10-KE` — X25519+ML-KEM-768, SHAKE256, AES-256-GCM
  - `HPKE-11-KE` — X25519+ML-KEM-768, SHAKE256, ChaCha20Poly1305

All features activate via a blank import:

```go
import _ "github.com/jwx-go/reddy-pqchpke/v4"
```

# Scope

This module intentionally implements **only** the X25519+ML-KEM-768 HPKE-KE ciphersuites from the draft. Rationale:

- X25519+ML-KEM-768 is the only hybrid in the draft that can be built entirely on Go standard library (`crypto/mlkem`, `crypto/ecdh`, `golang.org/x/crypto/sha3`).
- It mirrors TLS 1.3's `X25519MLKEM768`, which is the hybrid PQ KEM most production deployments are asking about.
- Key-encryption (`-KE`) mode slots into jwx's existing HPKE-KE machinery with minimal surgery.

Out of scope (for now):
- HPKE Integrated Encryption mode (sealing the plaintext directly instead of a CEK).
- Other ciphersuites from the draft (ML-KEM+P-256, ML-KEM+P-384, pure ML-KEM-512/768/1024).
- Cross-implementation interop vectors (the draft publishes none yet).

# Why a separate module?

Two reasons:

1. **Draft stability.** `draft-reddy-cose-jose-pqc-hybrid-hpke` is an individual submission, not a working group document. The adopted JOSE PQ draft is `draft-ietf-jose-pqc-kem`, which jwx v4 implements in-tree. Keeping this experimental draft in a separate module prevents pre-adoption churn from affecting jwx's main API.
2. **Hand-rolled crypto.** This module implements the HPKE key schedule (RFC 9180 §5.1) on top of SHAKE256 from scratch, because Go's `crypto/hpke` only supports HKDF-based KDFs and DHKEM. Until stdlib grows extension points for custom KEMs and KDFs, that logic lives here rather than in the main module.

# Installation

```
go get github.com/jwx-go/reddy-pqchpke/v4
```

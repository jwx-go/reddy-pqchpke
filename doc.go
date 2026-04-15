// Package pqchpke provides hybrid post-quantum HPKE key encryption
// for the jwx library, implementing a subset of
// draft-reddy-cose-jose-pqc-hybrid-hpke.
//
// Specifically, it implements the X25519+ML-KEM-768 HPKE key-encryption
// (-KE) ciphersuites:
//
//   - HPKE-10-KE: X25519+ML-KEM-768, SHAKE256, AES-256-GCM
//   - HPKE-11-KE: X25519+ML-KEM-768, SHAKE256, ChaCha20Poly1305
//
// The draft is an individual IETF submission, not a working group
// document. Algorithm identifiers and wire formats may change without
// notice as the draft evolves. This module has no API stability
// guarantees of its own.
//
// To enable support, import the package for its side effects:
//
//	import _ "github.com/jwx-go/reddy-pqchpke/v4"
//
// This registers the hybrid AKP key types, the HPKE-10-KE / HPKE-11-KE
// key encryption algorithms, and the JWK importers/exporters needed to
// round-trip hybrid keys through jwx's JWK and JWE machinery.
//
// Registration runs from init() and will panic if any of the jwa, jwk, or
// jwebb registrations fail — for example, if another module has already
// claimed HPKE-10-KE or HPKE-11-KE. This is intentional: a partially
// registered extension would otherwise produce opaque "algorithm not found"
// errors deep inside jwe.Encrypt / jwe.Decrypt, so the failure is surfaced
// at program startup instead.
//
// # Why a separate module
//
// Go's crypto/hpke only supports HKDF-based KDFs and DHKEM, while the
// draft mandates a SHAKE256 KDF and a PQ/classical hybrid KEM. This
// module therefore reimplements the RFC 9180 HPKE key schedule on top of
// golang.org/x/crypto/sha3's cSHAKE256, and implements its own KEM
// combiner over crypto/mlkem and crypto/ecdh.
//
// Because the draft is pre-adoption, keeping this work in a separate
// module prevents its churn from affecting jwx's main public API.
package pqchpke

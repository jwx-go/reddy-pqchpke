// Package hpke implements the RFC 9180 HPKE key schedule for the
// MLKEM768-X25519 + SHAKE256 ciphersuites used by draft-reddy-cose-jose-pqc-hybrid-hpke.
//
// This is a hand-rolled implementation because Go stdlib crypto/hpke is
// HKDF-only and cloudflare/circl's released hpke package is also HKDF-only.
// The draft requires SHAKE256 as the HPKE KDF, which neither library supports
// as of 2026-04.
//
// The key schedule is KDF-pluggable so tests can instantiate it with
// HKDF-SHA256 and compare byte-for-byte against circl/hpke as a structural
// cross-check. Production code uses the SHAKE256 variant.
//
// TODO(circl#553): https://github.com/cloudflare/circl/pull/553 adds
// SHAKE256 KDF support to circl's HPKE. When it merges and lands in a
// release, delete this package and use circl/hpke directly.
package hpke

import (
	"crypto/cipher"
	"errors"
)

// ErrNotImplemented is returned by stubs that have not been implemented yet.
// It will disappear once the implementation lands — test failures should
// reference it during the TDD phase only.
var ErrNotImplemented = errors.New("pqchpke/internal/hpke: not implemented")

// KDF is the HPKE KDF interface. Only Extract and Expand are required for
// the mode_base key schedule we implement. Two instantiations exist:
// SHAKE256 (production, per draft-ietf-hpke-pq §5) and HKDF-SHA256 (tests,
// for the circl cross-check).
type KDF interface {
	// Nh returns the output length of the Extract function in bytes.
	Nh() int

	// Extract performs LabeledExtract per RFC 9180 §4.
	Extract(salt, ikm []byte) []byte

	// Expand performs LabeledExpand per RFC 9180 §4. L is the desired
	// output length in bytes.
	Expand(prk, info []byte, L int) []byte

	// ID returns the IANA HPKE KDF identifier used when building suite_id
	// bytes. SHAKE256 = 0x0011, HKDF-SHA256 = 0x0001.
	ID() uint16
}

// AEAD is the HPKE AEAD interface.
type AEAD interface {
	// Nk returns the AEAD key length in bytes.
	Nk() int

	// Nn returns the AEAD nonce length in bytes.
	Nn() int

	// Nt returns the AEAD tag length in bytes.
	Nt() int

	// New returns a cipher.AEAD initialized with the given key.
	New(key []byte) (cipher.AEAD, error)

	// ID returns the IANA HPKE AEAD identifier. AES-128-GCM = 0x0001,
	// AES-256-GCM = 0x0002, ChaCha20-Poly1305 = 0x0003.
	ID() uint16
}

// Ciphersuite bundles a KEM id (numeric, from the IANA HPKE KEM registry)
// with a KDF and AEAD. The KEM itself is not part of this struct because
// HPKE key-schedule only cares about the KEM's ID (for suite_id) and the
// 32-byte shared secret it produces. Callers run the KEM separately.
type Ciphersuite struct {
	KEMID uint16
	KDF   KDF
	AEAD  AEAD
}

// Seal performs HPKE-KE sealing for mode_base. Given the 32-byte shared
// secret already produced by the KEM, the JOSE HPKE info bytes (see
// draft-ietf-jose-hpke-encrypt §6.1), and the CEK to seal, it returns the
// AEAD-sealed ciphertext. This is intentionally narrow: it does not run
// the KEM itself, and it does not derive or expose an exporter secret.
func Seal(suite Ciphersuite, sharedSecret, info, cek []byte) ([]byte, error) {
	_ = suite
	_ = sharedSecret
	_ = info
	_ = cek
	return nil, ErrNotImplemented
}

// Open performs HPKE-KE opening for mode_base.
func Open(suite Ciphersuite, sharedSecret, info, sealed []byte) ([]byte, error) {
	_ = suite
	_ = sharedSecret
	_ = info
	_ = sealed
	return nil, ErrNotImplemented
}
